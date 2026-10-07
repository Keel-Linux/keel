# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.vip and keel.mesh.vipmsg: claims, their order, the state
file, and the VIP routed in and out of the overlay's file (0049)"""

import os
import shutil
import tempfile
import unittest
from datetime import timedelta

from vip_helpers import KEYS, NOW, VIP, address

from keel.mesh import signing, vipmsg
from keel.mesh import vip as vipstate
from keel.mesh.protocol import ProtocolError
from keel.mesh.vip import Claim, Held

MESH_HEX = bytes(range(16)).hex()


def claim(epoch: int, key: str = KEYS[0], vip: str = VIP) -> Claim:
    return Claim(vip, epoch, key, address(0), b"raw")


class Scratch(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)


class TestTheOrder(unittest.TestCase):
    def test_a_higher_epoch_wins(self):
        held = Held(VIP, claim(3))
        self.assertTrue(vipstate.newer(claim(4, KEYS[1]), held))
        self.assertFalse(vipstate.newer(claim(2, KEYS[1]), held))
        self.assertTrue(vipstate.newer(claim(1), None))
        self.assertTrue(vipstate.newer(claim(1), Held(VIP)))

    def test_the_same_epoch_goes_to_the_lower_key(self):
        low, high = sorted(KEYS[:2], key=lambda k: __import__(
            "base64").b64decode(k))
        self.assertTrue(vipstate.newer(claim(3, low), Held(VIP,
                                                         claim(3, high))))
        self.assertFalse(vipstate.newer(claim(3, high), Held(VIP,
                                                           claim(3, low))))
        self.assertFalse(vipstate.newer(claim(3, low), Held(VIP,
                                                          claim(3, low))))


class TestTheRole(unittest.TestCase):
    doc = {"appliance": {"name": "core", "vip": VIP}}

    def test_primary_is_the_holder_neither_fenced_nor_released(self):
        held = Held(VIP, claim(1, KEYS[0]))
        self.assertEqual(vipstate.role(self.doc, held, KEYS[0]), "primary")
        self.assertEqual(vipstate.role(self.doc, held, KEYS[1]), "replica")
        self.assertEqual(vipstate.role(self.doc, vipstate.fenced(held),
                                       KEYS[0]), "replica")
        self.assertEqual(vipstate.role(self.doc, vipstate.released(held),
                                       KEYS[0]), "replica")
        self.assertEqual(vipstate.role(self.doc, None, KEYS[0]), "replica")

    def test_a_node_that_declares_no_vip_has_no_role(self):
        self.assertIsNone(vipstate.role({}, None, KEYS[0]))
        self.assertIsNone(vipstate.declared({"appliance": "core"}))
        self.assertEqual(vipstate.declared(
            {"appliance": {"vip": f"{VIP}/128"}}), VIP)
        with self.assertRaises(ValueError):
            vipstate.address(7)
        self.assertFalse(Held(VIP).held_by(KEYS[0]))
        self.assertFalse(Held(VIP, claim(1)).held_by(None))


class TestTheFile(Scratch):
    def signed(self, epoch: int = 1) -> Claim:
        signing.ensure(self.root)
        return vipmsg.claim(self.root, MESH_HEX, KEYS[0], NOW, VIP, epoch,
                            address(0))

    def test_written_and_read_back(self):
        held = Held(VIP, self.signed(2), lease="77", released=True)
        vipstate.write(self.root, held)
        self.assertEqual(vipstate.read(self.root, VIP), held)
        self.assertEqual(vipstate.known(self.root), (VIP,))
        self.assertEqual(vipstate.holders_of(self.root), {VIP: KEYS[0]})
        mode = os.stat(os.path.join(self.root, vipstate.file_of(VIP)))
        self.assertEqual(mode.st_mode & 0o777, 0o600)

    def test_none_without_a_file_and_nothing_known(self):
        self.assertIsNone(vipstate.read(self.root, VIP))
        self.assertEqual(vipstate.known(self.root), ())
        self.assertEqual(vipstate.held_all(self.root), [])

    def test_a_damaged_file_is_refused_never_guessed(self):
        vipstate.ensure(self.root)
        for text in ("{", '{"vip": "fd00::1"}', '{"vip": "%s", "claim":'
                     ' "!!", "fenced": false, "lease": null}' % VIP):
            with open(os.path.join(self.root, vipstate.file_of(VIP)),
                      "w") as fob:
                fob.write(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                vipstate.read(self.root, VIP)
        self.assertEqual(vipstate.held_all(self.root), [])

    def test_other_files_are_not_vips(self):
        vipstate.ensure(self.root)
        for name in ("lock", "not-an-address.json"):
            open(os.path.join(self.root, vipstate.DIR, name), "w").close()
        self.assertEqual(vipstate.known(self.root), ())


class TestRouted(unittest.TestCase):
    overlay = {"address": f"{address(0)}/64", "peers": [
        {"public_key": KEYS[1], "allowed_ips": [f"{address(1)}/128"]},
        {"public_key": KEYS[2], "allowed_ips": [f"{address(2)}/128"]}]}

    def test_the_vip_goes_to_its_holder_s_peer_only(self):
        found = vipstate.routed(self.overlay, {VIP: KEYS[1]})
        self.assertEqual(found["peers"][0]["allowed_ips"],
                         [f"{address(1)}/128", f"{VIP}/128"])
        self.assertEqual(found["peers"][1], self.overlay["peers"][1])
        # the spec's document is never changed
        self.assertEqual(self.overlay["peers"][0]["allowed_ips"],
                         [f"{address(1)}/128"])
        self.assertEqual(vipstate.routed({"address": "x"}, {VIP: KEYS[1]}),
                         {"address": "x"})

    def test_read_back_without_it(self):
        routed = vipstate.routed(self.overlay, {VIP: KEYS[1]})
        self.assertEqual(vipstate.unrouted(routed, (VIP,)), self.overlay)
        self.assertEqual(vipstate.unrouted(routed, ()), routed)
        self.assertEqual(vipstate.unrouted({"address": "x"}, (VIP,)),
                         {"address": "x"})

    def test_the_problems_of_a_vip(self):
        self.assertIsNone(vipstate.problem(VIP, self.overlay))
        self.assertIn("outside", vipstate.problem("fd00:1::1",
                                                  self.overlay))
        self.assertIn("own", vipstate.problem(address(0), self.overlay))
        self.assertIn("routed at runtime",
                      vipstate.problem(address(1), self.overlay))
        self.assertIn("needs", vipstate.problem(VIP, {}))


class TestMessages(Scratch):
    def setUp(self):
        super().setUp()
        signing.ensure(self.root)

    def test_a_claim_is_signed_and_read_back(self):
        made = vipmsg.claim(self.root, MESH_HEX, KEYS[0], NOW, VIP, 3,
                            address(0))
        self.assertEqual((made.vip, made.epoch, made.holder, made.address),
                         (VIP, 3, KEYS[0], address(0)))
        message = vipmsg.loads(made.raw)
        self.assertTrue(message.verified(signing.public(self.root)))
        self.assertTrue(message.fresh(NOW + timedelta(minutes=4)))
        self.assertFalse(message.fresh(NOW + timedelta(minutes=6)))
        self.assertEqual(vipmsg.answer_claim(vipmsg.epoch_answer(made)),
                         made)
        self.assertIsNone(vipmsg.answer_claim(vipmsg.epoch_answer(None)))

    def test_what_is_not_a_message(self):
        good = vipmsg.signed(self.root, "epoch", MESH_HEX, KEYS[0], NOW,
                             {"vip": VIP})
        for data in (b"x" * 5000, b"[]", b'{"message": 1}',
                     good.replace(b'"epoch"', b'"other"'),
                     good.replace(b'"signature": "', b'"signature": "!')):
            with self.subTest(data=data[:40]), \
                    self.assertRaises(ProtocolError):
                vipmsg.loads(data)
        with self.assertRaises(ProtocolError):
            vipmsg.claim_of(good)
        message = vipmsg.loads(vipmsg.signed(
            self.root, "release", MESH_HEX, KEYS[0], NOW,
            {"vip": "x", "epoch": 0}))
        with self.assertRaises(ProtocolError):
            message.vip()
        with self.assertRaises(ProtocolError):
            message.epoch()
        with self.assertRaises(ProtocolError):
            vipmsg.claim_of(vipmsg.signed(self.root, "claim", MESH_HEX,
                                          KEYS[0], NOW, {"vip": VIP,
                                                         "epoch": 1}))
        for answer in (b'{"claim": 3}', b'{"claim": "!!"}'):
            with self.assertRaises(ProtocolError):
                vipmsg.answer_claim(answer)


if __name__ == "__main__":
    unittest.main()
