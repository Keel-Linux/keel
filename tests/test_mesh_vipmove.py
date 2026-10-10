# Copyright (c) 2026 KeelLinux maintainers
"""The VIP before etcd: promote, release, the announcement, the check,
and what the members' channel refuses (decision 0049), with a pair and
a third node in one process (tests/vip_helpers.py)"""

import json
import os
import unittest
import unittest.mock

from vip_helpers import KEYS, NOW, VIP, FakeNet, Pair, address

from keel import exits
from keel.mesh import signing, trust, vipmsg, vipnet, vipnode, vippromote
from keel.mesh import vip as vipstate
from keel.mesh.memberlink import LinkError
from keel.mesh.vipnode import VipError
from keel.network import wireguard

MESH_HEX = bytes(range(16)).hex()


class TestPromote(Pair):
    def promote(self, index: int, gone: bool = False) -> tuple[int, str]:
        said: list[str] = []
        code = vippromote.promote(self.all[index], gone, said.append)
        return code, "\n".join(said)

    def test_the_first_claim_is_epoch_one_and_every_peer_routes_it(self):
        self.nodes()
        code, said = self.promote(0)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("at epoch 1", said)
        self.assertTrue(self.carried(0))
        self.assertEqual((self.routed(1), self.routed(2)), (KEYS[0],) * 2)
        self.assertIsNone(self.routed(0))
        self.assertEqual(vipstate.role(self.all[0].node.document(),
                                       vipnode.current(self.all[0], VIP),
                                       KEYS[0]), "primary")
        # again: nothing to do
        code, said = self.promote(0)
        self.assertEqual(code, exits.OK)
        self.assertIn("holds", said)

    def test_a_planned_promote_releases_first(self):
        self.nodes()
        self.promote(0)
        code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("released by", said)
        self.assertIn("at epoch 2", said)
        self.assertEqual((self.carried(0), self.carried(1)), (False, True))
        self.assertEqual((self.routed(0), self.routed(2)), (KEYS[1],) * 2)
        # released, then the new claim taken: a replica, never fenced
        old = vipnode.current(self.all[0], VIP)
        self.assertFalse(old.released)
        self.assertFalse(old.fenced)
        self.assertEqual(old.holder, KEYS[1])
        self.assertIn("released by this node", self.text(0))

    def test_an_old_primary_that_does_not_answer_is_refused(self):
        self.nodes()
        self.promote(0)
        self.down.add(address(0))
        code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("--old-primary-gone", said)
        self.assertFalse(self.carried(1))
        self.assertEqual(self.routed(2), KEYS[0])

    def test_old_primary_gone_takes_it_and_the_old_one_drops_it_later(self):
        self.nodes()
        self.promote(0)
        self.down.add(address(0))
        code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("did not take the claim now", said)
        self.assertTrue(self.carried(1))
        self.assertTrue(self.carried(0))
        self.assertEqual(self.routed(2), KEYS[1])
        # it comes back: its check learns the newer claim, drops the VIP,
        # and is fenced: it never claims it again by itself
        self.down.clear()
        said = []
        self.assertEqual(vippromote.check(self.all[0], said.append),
                         exits.OK)
        self.assertFalse(self.carried(0))
        self.assertEqual(self.routed(0), KEYS[1])
        held = vipnode.current(self.all[0], VIP)
        self.assertTrue(held.fenced)
        self.assertIn("took epoch 2", "\n".join(said))
        self.assertEqual(vipstate.role(self.all[0].node.document(), held,
                                       KEYS[0]), "replica")

    def test_without_etcd_a_slow_old_primary_still_releases_first(self):
        """keel#108's safety review: without etcd nothing fences a live
        old primary, so its release is waited for with the channel's
        full timeout, never the 1.5 s bound (a slow but live old primary
        must not stay writable beside the new one)"""
        import time
        from unittest import mock
        self.nodes()
        self.promote(0)
        real = self.all[1].exchange

        def slow(at: str, iface: str, body: bytes) -> bytes:
            if at == address(0):
                time.sleep(0.6)
            return real(at, iface, body)
        self.all[1].exchange = slow
        with mock.patch.object(vipnode, "GONE_BOUND", 0.3):
            code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertIn(f"released by {address(0)}", said)
        self.assertNotIn("no answer within", said)
        self.assertFalse(self.carried(0))
        self.assertTrue(self.carried(1))

    def slow(self, index: int, host: str, seconds: float,
             answers: bool = True):
        """Node `index`'s exchanges with `host` take `seconds`, then
        answer, or fail as a dead node does"""
        import time as clock
        real = self.all[index].exchange

        def exchange(at: str, iface: str, body: bytes) -> bytes:
            if at == host:
                clock.sleep(seconds)
                if not answers:
                    raise LinkError(f"[{at}]:51821 through {iface}: timed out")
            return real(at, iface, body)
        self.all[index].exchange = exchange

    def test_a_member_outside_the_pair_down_does_not_hold_up_the_promote(
            self):
        """keel#137: one unreachable member outside the pair added two
        10 s timeouts to every promote. Only the other member of the
        pair gates the handover; the others are told after, in the
        background, and what they said is logged"""
        import time as clock
        from unittest import mock
        self.nodes()
        self.promote(0)
        self.slow(1, address(2), 1.0, answers=False)
        started = clock.monotonic()
        with mock.patch.object(vippromote, "BACKGROUND", True):
            code, said = self.promote(1)
        took = clock.monotonic() - started
        self.assertEqual(code, exits.OK, said)
        self.assertLess(took, 0.8, said)
        self.assertTrue(self.carried(1))
        self.assertFalse(self.carried(0))
        self.assertIn(f"released by {address(0)}", said)
        self.assertIn("taken by the other member of the pair", said)
        self.assertEqual(vippromote.announced(), 1)
        self.assertIn(f"vip {VIP}: {address(2)}: unreachable",
                      self.text(1))

    def test_a_member_outside_the_pair_still_learns_the_claim_after(self):
        from unittest import mock
        self.nodes()
        self.promote(0)
        self.slow(1, address(2), 0.5)
        with mock.patch.object(vippromote, "BACKGROUND", True):
            code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertEqual(vippromote.announced(), 1)
        self.assertEqual(self.routed(2), KEYS[1])
        self.assertIn(f"vip {VIP}: {address(2)}: applied", self.text(1))

    def kinds(self, index: int) -> list[tuple[str, str]]:
        """Every message node `index` sends: (to, kind)"""
        real = self.all[index].exchange
        sent: list[tuple[str, str]] = []

        def exchange(at: str, iface: str, body: bytes) -> bytes:
            sent.append((at, vipmsg.loads(body).kind))
            return real(at, iface, body)
        self.all[index].exchange = exchange
        return sent

    def test_a_planned_promote_asks_no_epoch_it_knows(self):
        """Two round trips with the other member, not three: the replica
        holds the primary's claim, so it asks the release at the next
        epoch at once"""
        self.nodes()
        self.promote(0)
        sent = self.kinds(1)
        code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertEqual([kind for at, kind in sent if at == address(0)],
                         [vipmsg.RELEASE, vipmsg.CLAIM])

    def test_a_release_refused_as_stale_asks_the_epoch_and_again(self):
        """B missed A's newer claim: A refuses the release as stale, B
        asks its epoch, and asks the release again at the next one"""
        self.nodes()
        self.promote(0)
        self.down.add(address(1))
        self.promote(0)
        held = vipnode.current(self.all[0], VIP)
        self.down.clear()
        # A claims again at a newer epoch while B is away
        made = vipnode.signed_claim(self.all[0], VIP, held.epoch + 1)
        vipnode.hold(self.all[0], made, True)
        sent = self.kinds(1)
        code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        kinds = [kind for at, kind in sent if at == address(0)]
        self.assertEqual(kinds, [vipmsg.RELEASE, vipmsg.EPOCH,
                                 vipmsg.RELEASE, vipmsg.CLAIM], said)
        self.assertEqual(vipnode.current(self.all[1], VIP).epoch,
                         held.epoch + 2)
        self.assertFalse(self.carried(0))

    def test_the_other_member_refusing_the_claim_stops_it(self):
        self.nodes()
        self.promote(0)
        real = self.all[1].exchange
        seen: list[str] = []

        def exchange(at: str, iface: str, body: bytes) -> bytes:
            message = vipmsg.loads(body)
            seen.append(message.kind)
            if at == address(0) and message.kind == vipmsg.CLAIM:
                raise LinkError(f"[{at}]:51821 refused: stale claim")
            return real(at, iface, body)
        self.all[1].exchange = exchange
        code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED, said)
        self.assertIn("did not take the claim", said)
        self.assertFalse(self.carried(1))
        self.assertTrue(vipnode.current(self.all[1], VIP).released)

    def test_a_first_promote_with_the_other_member_down_is_refused(self):
        self.nodes()
        self.down.add(address(1))
        code, said = self.promote(0)
        self.assertEqual(code, exits.MESH_REFUSED, said)
        self.assertFalse(self.carried(0))
        # --old-primary-gone: the operator's word, as before
        code, said = self.promote(0, gone=True)
        self.assertEqual(code, exits.OK, said)

    def test_a_node_that_declares_no_vip_promotes_nothing(self):
        self.nodes()
        code, said = self.promote(2)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("declares no appliance.vip", said)

    def test_a_vip_outside_the_prefix_is_refused(self):
        self.nodes(vips=("fd00:1::5", "fd00:1::5"))
        code, said = self.promote(0)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("outside", said)

    def test_a_vip_that_cannot_be_carried_fails(self):
        self.nodes()
        self.nets[0].fail[("ip", "-6", "addr", "replace")] = "ip: no"
        code, said = self.promote(0)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("could not be added", said)

    def test_no_mesh_identity_is_said(self):
        self.nodes()
        os.remove(os.path.join(self.all[0].root, "var/lib/keel/mesh/"
                               "identity"))
        code, said = self.promote(0)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("mesh identity", said)

    def test_a_peer_that_does_not_answer_is_said(self):
        self.nodes()
        self.down.add(address(2))
        code, said = self.promote(0)
        self.assertEqual(code, exits.OK)
        # a member outside the pair is told after the handover, and what
        # it said is logged (keel#137)
        self.assertIn(f"{address(2)}: unreachable: [{address(2)}]:51821",
                      self.text(0))


class TestTheChannelRefuses(Pair):
    def setUp(self):
        super().setUp()
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)

    def answer(self, index: int, body: bytes, sender: int):
        from keel.mesh import vipserve
        return vipserve.answer(self.all[index], body, KEYS[sender])

    def message(self, sender: int, kind: str, body: dict,
                mesh: str = MESH_HEX, now=NOW) -> bytes:
        return vipmsg.signed(self.all[sender].root, kind, mesh, KEYS[sender],
                             now, body)

    def test_a_stale_claim(self):
        for index in (1, 0):
            vippromote.promote(self.all[index], False, lambda line: None)
        old = vipnode.signed_claim(self.all[1], VIP, 2)
        found = self.answer(2, old.raw, 1)
        self.assertEqual(found.status, 409)
        self.assertIn(b"stale claim", found.body)
        self.assertEqual(self.routed(2), KEYS[0])

    def test_the_same_claim_again_is_known(self):
        held = vipnode.current(self.all[2], VIP)
        found = self.answer(2, held.claim.raw, 0)
        self.assertEqual(found.status, 200)
        self.assertEqual(json.loads(found.body)["applied"], False)

    def test_a_claim_from_another_sender_than_its_holder(self):
        made = vipnode.signed_claim(self.all[1], VIP, 5)
        found = self.answer(2, made.raw, 0)
        self.assertEqual(found.status, 403)
        self.assertIn(b"not the sender", found.body)

    def test_a_claim_for_another_mesh_or_unsigned(self):
        found = self.answer(2, self.message(1, "claim", {
            "vip": VIP, "epoch": 5, "address": address(1)},
            mesh="ab" * 16), 1)
        self.assertEqual(found.status, 403)
        store = trust.load(self.all[2].root)
        store.members[KEYS[1]].sign_key = signing.public(self.all[0].root)
        trust.save(self.all[2].root, store)
        found = self.answer(2, self.message(1, "claim", {
            "vip": VIP, "epoch": 5, "address": address(1)}), 1)
        self.assertEqual(found.status, 403)
        self.assertIn(b"not signed", found.body)

    def test_a_claim_at_another_address_or_off_the_prefix(self):
        found = self.answer(2, self.message(1, "claim", {
            "vip": VIP, "epoch": 5, "address": address(0)}), 1)
        self.assertEqual(found.status, 403)
        self.assertIn(b"not a peer", found.body)
        found = self.answer(2, self.message(1, "claim", {
            "vip": "fd00:9::1", "epoch": 5, "address": address(1)}), 1)
        self.assertEqual(found.status, 403)
        self.assertIn(b"outside", found.body)

    def test_malformed(self):
        found = self.answer(2, b"{", 1)
        self.assertEqual(found.status, 400)
        found = self.answer(2, self.message(1, "claim", {"vip": VIP}), 1)
        self.assertEqual(found.status, 400)

    def test_a_release_only_from_the_pair_fresh_and_newer(self):
        found = self.answer(2, self.message(1, "release", {
            "vip": VIP, "epoch": 2}), 1)
        self.assertEqual(found.status, 403)
        self.assertIn(b"only the nodes of the pair", found.body)
        found = self.answer(0, self.message(1, "release", {
            "vip": VIP, "epoch": 1}), 1)
        self.assertEqual(found.status, 409)
        from datetime import timedelta
        found = self.answer(0, self.message(1, "release", {
            "vip": VIP, "epoch": 2}, now=NOW - timedelta(hours=1)), 1)
        self.assertEqual(found.status, 403)
        self.assertIn(b"stale", found.body)
        self.assertTrue(self.carried(0))

    def test_a_release_that_cannot_drop_the_address(self):
        self.nets[0].fail[("ip", "-6", "addr", "del")] = "ip: busy"
        found = self.answer(0, self.message(1, "release", {
            "vip": VIP, "epoch": 2}), 1)
        self.assertEqual(found.status, 503)
        self.assertFalse(vipnode.current(self.all[0], VIP).released)

    def test_the_epoch_is_answered(self):
        found = self.answer(2, self.message(1, "epoch", {"vip": VIP}), 1)
        self.assertEqual(found.status, 200)
        self.assertEqual(vipmsg.answer_claim(found.body).epoch, 1)


class TestTheCheck(Pair):
    def check(self, index: int) -> str:
        said: list[str] = []
        self.assertEqual(vippromote.check(self.all[index], said.append),
                         exits.OK)
        return "\n".join(said)

    def test_the_holder_carries_it_again_after_a_restart(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        self.nets[0].addresses.clear()
        self.assertIn("carried again", self.check(0))
        self.assertTrue(self.carried(0))

    def test_carried_again_the_state_is_written_again_so_follow_runs(self):
        """keel-database-follow.path watches the VIP's state: the
        address carried again is the proof follow waits for (keel#104)"""
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        self.nets[0].addresses.clear()
        written: list = []
        real = vipstate.write

        def spy(root, held):
            written.append(held)
            real(root, held)
        with unittest.mock.patch.object(vipstate, "write", side_effect=spy):
            self.check(0)
            self.assertEqual(len(written), 1, written)
            self.assertTrue(written[0].holds(KEYS[0]))
            # carried already: nothing written, so no follow for nothing
            self.check(0)
            self.assertEqual(len(written), 1, written)

    def test_not_carried_again_when_no_peer_answers(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        self.nets[0].addresses.clear()
        self.down.update({address(1), address(2)})
        self.check(0)
        self.assertFalse(self.carried(0))

    def test_a_vip_not_held_is_dropped_and_the_table_set_again(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        self.nets[1].addresses.append(f"{VIP}/128")
        self.nets[2].routes[KEYS[1]].append(f"{VIP}/128")
        self.assertIn("dropped", self.check(1))
        self.assertFalse(self.carried(1))
        self.check(2)
        self.assertEqual(self.routed(2), KEYS[0])

    def test_a_damaged_file_is_said(self):
        self.nodes()
        vipstate.ensure(self.all[0].root)
        with open(os.path.join(self.all[0].root, vipstate.file_of(VIP)),
                  "w") as fob:
            fob.write("{")
        said: list[str] = []
        self.assertEqual(vippromote.check(self.all[0], said.append),
                         exits.APPLY_FAILED)
        self.assertIn("damaged", "\n".join(said))


class TestStatus(Pair):
    def test_the_lines(self):
        self.nodes()
        self.assertIn("vip: none", vippromote.lines(self.all[2], True)[0])
        vippromote.promote(self.all[0], False, lambda line: None)
        primary = "\n".join(vippromote.lines(self.all[0], True))
        self.assertIn("role: primary", primary)
        self.assertIn("carried here: yes", primary)
        third = "\n".join(vippromote.lines(self.all[2], True))
        self.assertIn("another pair's", third)
        self.assertIn(f"routed to: {KEYS[0]}", third)
        self.nets[2].down = True
        offline = "\n".join(vippromote.lines(self.all[2], False))
        self.assertIn("not the live system", offline)
        self.assertIn("unknown", "\n".join(vippromote.lines(self.all[2],
                                                            True)))

    def test_fenced_released_and_damaged(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        vippromote.promote(self.all[1], False, lambda line: None)
        held = vipnode.current(self.all[0], VIP)
        vipstate.write(self.all[0].root, vipstate.released(held))
        self.assertIn("released:", "\n".join(vippromote.lines(self.all[0],
                                                              False)))
        held = vipnode.current(self.all[1], VIP)
        vipstate.write(self.all[1].root, vipstate.fenced(held))
        self.assertIn("fenced:", "\n".join(vippromote.lines(self.all[1],
                                                            False)))
        with open(os.path.join(self.all[1].root, vipstate.file_of(VIP)),
                  "w") as fob:
            fob.write("{")
        self.assertIn("damaged", "\n".join(vippromote.lines(self.all[1],
                                                            False)))
        with open(self.all[1].node.path, "w") as fob:
            fob.write("version: [")
        self.assertIn("vip:", vippromote.lines(self.all[1], False)[0])


class TestTheNet(unittest.TestCase):
    def test_a_table_that_does_not_answer(self):
        net = FakeNet({})
        net.down = True
        self.assertIsNone(vipnet.carried("wg0", VIP, net.output))
        self.assertEqual(vipnet.route("wg0", {}, VIP, None, net.run,
                                      net.output)[0][:7], "wg show")
        self.assertIsNone(vipnet.routed_to("wg0", VIP, net.output))

    def test_a_failed_wg_set_is_said(self):
        net = FakeNet({KEYS[1]: [f"{address(1)}/128"]})
        net.fail[("wg", "set")] = "wg: no"
        overlay = {"peers": [{"public_key": KEYS[1],
                              "allowed_ips": [f"{address(1)}/128"]}]}
        self.assertEqual(vipnet.route("wg0", overlay, VIP, KEYS[1], net.run,
                                      net.output), ["wg: no"])

    def test_the_file_is_written_only_when_it_differs(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        overlay = {"address": f"{address(0)}/64", "peers": [
            {"public_key": KEYS[1], "allowed_ips": [f"{address(1)}/128"]}]}
        self.assertIsNone(vipnet.written(root, overlay))
        os.makedirs(os.path.join(root, "etc/wireguard"))
        conf = os.path.join(root, "etc/wireguard/wg0.conf")
        with open(conf, "w") as fob:
            fob.write(wireguard.render(overlay))
        self.assertIsNone(vipnet.written(root, overlay))
        vipstate.write(root, vipstate.Held(VIP, vipstate.Claim(
            VIP, 1, KEYS[1], address(1), b"")))
        # read() needs a real claim; the routing reads the holders
        from unittest import mock
        with mock.patch.object(vipstate, "holders_of",
                               return_value={VIP: KEYS[1]}):
            self.assertIsNone(vipnet.written(root, overlay))
        with open(conf) as fob:
            self.assertIn(f"{VIP}/128", fob.read())
        os.chmod(os.path.join(root, "etc/wireguard"), 0o500)
        self.addCleanup(os.chmod, os.path.join(root, "etc/wireguard"),
                        0o700)
        if os.geteuid() != 0:
            self.assertIn("wg0.conf", vipnet.written(root, overlay))
        os.chmod(conf, 0)
        if os.geteuid() != 0:
            self.assertIn("wg0.conf", vipnet.written(root, overlay))


class TestTheNodeErrors(Pair):
    def test_no_key_and_no_overlay(self):
        self.nodes()
        here = self.all[0]
        here.node.key = None
        with self.assertRaises(VipError):
            here.own_key()
        with open(here.node.path, "w") as fob:
            fob.write("version: 1\n")
        with self.assertRaises(VipError):
            here.own_address()

    def test_a_damaged_identity(self):
        self.nodes()
        with open(os.path.join(self.all[0].root,
                               "var/lib/keel/mesh/identity"), "w") as fob:
            fob.write("nonsense\n")
        with self.assertRaises(VipError):
            self.all[0].mesh_id()

    def test_hold_refuses_an_older_claim_than_it_knows(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        vippromote.promote(self.all[1], False, lambda line: None)
        old = vipnode.signed_claim(self.all[0], VIP, 1)
        with self.assertRaises(VipError):
            vipnode.hold(self.all[0], old, True)

    def test_newest_of_none_and_epochs_without_peers(self):
        self.assertIsNone(vipnode.newest([]))
        self.nodes(count=1)
        self.assertEqual(vipnode.epochs(self.all[0], VIP), {})
        made = vipmsg.claim(self.all[0].root, MESH_HEX, KEYS[0], NOW, VIP, 1,
                            address(0))
        self.assertEqual(vipnode.announce(self.all[0], made), {})
        with self.assertRaisesRegex(VipError, "no pair record"):
            vipnode.signed_claim(self.all[0], VIP, 1)

    def test_an_epoch_answer_for_another_vip_or_unverified(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        other = "fd00:6b65:1::200"
        vipstate.write(self.all[1].root, vipstate.Held(
            other, vipnode.current(self.all[1], VIP).claim))
        found = vipnode.epochs(self.all[1], other)
        self.assertEqual(set(found.values()) - {None}, set())


if __name__ == "__main__":
    unittest.main()


class TestTheReleaseQuiescesTheDatabase(Pair):
    """keel#138: a write in flight at the release lost its answer: the
    old primary dropped the VIP while the commit waited for the
    replica's acknowledgement. The database turns read only first,
    which waits for the commits in flight (the replica is still
    connected), and only then is the address dropped"""

    def promote(self, index: int) -> tuple[int, str]:
        said: list[str] = []
        code = vippromote.promote(self.all[index], False, said.append)
        return code, "\n".join(said)

    def test_the_database_is_read_only_before_the_address_goes(self):
        from unittest import mock
        from keel.mesh import vipserve
        self.nodes()
        self.promote(0)
        order: list[str] = []
        node = self.all[0].node
        real = node.run

        def run(argv):
            if argv[:4] == ("ip", "-6", "addr", "del"):
                order.append("drop")
            return real(argv)
        node.run = run
        with mock.patch.object(vipserve, "quiesced",
                               side_effect=lambda here, vip:
                               order.append("read only")):
            code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertEqual(order[:2], ["read only", "drop"], order)

    def test_quiesced_asks_the_database_only_where_one_is_declared(self):
        from unittest import mock
        from keel.mesh import vipserve
        self.nodes()
        here = self.all[0]
        with mock.patch("keel.system.dbreadonly.quiesce",
                        return_value=None) as asked:
            vipserve.quiesced(here, VIP)
        asked.assert_not_called()
        doc = here.node.document()
        doc["database"] = {"server": {"engine": "mariadb",
                                      "role": "primary"}}
        here.node.write(doc)
        with mock.patch("keel.system.dbreadonly.quiesce",
                        return_value=None) as asked:
            vipserve.quiesced(here, VIP)
        asked.assert_called_once()
        self.assertIn("read only before the release", self.text(0))
        with mock.patch("keel.system.dbreadonly.quiesce",
                        return_value="ERROR 2002"):
            vipserve.quiesced(here, VIP)
        self.assertIn("ERROR 2002); the release goes on", self.text(0))
