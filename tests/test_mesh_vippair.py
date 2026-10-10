# Copyright (c) 2026 KeelLinux maintainers
"""The pair record, and what it refuses (decision 0049, third round,
point 3): only the two nodes it names, signed by both, hold the VIP"""

import json
import os
from datetime import timedelta

from vip_helpers import KEYS, MESH, NOW, VIP, Pair, address

from keel import exits
from keel.mesh import (
    commands,
    trust,
    vipmsg,
    vipnode,
    vippair,
    vippromote,
    vipserve,
)
from keel.mesh import vip as vipstate
from keel.mesh.protocol import ProtocolError

MESH_HEX = MESH.hex()


def promote(here, gone=False) -> tuple[int, str]:
    said: list[str] = []
    code = vippromote.promote(here, gone, said.append)
    return code, "\n".join(said)


class TestTheRecord(Pair):
    def test_keel_vip_pair_signs_and_keeps_it_on_both(self):
        self.nodes(paired=False)
        said: list[str] = []
        self.assertEqual(vippromote.pair(self.all[0], address(1),
                                         said.append), exits.OK, said)
        mine = vippair.read(self.all[0].root, VIP)
        theirs = vippair.read(self.all[1].root, VIP)
        self.assertEqual(mine, theirs)
        self.assertEqual(len(mine.signatures), 2)
        self.assertTrue(mine.has(KEYS[0]) and mine.has(KEYS[1]))
        self.assertIn("signed by both", said[0])
        self.assertIsNone(vippair.read(self.all[2].root, VIP))
        # the third node learns it from the first claim, and keeps it
        code, out = promote(self.all[0])
        self.assertEqual(code, exits.OK, out)
        self.assertEqual(vippair.read(self.all[2].root, VIP), mine)

    def test_pair_refusals(self):
        self.nodes(vips=(VIP, "fd00:6b65:1::ffff:200"), paired=False)
        said: list[str] = []
        self.assertEqual(vippromote.pair(self.all[0], address(1),
                                         said.append), exits.MESH_REFUSED)
        self.assertIn("appliance.vip is fd00:6b65:1::ffff:200", said[-1])
        self.assertEqual(vippromote.pair(self.all[0], "fd00:6b65:1::77",
                                         said.append), exits.MESH_REFUSED)
        self.assertIn("no peer", said[-1])
        self.assertEqual(vippromote.pair(self.all[2], address(0),
                                         said.append), exits.MESH_REFUSED)
        self.assertIn("declares no appliance.vip", said[-1])

    def test_a_vip_that_is_a_member_s_address_or_off_the_range(self):
        """a VIP is an address of the overlay's top /112, no region's
        (0051, keel#97): the members may be in two regions"""
        for vip, why in ((address(1), "own overlay address"),
                         ("fd00:6b65:1::200", "outside the VIP range"),
                         ("fd00:6b65:1::ffff:0", "host 0")):
            with self.subTest(vip=vip):
                self.setUp()
                self.nodes(vips=(vip, vip), paired=False)
                said: list[str] = []
                self.assertEqual(vippromote.pair(self.all[0], address(1),
                                                 said.append),
                                 exits.MESH_REFUSED)
                self.assertIn(why, said[-1])
                self.doCleanups()

    def test_the_countersignature_is_refused_unless_both_and_fresh(self):
        self.nodes(paired=False)
        record = vippair.sign(self.all[0].root, vippair.made(
            MESH_HEX, VIP, (KEYS[0], KEYS[1])), KEYS[0])

        def ask(index, sender, pair, now=NOW):
            body = vipmsg.signed(self.all[sender].root, "pair", MESH_HEX,
                                 KEYS[sender], now, {"pair": pair.dumps()})
            return vipserve.answer(self.all[index], body, KEYS[sender])
        self.assertEqual(ask(2, 0, record).status, 403)
        self.assertEqual(ask(1, 0, record, NOW - timedelta(hours=1)).status,
                         403)
        unsigned = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1]))
        found = ask(1, 0, unsigned)
        self.assertEqual(found.status, 403)
        self.assertIn(b"not signed by its sender", found.body)
        found = ask(1, 0, record)
        self.assertEqual(found.status, 200)
        both = vippair.loads(json.loads(found.body)["pair"])
        self.assertEqual(len(both.signatures), 2)
        # a record naming other members for the same VIP is refused
        other = vippair.sign(self.all[2].root, vippair.made(
            MESH_HEX, VIP, (KEYS[1], KEYS[2])), KEYS[2])
        found = ask(1, 2, other)
        self.assertEqual(found.status, 409)
        self.assertIn(b"another pair", found.body)

    def test_a_trust_root_s_signature_stands_for_the_members(self):
        self.nodes(paired=False)
        record = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1]))
        by_root = vippair.sign(self.all[2].root, record, KEYS[2])
        here = self.all[0]
        self.assertIsNone(vippair.problem(by_root, vipnode.signer_of(here),
                                          vipnode.trust_roots(here)))
        store = trust.load(here.root)
        for one in store.members.values():
            one.root = False
        trust.save(here.root, store)
        self.assertIn("not signed by", vippair.problem(
            by_root, vipnode.signer_of(here), vipnode.trust_roots(here)))
        with open(os.path.join(here.root, "var/lib/keel/mesh/trust.json"),
                  "w") as fob:
            fob.write("{")
        self.assertEqual(vipnode.trust_roots(here), set())

    def test_what_is_not_a_record(self):
        good = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1])).dumps()
        for bad in (1, {"record": 1, "signatures": {}},
                    {**good, "signatures": {str(n): "x" for n in range(5)}},
                    {**good, "record": {**good["record"],
                                        "members": [KEYS[0], KEYS[0]]}},
                    {**good, "record": {**good["record"], "vip": "x"}},
                    {**good, "record": {**good["record"], "members": list(
                        reversed(good["record"]["members"]))}},
                    {**good, "signatures": {"x": "y"}},
                    {**good, "signatures": {KEYS[0]: "!"}}):
            with self.subTest(bad=str(bad)[:60]), \
                    self.assertRaises(ProtocolError):
                vippair.loads(bad)

    def test_a_damaged_kept_record(self):
        self.nodes()
        with open(os.path.join(self.all[0].root, vippair.file_of(VIP)),
                  "w") as fob:
            fob.write("{")
        with self.assertRaises(ValueError):
            vippair.read(self.all[0].root, VIP)
        code, said = promote(self.all[0])
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("damaged", said)


class TestClaimsAgainstTheRecord(Pair):
    def test_no_record_no_promote(self):
        self.nodes(paired=False)
        code, said = promote(self.all[0])
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("keel vip pair", said)

    def test_a_trusted_member_outside_the_pair_cannot_claim(self):
        self.nodes()
        self.assertEqual(promote(self.all[0])[0], exits.OK)
        pair = vippair.read(self.all[0].root, VIP)
        made = vipmsg.claim(self.all[2].root, MESH_HEX, KEYS[2], NOW, VIP, 2,
                            address(2), pair)
        found = vipserve.answer(self.all[1], made.raw, KEYS[2])
        self.assertEqual(found.status, 403)
        self.assertIn(b"not a member of the pair", found.body)
        bare = vipmsg.claim(self.all[2].root, MESH_HEX, KEYS[2], NOW, VIP, 2,
                            address(2))
        found = vipserve.answer(self.all[1], bare.raw, KEYS[2])
        self.assertIn(b"no pair record", found.body)
        self.assertEqual(self.routed(1), KEYS[0])

    def test_a_record_of_its_own_making_is_refused(self):
        """the third node signs a record naming itself with the replica:
        the replica never signed it"""
        self.nodes()
        promote(self.all[0])
        forged = vippair.sign(self.all[2].root, vippair.made(
            MESH_HEX, VIP, (KEYS[1], KEYS[2])), KEYS[2])
        store = trust.load(self.all[0].root)
        store.members[KEYS[2]].root = False
        trust.save(self.all[0].root, store)
        made = vipmsg.claim(self.all[2].root, MESH_HEX, KEYS[2], NOW, VIP, 2,
                            address(2), forged)
        found = vipserve.answer(self.all[0], made.raw, KEYS[2])
        self.assertEqual(found.status, 403)
        self.assertTrue(b"not signed by" in found.body or
                        b"another pair" in found.body, found.body)
        self.assertTrue(self.carried(0))

    def test_an_epoch_jump_is_refused(self):
        self.nodes()
        promote(self.all[0])
        far = vipnode.signed_claim(self.all[1], VIP,
                                   2 + vipnode.MAX_STEP)
        found = vipserve.answer(self.all[2], far.raw, KEYS[1])
        self.assertEqual(found.status, 403)
        self.assertIn(b"jumps", found.body)
        near = vipnode.signed_claim(self.all[1], VIP, 1 + vipnode.MAX_STEP)
        self.assertEqual(vipserve.answer(self.all[2], near.raw,
                                         KEYS[1]).status, 200)

    def test_a_release_only_from_the_other_member(self):
        self.nodes()
        promote(self.all[0])
        # the third node, a trusted member, is no member of the pair
        body = vipmsg.signed(self.all[2].root, "release", MESH_HEX, KEYS[2],
                             NOW, {"vip": VIP, "epoch": 2})
        found = vipserve.answer(self.all[0], body, KEYS[2])
        self.assertEqual(found.status, 403)
        self.assertIn(b"not the other member", found.body)
        self.assertTrue(self.carried(0))


class TestPromoteNeedsAMajority(Pair):
    def test_refused_by_every_peer_it_is_not_carried(self):
        self.nodes()
        promote(self.all[0])
        # B lost A's claim but A and C hold epoch 1: B's claim at 1 loses
        # to theirs only on the key's order; force refusals instead
        for index in (0, 2):
            store = trust.load(self.all[index].root)
            store.members[KEYS[1]].sign_key = None
            trust.save(self.all[index].root, store)
        self.down.clear()
        code, said = promote(self.all[1], gone=True)
        self.assertEqual(code, exits.MESH_REFUSED, said)
        self.assertIn("not a majority", said)
        self.assertFalse(self.carried(1))
        self.assertEqual(vipstate.role(self.all[1].node.document(),
                                       vipnode.current(self.all[1], VIP),
                                       KEYS[1]), "replica")

    def test_a_two_node_mesh_with_the_old_primary_gone(self):
        """the only peer is the old primary: none answers, and the
        operator's flag is the acceptance"""
        self.nodes(count=2)
        self.assertEqual(promote(self.all[0])[0], exits.OK)
        self.down.add(address(0))
        code, said = promote(self.all[1])
        self.assertEqual(code, exits.MESH_REFUSED, said)
        self.assertFalse(self.carried(1))
        code, said = promote(self.all[1], gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(1))
        # the old primary comes back, learns the newer claim and drops it
        self.down.clear()
        vippromote.check(self.all[0], lambda line: None)
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.current(self.all[0], VIP).fenced)

    def test_no_peer_answering_is_no_majority(self):
        self.nodes()
        self.down.update({address(1), address(2)})
        code, said = promote(self.all[0])
        self.assertEqual(code, exits.MESH_REFUSED)
        # the other member of the pair gates the handover (keel#137)
        self.assertIn("did not take the claim", said)
        self.assertFalse(self.carried(0))

    def test_a_carry_that_fails_after_the_majority(self):
        self.nodes()
        self.nets[0].fail[("ip", "-6", "addr", "replace")] = "ip: no"
        code, said = promote(self.all[0])
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("could not be added", said)


class TestTheAllocator(Pair):
    def test_declared_and_known_vips_are_reserved(self):
        self.nodes()
        promote(self.all[0])
        doc = self.all[2].node.document()
        self.assertEqual(commands.reserved_vips(self.all[2].root, doc),
                         (VIP,))
        self.assertEqual(commands.reserved_vips(
            self.all[0].root, {"appliance": {"vip": "fd00:6b65:1::ffff:300"}}),
            (VIP, "fd00:6b65:1::ffff:300"))
        self.assertEqual(commands.reserved_vips(
            self.parent, {"appliance": {"vip": 3}}), ())


class TestRecordEdges(Pair):
    def test_records_checked_without_trust_roots(self):
        self.nodes()
        here = self.all[2]
        pair = vippair.read(self.all[0].root, VIP)
        self.assertIsNone(vippair.problem(pair, vipnode.signer_of(here),
                                          set()))
        self.assertIn("own overlay address", vippair.placed(
            vippair.made(MESH_HEX, address(2), (KEYS[0], KEYS[1])),
            {KEYS[2]: address(2)}, vipnode.prefix(here)))
        other = vippair.made("ab" * 16, VIP, (KEYS[0], KEYS[1]))
        self.assertIn("another mesh", vipnode.record_problem(here, other))
        unsigned = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1]))
        self.assertIn("not signed", vipnode.record_problem(here, unsigned))
        vipstate.ensure(here.root)
        with open(os.path.join(here.root, vippair.file_of(VIP)),
                  "w") as fob:
            fob.write("{")
        self.assertIn("damaged", vipnode.record_problem(here, pair))

    def test_a_damaged_state_and_a_record_that_names_others(self):
        self.nodes()
        promote(self.all[0])
        here = self.all[2]
        with open(os.path.join(here.root, vipstate.file_of(VIP)),
                  "w") as fob:
            fob.write("{")
        made = vipnode.signed_claim(self.all[1], VIP, 2)
        self.assertIn("damaged", vipnode.stepped(here, made))
        # B keeps a record that does not name it: it signs no claim
        os.remove(os.path.join(self.all[1].root, vippair.file_of(VIP)))
        vippair.write(self.all[1].root, vippair.made(
            MESH_HEX, VIP, (KEYS[0], KEYS[2])))
        from keel.mesh.vipnode import VipError
        with self.assertRaisesRegex(VipError, "not a member"):
            vipnode.signed_claim(self.all[1], VIP, 3)

    def test_pair_edges_of_the_flow(self):
        self.nodes(paired=False)
        from unittest import mock

        from keel.mesh.signing import SigningError
        with mock.patch.object(vippair, "sign",
                               side_effect=[vippair.sign(
                                   self.all[0].root, vippair.made(
                                       MESH_HEX, VIP, (KEYS[0], KEYS[1])),
                                   KEYS[0]), SigningError("openssl: no")]):
            said: list[str] = []
            self.assertEqual(vippromote.pair(self.all[0], address(1),
                                             said.append),
                             exits.MESH_REFUSED)
        self.assertIn("openssl: no", said[-1])
        other = vippair.made(MESH_HEX, "fd00:6b65:1::201",
                             (KEYS[0], KEYS[1])).dumps()
        self.all[0].exchange = lambda at, iface, body: json.dumps(
            {"pair": other}).encode()
        self.assertEqual(vippromote.pair(self.all[0], address(1),
                                         said.append), exits.MESH_REFUSED)
        self.assertIn("another pair record", said[-1])
        record = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1])).dumps()
        self.all[0].exchange = lambda at, iface, body: json.dumps(
            {"pair": record}).encode()
        self.assertEqual(vippromote.pair(self.all[0], address(1),
                                         said.append), exits.MESH_REFUSED)
        self.assertIn("not signed", said[-1])

    def test_countersign_with_a_damaged_spec(self):
        self.nodes(paired=False)
        record = vippair.sign(self.all[0].root, vippair.made(
            MESH_HEX, VIP, (KEYS[0], KEYS[1])), KEYS[0])
        body = vipmsg.signed(self.all[0].root, "pair", MESH_HEX, KEYS[0],
                             NOW, {"pair": record.dumps()})
        from unittest import mock
        with mock.patch.object(vipstate, "declared",
                               side_effect=ValueError("x")):
            self.assertEqual(vipserve.answer(self.all[1], body,
                                             KEYS[0]).status, 403)

    def test_a_message_too_long_and_an_unreachable_peer(self):
        with self.assertRaises(ProtocolError):
            vipmsg.loads(b" " * (vipmsg.MAX_MESSAGE + 1))
        self.nodes()
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        self.all[0].exchange = lambda at, iface, body: b"not json"
        said = vipnode.announce(self.all[0], made)
        self.assertTrue(all(one.startswith("unreachable")
                            for one in said.values()))
