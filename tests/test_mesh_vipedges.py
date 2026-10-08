# Copyright (c) 2026 KeelLinux maintainers
"""The VIP's edges: what each flow says when a step fails (0049)"""

import json
import os
from unittest import mock

from vip_helpers import KEYS, NOW, VIP, Pair, address

from keel import exits
from keel.mesh import (
    etcdstate,
    vipcli,
    vipetcd,
    vipmsg,
    vipnet,
    vipnode,
    vippromote,
    vipserve,
)
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdstate import Cluster, Member
from keel.mesh.signing import SigningError
from keel.mesh.vipnode import VipError

MESH_HEX = bytes(range(16)).hex()


def first(pair: Pair) -> None:
    vippromote.promote(pair.all[0], False, lambda line: None)


class TestTakingAndRouting(Pair):
    def test_a_newer_claim_of_its_own_is_recorded_not_carried(self):
        self.nodes()
        made = vipnode.signed_claim(self.all[0], VIP, 4)
        self.assertTrue(vipnode.take(self.all[0], made))
        self.assertFalse(self.carried(0))
        self.assertEqual(vipnode.current(self.all[0], VIP).epoch, 4)

    def test_failures_while_taking_are_said(self):
        self.nodes()
        first(self)
        self.nets[0].fail[("ip", "-6", "addr", "del")] = "ip: busy"
        self.nets[0].fail[("wg", "set")] = "wg: no"
        made = vipnode.signed_claim(self.all[1], VIP, 2)
        self.assertTrue(vipnode.take(self.all[0], made))
        self.assertIn("cannot drop it: ip: busy", self.text(0))
        self.assertIn("wg: no", self.text(0))

    def test_routed_without_a_key_and_a_file_that_cannot_be_written(self):
        self.nodes()
        here = self.all[2]
        here.node.key = None
        with mock.patch.object(vipnet, "written", return_value="no room"):
            vipnode.routed(here, VIP, KEYS[0])
        self.assertIn("no room", self.text(2))
        self.assertEqual(self.routed(2), KEYS[0])

    def test_a_claim_not_verified(self):
        self.nodes()
        made = vipnode.signed_claim(self.all[1], VIP, 1)
        self.all[2].node.key = None
        self.assertIn("WireGuard key", vipnode.verified(self.all[2], made))
        self.all[2].node.key = KEYS[2]
        other = vipmsg.claim_of(vipmsg.signed(
            self.all[1].root, "claim", "ab" * 16, KEYS[1], NOW,
            {"vip": VIP, "epoch": 1, "address": address(1)}))
        self.assertIn("another mesh", vipnode.verified(self.all[2], other))
        stranger = vipmsg.claim_of(vipmsg.signed(
            self.all[1].root, "claim", MESH_HEX, KEYS[4], NOW,
            {"vip": VIP, "epoch": 1, "address": address(4)}))
        self.assertIn("not a peer", vipnode.verified(self.all[2], stranger))

    def test_a_lease_that_cannot_be_revoked_expires(self):
        self.nodes()
        first(self)
        held = vipnode.current(self.all[0], VIP)
        vipstate.write(self.all[0].root, vipstate.Held(
            VIP, held.claim, lease="9"))

        def refuse(lease):
            raise EtcdError("no leader")
        vipnode.release(self.all[0], VIP, refuse)
        self.assertIn("expires within its TTL", self.text(0))

    def test_carry_held_only_when_held_and_said_when_it_fails(self):
        self.nodes()
        self.assertFalse(vipnode.carry_held(self.all[0], VIP))
        first(self)
        self.nets[0].addresses.clear()
        self.nets[0].fail[("ip", "-6", "addr", "replace")] = "ip: no"
        self.assertFalse(vipnode.carry_held(self.all[0], VIP))
        self.assertIn("cannot carry it", self.text(0))

    def test_an_epoch_answer_for_another_vip(self):
        self.nodes()
        first(self)
        answer = vipmsg.epoch_answer(vipnode.current(self.all[0], VIP).claim)
        self.all[1].exchange = lambda host, iface, body: answer
        found = vipnode.epochs(self.all[1], "fd00:6b65:1::200")
        self.assertEqual(set(found.values()), {"an answer for another VIP"})

    def test_a_claim_that_cannot_be_signed(self):
        self.nodes()
        with mock.patch.object(vipmsg, "claim",
                               side_effect=SigningError("openssl: no")), \
                self.assertRaises(VipError):
            vipnode.signed_claim(self.all[0], VIP, 1)


class TestServeEdges(Pair):
    def test_no_identity_and_a_damaged_spec(self):
        self.nodes()
        first(self)
        body = vipmsg.signed(self.all[1].root, "epoch", MESH_HEX, KEYS[1],
                             NOW, {"vip": VIP})
        os.remove(os.path.join(self.all[2].root,
                               "var/lib/keel/mesh/identity"))
        self.assertEqual(vipserve.answer(self.all[2], body, KEYS[1]).status,
                         403)
        release = vipmsg.signed(self.all[1].root, "release", MESH_HEX,
                                KEYS[1], NOW, {"vip": VIP, "epoch": 2})
        with mock.patch.object(vipstate, "declared",
                               side_effect=ValueError("x")):
            found = vipserve.answer(self.all[0], release, KEYS[1])
        self.assertEqual(found.status, 403)


class TestPromoteEdges(Pair):
    def with_etcd(self):
        self.nodes(etcd="enabled")
        cluster = Cluster("new", tuple(Member(KEYS[i], address(i))
                                       for i in range(3)), MESH_HEX)
        for one in self.all:
            etcdstate.save_cluster(one.root, cluster)

    def test_etcd_away_while_waiting_for_the_lease(self):
        self.with_etcd()
        calls = iter([EtcdError("x"), {}])

        def seen(client, mesh, err=None):
            found = next(calls)
            if isinstance(found, Exception):
                raise found
            return found
        with mock.patch.object(vipetcd, "seen", side_effect=seen):
            found = vippromote.gone_lease(self.all[0], VIP, None, 5)
        self.assertEqual(found, vipetcd.Seen(VIP))
        # a lease that lives on past the wait
        self.kv.leases["9"] = self.monotonic() + 1000
        self.assertIsNone(vippromote.gone_lease(self.all[0], VIP, "9", 2))

    def test_the_race_lost_and_etcd_away_after_it(self):
        self.with_etcd()
        with mock.patch.object(vipetcd, "seen",
                               side_effect=EtcdError("gone")):
            said: list[str] = []
            self.assertEqual(vippromote.raced(self.all[0], VIP, KEYS[0],
                                              said.append),
                             exits.APPLY_FAILED)
        held = vipnode.signed_claim(self.all[0], VIP, 1)
        with mock.patch.object(vipetcd, "seen", return_value={
                VIP: vipetcd.Seen(VIP, held, 2, held, "9")}), \
                mock.patch.object(vippromote, "carried_soon",
                                  return_value=False):
            said = []
            self.assertEqual(vippromote.raced(self.all[0], VIP, KEYS[0],
                                              said.append),
                             exits.APPLY_FAILED)
        self.assertIn("is it running", "\n".join(said))

    def test_the_check_when_carrying_again_fails(self):
        self.nodes()
        first(self)
        self.nets[0].addresses.clear()
        with mock.patch.object(vipnode, "carry_held", return_value=False):
            said: list[str] = []
            vippromote.check(self.all[0], said.append)
        self.assertNotIn("carried again", "\n".join(said))

    def test_status_with_no_holder_and_a_lease(self):
        self.nodes()
        vipstate.write(self.all[0].root, vipstate.Held(VIP))
        self.assertIn("holder: none known yet",
                      "\n".join(vippromote.lines(self.all[0], False)))
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        vipstate.write(self.all[0].root, vipstate.Held(VIP, made,
                                                       lease="77"))
        self.assertIn("etcd lease 77",
                      "\n".join(vippromote.lines(self.all[0], False)))

    def test_stopped_leaves_what_it_does_not_carry(self):
        self.nodes()
        first(self)
        self.nets[0].addresses.clear()
        self.assertEqual(vipetcd.stopped(self.all[0]), ([], []))

class TestCliEdges(Pair):
    def test_the_controller_stops_on_sigterm(self):
        self.nodes(count=1)
        from keel import cli
        args = cli.build_parser().parse_args([
            "vip", "tend", "--spec", self.all[0].node.path, "--root",
            self.all[0].root])
        handlers = {}
        with mock.patch("signal.signal",
                        side_effect=lambda sig, fn: handlers.update(
                            {sig: fn})), \
                mock.patch.object(vipcli.vipbridge, "serve",
                                  side_effect=lambda here, stop:
                                  handlers[15](15, None)), \
                self.assertRaises(SystemExit):
            vipcli.vip_tend(args)
        self.assertTrue(vipcli.utcnow().tzinfo)

    def test_a_damaged_state_file_is_skipped_by_held_all(self):
        self.nodes(count=1)
        vipstate.ensure(self.all[0].root)
        with open(os.path.join(self.all[0].root, vipstate.file_of(VIP)),
                  "w") as fob:
            json.dump({"vip": "fd00::9", "claim": None, "fenced": False,
                       "lease": None, "renewed": None}, fob)
        self.assertEqual(vipstate.held_all(self.all[0].root), [])

