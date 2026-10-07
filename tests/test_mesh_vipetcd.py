# Copyright (c) 2026 KeelLinux maintainers
"""The VIP with etcd: the counter's compare-and-swap, the controller's
renewal, fence, following and failover, and promote through etcd
(decision 0049, third round), on a fake etcd (tests/vip_helpers.py)"""

import threading
import unittest
from unittest import mock

from vip_helpers import KEYS, VIP, Pair, address

from keel import exits
from keel.mesh import etcdstate, vipetcd, vipnode, vippromote
from keel.mesh import vip as vipstate
from keel.mesh.etcdstate import Cluster, Member

MESH_HEX = bytes(range(16)).hex()


class WithEtcd(Pair):
    def setUp(self):
        super().setUp()
        self.nodes(etcd="enabled")
        cluster = Cluster("new", tuple(Member(KEYS[i], address(i))
                                       for i in range(3)), MESH_HEX)
        for one in self.all:
            etcdstate.save_cluster(one.root, cluster)
        self.controllers = [vipetcd.Controller(one, threading.Event())
                            for one in self.all]

    def turn(self, *indexes: int) -> None:
        for index in indexes or range(3):
            self.controllers[index].holding()
            self.controllers[index].following()

    def promote(self, index: int, gone: bool = False) -> tuple[int, str]:
        said: list[str] = []
        with mock.patch.object(vippromote, "carried_soon",
                               side_effect=self.carry_soon):
            code = vippromote.promote(self.all[index], gone, said.append)
        return code, "\n".join(said)

    def carry_soon(self, here, vip):
        index = self.all.index(here)
        self.turn(index)
        return self.carried(index)


class TestTheCounter(WithEtcd):
    def test_the_first_claim_and_a_stale_one(self):
        here = self.all[0]
        made = vipetcd.claim(here, self.kv, VIP, vipetcd.Seen(VIP))
        self.assertEqual(made[0].epoch, 1)
        seen = vipetcd.seen(self.kv, MESH_HEX)[VIP]
        self.assertEqual((seen.epoch.epoch, seen.holder.epoch, seen.lease),
                         (1, 1, made[1]))
        # a lease alive: no other claim, even at the right revision
        self.assertIsNone(vipetcd.claim(self.all[1], self.kv, VIP, seen))
        self.kv.expire(made[1])
        seen = vipetcd.seen(self.kv, MESH_HEX)[VIP]
        self.assertIsNone(seen.holder)
        # a claim against the counter's old revision is refused
        old = vipnode.signed_claim(self.all[1], VIP, 1)
        self.assertTrue(vipetcd.stale(self.kv, MESH_HEX, VIP, old,
                                      seen.revision - 1))
        second = vipetcd.claim(self.all[1], self.kv, VIP, seen)
        self.assertEqual(second[0].epoch, 2)

    def test_values_that_are_not_claims_are_left_out(self):
        self.kv.kvs[f"/keel/{MESH_HEX}/vip/{VIP}/epoch"] = (b"x", 2, None)
        self.kv.kvs[f"/keel/{MESH_HEX}/vip/nonsense/epoch"] = (b"x", 2, None)
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        self.kv.kvs[f"/keel/{MESH_HEX}/vip/{VIP}/other"] = (made.raw, 2,
                                                            None)
        said: list[str] = []
        self.assertEqual(vipetcd.seen(self.kv, MESH_HEX, said.append), {})
        self.assertEqual(len(said), 3)

    def test_a_failed_swap_revokes_its_lease(self):
        self.kv.kvs[f"/keel/{MESH_HEX}/vip/{VIP}/holder"] = (b"x", 2, "9")
        self.assertIsNone(vipetcd.claim(self.all[0], self.kv, VIP,
                                        vipetcd.Seen(VIP)))
        self.assertEqual(self.kv.leases, set())
        self.kv.refuse = "revoke"
        self.assertIsNone(vipetcd.claim(self.all[0], self.kv, VIP,
                                        vipetcd.Seen(VIP)))


class TestPromoteWithEtcd(WithEtcd):
    def test_first_promote_then_planned(self):
        code, said = self.promote(0)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(0))
        self.turn()
        self.assertEqual(self.routed(2), KEYS[0])
        code, said = self.promote(0)
        self.assertIn("holds", said)
        code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("released by", said)
        self.assertEqual((self.carried(0), self.carried(1)), (False, True))
        self.turn()
        self.assertEqual(self.routed(2), KEYS[1])
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)

    def test_the_old_primary_unreachable_is_refused_or_waited_for(self):
        self.promote(0)
        self.down.add(address(0))
        code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("--old-primary-gone", said)
        # gone: the lease is never revoked, only waited for
        code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("never revokes", said)
        self.assertNotIn("revoke", self.kv.calls)
        lease = vipetcd.seen(self.kv, MESH_HEX)[VIP].lease
        original = self.sleep

        def expiring(seconds):
            original(seconds)
            self.kv.expire(lease)
        self.sleep = expiring
        self.all[1].sleep = expiring
        code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(1))

    def test_etcd_that_does_not_answer(self):
        self.kv.refuse = "connect"
        code, said = self.promote(0)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("etcd did not answer", said)
        self.kv.refuse = "grant"
        code, said = self.promote(0)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("did not take the claim", said)

    def test_a_controller_that_does_not_carry_it(self):
        said: list[str] = []
        with mock.patch.object(vippromote, "CARRY_WAIT", 1.0):
            code = vippromote.promote(self.all[0], False, said.append)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("keel-vip.service", "\n".join(said))

    def test_the_race_with_its_own_controller(self):
        self.promote(0)
        self.turn()
        # B's controller claims first, once A released
        vipnode.release(self.all[0], VIP, self.kv.revoke)
        self.turn(1)
        self.turn(1)
        self.assertTrue(self.carried(1))
        said: list[str] = []
        with mock.patch.object(vipetcd, "claim", return_value=None), \
                mock.patch.object(vipetcd, "seen", side_effect=[
                    {}, vipetcd.seen(self.kv, MESH_HEX)]):
            code = vippromote.promote(self.all[1], False, said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("claimed by its controller", "\n".join(said))

    def test_another_node_s_claim_came_first(self):
        self.promote(0)
        vipnode.release(self.all[0], VIP, self.kv.revoke)
        with mock.patch.object(vipetcd, "claim", return_value=None):
            code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("another claim came first", said)


class TestTheController(WithEtcd):
    def test_a_holder_cut_off_drops_it_within_release_after(self):
        self.promote(0)
        self.kv.refuse = "keepalive"
        self.sleep(vipetcd.RELEASE_AFTER - 1)
        self.turn(0)
        self.assertTrue(self.carried(0))
        self.sleep(1.5)
        self.turn(0)
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.current(self.all[0], VIP).fenced)
        self.assertIn("no renewal", self.text(0))

    def test_the_replica_claims_once_the_lease_expired_never_before(self):
        self.promote(0)
        self.turn()
        lease = vipetcd.seen(self.kv, MESH_HEX)[VIP].lease
        self.turn(1)
        self.assertFalse(self.carried(1))
        self.kv.expire(lease)
        self.turn(1)
        self.turn(1)
        self.assertTrue(self.carried(1))
        self.assertIn("lease expired", self.text(1))
        # the old primary learns it and never claims again
        self.turn(0)
        self.assertFalse(self.carried(0))
        held = vipnode.current(self.all[0], VIP)
        self.assertTrue(held.fenced)
        self.assertEqual(held.holder, KEYS[1])
        self.controllers[1].stop.set()
        self.kv.expire(vipetcd.seen(self.kv, MESH_HEX)[VIP].lease)
        self.turn(0)
        self.assertFalse(self.carried(0))

    def test_a_lease_gone_is_dropped_at_once(self):
        self.promote(0)
        self.kv.expire(vipetcd.seen(self.kv, MESH_HEX)[VIP].lease)
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        self.assertFalse(self.carried(0))
        self.assertIn("lease is gone", self.text(0))

    def test_an_etcd_claim_not_verified_is_refused(self):
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        forged = made.raw.replace(b'"epoch": 1', b'"epoch": 9')
        self.kv.kvs[f"/keel/{MESH_HEX}/vip/{VIP}/epoch"] = (forged, 2, None)
        self.turn(2)
        self.assertIn("refused", self.text(2))
        self.assertIsNone(self.routed(2))

    def test_etcd_away_and_failures_are_survived(self):
        self.promote(0)
        self.kv.refuse = "all"
        self.turn()
        self.kv.refuse = None
        with open(self.all[1].node.path, "w") as fob:
            fob.write("version: [")
        # a spec being edited: the turn fails, the loop (run) says it
        from keel.mesh.node import NodeError
        with self.assertRaises(NodeError):
            self.controllers[1].following()
        self.controllers[1].fail_over(self.kv, {})
        self.kv.refuse = "grant"
        self.kv.expire(vipetcd.seen(self.kv, MESH_HEX)[VIP].lease)
        self.turn(2)
        self.kv.refuse = None

    def test_the_claim_fails_and_is_said(self):
        self.promote(0)
        self.turn()
        self.kv.expire(vipetcd.seen(self.kv, MESH_HEX)[VIP].lease)
        self.kv.refuse = "grant"
        self.turn(1)
        self.assertIn("the claim failed", self.text(1))
        self.kv.refuse = None
        with mock.patch.object(vipetcd, "claim", return_value=None):
            self.turn(1)
        self.assertFalse(self.carried(1))

    def test_run_until_stopped(self):
        stop = self.controllers[2].stop
        with mock.patch.object(vipetcd.Controller, "following",
                               side_effect=lambda: stop.set()), \
                mock.patch.object(vipetcd.Controller, "holding",
                                  side_effect=vipnode.VipError("x")):
            self.controllers[2].run()
        with mock.patch.object(vipetcd.Controller, "following",
                               side_effect=vipnode.VipError("y")):
            stop.clear()
            threading.Timer(0.3, stop.set).start()
            self.controllers[2].run()
        self.assertIn("vip: y", self.text(2))

    def test_stopped_drops_what_it_carries(self):
        self.promote(0)
        self.assertEqual(vipetcd.stopped(self.all[0]), [VIP])
        self.assertFalse(self.carried(0))
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.nets[0].addresses.append(f"{VIP}/128")
        self.nets[0].fail[("ip", "-6", "addr", "del")] = "ip: busy"
        self.assertEqual(vipetcd.stopped(self.all[0]), [VIP])
        self.assertIn("ip: busy", self.text(0))

    def test_the_check_leaves_carrying_to_the_controller(self):
        self.promote(0)
        self.nets[0].addresses.clear()
        vippromote.check(self.all[0], lambda line: None)
        self.assertFalse(self.carried(0))
        self.assertTrue(vippromote.with_etcd(self.all[0]))
        with open(self.all[0].node.path, "w") as fob:
            fob.write("version: [")
        self.assertFalse(vippromote.with_etcd(self.all[0]))

    def test_the_renewed_time_is_kept(self):
        self.promote(0)
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        held = vipnode.current(self.all[0], VIP)
        self.assertEqual(held.renewed, self.monotonic())
        self.assertEqual(vipstate.role(self.all[0].node.document(), held,
                                       KEYS[0]), "primary")


if __name__ == "__main__":
    unittest.main()
