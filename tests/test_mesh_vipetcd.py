# Copyright (c) 2026 KeelLinux maintainers
"""The VIP with etcd: the counter's compare-and-swap, the lease signed
into each claim, the controller's renewal, carry, following and
failover through the root half, a member outside the pair writing,
deleting and revoking, and promote through etcd (decision 0049, third
round), on a fake etcd with a clock (tests/vip_helpers.py)"""

import threading
import unittest
from unittest import mock

from vip_helpers import KEYS, NOW, VIP, Pair, address

from keel import exits
from keel.mesh import etcdstate, vipetcd, vipmsg, vipnode, vippromote
from keel.mesh import vip as vipstate
from keel.mesh.etcdstate import Cluster, Member
from keel.mesh.vipnode import VipError

MESH_HEX = bytes(range(16)).hex()
HOLDER = f"/keel/{MESH_HEX}/vip/{VIP}/holder"
EPOCH = f"/keel/{MESH_HEX}/vip/{VIP}/epoch"


class WithEtcd(Pair):
    def setUp(self):
        super().setUp()
        self.nodes(etcd="enabled")
        cluster = Cluster("new", tuple(Member(KEYS[i], address(i))
                                       for i in range(3)), MESH_HEX)
        for one in self.all:
            etcdstate.save_cluster(one.root, cluster)
        self.announced: list[tuple[str, bytes]] = []
        self.controllers = [self.controller(i) for i in range(3)]
        self.both: list[float] = []

    def controller(self, index: int) -> vipetcd.Controller:
        """A controller as a start makes it: nothing in memory"""
        return vipetcd.Controller(
            vipetcd.Ops(self.all[index]), lambda: self.kv,
            threading.Event(), self.said[index].append, self.monotonic,
            lambda at, iface, raw: self.announced.append((at, raw)))

    def turn(self, *indexes: int) -> None:
        for index in indexes or range(3):
            self.controllers[index].holding()
            self.controllers[index].following()
        if self.carried(0) and self.carried(1):
            self.both.append(self.monotonic())

    def run_for(self, seconds: float, *indexes: int) -> None:
        """The controllers' turns, each second, for `seconds`"""
        for _ in range(int(seconds)):
            self.sleep(1.0)
            self.turn(*indexes)

    def promote(self, index: int, gone: bool = False) -> tuple[int, str]:
        said: list[str] = []
        with mock.patch.object(vippromote, "carried_soon",
                               side_effect=self.carry_soon):
            code = vippromote.promote(self.all[index], gone, said.append)
        return code, "\n".join(said)

    def carry_soon(self, here, vip):
        # a promote with --old-primary-gone acts as a copy of the node
        # whose asks of the old primary are bounded (keel#108)
        index = next(i for i, one in enumerate(self.all)
                     if one.root == here.root)
        self.sleep(vipetcd.RENEW)
        self.turn(index)
        return self.carried(index)

    def lease(self) -> str:
        return vipetcd.seen(self.kv, MESH_HEX)[VIP].epoch.lease

    def holds(self) -> list[int]:
        return [i for i in range(3) if self.carried(i)]


class TestTheCounter(WithEtcd):
    def sign(self, index: int):
        return lambda vip, epoch, lease: vipnode.signed_claim(
            self.all[index], vip, epoch, lease)

    def test_the_lease_is_signed_into_the_claim(self):
        made = vipetcd.claim(self.kv, MESH_HEX, VIP, vipetcd.Seen(VIP), 0,
                             self.sign(0), self.monotonic)
        self.assertEqual(made[0].epoch, 1)
        self.assertEqual(made[0].lease, made[1])
        seen = vipetcd.seen(self.kv, MESH_HEX)[VIP]
        self.assertEqual((seen.epoch.epoch, seen.holder.epoch, seen.lease),
                         (1, 1, made[1]))
        # a claim against the counter's old revision is refused
        old = vipnode.signed_claim(self.all[1], VIP, 1)
        self.assertTrue(vipetcd.stale(self.kv, MESH_HEX, VIP, old,
                                      seen.revision - 1))
        self.assertIsNone(vipetcd.claim(self.kv, MESH_HEX, VIP, vipetcd.Seen(
            VIP, None, seen.revision - 1), 1, self.sign(1), self.monotonic))
        second = vipetcd.claim(self.kv, MESH_HEX, VIP, seen, 1, self.sign(1),
                               self.monotonic)
        self.assertEqual(second[0].epoch, 2)

    def test_a_counter_that_is_no_claim_is_replaced_not_obeyed(self):
        self.kv.put(EPOCH, b"garbage")
        said: list[str] = []
        seen = vipetcd.seen(self.kv, MESH_HEX, said.append)[VIP]
        self.assertIsNone(seen.epoch)
        self.assertEqual(seen.revision, self.kv.revision)
        self.assertIn("not a claim", said[0])
        made = vipetcd.claim(self.kv, MESH_HEX, VIP, seen, 0, self.sign(0),
                             self.monotonic)
        self.assertEqual(made[0].epoch, 1)

    def test_values_that_are_not_claims_are_left_out(self):
        self.kv.put(f"/keel/{MESH_HEX}/vip/nonsense/epoch", b"x")
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        self.kv.put(f"/keel/{MESH_HEX}/vip/{VIP}/other", made.raw)
        said: list[str] = []
        found = vipetcd.seen(self.kv, MESH_HEX, said.append)
        self.assertIsNone(found[VIP].epoch)
        self.assertEqual(len(said), 2)

    def test_a_failed_swap_or_signature_revokes_its_lease(self):
        self.kv.put(EPOCH, b"x")
        self.assertIsNone(vipetcd.claim(self.kv, MESH_HEX, VIP,
                                        vipetcd.Seen(VIP), 0, self.sign(0),
                                        self.monotonic))
        self.assertEqual(self.kv.leases, {})
        self.kv.refuse = "revoke"
        self.assertIsNone(vipetcd.claim(self.kv, MESH_HEX, VIP,
                                        vipetcd.Seen(VIP), 0, self.sign(0),
                                        self.monotonic))
        self.kv.refuse = None

        def refused(vip, epoch, lease):
            raise VipError("no")
        with self.assertRaises(VipError):
            vipetcd.claim(self.kv, MESH_HEX, VIP, vipetcd.Seen(VIP), 0,
                          refused, self.monotonic)
        self.kv.refuse = "revoke"
        with self.assertRaises(VipError):
            vipetcd.claim(self.kv, MESH_HEX, VIP, vipetcd.Seen(VIP), 0,
                          refused, self.monotonic)


class TestTheRootHalf(WithEtcd):
    """What the controller may ask, checked by the root half"""

    def test_it_signs_only_its_own_vip_above_what_it_knows(self):
        ops = vipetcd.Ops(self.all[0])
        self.assertEqual(ops.sign(VIP, 1, "77").lease, "77")
        with self.assertRaises(VipError):
            ops.sign("fd00:6b65:1::200", 1)
        with self.assertRaises(VipError):
            vipetcd.Ops(self.all[2]).sign(VIP, 1)
        self.promote(0)
        with self.assertRaises(VipError):
            ops.sign(VIP, 1)
        with self.assertRaises(VipError):
            ops.sign(VIP, 1 + vipnode.MAX_STEP + 5)

    def test_it_holds_only_its_own_verified_claim(self):
        made = vipnode.signed_claim(self.all[1], VIP, 1)
        with self.assertRaises(VipError):
            vipetcd.Ops(self.all[0]).hold(made.raw, "5")
        third = vipmsg.claim(self.all[2].root, MESH_HEX, KEYS[2], NOW, VIP,
                             1, address(2), made.pair)
        with self.assertRaisesRegex(VipError, "not a member"):
            vipetcd.Ops(self.all[2]).hold(third.raw, "5")
        self.assertIn("not a signed VIP message",
                      vipetcd.Ops(self.all[0]).take(b"{}"))

    def test_a_plain_drop_is_said_and_facts_survive_a_damaged_spec(self):
        self.nets[0].addresses.append(f"{VIP}/128")
        vipetcd.Ops(self.all[0]).drop(VIP, False, "a test")
        self.assertFalse(self.carried(0))
        self.assertIn("dropped, a test", self.text(0))
        with mock.patch.object(vipstate, "declared",
                               side_effect=ValueError("x")):
            self.assertIsNone(vipetcd.Ops(self.all[0]).facts().vip)


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
        self.assertEqual(self.holds(), [1])
        self.turn()
        self.assertEqual(self.routed(2), KEYS[1])
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)

    def test_the_old_primary_unreachable_is_refused_or_waited_for(self):
        self.promote(0)
        self.turn()
        self.down.add(address(0))
        code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("--old-primary-gone", said)
        # gone: the lease is never revoked, only waited for
        lease = self.lease()
        self.kv.leases[lease] = self.monotonic() + 1000
        code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("never revokes", said)
        self.assertNotIn("revoke", self.kv.calls)
        self.kv.leases[lease] = self.monotonic() + 5
        code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(1))

    def slow_old_primary(self, seconds: float, answers: bool):
        """Node 0 answers node 1 only after `seconds`, or not at all"""
        import time
        from keel.mesh.memberlink import LinkError
        real = self.all[1].exchange
        asked: list[str] = []

        def exchange(at: str, iface: str, body: bytes) -> bytes:
            if at == address(0):
                asked.append(at)
                time.sleep(seconds)
                if not answers:
                    raise LinkError(f"[{at}]:51821 through {iface}: timed out")
            return real(at, iface, body)
        self.all[1].exchange = exchange
        return asked

    def test_with_etcd_the_gone_old_primary_costs_the_bound(self):
        """keel#108: with etcd formed, the lease fences the old primary,
        so each ask of it waits at most the bound"""
        import time
        self.promote(0)
        self.turn()
        asked = self.slow_old_primary(1.0, answers=False)
        self.kv.leases[self.lease()] = self.monotonic() + 5
        started = time.monotonic()
        with mock.patch.object(vipnode, "GONE_BOUND", 0.2):
            code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("no answer within 0.2 s", said)
        self.assertTrue(self.carried(1))
        self.assertGreaterEqual(len(asked), 1, asked)
        # the late asks were joined before the promote returned
        self.assertLess(time.monotonic() - started, 6.0)

    def test_an_old_primary_that_answers_after_the_bound_still_drops_it(
            self):
        """The ask goes on after the bound, and the promote waits for it
        before it returns: a live old primary that is slow still gets
        the release and drops the VIP"""
        self.promote(0)
        self.turn()
        self.assertTrue(self.carried(0))
        self.slow_old_primary(0.6, answers=True)
        self.kv.leases[self.lease()] = self.monotonic() + 5
        with mock.patch.object(vipnode, "GONE_BOUND", 0.2):
            code, said = self.promote(1, gone=True)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("no answer within 0.2 s", said)
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.current(self.all[0], VIP).released or
                        not vipnode.current(self.all[0], VIP).holds(KEYS[0]))

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

    def test_another_node_s_claim_came_first_or_its_own(self):
        self.promote(0)
        vipnode.release(self.all[0], VIP, self.kv.revoke)
        with mock.patch.object(vipetcd, "claim", return_value=None):
            code, said = self.promote(1)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("another claim came first", said)
        made = vipetcd.claim(
            self.kv, MESH_HEX, VIP, vipetcd.seen(self.kv, MESH_HEX)[VIP], 1,
            lambda vip, epoch, lease: vipnode.signed_claim(
                self.all[1], vip, epoch, lease), self.monotonic)
        vipnode.hold(self.all[1], made[0], False, made[1])
        with mock.patch.object(vippromote, "carried_soon",
                               return_value=True):
            said = []
            self.assertEqual(vippromote.raced(self.all[1], VIP, KEYS[1],
                                              said.append), exits.OK)
        with mock.patch.object(vippromote, "carried_soon",
                               return_value=False):
            self.assertEqual(vippromote.raced(self.all[1], VIP, KEYS[1],
                                              said.append),
                             exits.APPLY_FAILED)
        self.kv.refuse = "all"
        self.assertEqual(vippromote.raced(self.all[1], VIP, KEYS[1],
                                          said.append), exits.APPLY_FAILED)

    def test_promote_finds_its_own_controller_claimed_while_it_waited(self):
        self.promote(0)
        self.turn()
        with mock.patch.object(vippromote, "gone_lease",
                               side_effect=lambda here, vip, lease, wait:
                               self.own_claim(1)):
            with mock.patch.object(vippromote, "carried_soon",
                                   return_value=True):
                code, said = self.promote(1)
        self.assertEqual(code, exits.OK, said)
        self.assertIn("claimed by its controller", said)

    def own_claim(self, index: int) -> vipetcd.Seen:
        vipnode.release(self.all[0], VIP, self.kv.revoke)
        made = vipetcd.claim(
            self.kv, MESH_HEX, VIP, vipetcd.seen(self.kv, MESH_HEX)[VIP], 1,
            lambda vip, epoch, lease: vipnode.signed_claim(
                self.all[index], vip, epoch, lease), self.monotonic)
        vipnode.hold(self.all[index], made[0], False, made[1])
        return vipetcd.seen(self.kv, MESH_HEX)[VIP]

    def test_waiting_for_the_lease_survives_etcd_away(self):
        calls = iter([True, False])
        here = self.all[1]
        with mock.patch.object(vipetcd, "seen", side_effect=lambda *a, **k:
                               (_ for _ in ()).throw(
                                   vipetcd.EtcdError("x")) if next(calls)
                               else {}):
            found = vippromote.gone_lease(here, VIP, None, 5)
        self.assertEqual(found, vipetcd.Seen(VIP))


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
        # not fenced: its lease may live; renewed again, it carries
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.assertIn("no renewal the majority confirmed", self.text(0))
        self.kv.refuse = None
        self.sleep(vipetcd.RENEW)
        self.turn(0)
        self.assertTrue(self.carried(0))

    def test_a_renewal_the_majority_does_not_confirm_is_none(self):
        """etcd's leader cut off renews leases by itself; the read that
        needs the majority fails"""
        self.promote(0)
        self.kv.refuse = "prefix"
        for _ in range(int(vipetcd.RELEASE_AFTER / vipetcd.RENEW) + 1):
            self.sleep(vipetcd.RENEW)
            self.controllers[0].holding()
        self.assertFalse(self.carried(0))

    def test_a_restarted_holder_carries_nothing_before_it_renews(self):
        self.promote(0)
        self.turn()
        self.nets[0].addresses.clear()
        self.kv.refuse = "keepalive"
        self.controllers[0] = self.controller(0)
        self.controllers[0].holding()
        self.assertFalse(self.carried(0))
        self.kv.refuse = None
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        self.assertTrue(self.carried(0))

    def test_the_replica_claims_once_the_lease_expired_never_before(self):
        self.promote(0)
        self.run_for(30)
        self.assertEqual(self.holds(), [0])
        # A stops renewing (dead): its lease runs out its TTL
        self.controllers[0].stop.set()
        self.nets[0].addresses.clear()
        for second in range(60):
            self.sleep(1.0)
            self.turn(1, 2)
            if self.carried(1):
                break
        self.assertTrue(self.carried(1))
        # at the TTL, not later: the lease expired naturally
        self.assertLessEqual(second, vipetcd.TTL + 2)
        self.assertIn("is gone", self.text(1))
        self.assertEqual({at for at, _ in self.announced},
                         {address(0), address(2)})
        self.turn(2)
        self.assertEqual(self.routed(2), KEYS[1])
        # the old primary comes back: it learns it, is fenced, and never
        # claims again
        self.controllers[0] = self.controller(0)
        self.run_for(5, 0)
        self.assertFalse(self.carried(0))
        held = vipnode.current(self.all[0], VIP)
        self.assertTrue(held.fenced)
        self.assertEqual(held.holder, KEYS[1])

    def test_a_rebooted_old_holder_never_carries_the_replica_s_vip(self):
        self.promote(0)
        self.run_for(5)
        lease = self.lease()
        self.nets[0].addresses.clear()
        self.controllers[0].stop.set()
        for _ in range(40):
            self.sleep(1.0)
            self.turn(1, 2)
        self.assertTrue(self.carried(1))
        self.assertEqual(vipnode.current(self.all[0], VIP).lease, lease)
        self.controllers[0] = self.controller(0)
        self.run_for(5, 0)
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.current(self.all[0], VIP).fenced)

    def test_an_etcd_claim_not_verified_is_refused(self):
        made = vipnode.signed_claim(self.all[0], VIP, 1)
        self.kv.put(EPOCH, made.raw.replace(b'"epoch": 1', b'"epoch": 9'))
        self.turn(2)
        self.assertIn("refused", self.text(2))
        self.assertIsNone(self.routed(2))

    def test_etcd_away_and_the_claim_failing_are_survived(self):
        self.promote(0)
        self.run_for(3)
        self.kv.refuse = "all"
        self.turn()
        self.kv.refuse = None
        self.controllers[0].stop.set()
        self.kv.expire(self.lease())
        self.kv.refuse = "grant"
        self.run_for(vipetcd.GRACE + 2, 1)
        self.assertIn("the claim failed", self.text(1))
        self.kv.refuse = "time_to_live"
        self.turn(1)
        self.kv.refuse = None
        with mock.patch.object(vipetcd, "claim", return_value=None):
            self.turn(1)
        self.assertFalse(self.carried(1))

    def test_a_peer_that_does_not_take_the_announcement_is_said(self):
        def refuse(at, iface, raw):
            raise OSError("down")
        self.controllers[1].exchange = refuse
        self.controllers[1].announce(vipetcd.Ops(self.all[1]).facts(),
                                     vipnode.signed_claim(self.all[1], VIP,
                                                          1))
        self.assertIn("did not take the claim", self.text(1))

    def test_run_until_stopped(self):
        stop = self.controllers[2].stop
        with mock.patch.object(vipetcd.Controller, "following",
                               side_effect=lambda: stop.set()), \
                mock.patch.object(vipetcd.Controller, "holding",
                                  side_effect=VipError("x")):
            self.controllers[2].run()
        with mock.patch.object(vipetcd.Controller, "following",
                               side_effect=VipError("y")):
            stop.clear()
            threading.Timer(0.3, stop.set).start()
            self.controllers[2].run()
        self.assertIn("vip: y", self.text(2))

    def test_stopped_drops_what_it_carries(self):
        self.promote(0)
        self.assertEqual(vipetcd.stopped(self.all[0]), ([VIP], []))
        self.assertFalse(self.carried(0))
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.nets[0].addresses.append(f"{VIP}/128")
        self.nets[0].fail[("ip", "-6", "addr", "del")] = "ip: busy"
        self.assertEqual(vipetcd.stopped(self.all[0]), ([VIP], []))
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

    def test_carry_held_rechecks_the_lease_s_freshness(self):
        self.promote(0)
        self.nets[0].addresses.clear()
        self.assertFalse(vipnode.carry_held(self.all[0], VIP))
        self.assertFalse(vipnode.carry_held(self.all[0], VIP,
                                            vipetcd.RELEASE_AFTER))
        self.assertTrue(vipnode.carry_held(self.all[0], VIP, 1.0))

    def test_a_node_that_released_is_not_fenced_by_its_old_lease(self):
        self.promote(0)
        held = vipnode.current(self.all[0], VIP)
        vipnode.release(self.all[0], VIP, self.kv.revoke)
        self.controllers[0].renew(vipetcd.Ops(self.all[0]).facts(), held,
                                  self.monotonic())
        self.turn(0)
        after = vipnode.current(self.all[0], VIP)
        self.assertFalse(after.fenced)
        self.assertTrue(after.released)
        # it released it: it claims nothing again
        self.assertNotIn(VIP, self.controllers[0].reclaim)
        self.assertEqual(vipetcd.seen(self.kv, MESH_HEX)[VIP].epoch.epoch, 1)
        # a lease gone long after its last renewal (cut off) still fences
        self.promote(1)
        held = vipnode.current(self.all[1], VIP)
        self.controllers[1].renewed[VIP] = self.monotonic() - 60
        self.kv.revoke(held.lease)
        self.controllers[1].renew(vipetcd.Ops(self.all[1]).facts(), held,
                                  self.monotonic())
        self.assertTrue(vipnode.current(self.all[1], VIP).fenced)


class TestAMemberOutsideThePair(WithEtcd):
    """C, a trusted member with a client certificate, is no member of the
    pair; etcd lets it write any key and revoke any lease"""

    def setUp(self):
        super().setUp()
        self.promote(0)
        self.run_for(5)
        self.assertEqual(self.holds(), [0])

    def steady(self, seconds: float = 40) -> None:
        """A keeps the VIP, alone, and B never fails over"""
        self.run_for(seconds)
        self.assertEqual(self.holds(), [0])
        self.assertEqual(vipnode.current(self.all[1], VIP).epoch, 1)
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.assertEqual(self.both, [])

    def test_an_old_valid_claim_put_under_the_holder_key(self):
        old = vipnode.signed_claim(self.all[1], VIP, 1)
        self.kv.put(HOLDER, old.raw)
        self.steady()

    def test_the_current_claim_put_without_its_lease(self):
        current = vipetcd.seen(self.kv, MESH_HEX)[VIP].epoch
        self.kv.put(HOLDER, current.raw)
        self.steady()

    def test_the_holder_key_deleted(self):
        self.kv.delete(HOLDER)
        self.steady()

    def test_an_old_claim_put_under_the_counter(self):
        self.promote(1)
        self.run_for(5)
        older = vipetcd.seen(self.kv, MESH_HEX)[VIP]
        self.kv.put(EPOCH, vipnode.signed_claim(self.all[0], VIP, 1).raw)
        self.run_for(30)
        self.assertEqual(self.holds(), [1])
        self.assertEqual(self.both, [])
        self.assertIsNotNone(older)

    def recovered(self, revoked_at: float) -> float:
        """The seconds until a node carries the VIP again after a revoke;
        the holder drops it at its next renewal first"""
        dropped = None
        for _ in range(int(vipetcd.TTL) + 10):
            self.sleep(1.0)
            self.turn()
            if dropped is None and not self.holds():
                dropped = self.monotonic()
            if dropped is not None and self.holds():
                return self.monotonic() - revoked_at
        self.fail(f"nobody carries the VIP: {self.text(0)}\n{self.text(1)}")

    def test_the_holder_s_lease_revoked(self):
        """the holder learns it at its next renewal, drops the VIP, and,
        having lost nothing, claims again at the next epoch; nobody stays
        fenced and nobody carries it twice"""
        revoked_at = self.monotonic()
        self.kv.revoke(self.lease())
        took = self.recovered(revoked_at)
        self.assertLess(took, vipetcd.TTL)
        self.assertEqual(self.holds(), [0])
        self.assertEqual(vipnode.current(self.all[0], VIP).epoch, 2)
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.assertIn("claiming again", self.text(0))
        self.assertEqual(self.both, [])

    def test_two_revokes_in_a_row(self):
        for expected in (2, 3):
            revoked_at = self.monotonic()
            self.kv.revoke(self.lease())
            took = self.recovered(revoked_at)
            self.assertLess(took, vipetcd.TTL)
            self.assertEqual(len(self.holds()), 1)
            self.assertEqual(vipetcd.seen(self.kv, MESH_HEX)[VIP].epoch.epoch,
                             expected)
            self.run_for(3)
        self.assertFalse(any(vipnode.current(one, VIP).fenced
                             for one in self.all[:2]))
        self.assertEqual(self.both, [])

    def test_a_revoke_the_other_node_s_claim_beats(self):
        """B claims first (A slow to retry): the counter's transaction
        lets only one claim through, and A takes B's"""
        self.kv.revoke(self.lease())
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        self.assertFalse(self.carried(0))
        self.assertIn(VIP, self.controllers[0].reclaim)
        # B's claim lands first
        made = vipetcd.claim(
            self.kv, MESH_HEX, VIP, vipetcd.seen(self.kv, MESH_HEX)[VIP], 1,
            lambda vip, epoch, lease: vipnode.signed_claim(
                self.all[1], vip, epoch, lease), self.monotonic)
        vipnode.hold(self.all[1], made[0], False, made[1])
        self.turn(0)
        self.assertNotIn(VIP, self.controllers[0].reclaim)
        self.assertFalse(self.carried(0))
        self.assertEqual(vipnode.current(self.all[0], VIP).holder, KEYS[1])
        self.assertEqual(self.both, [])

    def test_a_reclaim_whose_state_moved_on(self):
        self.controllers[0].reclaim.add(VIP)
        vipnode.release(self.all[0], VIP, lambda lease: None)
        self.turn(0)
        self.assertNotIn(VIP, self.controllers[0].reclaim)

    def test_the_holder_s_lease_revoked_while_it_is_cut_off(self):
        """the worst case for the grace: A cannot renew and does not learn
        of the revoke; it drops at RELEASE_AFTER, before B claims"""
        self.kv.refuse = None
        revoked_at = self.monotonic()
        original = self.kv.keepalive
        self.kv.keepalive = lambda lease: (_ for _ in ()).throw(
            vipetcd.EtcdError("cut off"))
        self.kv.revoke(self.lease())
        for _ in range(int(vipetcd.GRACE) + 10):
            self.sleep(1.0)
            self.turn()
            if self.carried(1):
                break
        self.kv.keepalive = original
        self.assertTrue(self.carried(1))
        self.assertFalse(self.carried(0))
        self.assertEqual(self.both, [])
        self.assertGreaterEqual(self.monotonic() - revoked_at,
                                vipetcd.GRACE)


class TestStatusWithEtcd(WithEtcd):
    def test_a_holder_restarted_with_its_controller_gone_status(self):
        self.promote(0)
        lines = "\n".join(vippromote.lines(self.all[0], True))
        self.assertIn("etcd lease", lines)


if __name__ == "__main__":
    unittest.main()
