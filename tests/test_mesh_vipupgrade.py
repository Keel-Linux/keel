# Copyright (c) 2026 KeelLinux maintainers
"""Upgrades keep the VIP (the maintainer's requirement of 2026-10-10):
the address carried with a lifetime the kernel ends by the release
deadline, a restarted controller that leaves a bounded address alone
until its own renewal, ExecStopPost that keeps it on a restart, and the
controller renewing through any member, on a fake etcd with a clock
(tests/vip_helpers.py)"""

import json
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from test_mesh_vipetcd import WithEtcd
from vip_helpers import VIP, address

from keel.mesh import etcdstate, vipbridge, vipetcd, vipnet, vipnode, vipunit
from keel.mesh.vip import RELEASE_AFTER

HOST = f"{VIP}/128"


class TestTheLifetime(unittest.TestCase):
    def test_it_ends_before_the_release_deadline(self):
        # the kernel removes an address up to EXPIRY_SLACK late
        for age in (0.0, 0.4, 1.7, 2.0, 3.9, 6.5, 7.9):
            with self.subTest(age=age):
                valid = vipnet.lifetime(age)
                self.assertGreaterEqual(valid, 1)
                self.assertLessEqual(age + valid + vipnet.EXPIRY_SLACK,
                                     RELEASE_AFTER)
        self.assertEqual(vipnet.lifetime(0.0), 9)
        self.assertEqual(vipnet.lifetime(0.6), 8)
        self.assertEqual(vipnet.lifetime(8.5), None)
        self.assertIsNone(vipnet.lifetime(9.0))
        self.assertIsNone(vipnet.lifetime(RELEASE_AFTER))
        self.assertIsNone(vipnet.lifetime(-1.0))

    def test_the_address_is_replaced_with_it(self):
        calls = []
        vipnet.carry("wg0", VIP, lambda argv: calls.append(argv), 6)
        vipnet.carry("wg0", VIP, lambda argv: calls.append(argv))
        self.assertEqual(calls[0], (
            "ip", "-6", "addr", "replace", HOST, "dev", "wg0", "valid_lft",
            "6", "preferred_lft", "0", "nodad"))
        self.assertNotIn("valid_lft", calls[1])

    def test_bounded_reads_ip(self):
        def output(text):
            return lambda argv: text
        line = (f"5: wg0    inet6 {HOST} scope global dynamic deprecated"
                " nodad \\       valid_lft {} preferred_lft 0sec\n")
        self.assertTrue(vipnet.bounded("wg0", VIP, output(
            line.format("7sec"))))
        self.assertFalse(vipnet.bounded("wg0", VIP, output(
            line.format("forever"))))
        self.assertIsNone(vipnet.bounded("wg0", VIP, output("")))
        self.assertIsNone(vipnet.bounded("wg0", VIP, output(None)))


class TestTheHolder(WithEtcd):
    def lifetime(self, index: int = 0):
        return self.nets[index].lifetimes.get(HOST)

    def test_every_confirmed_renewal_gives_it_a_new_lifetime(self):
        self.promote(0)
        self.turn()
        self.assertTrue(self.carried(0))
        self.assertIsNotNone(self.lifetime())
        replaced = len([one for one in self.nets[0].calls
                        if one[3:4] == ("replace",)])
        for _ in range(3):
            self.sleep(vipetcd.RENEW)
            self.controllers[0].holding()
        now = len([one for one in self.nets[0].calls
                   if one[3:4] == ("replace",)])
        self.assertEqual(now - replaced, 3)
        # between renewals, nothing is replaced
        self.sleep(0.2)
        self.controllers[0].holding()
        self.assertEqual(len([one for one in self.nets[0].calls
                              if one[3:4] == ("replace",)]), now)

    def test_a_renewal_too_late_to_bound_is_not_carried(self):
        self.assertFalse(vipnode.carry_held(self.all[0], VIP, 1.0))
        self.promote(0)
        self.nets[0].addresses.clear()
        self.assertFalse(vipnode.carry_held(self.all[0], VIP, 8.9))
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.carry_held(self.all[0], VIP, 0.5))
        self.assertEqual(self.lifetime(), vipnet.lifetime(0.5))

    def test_a_restarted_controller_keeps_a_bounded_address(self):
        """What a graceful restart leaves: the address, bounded, and the
        lease in the state file; the new controller extends it only once
        it renewed that lease"""
        self.promote(0)
        self.run_for(4)
        lease = self.lease()
        self.controllers[0] = self.controller(0)
        self.kv.refuse = "keepalive"
        self.controllers[0].holding()
        self.assertTrue(self.carried(0))
        before = [one for one in self.nets[0].calls]
        self.kv.refuse = None
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        self.assertTrue(self.carried(0))
        self.assertGreater(len(self.nets[0].calls), len(before))
        self.assertEqual(self.lease(), lease)
        self.assertFalse(vipnode.current(self.all[0], VIP).fenced)
        self.assertNotIn("not renewed since", self.text(0))

    def test_a_restarted_controller_drops_an_unbounded_address(self):
        """An address an older keel carried has no lifetime: nothing but
        a controller could take it away, so a new one drops it"""
        self.promote(0)
        self.turn()
        self.nets[0].lifetimes[HOST] = None
        self.controllers[0] = self.controller(0)
        self.kv.refuse = "keepalive"
        self.controllers[0].holding()
        self.assertFalse(self.carried(0))
        self.assertIn("not renewed since this controller started",
                      self.text(0))

    def test_a_restarted_controller_whose_lease_is_gone_fences(self):
        self.promote(0)
        self.turn()
        self.kv.expire(self.lease())
        self.controllers[0] = self.controller(0)
        self.sleep(vipetcd.RENEW)
        self.controllers[0].holding()
        self.assertFalse(self.carried(0))
        self.assertTrue(vipnode.current(self.all[0], VIP).fenced)

    def test_no_renewal_still_drops_it_at_the_release_time(self):
        self.promote(0)
        self.turn()
        self.kv.refuse = "all"
        for _ in range(int(RELEASE_AFTER / vipetcd.RENEW) + 1):
            self.sleep(vipetcd.RENEW)
            self.controllers[0].holding()
        self.assertFalse(self.carried(0))


class TestStopped(WithEtcd):
    def carry(self, bounded: bool) -> None:
        self.promote(0)
        self.turn()
        if not bounded:
            self.nets[0].lifetimes[HOST] = None

    def test_a_stop_drops_it(self):
        self.carry(True)
        self.assertEqual(vipetcd.stopped(self.all[0]), ([VIP], []))
        self.assertFalse(self.carried(0))

    def test_a_restart_keeps_a_bounded_address(self):
        self.carry(True)
        self.assertEqual(vipetcd.stopped(self.all[0], restarting=True),
                         ([], [VIP]))
        self.assertTrue(self.carried(0))
        # and the state keeps the lease the next controller renews
        self.assertIsNotNone(vipnode.current(self.all[0], VIP).lease)

    def test_a_restart_drops_an_unbounded_address(self):
        self.carry(False)
        self.assertEqual(vipetcd.stopped(self.all[0], restarting=True),
                         ([VIP], []))
        self.assertFalse(self.carried(0))


class TestTheUnit(unittest.TestCase):
    def cgroup(self, text: str) -> str:
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fob:
            fob.write(text)
        return path

    def test_own_unit(self):
        self.assertEqual(vipunit.own(self.cgroup(
            "0::/system.slice/keel-vip.service\n")), "keel-vip.service")
        self.assertIsNone(vipunit.own(self.cgroup("0::/user.slice\n")))
        self.assertIsNone(vipunit.own("/nonexistent/cgroup"))

    def jobs(self, text):
        return lambda argv: text if argv[:2] == ("systemctl",
                                                 "list-jobs") else None

    def test_restarting(self):
        path = self.cgroup("0::/system.slice/keel-vip.service\n")
        self.assertTrue(vipunit.restarting(
            {"SERVICE_RESULT": "success"}, self.jobs(
                "812 keel-vip.service restart running\n"), path))
        self.assertTrue(vipunit.restarting(
            {}, self.jobs("9 keel-vip.service try-restart waiting\n"), path))
        # a helper that died: Restart=always starts it again
        self.assertTrue(vipunit.restarting(
            {"SERVICE_RESULT": "signal"}, self.jobs(""), path))
        self.assertTrue(vipunit.restarting(
            {"SERVICE_RESULT": "exit-code"}, self.jobs(None), path))
        # a stop, or another unit's restart
        self.assertFalse(vipunit.restarting(
            {"SERVICE_RESULT": "success"}, self.jobs(
                "812 keel-vip.service stop running\n"
                "813 nginx.service restart waiting\n"), path))
        self.assertFalse(vipunit.restarting({}, self.jobs(None), path))
        self.assertFalse(vipunit.restarting(
            {}, self.jobs("1 keel-vip.service restart running\n"),
            "/nonexistent"))


class TestTheBridge(WithEtcd):
    def test_bounded_over_the_bridge(self):
        self.promote(0)
        self.turn()
        ops = vipetcd.Ops(self.all[0])
        self.assertEqual(vipbridge.answered(ops, json.dumps(
            {"op": "bounded", "vip": VIP}).encode()), {"ok": True})
        remote = vipbridge.Remote(None, threading.Event())
        with mock.patch.object(remote, "ask", return_value=False) as ask:
            self.assertFalse(remote.bounded(VIP))
        ask.assert_called_once_with("bounded", vip=VIP)


class TestTheEndpoints(WithEtcd):
    def test_loopback_first_then_every_other_member(self):
        here = self.all[0]
        self.assertEqual(vipbridge.endpoints(here), [
            etcdstate.client_url(etcdstate.LOOPBACK),
            etcdstate.client_url(address(1)),
            etcdstate.client_url(address(2))])

    def test_without_a_cluster_record_the_loopback_alone(self):
        with mock.patch.object(etcdstate, "cluster", return_value=None):
            self.assertEqual(vipbridge.endpoints(self.all[0]), [
                etcdstate.client_url(etcdstate.LOOPBACK)])
        with mock.patch.object(etcdstate, "cluster",
                               side_effect=etcdstate.StateError("x")):
            self.assertEqual(len(vipbridge.endpoints(self.all[0])), 1)

    def test_the_controller_asks_them_in_order(self):
        theirs, ours = socket.socketpair()
        self.addCleanup(theirs.close)
        made = {}

        class Client:
            def __init__(self, endpoints, tls, timeout):
                made["endpoints"] = endpoints

        def run(controller):
            made["ran"] = True
        body = {"endpoint": "https://[::1]:2379",
                "endpoints": ["https://[::1]:2379",
                              "https://[fd00::2]:2379"]}
        with mock.patch.object(vipbridge, "connected_to_helper",
                               return_value=ours), \
                mock.patch.object(socket, "recv_fds", return_value=(
                    json.dumps(body).encode(), [], 0, None)), \
                mock.patch.object(vipbridge, "held_files"), \
                mock.patch.object(vipbridge, "Client", Client), \
                mock.patch.object(vipetcd.Controller, "run", run), \
                mock.patch.object(vipbridge, "capabilities", return_value=0):
            vipbridge.control("@x", lambda line: None, status=__file__,
                              stop=threading.Event())
        self.assertEqual(made["endpoints"], tuple(body["endpoints"]))


if __name__ == "__main__":
    unittest.main()
