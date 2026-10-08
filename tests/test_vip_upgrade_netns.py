# Copyright (c) 2026 KeelLinux maintainers
"""Upgrades on a pair whose VIP is active (the maintainer's requirement
of 2026-10-10): an upgrade-style restart of keel-vip.service on the
holder, on the replica and a crash of its helper; etcd restarted as its
package does on each member in turn, through keel-overlay-etcd's gate;
a second member's restart held back while the first is down; and the
holder's controller frozen, the address dropped by the kernel

tests/vip_upgrade_netns.py, as root in a network namespace of its own,
on the nodes and links tests/vip_netns.py makes (250 ms ±25 ms, 2% loss,
measured first). In CI a missing tool fails instead of skipping; it runs
in its own job, "vip-upgrade / trixie", which sets KEEL_VIP_UPGRADE_NETNS.
"""

import json
import os
import shutil
import subprocess
import sys
import unittest

import wgtools
from test_etcd_netns import etcd_dir

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "vip_upgrade_netns.py")
# the longest gap in C's answers to the VIP, every 50 ms, an upgrade-style
# restart may cause: a few pings lost on the links' own 2% each way, and
# no more
MAX_BLIP = 1.0
RELEASE_AFTER = 10.0


class TestUpgradesKeepTheVip(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and \
                not os.environ.get("KEEL_VIP_UPGRADE_NETNS"):
            self.skipTest("runs in the vip-upgrade / trixie job")
        tools = wgtools.require(self)
        etcd = etcd_dir()
        if etcd is None:
            if os.environ.get("CI"):
                self.fail("etcd is not installed in CI")
            self.skipTest("etcd not found (set KEEL_ETCD_DIR)")
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not shutil.which("tc") and not os.environ.get("CI"):
            self.skipTest("tc not found (iproute2)")
        if not self.found:
            self.found.update(self.run_driver(f"{tools}:{etcd}"))

    def run_driver(self, path: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        done = subprocess.run(
            prefix + ["env", f"PATH={path}:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}:{os.path.join(REPO, 'tests')}",
                      f"TMPDIR={os.environ.get('TMPDIR') or '/tmp'}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=1500)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_the_links_are_the_design_case(self):
        link = self.found["link"]
        self.assertNotIn("error", self.found, self.found.get("error"))
        self.assertEqual(self.found["netem_leg"], ["125ms", "12.5ms", "2%"])
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_min_ms"], 280, link)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertGreater(link["loss"], 0.005, link)
        self.assertLess(link["loss"], 0.08, link)

    def test_a_the_vip_is_up_before_anything_restarts(self):
        found = self.found
        self.assertEqual(found["a"]["code"], 0, found["a"])
        self.assertEqual(found["a_holder"], ["A"], found)
        self.assertGreater(found["a_answers"], 100, found)

    def no_move(self, one: dict) -> None:
        # no failover: the counter's claim is the one before, A's
        self.assertIsNotNone(one["epoch_before"], one)
        self.assertEqual(one["epoch_after"], one["epoch_before"], one)
        for holders in one["holders_seen"]:
            self.assertLessEqual(len(holders), 1, one)

    def test_a_the_holder_restarted_as_an_upgrade_does(self):
        for one in self.found["restarts"]:
            with self.subTest(at=one.get("epoch_before")):
                self.no_move(one)
                self.assertEqual(one["holders_after"], ["A"], one)
                # the address never left wg0
                self.assertIsNone(one["dropped_s"], one)
                self.assertLess(one["gap_s"], MAX_BLIP, one)

    def test_a_the_replica_restarted(self):
        one = self.found["replica_restart"]
        self.no_move(one)
        self.assertEqual(one["holders_after"], ["A"], one)
        self.assertLess(one["gap_s"], MAX_BLIP, one)

    def test_a_the_holder_s_helper_crashed(self):
        """Restart=always brings it back RestartSec later; the address
        stays the kernel's lifetime meanwhile, and nothing moves"""
        one = self.found["crash"]
        self.no_move(one)
        self.assertEqual(one["holders_after"], ["A"], one)
        self.assertLess(one["gap_s"], RELEASE_AFTER, one)

    def test_b_etcd_restarted_on_each_member_in_turn(self):
        restarts = self.found["etcd_restarts"]
        self.assertEqual([one["node"] for one in restarts], ["C", "A", "B"])
        for one in restarts:
            with self.subTest(node=one["node"]):
                self.assertEqual(one["gate_stop"]["code"], 0, one)
                self.assertEqual(one["gate_started"]["code"], 0, one)
                self.no_move(one)
                self.assertLess(one["gap_s"], MAX_BLIP, one)
                # the other two kept the majority: they kept writing
                for name, seen in one["quorum"].items():
                    self.assertGreater(seen["puts"], 0, (name, one))
                    self.assertLessEqual(seen["put_failures"], 1,
                                         (name, one))

    def test_c_a_second_member_waits_for_the_first(self):
        found = self.found
        self.assertEqual(found["c_gate_stop"]["code"], 0, found)
        check = found["upgrade_check_c_down"]
        self.assertNotEqual(check["code"], 0, check)
        self.assertTrue(any("fd00:6b65:f1b::3" in line
                            for line in check["said"]), check)
        refused = found["b_gate_refused"]
        self.assertNotEqual(refused["code"], 0, refused)
        self.assertGreaterEqual(refused["took_s"], 20, refused)
        self.assertTrue(found["b_etcd_running"], found)
        self.assertEqual(found["c_gate_started"]["code"], 0, found)
        self.assertEqual(found["upgrade_check_healthy"]["code"], 0, found)
        after = found["b_gate_after"]
        self.assertEqual(after["code"], 0, after)
        self.assertEqual(found["b_gate_after_started"]["code"], 0, found)
        for holders in found["c_holders_seen"]:
            self.assertEqual(holders, ["A"], found)

    def test_d_a_frozen_controller_is_dropped_by_the_kernel(self):
        found = self.found
        self.assertIsNotNone(found["d_dropped_sampled_s"], found)
        # within the release time of A's last confirmed renewal, which
        # was at most a renewal period before the freeze
        self.assertLess(found["d_dropped_sampled_s"], RELEASE_AFTER, found)
        self.assertIsNotNone(found["d_carried_s"], found)
        self.assertGreater(found["d_carried_s"],
                           found["d_dropped_sampled_s"], found)
        self.assertEqual(found["d_holder"], ["B"], found)

    def test_no_two_nodes_ever_carry_it(self):
        self.assertGreater(self.found["samples"], 100, self.found)
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
