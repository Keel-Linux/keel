# Copyright (c) 2026 KeelLinux maintainers
"""The VIP on the WireGuard mesh, under the design case of decision 0050

tests/vip_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), with the real wg-quick, the real etcd 3.5
(on PATH, or its directory named by KEEL_ETCD_DIR) and keel's members'
channel and VIP controller, on links of 250 ms ±25 ms with 2% loss,
measured before the scenario. A and B are a pair, C routes their VIP:
(a) C reaches the VIP at A; (b) a planned promote moves it to B, and
the downtime C sees is measured; (c) B cut off from the majority drops
it within its lease's release time and A claims it, and at no sample,
every 200 ms, do two nodes carry it; (d) healed, B never carries it
again; (e) a stale claim is refused on the members' channel and by
etcd. In CI a missing tool fails instead of skipping; it runs in its own
job, "vip / trixie", which sets KEEL_VIP_NETNS.
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
DRIVER = os.path.join(REPO, "tests", "vip_netns.py")


class TestTheVipOnAPoorNetwork(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and not os.environ.get("KEEL_VIP_NETNS"):
            self.skipTest("runs in the vip / trixie job, on trixie's etcd")
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
                      f"PYTHONPATH={REPO}",
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
        """Measured before the scenario, judged by the minimum round trip
        as tests/test_etcd_netns.py judges it"""
        link = self.found["link"]
        self.assertEqual(self.found["netem_leg"], ["125ms", "12.5ms", "2%"])
        self.assertIn("rtt_min_ms", link, link)
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_min_ms"], 280, link)
        # the median, not the mean (tests/test_etcd_netns.py says why)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertGreater(link["loss"], 0.005, link)
        self.assertLess(link["loss"], 0.08, link)

    def test_the_lease_is_the_decided_one(self):
        self.assertEqual((self.found["ttl_s"],
                          self.found["release_after_s"]), (20, 10.0))
        self.assertIsNotNone(self.found["etcd_formed_s"], self.found)

    def test_a_the_vip_is_reached_at_the_primary(self):
        found = self.found
        self.assertEqual(found["a"]["code"], 0, found["a"])
        self.assertIsNotNone(found["a_routed_s"], found)
        self.assertEqual(found["a_holder"], ["A"], found)
        # 10 s of pings every 50 ms, most of them answered
        self.assertGreater(found["a_answers"], 100, found)

    def test_b_a_planned_promote_moves_it(self):
        found = self.found
        self.assertEqual(found["b"]["code"], 0, found["b"])
        self.assertTrue(any("released by" in line
                            for line in found["b"]["said"]), found["b"])
        self.assertIsNotNone(found["b_routed_s"], found)
        self.assertEqual(found["b_holder"], ["B"], found)
        self.assertIsNotNone(found["b_downtime_s"], found)
        # a release, a compare-and-swap and the claim's announcement,
        # each a few round trips at 250 ms
        self.assertLess(found["b_downtime_s"], 15, found)

    def partitioned(self, key: str):
        found = self.found
        dropped, carried = found[f"{key}_dropped_s"], found[f"{key}_carried_s"]
        self.assertIsNotNone(dropped, found)
        self.assertIsNotNone(carried, found)
        # B drops it RELEASE_AFTER after its last renewal the majority
        # confirmed, a renewal period and a call's timeout late at most,
        # leader or not: within the TTL
        self.assertLess(dropped, 10 + 2 + 2 + 1, found)
        self.assertLess(dropped, found["ttl_s"], found)
        # never before B dropped it: the lease outlives the release
        self.assertGreater(carried, dropped, found)
        self.assertEqual(found[f"{key}_holder"], ["A"], found)
        self.assertIsNotNone(found[f"{key}_reachable_again_s"], found)

    def test_c_the_cut_off_primary_and_etcd_leader(self):
        self.assertTrue(self.found["c_was_etcd_leader"], self.found)
        self.partitioned("c")

    def test_f_the_cut_off_primary_and_etcd_follower(self):
        self.assertEqual(self.found["f_promote_b"]["code"], 0, self.found)
        self.assertFalse(self.found["f_was_etcd_leader"], self.found)
        self.partitioned("f")

    def test_g_a_member_outside_the_pair_writing_and_revoking(self):
        found = self.found
        self.assertEqual(found["g_promote_b"]["code"], 0, found)
        self.assertNotIn("error", found["g_keys"], found)
        # the holder key written and deleted: B alone, all along
        self.assertEqual(found["g_holders_after_keys"], [["B"]], found)
        self.assertNotIn("error", found["g_revoke"], found)
        dropped, carried = found["g_b_dropped_s"], found["g_a_carried_s"]
        self.assertIsNotNone(dropped, found)
        self.assertIsNotNone(carried, found)
        # B learns the revoke at its next renewal (2 s), a call late
        self.assertLess(dropped, 2 + 2 + 2, found)
        # A waits its grace after it saw the lease end early
        self.assertGreaterEqual(carried, 14 - 1, found)
        self.assertLess(carried - dropped, found["ttl_s"], found)
        self.assertEqual(found["g_holder"], ["A"], found)

    def test_the_pair_and_the_units_hardening(self):
        found = self.found
        self.assertEqual(found["paired"]["code"], 0, found["paired"])
        for name, seen in found["hardening"].items():
            with self.subTest(node=name):
                controller, helper = seen["controller"], seen["helper"]
                # a dynamic user, no capability at all, no new privileges
                self.assertNotEqual(controller.get("Uid"), "0", seen)
                self.assertEqual(int(controller["CapEff"], 16), 0, seen)
                self.assertEqual(int(controller["CapBnd"], 16), 0, seen)
                self.assertEqual(controller.get("NoNewPrivs"), "1", seen)
                # the root helper: CAP_NET_ADMIN (bit 12) and nothing
                # else, and no new privileges
                self.assertEqual(int(helper["CapBnd"], 16), 1 << 12, seen)
                self.assertEqual(helper.get("NoNewPrivs"), "1", seen)

    def test_c_no_two_nodes_ever_carry_it(self):
        self.assertGreater(self.found["samples"], 100, self.found)
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])

    def test_d_the_old_primary_never_claims_it_again(self):
        found = self.found
        self.assertFalse(found["d_b_carried_after_heal"], found)
        self.assertTrue(found["d_c_routes_to_a"], found)
        self.assertEqual(found["d_holder"], ["A"], found)
        self.assertTrue(any("fenced" in line for line in
                            found["d_b_status"]["lines"]), found)

    def test_e_a_stale_claim_is_refused(self):
        found = self.found["e"]
        self.assertTrue(found["channel"].startswith("refused"), found)
        self.assertIn("stale claim", found["channel"], found)
        self.assertTrue(found["etcd_refused"], found)
        self.assertEqual(found["counter_epoch"],
                         found["counter_epoch_after"], found)
        self.assertTrue(self.found["e_c_routes_to_a"], self.found)
        self.assertEqual(self.found["e_holder"], ["A"], self.found)


if __name__ == "__main__":
    unittest.main()
