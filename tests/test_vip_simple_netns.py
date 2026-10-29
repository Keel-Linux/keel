# Copyright (c) 2026 KeelLinux maintainers
"""keel vip promote in cloud simple with a member outside the pair down
(keel#137)

tests/vip_simple_netns.py, as root in a network namespace of its own, on
tests/vip_netns.py's nodes and links (250 ms ±25 ms, 2 % loss), every
spec in cloud simple: with C, outside the pair, cut off, a planned
promote takes the VIP in less than 3 s (on keel 0.23.13 it waited two
10 s timeouts on C), and at no instant do two nodes carry it
(tests/vip_overlap.py). In CI it runs in its own job, "vip-simple /
trixie", which sets KEEL_VIP_SIMPLE_NETNS.
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
DRIVER = os.path.join(REPO, "tests", "vip_simple_netns.py")


class TestAMemberOutsideThePairDown(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and \
                not os.environ.get("KEEL_VIP_SIMPLE_NETNS"):
            self.skipTest("runs in the vip-simple / trixie job")
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
        link = self.found["link"]
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertNotIn("error", self.found, self.found)
        self.assertEqual(self.found["a"]["code"], 0, self.found["a"])
        # cloud simple: no lease
        self.assertFalse(any("etcd lease" in line for line in
                             self.found["a_status"]["lines"]), self.found)

    def test_a_planned_promote_with_a_member_down_takes_under_3_s(self):
        found = self.found
        print(f"planned promote, C down: {found['b_s']} s", file=sys.stderr)
        self.assertEqual(found["b"]["code"], 0, found["b"])
        self.assertLess(found["b_s"], 3.0, found["b"])
        self.assertIsNotNone(found["b_holds_s"], found)
        self.assertTrue(found["a_dropped"], found)
        self.assertEqual(found["holders_after"], ["B"], found)

    def test_no_two_nodes_carry_it_at_one_instant(self):
        atomic = self.found["atomic"]
        self.assertTrue(atomic["ended"], atomic)
        self.assertGreater(atomic["rounds"], 1000, atomic)
        self.assertEqual(atomic["overlaps"], [], atomic)
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
