# Copyright (c) 2026 KeelLinux maintainers
"""keel vip promote when the claim's transaction times out (keel#135)

tests/vip_claim_netns.py, as root in a network namespace of its own, on
tests/vip_netns.py's nodes, etcd and links (250 ms ±25 ms, 2 % loss):
B's claim committed in etcd while its answer was lost, and A's claim not
run while its answer was lost. Each promote takes the VIP, and at no
instant do two nodes carry it (tests/vip_overlap.py). In CI it runs in
its own job, "vip-claim / trixie", which sets KEEL_VIP_CLAIM_NETNS.
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
DRIVER = os.path.join(REPO, "tests", "vip_claim_netns.py")


class TestAClaimWhoseAnswerIsLost(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and \
                not os.environ.get("KEEL_VIP_CLAIM_NETNS"):
            self.skipTest("runs in the vip-claim / trixie job")
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

    def test_a_committed_claim_whose_answer_is_lost_is_held(self):
        found = self.found
        self.assertTrue((found["b_fired"] or "").startswith("commit-hang"),
                        found)
        self.assertEqual(found["b"]["code"], 0, found["b"])
        self.assertIsNotNone(found["b_holds_s"], found["b_status"])
        self.assertIn("etcd lease", " ".join(found["b_status"]["lines"]),
                      found["b_status"])

    def test_a_claim_not_run_is_tried_again_and_taken(self):
        found = self.found
        self.assertTrue((found["a2_fired"] or "").startswith("hang"), found)
        self.assertEqual(found["a2"]["code"], 0, found["a2"])
        self.assertIsNotNone(found["a2_holds_s"], found["a2_status"])
        self.assertEqual(found["holders_after"], ["A"], found)

    def test_no_two_nodes_carry_it_at_one_instant(self):
        atomic = self.found["atomic"]
        self.assertTrue(atomic["ended"], atomic)
        self.assertGreater(atomic["rounds"], 1000, atomic)
        self.assertEqual(atomic["overlaps"], [], atomic)
        self.assertEqual(atomic["overlap_rounds"], 0, atomic)
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
