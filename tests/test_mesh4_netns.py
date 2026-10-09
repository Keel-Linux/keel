# Copyright (c) 2026 KeelLinux maintainers
"""keel#99 across four network namespaces: a join into a mesh built by hand

tests/mesh4_netns.py, run as tests/test_mesh_netns.py runs its driver
(as root in a network namespace of its own, the real wg and wg-quick,
the wireguard kernel module; in CI a missing tool or namespace fails).
A, B and C are a mesh built by hand and adopted, so they are each
other's trust roots with no admission evidence; D joins through A. D
takes B and C as peers from A's answer, B and C take D from A's
announcement and confirm it by D's handshake, and every node pings the
three others and holds a WireGuard handshake with each.

On clean links, and on poor ones (250 ms ±25 ms, 2% loss).
"""

import json
import os
import shutil
import subprocess
import sys
import unittest

import wgtools
from test_mesh_netns import POOR

from keel import exits

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "mesh4_netns.py")
NAMES = ("A", "B", "C", "D")


class TestFourNamespaces(unittest.TestCase):
    netem = ""
    reports: dict = {}

    def setUp(self):
        tools = wgtools.require(self)
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if self.netem and not shutil.which("tc") and \
                not os.environ.get("CI"):
            self.skipTest("tc not found (iproute2)")
        if self.netem not in self.reports:
            self.reports[self.netem] = self.run_driver(tools)
        self.found = self.reports[self.netem]

    def run_driver(self, tools: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        done = subprocess.run(
            prefix + ["env", f"PATH={tools}:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}", f"MESH_NETEM={self.netem}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=900)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def key(self, name: str) -> str:
        return self.found["d"]["key"] if name == "D" else \
            self.found["keys"][name]

    def test_a_b_and_c_are_roots_without_evidence(self):
        """the state of web-1, web-2 and web-3 on real nodes"""
        self.assertEqual(self.found["create"], exits.OK,
                         self.found["create_said"])
        for name in ("B", "C"):
            self.assertEqual(self.found["a_roots"][self.key(name)],
                             [True, False])

    def test_d_takes_every_member_from_the_answer(self):
        d = self.found["d"]
        self.assertEqual(d["code"], exits.OK, d)
        self.assertEqual(self.found["serve"], [exits.OK])
        self.assertTrue(d["ping"], d)
        self.assertIn("the mesh has 4 nodes: this node has them all",
                      d["out"][-1])
        for name in ("B", "C"):
            self.assertEqual(self.found["d_roots"][self.key(name)],
                             [True, False])

    def test_b_and_c_take_d_and_confirm_it(self):
        for name in ("B", "C"):
            checked = self.found["checks"][name]
            with self.subTest(name=name):
                self.assertIn(self.key("D"), checked["peers"], checked)
                self.assertEqual(checked["outcome"], "confirmed", checked)
                self.assertTrue(checked["ping"], checked)

    def test_all_four_see_each_other_with_handshakes(self):
        for name in NAMES:
            others = [one for one in NAMES if one != name]
            with self.subTest(name=name):
                self.assertEqual(
                    sorted(self.found["pings"][name]),
                    sorted(self.found["addresses"][one] for one in others))
                self.assertTrue(all(self.found["pings"][name].values()),
                                self.found["pings"][name])
                shown = self.found["handshakes"][name]
                self.assertEqual(sorted(shown),
                                 sorted(self.key(one) for one in others))
                self.assertTrue(all(shown.values()), shown)


class TestFourNamespacesOnAPoorNetwork(TestFourNamespaces):
    netem = POOR


if __name__ == "__main__":
    unittest.main()
