# Copyright (c) 2026 KeelLinux maintainers
"""keel#117 across three network namespaces: two members add each other
three minutes apart

tests/mesh_late_netns.py, run as tests/test_mesh_netns.py runs its
driver (as root in a network namespace of its own, the real wg and
wg-quick, the wireguard kernel module; in CI a missing tool or
namespace fails). B adds C live, and 180 s later C adds B: each keeps
the other with no handshake at first, no change reverts and no member
waits an hour, and once both have the other they complete a handshake
and ping each other. On clean links, and on poor ones.
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
DRIVER = os.path.join(REPO, "tests", "mesh_late_netns.py")


class TestAddedMinutesApart(unittest.TestCase):
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
            capture_output=True, text=True, check=False, timeout=1200)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_b_keeps_c_at_once_with_no_handshake(self):
        b = self.found["b_adopt"]
        self.assertEqual(b["code"], exits.OK, b)
        said = "\n".join(b["err"])
        self.assertIn(f"member {self.found['keys']['C']} is kept with no"
                      " handshake yet", said)
        self.assertNotIn("reverts by itself", said)
        # no 120 s window was waited for
        self.assertLess(self.found["b_adopt_s"], 60)
        self.assertEqual(self.found["b_roots"][self.found["keys"]["C"]],
                         [True, False])

    def test_c_adds_b_three_minutes_later(self):
        self.assertGreaterEqual(self.found["late_s"], 180)
        c = self.found["c_adopt"]
        self.assertEqual(c["code"], exits.OK, c)
        self.assertNotIn("reverts by itself", "\n".join(c["err"]))

    def test_both_keep_the_other_and_shake_hands(self):
        keys = self.found["keys"]
        for name, other in (("B", "C"), ("C", "B")):
            checked = self.found[f"{name.lower()}_check"]
            with self.subTest(node=name):
                self.assertIn(keys[other], checked["peers"], checked)
                self.assertEqual(checked["outcome"], "confirmed", checked)
                self.assertTrue(checked["ping"], checked)
                self.assertGreater(
                    self.found["handshakes"][name][keys[other]], 0,
                    self.found["handshakes"])


class TestAddedMinutesApartOnAPoorNetwork(TestAddedMinutesApart):
    netem = POOR


if __name__ == "__main__":
    unittest.main()
