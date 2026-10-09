# Copyright (c) 2026 KeelLinux maintainers
"""The members' answer crosses a path of 1492 bytes (keel#119)

tests/overlay_mtu_netns.py, as root in a network namespace of its own
(tests/wgtools.py), with the real wg-quick and the wireguard kernel
module: node B is behind a link of 1492 bytes that drops longer packets
and sends no ICMPv6. With the wg0 files keel renders, A's 4 KiB answer
reaches B, and wg0 has the same MTU on both nodes. With the same files
without the MTU line (keel 0.23.7), the answer does not come within the
deadline: the test reproduces the failure on site BR2. In CI a missing
tool or namespace fails instead of skipping.
"""

import json
import os
import subprocess
import sys
import unittest

import wgtools

from keel.network import wireguard

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "overlay_mtu_netns.py")


class TestOverlayMtu(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        tools = wgtools.require(self)
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not TestOverlayMtu.found:
            TestOverlayMtu.found = self.run_driver(tools)
        self.found = TestOverlayMtu.found

    def run_driver(self, tools: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        done = subprocess.run(
            prefix + ["env", f"PATH={tools}:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}", sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=120)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_without_the_mtu_line_the_answer_is_lost(self):
        plain = self.found["plain"]
        self.assertEqual((plain["mtu_a"], plain["mtu_b"]), (1420, 1412))
        self.assertLess(plain["received"], self.found["answer"], plain)

    def test_keels_file_carries_the_answer_across(self):
        keel = self.found["keel"]
        self.assertEqual(keel["received"], self.found["answer"], keel)
        self.assertEqual((keel["mtu_a"], keel["mtu_b"]),
                         (wireguard.OVERLAY_MTU, wireguard.OVERLAY_MTU))


if __name__ == "__main__":
    unittest.main()
