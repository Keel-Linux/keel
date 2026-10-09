# Copyright (c) 2026 KeelLinux maintainers
"""A peer added and reverted live keeps the other sessions (keel#99)

tests/overlay_live_netns.py, as root in a network namespace of its own
(tests/wgtools.py), with the real wg and wg-quick and the wireguard
kernel module: wg0 and wg1 complete a handshake over the loopback, then
keel.network.switch adds a peer to wg0, which also removes a stray peer
set on wg0 by hand, and reverts it. Neither runs
wg-quick, wg0 stays the same interface, and its handshake with wg1 is
the one from before; a change of [Interface] still bounces wg0. In CI
a missing tool or namespace fails instead of skipping.
"""

import json
import os
import subprocess
import sys
import unittest

import wgtools

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "overlay_live_netns.py")


class TestLivePeers(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        tools = wgtools.require(self)
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not TestLivePeers.found:
            TestLivePeers.found = self.run_driver(tools)
        self.found = TestLivePeers.found

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

    def test_a_peer_added_keeps_the_interface_and_its_sessions(self):
        first, added = self.found["first"], self.found["added"]
        self.assertIsNone(self.found["change"])
        self.assertIn(self.found["third"], added["peers"])
        # drift of the interface is corrected, as the bounce corrected it
        self.assertNotIn(self.found["stray"], added["peers"])
        self.assertEqual(added["quick"], [])
        self.assertEqual(added["index"], first["index"])
        self.assertEqual(added["handshake"], first["handshake"])

    def test_its_revert_keeps_them_too(self):
        first, reverted = self.found["first"], self.found["reverted"]
        worked, line = self.found["revert"]
        self.assertTrue(worked, line)
        self.assertNotIn(self.found["third"], reverted["peers"])
        self.assertEqual(reverted["quick"], [])
        self.assertEqual(reverted["index"], first["index"])
        self.assertEqual(reverted["handshake"], first["handshake"])

    def test_a_change_of_the_interface_still_bounces_it(self):
        ported = self.found["ported"]
        self.assertIsNone(self.found["port_change"])
        self.assertEqual(ported["quick"], [["wg-quick", "down"],
                                           ["wg-quick", "up"]])
        self.assertNotEqual(ported["index"], self.found["first"]["index"])


if __name__ == "__main__":
    unittest.main()
