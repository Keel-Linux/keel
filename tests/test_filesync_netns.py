# Copyright (c) 2026 KeelLinux maintainers
"""File replication with syncthing on the pair, under 0050's profiles

tests/filesync_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how): two nodes of a pair on the members' channel
alone (no etcd), the real syncthing from the Keel archive and keel's
flip, with the link tuned per profile — ideal, regional, the design
case, the design case with 2% loss, and a partition and heal. Every
profile: the device ID exchange over the members' channel (the first
ask, before the other node holds an identity, is refused), a full sync
of the blog's content and media but not the excluded cache, the
promote's flip with a write on the new primary crossing, and clean
counters. The lossy profile adds the one-writer rule's case: a local
write on the replica is counted, and when that node is promoted the
change crosses and the old content is kept (a version, or syncthing's
conflict copy). In CI a missing tool fails instead of skipping; it runs
in its own job, "filesync / trixie", which sets KEEL_FILE_SYNC_NETNS.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

import wgtools

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "filesync_netns.py")
DEVICE_ID_RE = re.compile(r"^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$")
CONTENT = "/var/www/blog/content"
# the round trip both legs of a profile make, and its loss
BOUNDS = {
    "ideal": (4, 8, 0.0, 0.001),
    "regional": (85, 115, 0.0, 0.001),
    "design": (220, 280, 0.0, 0.02),
    "lossy": (220, 280, 0.005, 0.08),
}


CLEAN = {"receiveOnlyChangedFiles": 0, "needFiles": 0}


def clean(counts: dict) -> dict:
    """The two counters of a folder's row"""
    return {name: counts[name] for name in CLEAN}


class TestTheFilesOnAPoorNetwork(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and not os.environ.get(
                "KEEL_FILE_SYNC_NETNS"):
            self.skipTest("runs in the filesync / trixie job")
        tools = wgtools.require(self)
        if shutil.which("syncthing") is None:
            if os.environ.get("CI"):
                self.fail("syncthing is not installed in CI")
            self.skipTest("syncthing not found")
        for tool in ("tc", "curl", "runuser", "setpriv", "nsenter", "ss"):
            if not shutil.which(tool) and not os.environ.get("CI"):
                self.skipTest(f"{tool} not found")
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not self.found:
            self.found.update(self.run_driver(f"{tools}"))

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
            capture_output=True, text=True, check=False, timeout=2400)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def profile(self, name: str) -> dict:
        self.assertIn(name, self.found, self.found.get("error"))
        return self.found[name]

    def test_the_syncthing_is_the_keel_archives(self):
        version = " ".join(self.found.get("syncthing", []))
        # Debian's 1.29 does not read the configuration's version 52:
        # the archive's 2.1 is the pinned one (0050's amendment)
        self.assertTrue(version.startswith("syncthing v2.1"), version)

    def test_the_agents_and_the_listeners_are_up(self):
        for name, said in self.found.get("agents", {}).items():
            self.assertIsNotNone(said.get("members"), (name, said))

    def check_link(self, name: str) -> dict:
        found = self.profile(name)
        low, high, loss_low, loss_high = BOUNDS[name]
        link = found["link"]
        self.assertIn("rtt_min_ms", link, link)
        self.assertGreater(link["rtt_min_ms"], low, link)
        self.assertLess(link["rtt_min_ms"], high, link)
        self.assertLess(link["rtt_median_ms"], high * 1.4, link)
        self.assertGreaterEqual(link["loss"], loss_low, link)
        self.assertLessEqual(link["loss"], loss_high, link)
        return found

    def check_sync(self, name: str) -> dict:
        """What every profile proves: the exchange, the sync, the flip"""
        found = self.check_link(name)
        # B asked first, before A held an identity: refused and said
        self.assertTrue(any("holds no syncthing identity" in line
                            for line in found["b_first"]["said"]),
                        found["b_first"])
        devices = found["devices"]
        self.assertIsNotNone(DEVICE_ID_RE.match(devices["device"]), devices)
        self.assertIsNotNone(DEVICE_ID_RE.match(devices["peer"]), devices)
        # every seeded file crossed, within the profile's time
        self.assertIsNotNone(found["sync_s"], found)
        self.assertFalse(found["b_cache"],
                         "the excluded cache crossed the link")
        self.assertEqual(clean(found["b_counts"]["counts"][CONTENT]),
                         CLEAN, found["b_counts"])
        # the promote's flip: a write on the new primary crossed
        self.assertTrue(found["a_back"]["rendered"], found["a_back"])
        self.assertIsNotNone(found["flip_sync_s"], found)
        return found

    def test_the_ideal_link(self):
        self.assertLess(self.profile("ideal")["sync_s"], 30)

    def test_the_ideal_profile(self):
        self.check_sync("ideal")

    def test_the_regional_profile(self):
        self.check_sync("regional")

    def test_the_design_profile(self):
        self.check_sync("design")

    def test_the_lossy_profile(self):
        found = self.check_sync("lossy")
        # the one-writer rule's case: a local write on the replica is
        # counted (keel diff's row and the alert ride on this counter)
        self.assertIsNotNone(found["replica_edit_seen_s"], found)
        # the promoted replica's change crossed, and the old content is
        # kept on the other side, as a version or a conflict copy
        self.assertIsNotNone(found["promote_sync_s"], found)
        self.assertTrue(found["a_versions"], found)

    def test_the_partition_heals_clean(self):
        found = self.profile("partition")
        self.assertIsNotNone(self.found["partition_baseline_s"],
                             self.found)
        self.assertIsNotNone(found["heal_sync_s"], found)
        for side in ("a_counts", "b_counts"):
            for path, counts in found[side]["counts"].items():
                with self.subTest(side=side, path=path):
                    self.assertEqual(clean(counts), CLEAN, found[side])

    def test_a_cut_primary_sends_nothing_until_it_is_proven_again(self):
        found = self.profile("cut_primary")
        # the pause reached the running folders, through the API
        self.assertNotIn("error", found["paused"], found)
        for path, counts in found["a_counts"]["counts"].items():
            self.assertTrue(counts["paused"], (path, found))
        # what it wrote while paused did not cross the healed link
        self.assertFalse(found["reached_while_paused"], found)
        # the proven role sends it
        self.assertNotIn("error", found["proven_again"], found)
        self.assertIsNotNone(found["resume_sync_s"], found)


if __name__ == "__main__":
    unittest.main()
