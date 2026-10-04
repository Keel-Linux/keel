# Copyright (c) 2026 KeelLinux maintainers
"""etcd over the WireGuard mesh, under the design case of decision 0050

tests/etcd_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), with the real wg-quick and the real etcd 3.5
(on PATH, or its directory named by KEEL_ETCD_DIR: `apt-get download
etcd-server` and `dpkg-deb -x` give one without installing it), keel's
CA, intermediates and leaves, and keel's rendered configuration, on
links of 250 ms ±25 ms with 2% loss. The cluster forms; its leader and
term do not move while it is left alone; a follower cut off for a while
leaves the other two their quorum and their writes, and comes back
without raising the term (pre-vote); a learner is added and removed
with keel's client. In CI a missing tool fails instead of skipping.

The CI job runs 60 s of stability and a 45 s partition; ETCD_SOAK=full
runs the brief's 5 minutes and 2 minutes, by hand, and the PR carries
that run's result. In CI it runs in its own job, "etcd / trixie",
which sets KEEL_ETCD_NETNS and installs trixie's etcd; the unit test
job, on another distribution's etcd, leaves it to that one.
"""

import json
import os
import shutil
import subprocess
import sys
import unittest

import wgtools

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "etcd_netns.py")


def etcd_dir() -> str | None:
    named = os.environ.get("KEEL_ETCD_DIR")
    if named:
        return named if os.access(os.path.join(named, "etcd"),
                                  os.X_OK) else None
    found = shutil.which("etcd")
    return os.path.dirname(found) if found else None


class TestThreeMembersOnAPoorNetwork(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and not os.environ.get("KEEL_ETCD_NETNS"):
            self.skipTest("runs in the etcd / trixie job, on trixie's etcd")
        tools = wgtools.require(self)
        etcd = etcd_dir()
        if etcd is None:
            if os.environ.get("CI"):
                self.fail("etcd is not installed in CI")
            self.skipTest("etcd not found (set KEEL_ETCD_DIR)")
        for need in ("/sys/module/wireguard",):
            if not os.path.exists(need) and not os.environ.get("CI"):
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
                      f"ETCD_SOAK={os.environ.get('ETCD_SOAK', '')}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=1500)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_it_forms_under_the_design_case(self):
        self.assertEqual(self.found["netem_leg"], ["125ms", "12.5ms", "2%"])
        self.assertIsNotNone(self.found["formed_s"], self.found)
        self.assertEqual((self.found["heartbeat_ms"],
                          self.found["election_ms"]), (300, 5000))

    def test_the_leader_stays_without_flapping(self):
        leader = self.found["leader_at_formation"]
        for name, seen in self.found["stable"].items():
            with self.subTest(member=name):
                self.assertEqual(seen["leaders"], [leader], seen)
                self.assertEqual(len(seen["terms"]), 1, seen)
                self.assertEqual(seen["put_failures"], 0, seen)
                self.assertGreater(seen["samples"],
                                   self.found["stable_s"] // 4)

    def test_a_partitioned_follower_leaves_the_quorum_and_rejoins(self):
        cut = self.found["partitioned"]
        self.assertFalse(self.found["partitioned_was_leader"])
        during = self.found["during_partition"]
        terms = set()
        for name, seen in during.items():
            if name == cut:
                self.assertEqual(seen["puts"], 0, seen)
                continue
            with self.subTest(member=name):
                self.assertEqual(seen["leaders"],
                                 [self.found["leader_at_formation"]], seen)
                self.assertEqual(seen["put_failures"], 0, seen)
                self.assertGreater(seen["puts"], 0, seen)
                terms.update(seen["terms"])
        self.assertIsNotNone(self.found["rejoined_s"], self.found)
        self.assertEqual(self.found["leader_after_heal"],
                         self.found["leader_at_formation"])
        # pre-vote: the member that came back raised no term
        after = set()
        for seen in self.found["after_heal"].values():
            after.update(seen["terms"])
        self.assertEqual(after, terms)

    def test_a_learner_added_and_removed_with_keel_s_client(self):
        self.assertEqual(self.found["learner"], {
            "added": True, "listed_unstarted": True, "removed": True})


if __name__ == "__main__":
    unittest.main()
