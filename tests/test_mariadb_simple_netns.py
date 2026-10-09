# Copyright (c) 2026 KeelLinux maintainers
"""The unplanned failover of a cloud simple MariaDB pair, measured

tests/mariadb_simple_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), on tests/mariadb_netns.py's nodes with the
specs in cloud simple: no etcd lease, the VIP moved by the members'
channel, as on the real pair (keel#108, keel#118). The primary's server
is killed and the primary cut off; the operator's `keel database promote
--old-primary-gone` on the replica starts exactly 2 s after. The writes
at the VIP come back within 15 s of the promote's start plus the three
full timeouts the promote waits on the dead old primary without etcd,
and no row the application had acknowledged is lost. In CI a missing tool fails instead
of skipping; it runs in its own job, "mariadb-simple / trixie", which
sets KEEL_MARIADB_SIMPLE_NETNS.
"""

import json
import os
import subprocess
import sys
import unittest

import wgtools
from test_etcd_netns import etcd_dir
from test_mariadb_netns import SCRATCH

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "mariadb_simple_netns.py")
# the target the rollout of 0.23.7 set (Keel-Linux/handbook#62), plus
# what the safety review of keel#108 keeps without etcd: nothing fences
# a live old primary there, so each of the promote's three asks of it
# (its epoch, the release, the announcement) waits the members'
# channel's full connect timeout
ASKS_OF_THE_OLD_PRIMARY = 3
TARGET_S = 15.0 + ASKS_OF_THE_OLD_PRIMARY * 10.0


class TestACloudSimplePairFailsOver(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and \
                not os.environ.get("KEEL_MARIADB_SIMPLE_NETNS"):
            self.skipTest("runs in the mariadb-simple / trixie job")
        tools = wgtools.require(self)
        etcd = etcd_dir()
        if etcd is None:
            if os.environ.get("CI"):
                self.fail("etcd is not installed in CI")
            self.skipTest("etcd not found (set KEEL_ETCD_DIR)")
        if not os.path.exists("/usr/sbin/mariadbd"):
            if os.environ.get("CI"):
                self.fail("mariadb-server is not installed in CI")
            self.skipTest("mariadb-server not installed")
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not self.found:
            self.found.update(self.run_driver(f"{tools}:{etcd}"))

    def run_driver(self, path: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        os.makedirs(SCRATCH, exist_ok=True)
        os.chmod(SCRATCH, 0o1777)
        done = subprocess.run(
            prefix + ["env",
                      f"PATH={path}:/usr/sbin:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}:{REPO}/tests", f"TMPDIR={SCRATCH}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=1800)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-4000:]}\n"
                  f"{done.stderr[-4000:]}")

    def test_the_links_are_the_design_case_and_the_pair_is_up(self):
        found = self.found
        link = found["link"]
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertGreater(link["loss"], 0.005, link)
        self.assertNotIn("setup_error", found, found)
        self.assertNotIn("error", found, found)
        self.assertFalse(found["a_apply"]["failed"], found["a_apply"])
        self.assertFalse(found["b_apply"]["failed"], found["b_apply"])
        self.assertIsNotNone(found["b_streaming_s"], found)
        self.assertIsNotNone(found["semisync_s"], found)
        # no etcd: the VIP holds no lease
        self.assertFalse(any("etcd lease" in line for line in
                             found["with_etcd"]["lines"]), found)

    def test_the_writes_come_back_within_15_s_of_the_promote(self):
        found = self.found["downtime"]
        print(f"cloud simple downtime: {found}", file=sys.stderr)
        self.assertEqual(self.found["promote"]["code"], 0,
                         self.found["promote"])
        self.assertIsNotNone(found["first_ok_after_s"], found)
        self.assertAlmostEqual(found["promote_started_s"], 2.0, delta=0.5)
        after_promote = found["first_ok_after_s"] - found["promote_started_s"]
        self.assertLess(after_promote, TARGET_S, found)
        self.assertLess(found["writable_after_carried_s"], 3.0, found)

    def test_no_acknowledged_row_is_lost(self):
        self.assertEqual(self.found["acked_missing"], [],
                         self.found["downtime"])
        self.assertGreater(self.found["downtime"]["acked"], 0)

    def test_without_etcd_the_old_primary_is_waited_for_in_full(self):
        from keel.mesh import memberlink
        self.assertEqual(memberlink.CONNECT_TIMEOUT, 10)
        said = " ".join(self.found["promote"]["out"])
        self.assertNotIn("no answer within", said)
        self.assertIn("timed out", said)


if __name__ == "__main__":
    unittest.main()
