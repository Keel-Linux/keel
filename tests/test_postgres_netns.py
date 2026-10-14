# Copyright (c) 2026 KeelLinux maintainers
"""A PostgreSQL pair on the mesh under the design case of decision 0050

tests/postgres_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), on tests/vip_netns.py's three nodes: the
real wg-quick, etcd 3.5, keel's members' channel and VIP controller, and
a PostgreSQL 17 server per node, on links of 250 ms +-25 ms with 2 %
loss measured first. Case (a) of docs/replication.md, the PostgreSQL
wording: A applied as the primary, B as the replica, seeded over TLS
with pg_basebackup (the walreceiver streams with sslmode=verify-full,
the pair's slot on A); a write on the primary through its loopback is
read on B, the lag measured from the write's acknowledgement; the
pair's synchronous commit on, a commit paying one round trip; the
replica refusing writes while it is in recovery; `keel diff` clean on
both. Cases (b) to (e) are the follow-up pull request's. In CI a
missing tool fails instead of skipping; it runs in its own job,
"postgres / trixie", which sets KEEL_POSTGRES_NETNS.
"""

import glob
import json
import os
import subprocess
import sys
import unittest

import wgtools
from test_etcd_netns import etcd_dir

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "postgres_netns.py")
# the nodes' scratch roots, on disk and not under /tmp: a systemd unit
# in a network namespace gets a /tmp of its own, where the servers'
# sockets would be out of the agents' reach
SCRATCH = "/var/tmp/keel-postgres-netns"


class TestAPostgresqlPairOnAPoorNetwork(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and not os.environ.get("KEEL_POSTGRES_NETNS"):
            self.skipTest("runs in the postgres / trixie job")
        tools = wgtools.require(self)
        etcd = etcd_dir()
        if etcd is None:
            if os.environ.get("CI"):
                self.fail("etcd is not installed in CI")
            self.skipTest("etcd not found (set KEEL_ETCD_DIR)")
        if not glob.glob("/usr/lib/postgresql/*/bin/postgres"):
            if os.environ.get("CI"):
                self.fail("postgresql is not installed in CI")
            self.skipTest("postgresql-server not installed")
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
            prefix + ["env", f"PATH={path}:/usr/sbin:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}:{REPO}/tests", f"TMPDIR={SCRATCH}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=1800)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-4000:]}\n"
                  f"{done.stderr[-4000:]}")

    def test_the_links_are_the_design_case(self):
        link = self.found["link"]
        self.assertEqual(self.found["netem_leg"], ["125ms", "12.5ms", "2%"])
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_min_ms"], 280, link)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertGreater(link["loss"], 0.005, link)
        self.assertLess(link["loss"], 0.08, link)
        self.assertNotIn("setup_error", self.found, self.found)
        self.assertNotIn("error", self.found, self.found)

    def test_a_both_nodes_apply_and_the_replica_is_seeded_over_tls(self):
        found = self.found
        self.assertFalse(found["a_apply"]["failed"], found["a_apply"])
        self.assertFalse(found["b_apply"]["failed"], found["b_apply"])
        self.assertIsNotNone(found["b_connected_s"], found["b_status_a"])
        status = found["b_status_a"]
        self.assertEqual(status.get("in_recovery"), "t", status)
        self.assertEqual(status.get("status"), "streaming", status)
        # the walreceiver's connection of the seed's follow drop-in:
        # the primary's overlay address, the certificate verified both
        # ways, the pair's application name
        self.assertIn("host=fd00:6b65:f1b::1", status.get("conninfo") or "",
                      status)
        self.assertIn("sslmode=verify-full", status.get("conninfo") or "",
                      status)
        self.assertIn("application_name=keel", status.get("conninfo") or "",
                      status)
        # the pair's synchronous commit and slot, on the primary
        self.assertIn("FIRST 1 (keel)", found["a_sync"]["out"], found)
        slot = found["a_slot"]["out"]
        self.assertIn("keel", slot, found)
        self.assertIn("t", slot.split(), found)
        # the seed carried the application's data
        self.assertEqual(found["a_rows_a"], found["b_rows_a"], found)
        self.assertGreaterEqual(found["b_rows_a"], 1, found)

    def test_a_a_write_on_the_primary_is_read_on_the_replica(self):
        found = self.found
        self.assertEqual(found["a_write"]["code"], 0, found["a_writes"])
        self.assertIsNotNone(found["a_lag_s"], found["a_writes"])
        # acknowledged once the standby received and flushed it, so on
        # the standby within its replay: measured 0.04 to 0.07 s in CI
        # on the MariaDB twin
        self.assertLess(found["a_lag_s"], 1, found["a_writes"])
        # a synchronous commit pays the standby's acknowledgement, one
        # round trip: measured 0.28 to 0.31 s at 250 ms on the twin
        self.assertTrue(all(cost < 1.5 for cost in found["a_commit_costs_s"]),
                        found["a_commit_costs_s"])

    def test_a_the_replica_refuses_writes_and_serves_nothing(self):
        found = self.found
        refused = found["b_refused"]
        self.assertNotEqual(refused["code"], 0, refused)
        self.assertIn("read-only", refused["err"], refused)
        self.assertEqual(found["b_in_recovery"]["out"], "t", found)
        self.assertIn("role=replica", found["b_role_file"]["text"])

    def test_a_only_the_other_member_s_database_leaf_replicates(self):
        found = self.found
        self.assertEqual(found["a_repl_database_leaf"]["code"], 0,
                         found["a_repl_database_leaf"])
        self.assertTrue(found["a_repl_database_leaf"]["out"],
                        found["a_repl_database_leaf"])
        self.assertNotEqual(found["a_repl_etcd_leaf"]["code"], 0,
                            found["a_repl_etcd_leaf"])

    def test_a_a_restarted_primary_serves_again(self):
        """PostgreSQL has no read-only boot: a standby's refusal is
        recovery, and a primary serves again the moment it answers"""
        found = self.found
        self.assertEqual(found["a_restart"]["in_recovery"], "f",
                         found["a_restart"])
        self.assertIsNone(found["a_follow_after_restart"]["problem"],
                          found["a_follow_after_restart"])
        self.assertEqual(found["a_writable_after_restart"]["code"], 0,
                         found["a_writable_after_restart"])
        self.assertIsNotNone(found["b_streaming_after_restart_s"],
                             found["b_status_a"])

    def test_a_diff_is_clean_on_both(self):
        found = self.found
        # no drift in the database section on either node (the harness
        # roots are no appliance image: the appliance's own lines are
        # not the database's)
        for name in ("a_diff", "b_diff"):
            with self.subTest(node=name):
                self.assertFalse(any(line.startswith("database.")
                                     and ": drift" in line
                                     for line in found[name]["out"]),
                                 found[name])

    def test_no_two_nodes_ever_carry_the_vip(self):
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
