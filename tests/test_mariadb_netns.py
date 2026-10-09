# Copyright (c) 2026 KeelLinux maintainers
"""A MariaDB pair on the mesh under the design case of decision 0050

tests/mariadb_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), on tests/vip_netns.py's three nodes: the
real wg-quick, etcd 3.5, keel's members' channel and VIP controller, and
a MariaDB 11.8 server per node, on links of 250 ms ±25 ms with 2 % loss
measured first. Case (a) of docs/replication.md: A applied as the
primary, B as the replica, seeded over TLS with the replication account
`REQUIRE X509`; a row written at the VIP is read on B, the lag measured
from the write's acknowledgement; semi-synchronous replication on; the
replica read only with no account but the server's own holding
READ_ONLY ADMIN; `keel diff` clean on both. Cases (b) to (e) are the
follow-up pull request's. In CI a missing tool fails instead of
skipping; it runs in its own job, "mariadb / trixie", which sets
KEEL_MARIADB_NETNS.
"""

import json
import os
import subprocess
import sys
import unittest

import wgtools
from test_etcd_netns import etcd_dir

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "mariadb_netns.py")
# the nodes' scratch roots, on disk and not under /tmp: a systemd unit
# in a network namespace gets a /tmp of its own, where the servers'
# sockets would be out of the agents' reach
SCRATCH = "/var/tmp/keel-mariadb-netns"


class TestAMariadbPairOnAPoorNetwork(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and not os.environ.get("KEEL_MARIADB_NETNS"):
            self.skipTest("runs in the mariadb / trixie job")
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
        self.assertEqual(status.get("Slave_IO_Running"), "Yes", status)
        self.assertEqual(status.get("Slave_SQL_Running"), "Yes", status)
        self.assertEqual(status.get("Master_SSL_Allowed"), "Yes", status)
        self.assertEqual(status.get("Master_SSL_Verify_Server_Cert"), "Yes",
                         status)
        self.assertEqual(status.get("Using_Gtid"), "Slave_Pos", status)
        # the other member's database certificate alone
        self.assertIn("SPECIFIED", found["a_grants"]["out"], found["a_grants"])
        self.assertIn("mariadb", found["a_grants"]["out"], found["a_grants"])
        self.assertIn("etcd root", found["a_grants"]["out"], found["a_grants"])
        # the seed carried the application's data
        self.assertEqual(found["a_rows_a"], found["b_rows_a"], found)
        self.assertGreaterEqual(found["b_rows_a"], 1, found)

    def test_a_a_write_at_the_vip_is_read_on_the_replica(self):
        found = self.found
        self.assertEqual(found["a_write"]["code"], 0, found["a_writes"])
        self.assertIsNotNone(found["a_lag_s"], found["a_writes"])
        # acknowledged once the replica received it (AFTER_SYNC), so on
        # the replica within the apply of the relay log: measured 0.04 to
        # 0.07 s in CI
        self.assertLess(found["a_lag_s"], 1, found["a_writes"])
        self.assertEqual(found["a_semisync"], "ON", found)
        # a commit pays the replica's acknowledgement, one round trip:
        # measured 0.28 to 0.31 s at 250 ms
        self.assertTrue(all(cost < 1.5 for cost in found["a_commit_costs_s"]),
                        found["a_commit_costs_s"])

    def test_a_the_replica_applied_again_keeps_applying(self):
        """Its own authorizations never enter its binary log, so the
        primary's next event is applied under gtid_strict_mode"""
        found = self.found
        self.assertFalse(found["b_apply_again"]["failed"],
                         found["b_apply_again"])
        after = found["b_after_apply"]
        self.assertTrue(after["write_ok"], after)
        self.assertIsNotNone(after["seen_s"], after)
        self.assertEqual(after["status"].get("Slave_SQL_Running"), "Yes",
                         after)
        self.assertNotEqual(after["status"].get("Last_SQL_Errno"), "1950",
                            after)

    def test_a_only_the_other_member_s_database_leaf_replicates(self):
        found = self.found
        self.assertEqual(found["a_repl_database_leaf"]["code"], 0,
                         found["a_repl_database_leaf"])
        self.assertIn("repl@", found["a_repl_database_leaf"]["out"])
        self.assertNotEqual(found["a_repl_etcd_leaf"]["code"], 0,
                            found["a_repl_etcd_leaf"])
        self.assertIn("1045", found["a_repl_etcd_leaf"]["err"],
                      found["a_repl_etcd_leaf"])

    def test_a_a_restarted_primary_boots_read_only_until_follow(self):
        found = self.found
        self.assertEqual(found["a_restart"]["read_only"], "1",
                         found["a_restart"])
        self.assertIsNone(found["a_follow_after_restart"]["problem"],
                          found["a_follow_after_restart"])
        self.assertEqual(found["a_read_only_after_follow"]["out"], "0",
                         found)

    def test_a_the_replica_serves_nothing_and_diff_is_clean(self):
        found = self.found
        self.assertEqual(found["b_read_only"]["out"], "1", found)
        self.assertEqual(found["b_bypass"]["out"], "'mysql'@'localhost'",
                         found["b_bypass"])
        self.assertIn("role=replica", found["b_role_file"]["text"])
        self.assertTrue(any("semi_sync: same" in line
                            for line in found["a_diff"]["out"]),
                        found["a_diff"])
        # no drift in the database section on either node (the harness
        # roots are no appliance image: the appliance's own lines are
        # not the database's)
        for name in ("a_diff", "b_diff"):
            with self.subTest(node=name):
                self.assertFalse(any(line.startswith("database.")
                                     and ": drift" in line
                                     for line in found[name]["out"]),
                                 found[name])

    def test_a_crashed_primary_boots_read_only_and_follows_the_new_one(self):
        """keel#104: B promoted at a newer epoch while A was down; A
        boots with its old claim, and never takes a write"""
        found = self.found
        self.assertEqual(found["k104_promote"]["code"], 0,
                         found["k104_promote"])
        self.assertEqual(found["k104_b_read_only"]["out"], "0", found)
        self.assertEqual(found["k104_boot_read_only"], "1", found)
        follow = found["k104_follow_at_boot"]
        self.assertIsNone(follow["problem"], follow)
        self.assertIn("not proven", " ".join(follow["lines"]), follow)
        self.assertEqual(found["k104_after_follow"], "1", found)
        self.assertIsNotNone(found["k104_replica_s"],
                             found["k104_a_follow_log"])
        # every sample from the boot to the rejoin: never writable
        samples = found["k104_read_only_samples"]
        self.assertTrue(samples, found)
        self.assertNotIn("0", samples, samples)
        status = found["k104_a_status"]
        self.assertEqual(status.get("Slave_IO_Running"), "Yes", status)
        self.assertEqual(status.get("Master_SSL_Allowed"), "Yes", status)
        self.assertEqual(status.get("Using_Gtid"), "Slave_Pos", status)

    def test_the_unplanned_write_downtime_and_no_acked_row_lost(self):
        """keel#108, keel#118: the promote with the old primary gone and
        the database following the VIP at once, measured at 250 ms; with
        etcd the old primary's lease must expire first (0049), so the
        downtime is that wait plus keel's own part"""
        found = self.found["k108_downtime"]
        print(f"k108 downtime: {found}", file=sys.stderr)
        self.assertEqual(self.found["k108_acked_missing"], [], found)
        self.assertIsNotNone(found["downtime_s"], found)
        self.assertIsNotNone(found["writable_after_carried_s"], found)
        self.assertIsNotNone(self.found["k108_semisync_s"], found)
        # each ask of the dead old primary waited 1.5 s, not 10 s
        said = " ".join(self.found["k104_promote"]["out"])
        self.assertIn("no answer within 1.5 s", said)
        self.assertNotIn("timed out", said)

    def test_no_two_nodes_ever_carry_the_vip(self):
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
