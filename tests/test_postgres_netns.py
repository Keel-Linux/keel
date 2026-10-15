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
both. Then cases (b) to (e): the replica cut off, a commit waiting and
alerted, acknowledged after the heal; the primary cut off and killed
while the application writes, the automatic failover once its lease
expired, no acknowledged row lost and the downtime; the old primary back, never acknowledging a
write, fenced, dumped, recorded and alerted once; and its confirmed
reseed, the one rejoin path of 0054. In CI a missing tool fails
instead of skipping; it runs in its own job, "postgres / trixie",
which sets KEEL_POSTGRES_NETNS.
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
            capture_output=True, text=True, check=False, timeout=2700)
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

    def test_b_a_commit_waits_for_the_cut_replica_and_is_alerted(self):
        """No timeout and no fallback (0054): the commit waits while the
        replica is cut off, the primary keeps the VIP, the watch alerts
        within the 10 s wait and one watch run, and the commit is
        acknowledged after the heal"""
        found = self.found
        print(f"(b): alerted {found['b_waits_alerted_s']} s after the cut;"
              f" acknowledged {found['b_ack_after_heal_s']} s after the"
              f" heal; synchronous again {found['b_sync_after_heal_s']} s",
              file=sys.stderr)
        self.assertIsNotNone(found["b_sync_before_s"], found)
        self.assertIsNotNone(found["b_waits_alerted_s"], found["b_alerts"])
        self.assertLess(found["b_waits_alerted_s"], 45, found["b_alerts"])
        self.assertTrue(found["b_pending_at_alert"], found["b_cut_write"])
        self.assertTrue(found["b_pending_at_heal"], found["b_cut_write"])
        self.assertTrue(found["b_a_holds_vip"], found)
        self.assertTrue(found["b_cut_write"]["ok"], found["b_cut_write"])
        # the walreceiver is back within its own timeout (60 s) and one
        # retry (5 s), whatever TCP's backoff was
        self.assertLess(found["b_ack_after_heal_s"], 90, found)
        self.assertIsNotNone(found["b_sync_after_heal_s"], found)
        self.assertIsNotNone(found["b_back_alerted_s"], found["b_alerts"])
        self.assertEqual(found["b_row_on_b"], "1", found)

    def test_c_the_unplanned_failover_loses_no_acknowledged_row(self):
        """The primary cut off and killed while the application writes;
        B's VIP controller claims once the lease of A's claim expired,
        and B takes writes with no operator (keel#165)"""
        found = self.found
        downtime = found["c_downtime"]
        print(f"(c) downtime: {downtime}", file=sys.stderr)
        # no operator: the expired lease states the old primary gone
        # (keel#165, the 0054 amendment of 2026-10-15)
        self.assertIsNotNone(found["c_automatic_s"], downtime)
        self.assertTrue(any("expired" in line
                            for line in found["c_b_vip_log"]),
                        found["c_b_vip_log"])
        self.assertEqual(found["c_acked_missing"], [], downtime)
        self.assertIsNotNone(downtime["carried_s"], downtime)
        self.assertIsNotNone(downtime["promoted_s"], downtime)
        # follow does not lag the VIP (keel#118, the MariaDB twin's bound)
        self.assertLess(downtime["promoted_s"] - downtime["carried_s"], 3.0,
                        downtime)
        # a base backup copies no slot: the new holder made the pair's
        self.assertIn("keel", found["c_b_slot"], found)
        # the expired lease: the new primary commits alone, alerted at
        # each watch run (0054's exception, amendment of 2026-10-15)
        self.assertEqual(found["c_b_sync_names"], "", found)
        self.assertIsNotNone(found["c_b_alone_alerted_s"], found["alerts"])
        self.assertIsNotNone(downtime["first_ok_after_s"], downtime)
        self.assertIsNotNone(found["d_a_streaming_s"], found)

    def test_c_the_writes_resume_within_5_s_after_the_vip_lands(self):
        """The client-side bound of keel#148: the writes resume at most
        5 s after the VIP lands on the new primary. After the expired
        lease the new primary commits alone (0054, amendment of
        2026-10-15); before it, every commit waited until the old primary
        was reseeded (216 s in CI)"""
        downtime = self.found["c_downtime"]
        self.assertIsNotNone(downtime["first_ok_after_s"], downtime)
        self.assertLess(downtime["first_ok_after_s"] - downtime["carried_s"],
                        5.0, downtime)

    def test_e_the_old_primary_back_takes_no_write_and_is_fenced(self):
        """Back from its crash it never acknowledges a write; it is
        fenced as a standby that follows nobody, dumped (the dump holds
        its own unacknowledged rows), recorded and alerted once"""
        found = self.found
        boot = found["e_follow_at_boot"]
        joined = " ".join(boot["lines"])
        if boot["problem"] is None:
            self.assertIn("stopped", joined, boot)
        else:
            self.assertIn("diverged", boot["problem"], boot)
        self.assertIsNotNone(found["e_diverged_s"], found["e_follow_log"])
        self.assertTrue(found["e_boot_writes"], found)
        self.assertFalse(any(one["ok"] for one in found["e_boot_writes"]),
                         found["e_boot_writes"])
        record = found["e_record"]
        self.assertEqual(record["holder"], "fd00:6b65:f1b::2", record)
        self.assertEqual(record["own_timeline"], "1", record)
        self.assertEqual(record["holder_timeline"], "2", record)
        self.assertEqual(found["e_in_recovery"], "t", found)
        self.assertEqual(found["e_receivers"], "0", found)
        self.assertNotEqual(found["e_refused"]["code"], 0, found)
        self.assertIn("read-only", found["e_refused"]["err"], found)
        self.assertTrue(found["e_a_unacked"], found["c_writes"])
        self.assertEqual(found["e_a_holds"], found["e_a_unacked"], found)
        self.assertEqual(found["e_dump_holds"], found["e_a_unacked"],
                         found["e_dumps"])
        self.assertEqual(len(found["e_dumps"]), 1, found["e_dumps"])
        self.assertEqual(found["e_dumps_later"], found["e_dumps"])
        self.assertEqual(len(found["e_alerts"]), 1, found["e_alerts"])
        self.assertTrue(any(line.startswith("database.server.diverged")
                            and "timeline 1 against the holder's 2" in line
                            for line in found["e_diff"]["out"]),
                        found["e_diff"])

    def test_d_the_confirmed_reseed_rejoins_the_old_primary(self):
        found = self.found
        print(f"(d) reseed: {found['d_apply'].get('took_s')} s, streaming"
              f" {found['d_streaming_s']} s after", file=sys.stderr)
        self.assertFalse(found["d_apply"]["failed"], found["d_apply"])
        self.assertIsNotNone(found["d_streaming_s"], found["d_status"])
        self.assertEqual(found["d_status"]["in_recovery"], "t", found)
        self.assertTrue(found["d_a_status_line"], found["d_status"])
        self.assertIsNone(found["d_record_after"], found)
        self.assertIsNotNone(found["d_b_sync_s"], found)
        # the pair's synchronous line is back on B once A streams
        self.assertEqual(found["d_b_sync_names"], "FIRST 1 (keel)", found)
        # keel#166: the reseeded node may take the VIP by itself again
        self.assertIsNotNone(found["d_a_unfenced_s"], found)
        self.assertIsNotNone(found["d_first_ack_s"], found)
        self.assertIsNotNone(found["d_rows_equal_s"], found)
        self.assertEqual(found["d_a_holds_unacked"],
                         found["d_b_holds_unacked"], found)
        self.assertIsNotNone(found["d_back_alerted_s"], found["alerts"])

    def test_no_two_nodes_ever_carry_the_vip(self):
        self.assertEqual(self.found["max_holders"], 1,
                         self.found["double_holder_samples"])


if __name__ == "__main__":
    unittest.main()
