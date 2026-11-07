# Copyright (c) 2026 KeelLinux maintainers
"""keel database watch (keel.system.dbwatch): the semi-synchronous read
is engine-aware, and a node with no server says so plainly"""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from keel.inspect import dbreading
from keel.system import dbpair, dbwatch

VIP = "fd00:6b65:f1b::ffff:100"
PAIR = dbpair.PairState(VIP, "own-key", "peer-key", "fd00:6b65:f1b::2")


def server(engine: str, reading) -> mock.Mock:
    found = mock.Mock()
    found.engine.name = engine
    found.reading.return_value = reading
    return found


class TestSemiSync(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.out: list[str] = []

    def ask(self, servers):
        with mock.patch.object(dbwatch, "Tree"), \
                mock.patch.object(dbwatch, "database_servers",
                                 return_value=servers):
            return dbwatch.semi_sync(self.root, PAIR,
                                     self.out.append, self.out.append)

    def test_a_postgresql_node_is_not_asked_about_semi_sync(self):
        """PostgreSQL has no semi-synchronous fallback to fall from (the
        pair's synchronous commit waits, docs/replication-postgresql.
        md): the mariadb-only read called a healthy node "no server" and
        its reading never reached needs_follow (found by the pair's
        network-namespace test of this release)"""
        reading = dbreading.Reading(
            role=dbreading.found("primary", "probe"))
        found = self.ask([server("postgresql", reading)])
        self.assertIs(found, reading)
        self.assertEqual(self.out, [])

    def test_a_mariadb_node_keeps_its_not_readable_report(self):
        reading = dbreading.Reading(
            semi_sync=dbreading.unknown("the probe did not answer"))
        found = self.ask([server("mariadb", reading)])
        self.assertIs(found, reading)
        self.assertEqual(len(self.out), 1)
        self.assertIn("semi-synchronous status not readable", self.out[0])
        self.assertIn("the probe did not answer", self.out[0])

    def test_no_server_at_all_says_there_is_nothing_to_watch(self):
        self.assertIsNone(self.ask([]))
        self.assertEqual(len(self.out), 1)
        self.assertIn("no database server", self.out[0])


class TestTheFallback(unittest.TestCase):
    """keel#270: with the replica away, the primary acknowledges each
    write with no copy. A cut ends the dump thread first (about 12.6 s),
    so the timeout never runs and Rpl_semi_sync_master_status stays ON:
    its signal is Rpl_semi_sync_master_clients 0 (evidence of 2026-11-01,
    case F1)"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.out: list[str] = []
        self.primary = dbpair.PairState(VIP, "own-key", "peer-key",
                                        "fd00:6b65:f1b::2", role="primary")
        self.taken = True

    def reading(self, master="ON", clients="1", read_only=False,
                unacknowledged="0"):
        return dbreading.Reading(
            read_only=dbreading.found(read_only, "probe"),
            semi_sync=dbreading.found(
                {"master": master, "slave": "OFF", "clients": clients,
                 "acknowledged": "9", "unacknowledged": unacknowledged},
                "probe"))

    def ask(self, reading, pair=None):
        with mock.patch.object(dbwatch, "Tree"), \
                mock.patch.object(dbwatch, "database_servers",
                                  return_value=[server("mariadb", reading)]), \
                mock.patch("keel.monitor.alerting.alert",
                           return_value=self.taken) as alerted:
            dbwatch.semi_sync(self.root, pair or self.primary,
                              self.out.append, self.out.append)
        return alerted

    def test_status_on_with_no_replica_is_alerted_once_and_its_end_once(self):
        self.ask(self.reading()).assert_not_called()
        alerted = self.ask(self.reading(clients="0", unacknowledged="77"))
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.FELL_BACK)
        text = alerted.call_args.args[3]
        self.assertIn("no replica is connected", text)
        self.assertIn("77", text)
        self.assertIn("Rpl_semi_sync_master_clients", text)
        self.assertIn("semi-synchronous no replica", self.out[-1])
        self.ask(self.reading(clients="0")).assert_not_called()
        alerted = self.ask(self.reading())
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.BACK)
        self.assertEqual(alerted.call_args.args[5], "recovery")

    def test_one_fallback_changing_form_is_not_a_second_alert(self):
        """A replica that comes back behind: 0 clients, then 1 client
        and status OFF until it caught up (the timeout's path)"""
        self.ask(self.reading(clients="0"))
        self.ask(self.reading(master="OFF")).assert_not_called()
        self.ask(self.reading(clients="0")).assert_not_called()

    def test_the_timeout_s_fallback_keeps_its_own_text(self):
        text = self.ask(self.reading(master="OFF")).call_args.args[3]
        self.assertIn("Rpl_semi_sync_master_status OFF", text)

    def test_a_replica_node_with_no_clients_is_not_a_fallback(self):
        replica = dbpair.PairState(VIP, "own-key", "peer-key",
                                   "fd00:6b65:f1b::2", role="replica")
        self.ask(self.reading(clients="0"), replica).assert_not_called()
        self.assertIn("semi-synchronous on", self.out[-1])

    def test_a_read_only_primary_acknowledges_nothing_so_nothing_is_alerted(
            self):
        """A holder that waits for its replica (keel#242) or doubts its
        lease (keel#195) gives an error, not an OK with no copy"""
        self.ask(self.reading()).assert_not_called()
        self.ask(self.reading(clients="0",
                              read_only=True)).assert_not_called()
        self.ask(self.reading(clients="0")).assert_called_once()

    def test_an_alert_no_channel_took_is_tried_again_at_the_next_watch(self):
        """A channel that is down at that moment must not lose the only
        signal, and a channel set up later still gets it"""
        self.taken = False
        self.ask(self.reading(clients="0")).assert_called_once()
        self.taken = True
        self.ask(self.reading(clients="0")).assert_called_once()
        self.ask(self.reading(clients="0")).assert_not_called()


class TestTheFallbackInStatus(unittest.TestCase):
    def test_the_words_of_each_state(self):
        for values, role, read_only, expected in (
                ({"master": "ON", "clients": "1"}, "primary", False, "on"),
                ({"master": "ON", "clients": "0"}, "primary", False,
                 "no replica"),
                ({"master": "OFF", "clients": "1"}, "primary", False, "off"),
                ({"master": "ON", "clients": "0"}, "replica", False, "on"),
                ({"master": "ON", "clients": "0"}, "primary", True, "on"),
                ({"master": "ON"}, "primary", False, "on")):
            with self.subTest(values=values, role=role, read_only=read_only):
                self.assertEqual(
                    dbwatch.commits(values, role, read_only), expected)


class TestSyncCommit(unittest.TestCase):
    """0054: the pair's synchronous commit has no fallback, and the
    watch alerts while the primary's commits wait, once each way (0054
    asks for it; the watch said nothing while every commit waited for
    a cut standby)"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.out: list[str] = []
        self.answer = "1\t0\t0\t1\n"
        self.asked: list[list[str]] = []
        self.primary = dbpair.PairState(VIP, "own-key", "peer-key",
                                        "fd00:6b65:f1b::2", role="primary")
        self.reading = dbreading.Reading(
            role=dbreading.found("primary", "probe"))

    def run_psql(self, argv, **kwargs):
        self.asked.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, self.answer, "")

    def ask(self, pair=None, reading=None):
        with mock.patch.object(dbwatch, "Tree"), \
                mock.patch.object(dbwatch, "database_servers",
                                 return_value=[server(
                                     "postgresql", reading or self.reading)]), \
                mock.patch("keel.monitor.alerting.alert",
                           return_value=True) as alerted:
            dbwatch.semi_sync(self.root, pair or self.primary,
                              self.out.append, self.out.append,
                              runner=self.run_psql)
        return alerted

    def test_a_standby_that_acknowledges_alerts_nothing(self):
        alerted = self.ask()
        alerted.assert_not_called()
        self.assertIn("synchronous commit flowing", self.out[-1])
        self.assertIn(dbwatch.SYNC_SQL, self.asked[0])

    def test_commits_that_wait_are_alerted_once_and_their_end_once(self):
        self.answer = "1\t2\t0\t1\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_WAITS)
        self.assertIn("2 commit(s) waited more than 10 s",
                      alerted.call_args.args[3])
        # the next watch, still waiting: no second alert
        self.ask().assert_not_called()
        self.answer = "1\t0\t0\t1\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_BACK)
        self.assertEqual(alerted.call_args.args[5], "recovery")

    def test_no_standby_at_all_is_a_wait(self):
        """A new primary after a failover: no standby streams, so
        every commit waits until the other node is reseeded"""
        self.answer = "0\t0\t0\t0\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertIn("no standby streams from it",
                      alerted.call_args.args[3])

    def test_a_primary_that_commits_alone_is_alerted_at_each_run(self):
        """keel database promote --old-primary-gone: the new primary
        commits alone (0054's one exception), and the watch says so at
        every run, the way the wait is alerted"""
        self.answer = "0\t0\t1\t0\n"
        for _ in range(2):
            alerted = self.ask()
            self.assertEqual(alerted.call_count, 1)
            self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_ALONE)
            self.assertEqual(alerted.call_args.args[4], dbwatch.SYNC_CHECK)
        self.assertIn("synchronous commit alone", self.out[-1])

    def test_a_standby_that_streams_again_brings_the_line_back(self):
        self.answer = "0\t0\t1\t0\n"
        self.ask()
        self.answer = "0\t0\t1\t1\n"
        with mock.patch("keel.system.dbpgfollow.synchronous_again",
                        return_value=("", True)) as again:
            alerted = self.ask()
        again.assert_called_once()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_BACK)

    def test_the_question_names_the_pair_s_standby_and_the_wait(self):
        from keel.system import dbpostgres
        self.assertIn(f"application_name = '{dbpostgres.SLOT}'",
                      dbwatch.SYNC_SQL)
        self.assertIn(f"interval '{dbwatch.SYNC_WAIT_ALERT_S} seconds'",
                      dbwatch.SYNC_SQL)

    def test_a_standby_is_not_asked(self):
        replica = dbpair.PairState(VIP, "own-key", "peer-key",
                                   "fd00:6b65:f1b::2", role="replica")
        self.ask(pair=replica).assert_not_called()
        self.assertEqual(self.asked, [])

    def test_an_answer_that_cannot_be_read_says_so(self):
        self.answer = " 1 |  0\n"
        self.ask().assert_not_called()
        self.assertIn("not readable", self.out[-1])


class TestTheSyncFallback(TestSyncCommit):
    """0054 amended 2026-11-06 (the maintainer: "b"): a primary whose
    standby is away falls back to asynchronous commits after
    SYNC_FALLBACK_S, with an alert, as MariaDB does (0031); the
    synchronous line comes back once the standby streams again. Before,
    every write of an Odoo primary waited without end for a standby that
    never came (BR1 9360, keel 0.23.84)"""

    def at(self, seconds: float):
        from datetime import datetime, timedelta, timezone
        start = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
        return mock.patch.object(dbwatch, "_now",
                                 return_value=start + timedelta(
                                     seconds=seconds))

    def test_no_standby_ever_falls_back_after_the_timeout(self):
        self.answer = "0\t0\t0\t0\n"
        with self.at(0), mock.patch("keel.system.dbpgfollow.fall_back",
                                    return_value="") as fell:
            alerted = self.ask()
        fell.assert_not_called()
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_WAITS)
        with self.at(dbwatch.SYNC_FALLBACK_S - 1), \
                mock.patch("keel.system.dbpgfollow.fall_back",
                           return_value="") as fell:
            self.ask().assert_not_called()
        fell.assert_not_called()
        with self.at(dbwatch.SYNC_FALLBACK_S), \
                mock.patch("keel.system.dbpgfollow.fall_back",
                           return_value="") as fell:
            alerted = self.ask()
        fell.assert_called_once()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_FELL_BACK)
        self.assertIn(f"{dbwatch.SYNC_FALLBACK_S} s",
                      alerted.call_args.args[3])
        self.assertIn("fell back", self.out[-1])

    def test_a_primary_that_fell_back_is_alerted_once(self):
        self.answer = "0\t0\t1\t0\n"
        with mock.patch("keel.system.dbpgfollow.fell_back",
                        return_value=True):
            first = self.ask()
            second = self.ask()
        self.assertEqual(first.call_args.args[2], dbwatch.SYNC_FELL_BACK)
        second.assert_not_called()
        self.assertIn("asynchronous", self.out[-1])

    def test_the_standby_back_brings_the_synchronous_line_back(self):
        self.answer = "0\t0\t1\t0\n"
        with mock.patch("keel.system.dbpgfollow.fell_back",
                        return_value=True):
            self.ask()
        self.answer = "0\t0\t1\t1\n"
        with mock.patch("keel.system.dbpgfollow.synchronous_again",
                        return_value=("", True)) as again:
            alerted = self.ask()
        again.assert_called_once()
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_BACK)

    def test_a_fallback_that_cannot_be_written_stays_a_wait(self):
        self.answer = "0\t0\t0\t0\n"
        with self.at(0):
            self.ask()
        with self.at(dbwatch.SYNC_FALLBACK_S), \
                mock.patch("keel.system.dbpgfollow.fall_back",
                           return_value="the pair drop-in cannot be read"):
            self.ask().assert_not_called()
        self.assertIn("cannot be read", " ".join(self.out))
        self.assertIn("synchronous commit waiting", self.out[-1])

    def test_a_wait_that_was_not_seen_before_starts_the_clock(self):
        self.answer = "0\t0\t0\t0\n"
        dbwatch._write_state(self.root, {"sync_commit": "flowing"})
        with self.at(dbwatch.SYNC_FALLBACK_S * 10), \
                mock.patch("keel.system.dbpgfollow.fall_back",
                           return_value="") as fell:
            self.ask()
        fell.assert_not_called()


class TestTheFallbackDropin(unittest.TestCase):
    def test_a_since_that_cannot_be_read_counts_as_no_wait(self):
        self.assertEqual(dbwatch._waited("not a time"), 0.0)
        self.assertEqual(dbwatch._waited(None), 0.0)

    def test_the_fallback_and_its_end_rewrite_the_pair_s_line(self):
        from keel.system import dbpostgres
        text = dbpostgres.pair_dropin_text()
        fell = dbpostgres.fallback_text(text)
        self.assertIn("synchronous_standby_names = ''", fell)
        self.assertTrue(dbpostgres.fell_back(fell))
        self.assertFalse(dbpostgres.commits_alone(fell))
        self.assertEqual(dbpostgres.synchronous_text(fell), text)
        self.assertFalse(dbpostgres.fell_back(text))

    def test_fell_back_reads_the_pair_drop_in(self):
        from keel.system import dbpgfollow, dbpostgres
        root = tempfile.mkdtemp()
        self.assertFalse(dbpgfollow.fell_back(root))
        with mock.patch.object(dbpgfollow, "_pair_dropin",
                               return_value=os.path.join(root, "pair.conf")):
            with open(os.path.join(root, "pair.conf"), "w") as fob:
                fob.write(dbpostgres.fallback_text(
                    dbpostgres.pair_dropin_text()))
            self.assertTrue(dbpgfollow.fell_back(root))
            ran = []
            with open(os.path.join(root, "pair.conf"), "w") as fob:
                fob.write(dbpostgres.pair_dropin_text())
            self.assertEqual(dbpgfollow.fall_back(
                root, lambda argv, **kw: ran.append(argv) or
                subprocess.CompletedProcess(argv, 0, b"", b"")), "")
            self.assertTrue(dbpgfollow.fell_back(root))
            self.assertTrue(any("pg_reload_conf()" in " ".join(one)
                                for one in ran))


class TestDumpCheck(unittest.TestCase):
    def test_the_watch_checks_the_dump_of_a_pair(self):
        root = tempfile.mkdtemp()
        with mock.patch.object(dbwatch, "Node") as node, \
                mock.patch.object(dbwatch.dbpair, "observe_pair",
                                  return_value=PAIR), \
                mock.patch.object(dbwatch, "semi_sync", return_value=None), \
                mock.patch.object(dbwatch, "certificate", return_value=True), \
                mock.patch("keel.system.filesync.flip_pending",
                           return_value=False), \
                mock.patch("keel.system.filesync_watch.watch_counts"), \
                mock.patch("keel.system.dbdump.watch") as checked:
            node.return_value.document.return_value = {}
            dbwatch.watch(root, "spec", print, print)
        checked.assert_called_once()
        self.assertEqual(checked.call_args.args[:3], (root, {}, PAIR))


if __name__ == "__main__":
    unittest.main()
