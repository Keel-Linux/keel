# Copyright (c) 2026 KeelLinux maintainers
"""keel database watch (keel.system.dbwatch): the semi-synchronous read
is engine-aware, and a node with no server says so plainly"""

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


class TestSyncCommit(unittest.TestCase):
    """0054: the pair's synchronous commit has no fallback, and the
    watch alerts while the primary's commits wait, once each way (0054
    asks for it; the watch said nothing while every commit waited for
    a cut standby)"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.out: list[str] = []
        self.answer = "1\t0\n"
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
        self.answer = "1\t2\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_WAITS)
        self.assertIn("2 commit(s) waited more than 10 s",
                      alerted.call_args.args[3])
        # the next watch, still waiting: no second alert
        self.ask().assert_not_called()
        self.answer = "1\t0\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertEqual(alerted.call_args.args[2], dbwatch.SYNC_BACK)
        self.assertEqual(alerted.call_args.args[5], "recovery")

    def test_no_standby_at_all_is_a_wait(self):
        """A new primary after a failover: no standby streams, so
        every commit waits until the other node is reseeded"""
        self.answer = "0\t0\n"
        alerted = self.ask()
        self.assertEqual(alerted.call_count, 1)
        self.assertIn("no standby streams from it",
                      alerted.call_args.args[3])

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


if __name__ == "__main__":
    unittest.main()
