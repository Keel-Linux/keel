# Copyright (c) 2026 KeelLinux maintainers
"""keel database watch (keel.system.dbwatch): the semi-synchronous read
is engine-aware, and a node with no server says so plainly"""

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


if __name__ == "__main__":
    unittest.main()
