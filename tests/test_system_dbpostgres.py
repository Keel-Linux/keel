# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL twin of keel.system.dbmariadb (handbook decision 0054):
pure functions only, so every test here is Arrange-Act-Assert against
strings and a scratch root, with no server"""

import os
import shutil
import tempfile
import unittest

from keel.system import dbpostgres


class TestClusterPaths(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def make(self, version: str, with_datadir: bool = True):
        confd = os.path.join(
            self.root, "etc/postgresql", version, "main", "conf.d")
        os.makedirs(confd)
        if with_datadir:
            os.makedirs(os.path.join(
                self.root, "var/lib/postgresql", version, "main"))

    def test_the_installed_versions_paths_are_found(self):
        self.make("17")
        version, dropdir, datadir, hba = dbpostgres.cluster_paths(self.root)
        self.assertEqual(version, "17")
        self.assertTrue(dropdir.endswith("etc/postgresql/17/main/conf.d"))
        self.assertTrue(datadir.endswith("var/lib/postgresql/17/main"))
        self.assertTrue(hba.endswith(
            "etc/postgresql/17/main/conf.d/99-keel-pg_hba.conf"))

    def test_the_highest_version_wins_when_two_are_installed(self):
        self.make("15")
        self.make("17")
        version, dropdir, _, _ = dbpostgres.cluster_paths(self.root)
        self.assertEqual(version, "17")
        self.assertTrue(dropdir.endswith("etc/postgresql/17/main/conf.d"))

    def test_the_data_directory_falls_back_to_the_versions_default(self):
        self.make("17", with_datadir=False)
        _, _, datadir, _ = dbpostgres.cluster_paths(self.root)
        self.assertTrue(datadir.endswith("var/lib/postgresql/17/main"))

    def test_no_cluster_installed_is_an_error_the_planner_never_reaches(self):
        with self.assertRaises(FileNotFoundError):
            dbpostgres.cluster_paths(self.root)

    def test_rel_strips_the_root(self):
        self.assertEqual(
            dbpostgres.rel(os.path.join(self.root, "etc/x"), self.root),
            "etc/x")


class TestDropinText(unittest.TestCase):
    def test_a_replica_carries_the_hba_file_and_its_listen_addresses(self):
        text = dbpostgres.dropin_text(
            ["::1", "fd1a:bb4c:b407::1"], "replica", "/etc/p/keel_hba")
        self.assertIn("hba_file = '/etc/p/keel_hba'\n", text)
        self.assertIn(
            "listen_addresses = '::1,fd1a:bb4c:b407::1'\n", text)

    def test_a_primary_adds_the_lines_a_future_replica_asks_of_it(self):
        text = dbpostgres.dropin_text(["::1"], "primary", "/etc/p/keel_hba")
        self.assertIn("wal_level = replica\n", text)
        self.assertIn("max_wal_senders = 10\n", text)
        self.assertIn("max_replication_slots = 10\n", text)

    def test_a_replica_has_no_primary_lines_and_no_read_only_line(self):
        text = dbpostgres.dropin_text(["::1"], "replica", "/etc/p/keel_hba")
        self.assertNotIn("wal_level", text)
        self.assertNotIn("read_only", text)

    def test_no_listen_addresses_when_the_description_declared_none(self):
        text = dbpostgres.dropin_text(None, "primary", "/etc/p/keel_hba")
        self.assertNotIn("listen_addresses", text)


class TestHbaText(unittest.TestCase):
    def test_debian_base_rules_are_kept(self):
        text = dbpostgres.hba_text([], "secret")
        self.assertIn("local   all             all"
                      "                                     peer\n", text)
        self.assertIn("host    all             all             127.0.0.1/32"
                      "            scram-sha-256\n", text)
        self.assertIn("::1/128", text)

    def test_each_origin_gets_one_replication_line(self):
        text = dbpostgres.hba_text(
            ["fd1a:bb4c:b407::/64", "db.example.org"], "secret")
        self.assertEqual(text.count("hostssl replication repl "), 2)
        self.assertIn(
            "hostssl replication repl fd1a:bb4c:b407::/64"
            " scram-sha-256\n", text)
        self.assertIn(
            "hostssl replication repl db.example.org scram-sha-256\n",
            text)

    def test_the_password_is_not_in_the_file(self):
        text = dbpostgres.hba_text(["fd1a::/64"], "s3cret value")
        self.assertNotIn("s3cret", text)


class TestFollowDropinText(unittest.TestCase):
    def test_the_endpoint_and_the_role_are_carried(self):
        text = dbpostgres.follow_dropin_text("fd1a:bb4c:b407::1", 5432,
                                             "secret")
        self.assertIn(
            "primary_conninfo = 'host=fd1a:bb4c:b407::1 port=5432"
            " user=repl password=secret application_name=keel'\n", text)

    def test_a_password_quote_survives_both_parsers(self):
        # Arrange: a password with a quote, the awkward character for
        # both the libpq and the configuration file parsers
        text = dbpostgres.follow_dropin_text("fd1a::1", 5432, "it's")
        self.assertIn("password=it\\\\''s", text)

    def test_a_password_backslash_survives_both_parsers(self):
        text = dbpostgres.follow_dropin_text("fd1a::1", 5432, "a\\b")
        self.assertIn("password=a\\\\\\\\b", text)

    def test_a_password_with_both_is_doubly_escaped(self):
        text = dbpostgres.follow_dropin_text("fd1a::1", 5432, "a'b\\c")
        self.assertIn("password=a\\\\''b\\\\\\\\c", text)

    def test_tls_options_land_at_the_end(self):
        text = dbpostgres.follow_dropin_text(
            "fd1a::1", 5432, "secret",
            " sslmode=verify-full sslrootcert=/etc/p/ca.pem")
        self.assertIn("application_name=keel sslmode=verify-full", text)


class TestEscaping(unittest.TestCase):
    def test_the_sql_literal_doubles_quotes(self):
        self.assertEqual(dbpostgres.literal("it's"), "'it''s'")
        self.assertEqual(dbpostgres.literal("plain"), "'plain'")

    def test_control_characters_are_refused_before_quoting(self):
        self.assertIn("control character", dbpostgres.unquotable("a\x01b"))
        self.assertIn("control character", dbpostgres.unquotable("a\x7fb"))
        self.assertEqual(dbpostgres.unquotable("it's\nfine"), "")

    def test_conninfo_escapes_backslash_and_quote(self):
        self.assertEqual(dbpostgres.conninfo_value("a'b\\c"), "a\\'b\\\\c")

    def test_the_file_escapes_backslash_and_doubles_quotes(self):
        self.assertEqual(dbpostgres.file_value("a\\'b"), "a\\\\''b")


class TestPromote(unittest.TestCase):
    def test_promotion_is_one_statement(self):
        found = dbpostgres.promote()
        self.assertEqual(found.text, "SELECT pg_promote();\n")
        self.assertIn("take writes", found.summary)


class TestUserDatabases(unittest.TestCase):
    def test_the_servers_own_databases_are_not_somebodys_data(self):
        lines = ["postgres\n", "TEMPLATE1\n", " app \n", "template0\n"]
        self.assertEqual(dbpostgres.user_databases(lines), ["app"])

    def test_an_empty_list_means_the_server_holds_no_user_data(self):
        self.assertEqual(dbpostgres.user_databases(["postgres"]), [])


class TestQuestions(unittest.TestCase):
    def test_the_schemas_question_lists_databases_as_the_postgres_user(self):
        question = dbpostgres.schemas_question()
        self.assertEqual(question[:4],
                         ("runuser", "-u", "postgres", "--"))
        self.assertIn("SELECT datname FROM pg_database", question)


if __name__ == "__main__":
    unittest.main()
