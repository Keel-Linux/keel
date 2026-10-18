# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL twin of keel.system.dbmariadb (handbook decision 0054):
pure functions only, so every test here is Arrange-Act-Assert against
strings and a scratch root, with no server"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

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
        version, conf, dropdir, datadir = dbpostgres.cluster_paths(
            self.root)
        self.assertEqual(version, "17")
        self.assertTrue(conf.endswith("etc/postgresql/17/main"))
        self.assertTrue(dropdir.endswith("etc/postgresql/17/main/conf.d"))
        self.assertTrue(datadir.endswith("var/lib/postgresql/17/main"))

    def test_the_pair_files_live_beside_the_configuration_not_in_conf_d(
            self):
        """Debian's postgresql.conf includes conf.d, and every *.conf
        there is read as GUC: the hba and ident formats are not GUC, the
        server dies reading them (found by the pair's network-namespace
        test of this release). They live in the cluster's configuration
        directory, the way Debian keeps pg_hba.conf"""
        self.make("17")
        _, conf, dropdir, _ = dbpostgres.cluster_paths(self.root)
        for name in (dbpostgres.HBA_NAME, dbpostgres.IDENT_NAME):
            self.assertEqual(os.path.dirname(os.path.join(conf, name)),
                             conf)
            self.assertNotIn("conf.d", os.path.join(conf, name))
        self.assertTrue(dropdir.endswith("conf.d"))

    def test_the_highest_version_wins_when_two_are_installed(self):
        self.make("15")
        self.make("17")
        version, _, dropdir, _ = dbpostgres.cluster_paths(self.root)
        self.assertEqual(version, "17")
        self.assertTrue(dropdir.endswith("etc/postgresql/17/main/conf.d"))

    def test_the_data_directory_falls_back_to_the_versions_default(self):
        self.make("17", with_datadir=False)
        _, _, _, datadir = dbpostgres.cluster_paths(self.root)
        self.assertTrue(datadir.endswith("var/lib/postgresql/17/main"))

    def test_no_cluster_installed_is_an_error_the_planner_never_reaches(self):
        with self.assertRaises(FileNotFoundError):
            dbpostgres.cluster_paths(self.root)

    def test_rel_strips_the_root(self):
        self.assertEqual(
            dbpostgres.rel(os.path.join(self.root, "etc/x"), self.root),
            "etc/x")


class TestUnits(unittest.TestCase):
    """The cluster's own unit for every stop and start (keel#153)

    On Debian, postgresql@17-main.service is PartOf= and Before= the
    umbrella postgresql.service. A stop of the umbrella returns before
    the cluster stops, and a start of the active umbrella starts
    nothing: the old server wrote its pg_control into the new copy of a
    reseed (found on real nodes, keel 0.23.18)."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(dbpostgres.SERVICE_ENV, None)

    def test_the_server_unit_is_the_cluster_s_own(self):
        os.makedirs(os.path.join(self.root, "etc/postgresql/17/main"))
        self.assertEqual(dbpostgres.service(self.root),
                         "postgresql@17-main")

    def test_the_boot_unit_stays_the_umbrella(self):
        """the generator of postgresql-common wires the cluster into the
        umbrella, so enable and is-enabled ask the umbrella"""
        os.makedirs(os.path.join(self.root, "etc/postgresql/17/main"))
        self.assertEqual(dbpostgres.boot_unit(), "postgresql")

    def test_no_cluster_names_the_umbrella(self):
        self.assertEqual(dbpostgres.service(self.root), "postgresql")

    def test_the_environment_names_the_unit_of_a_test(self):
        os.makedirs(os.path.join(self.root, "etc/postgresql/17/main"))
        os.environ[dbpostgres.SERVICE_ENV] = "postgresql-keel-a"
        self.assertEqual(dbpostgres.service(self.root), "postgresql-keel-a")
        self.assertEqual(dbpostgres.boot_unit(), "postgresql-keel-a")


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

    def test_each_origin_also_gets_the_postgres_database_line(self):
        """the reach and seed probes connect as the replication role to
        the server's own postgres database (does it answer, does the
        role authenticate, is it a standby): without this line the seed
        is refused and the pair never forms (found by the pair's
        network-namespace test of this release). The method is the
        password in both modes: the probe presents no certificate, and
        user data stays unreachable — the database is `postgres`"""
        text = dbpostgres.hba_text(["fd1a:bb4c:b407::/64"], "secret")
        self.assertEqual(text.count("hostssl postgres repl "), 1)
        self.assertIn(
            "hostssl postgres repl fd1a:bb4c:b407::/64"
            " scram-sha-256\n", text)
        in_verify = dbpostgres.hba_text(
            ["fd1a:bb4c:b407::/64"], "secret", verify=True)
        self.assertIn(
            "hostssl postgres repl fd1a:bb4c:b407::/64"
            " scram-sha-256\n", in_verify)
        self.assertNotIn("hostssl postgres repl all", text)

    def test_the_password_is_not_in_the_file(self):
        text = dbpostgres.hba_text(["fd1a::/64"], "s3cret value")
        self.assertNotIn("s3cret", text)

    def test_a_bare_address_takes_the_host_mask(self):
        """The other member's address comes bare (dbpair.allowed_hosts);
        pg_hba.conf reads a bare token as a hostname, and a host token
        with no IP mask kills the server at hba load (found by the
        pair's network-namespace test of this release)"""
        text = dbpostgres.hba_text(["fd1a:bb4c:b407::2"], "secret")
        self.assertIn(
            "hostssl replication repl fd1a:bb4c:b407::2/128"
            " scram-sha-256\n", text)
        text = dbpostgres.hba_text(["192.0.2.10"], "secret")
        self.assertIn("hostssl replication repl 192.0.2.10/32"
                      " scram-sha-256\n", text)


class TestHbaVerify(unittest.TestCase):
    def test_the_pair_pins_the_peer_certificate_through_the_map(self):
        """pg refuses map= with a password method (the server dies
        loading the file; found by the pair's network-namespace test of
        this release): the pair's line is the cert method, which maps
        the certificate's CN through pg_ident, with the password left
        to the standalone lines. clientcert=verify-full is deliberately
        absent: it asks the client host's name of a DNS the mesh has
        not, and certificate authentication failed (found by the pair's
        network-namespace test of this release) — the map is the pin,
        the twin of MariaDB's REQUIRE SUBJECT"""
        text = dbpostgres.hba_text(["fd1a:bb4c:b407::/64"], "secret",
                                   verify=True)
        self.assertIn(
            "hostssl replication repl fd1a:bb4c:b407::/64"
            " cert map=keel\n", text)
        self.assertNotIn("clientcert", text)

    def test_without_verify_the_line_is_the_single_node_one(self):
        text = dbpostgres.hba_text(["fd1a:bb4c:b407::/64"], "secret")
        self.assertIn(" scram-sha-256\n", text)
        self.assertNotIn("clientcert", text)
        self.assertNotIn("map=", text)


class TestIdentText(unittest.TestCase):
    def test_each_cn_maps_to_the_replication_role(self):
        text = dbpostgres.ident_text(["keel-2001-db8-1-0-10 postgresql",
                                      "keel-2001-db8-1-0-20 postgresql"])
        self.assertEqual(len([one for one in text.splitlines()
                              if one.startswith('keel "')]), 2)
        self.assertIn('keel "keel-2001-db8-1-0-10 postgresql" repl\n',
                      text)
        self.assertIn('keel "keel-2001-db8-1-0-20 postgresql" repl\n',
                      text)

    def test_a_quote_in_a_cn_is_doubled(self):
        text = dbpostgres.ident_text(['a "quoted" cn'])
        self.assertIn('keel "a ""quoted"" cn" repl\n', text)


class TestPairDropinText(unittest.TestCase):
    def test_both_nodes_carry_the_synchronous_policy(self):
        text = dbpostgres.pair_dropin_text()
        self.assertIn("synchronous_standby_names = 'FIRST 1 (keel)'\n",
                      text)
        self.assertIn("synchronous_commit = on\n", text)
        self.assertIn("wal_log_hints = on\n", text)

    def test_the_ident_file_is_named_only_when_the_pair_sets_it(self):
        self.assertNotIn("ident_file", dbpostgres.pair_dropin_text())
        self.assertIn("ident_file = '/etc/p/keel_ident'\n",
                      dbpostgres.pair_dropin_text("/etc/p/keel_ident"))


class TestSlotStatements(unittest.TestCase):
    def test_the_slot_is_made_idempotently_on_a_primary_only(self):
        made = dbpostgres.slot_statements()
        self.assertIn("pg_create_physical_replication_slot('keel')",
                      made.text)
        self.assertIn("WHERE NOT pg_is_in_recovery()", made.text)
        self.assertIn("NOT EXISTS (SELECT 1 FROM pg_replication_slots"
                      " WHERE slot_name = 'keel')", made.text)
        self.assertIn("replication slot", made.summary)

    def test_the_slot_statement_commits_without_the_standby(self):
        """PG 17 writes the slot's creation to WAL, so the statement's
        commit waits under the pair's synchronous commit policy — for
        the standby that does not exist yet; this statement is what
        lets it exist (found by the pair's network-namespace test of
        this release): it comes first with synchronous_commit local"""
        made = dbpostgres.slot_statements()
        self.assertTrue(made.text.startswith(
            "SET synchronous_commit = local;\n"), made.text)


class TestThePairKeepsWalForTheRewind(unittest.TestCase):
    def test_the_pair_dropin_keeps_wal_and_hints(self):
        text = dbpostgres.pair_dropin_text("/etc/p/ident")
        self.assertIn("wal_log_hints = on\n", text)
        self.assertIn("wal_keep_size = 256MB\n", text)

    def test_the_older_text_has_no_keep_size(self):
        older = dbpostgres.pair_dropin_text("/etc/p/ident", legacy=True)
        self.assertIn("wal_log_hints = on\n", older)
        self.assertNotIn("wal_keep_size", older)
        self.assertIn("ident_file = '/etc/p/ident'\n", older)


class TestRewindStatements(unittest.TestCase):
    def test_the_role_may_call_the_four_functions_of_pg_rewind(self):
        made = dbpostgres.rewind_statements()
        self.assertEqual(len(dbpostgres.REWIND_FUNCTIONS), 4)
        for name in dbpostgres.REWIND_FUNCTIONS:
            self.assertIn(f"GRANT EXECUTE ON FUNCTION {name} TO repl;",
                          made.text)
        self.assertIn("pg_rewind", made.summary)

    def test_the_grants_are_refused_on_no_standby_and_commit_alone(self):
        """A grant is refused in recovery, and under the pair's
        synchronous commit it would wait for a standby that may not
        exist yet, the way slot_statements has it"""
        made = dbpostgres.rewind_statements()
        self.assertTrue(made.text.startswith(
            "SET synchronous_commit = local;\n"), made.text)
        self.assertIn("IF pg_is_in_recovery() THEN", made.text)
        self.assertLess(made.text.index("RETURN"),
                        made.text.index("GRANT"))

    def test_the_grants_wait_for_the_role(self):
        """The follow of a new primary runs before the apply that makes
        the role: a grant to a role that is not there fails (found by
        the pair's network-namespace test)"""
        text = dbpostgres.rewind_statements().text
        guard = text.index("IF NOT EXISTS (SELECT FROM pg_roles"
                           " WHERE rolname = 'repl')")
        self.assertLess(guard, text.index("GRANT"))


class TestSysctlText(unittest.TestCase):
    def test_the_pair_binds_the_vip_on_both_nodes(self):
        text = dbpostgres.sysctl_text()
        self.assertIn("net.ipv6.ip_nonlocal_bind = 1\n", text)
        self.assertIn("both nodes bind the pair's VIP", text)


class TestFollowDropinText(unittest.TestCase):
    def test_the_endpoint_and_the_role_are_carried(self):
        text = dbpostgres.follow_dropin_text("fd1a:bb4c:b407::1", 5432,
                                             "secret")
        self.assertIn(
            "primary_conninfo = 'host=fd1a:bb4c:b407::1 port=5432"
            " user=repl password=secret application_name=keel'\n", text)

    def test_the_pair_streams_from_its_slot(self):
        text = dbpostgres.follow_dropin_text("fd1a:bb4c:b407::1", 5432,
                                             "secret", slot="keel")
        self.assertIn("primary_slot_name = 'keel'\n", text)
        # the single node's follow names no slot
        self.assertNotIn(
            "primary_slot_name",
            dbpostgres.follow_dropin_text("fd1a:bb4c:b407::1", 5432,
                                          "secret"))

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

    def test_the_tls_block_is_one_line_inside_the_value(self):
        """keel.system.dbtls.options_lines gives one option per line;
        a configuration value ends at the newline, so the conninfo this
        file hands the server must be flattened or the server refuses
        the file (found by the pair's network-namespace test of this
        release)"""
        text = dbpostgres.follow_dropin_text(
            "fd1a::1", 5432, "secret",
            "sslmode=verify-full\nsslrootcert=/etc/p/ca.pem\n"
            "sslcert=/etc/p/server.pem\nsslkey=/etc/p/server.key\n")
        quoted = text.split("primary_conninfo = ", 1)[1].split("\n")[0]
        self.assertIn("sslmode=verify-full", quoted)
        self.assertIn("sslkey=/etc/p/server.key", quoted)
        self.assertEqual(text.count("\n"),
                         text.count("\n", 0, text.index("primary_conninfo"))
                         + 1)


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


class TestRoleStatements(unittest.TestCase):
    def test_the_replication_role_is_ensured_with_the_password(self):
        found = dbpostgres.role_statements("s3cret")
        self.assertIn("CREATE ROLE", found.text)
        self.assertIn(dbpostgres.REPLICATION_USER, found.text)
        self.assertIn(dbpostgres.literal("s3cret"), found.text)
        self.assertIn("replication", found.summary)

    def test_an_existing_role_gets_the_new_password(self):
        found = dbpostgres.role_statements("new-one")
        self.assertIn("ALTER ROLE", found.text)
        self.assertIn(dbpostgres.literal("new-one"), found.text)

    def test_a_quote_in_the_password_is_doubled_not_broken(self):
        found = dbpostgres.role_statements("it's")
        self.assertIn(dbpostgres.literal("it's"), found.text)

    def test_the_block_uses_a_dollar_quoted_label(self):
        found = dbpostgres.role_statements("x")
        self.assertIn("$keel$", found.text)

    def test_the_role_block_commits_without_the_standby(self):
        """the block writes WAL (CREATE/ALTER ROLE), so under the
        pair's no-timeout synchronous commit it would wait for the
        standby that does not exist yet (found by the pair's
        network-namespace test of this release): it comes first with
        synchronous_commit local, the way slot_statements has it"""
        found = dbpostgres.role_statements("x")
        self.assertTrue(found.text.startswith(
            "SET synchronous_commit = local;\n"), found.text)

    def test_on_a_standby_the_role_block_does_nothing(self):
        """The role arrives with the primary's copy, and a standby
        refuses ALTER ROLE: the block returns before it on a standby,
        or every apply on a standby fails once the client stops at an
        error"""
        text = dbpostgres.role_statements("x").text
        guard = text.index("IF pg_is_in_recovery() THEN")
        self.assertLess(guard, text.index("CREATE ROLE"))
        self.assertIn("RETURN;", text[guard:text.index("CREATE ROLE")])


class TestTheClient(unittest.TestCase):
    def test_a_failed_statement_fails_the_client(self):
        """Without ON_ERROR_STOP psql goes on after an error on standard
        input and exits 0: a refused pg_promote() read as done"""
        self.assertIn("--set=ON_ERROR_STOP=1", dbpostgres.CLIENT)

    def test_the_answers_have_one_tab_between_the_columns(self):
        self.assertIn("--no-align", dbpostgres.CLIENT)
        self.assertIn("--field-separator=\t", dbpostgres.CLIENT)


class TestQuestions(unittest.TestCase):
    def test_the_schemas_question_lists_databases_as_the_postgres_user(self):
        question = dbpostgres.schemas_question()
        self.assertEqual(question[:4],
                         ("runuser", "-u", "postgres", "--"))
        self.assertIn("SELECT datname FROM pg_database", question)


if __name__ == "__main__":
    unittest.main()
