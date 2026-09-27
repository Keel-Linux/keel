# Copyright (c) 2026 KeelLinux maintainers
"""The database probes, as pure functions over what a server answered

Every answer here is output measured on a real server, not invented: the
MariaDB rows come from a container booted from the published mariadb layer,
the Redis INFO sections from a redis-server on the same machine, and the
PostgreSQL rows from the published postgresql layer.

The two subjects are tested apart, because a machine can have either.
"""

import unittest

from helpers_database import (
    answers,
    mariadb_reading,
    postgresql_reading,
    redis_reading,
)

from keel.inspect.database import (  # noqa: E402
    Installed,
    probe_client,
    probe_database,
    probe_server,
)
from keel.inspect.dbclient import (  # noqa: E402
    READERS,
    read_nodebb,
    read_wordpress,
    split_host,
)
from keel.inspect.dbengines import ENGINES  # noqa: E402
from keel.inspect.dbreading import listening_on  # noqa: E402
from keel.inspect.report import INFERRED, NOT_INFERRED  # noqa: E402
from keel.inspect.tree import File  # noqa: E402

SOCKETS = """\
LISTEN 0      128      0.0.0.0:22    0.0.0.0:*
LISTEN 0      80     127.0.0.1:3306  0.0.0.0:*
LISTEN 0      128         [::]:22       [::]:*
LISTEN 0      80         [::1]:3306     [::]:*
"""

MARIADB_STANDALONE = {
    "status": "",
    "replicas": "",
    "variables": "log_bin\tOFF\nport\t3306\nserver_id\t1\nwsrep_on\tOFF\n",
    "grants": "localhost\nlocalhost\n::1\n127.0.0.1\n",
}
MARIADB_REPLICA_STATUS = """\
*************************** 1. row ***************************
                Slave_IO_State: Waiting for master to send event
                   Master_Host: 2001:db8:1::10
                   Master_User: repl
                   Master_Port: 3306
             Slave_IO_Running: Yes
            Slave_SQL_Running: Yes
"""
REDIS_MASTER = {
    "replication": "# Replication\nrole:master\nconnected_slaves:0\n"
                   "master_failover_state:no-failover\n",
    "cluster": "# Cluster\ncluster_enabled:0\n",
    "server": "# Server\nredis_version:8.0.2\ntcp_port:6379\n",
}
REDIS_REPLICA = {
    "replication": "# Replication\nrole:slave\nmaster_host:2001:db8:1::10\n"
                   "master_port:6379\nmaster_link_status:up\n",
    "cluster": "# Cluster\ncluster_enabled:0\n",
    "server": "# Server\ntcp_port:6379\n",
}
PG_STANDALONE = {
    "state": "f\t0\t5432\n",
    "receiver": "",
    "standby": "\n",
    "hba": "local\t\t\nhost\t127.0.0.1\t255.255.255.255\n",
}
WP_CONFIG = """<?php
define( 'DB_NAME', 'wordpress' );
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'never read');
define( 'DB_HOST', '[2001:db8:1::10]:3306' );
"""
NODEBB_CONFIG = """{
  "url": "http://forum.example.org",
  "database": "redis",
  "redis": {
    "host": "::1",
    "port": "6379",
    "password": "never read",
    "database": "0"
  }
}
"""


def statuses(findings, field: str) -> list[str]:
    return [one.status for one in findings if one.field == field]


def value_of(findings, field: str) -> str:
    return next(one.value for one in findings if one.field == field)


def reason_of(findings, field: str) -> str:
    return next(one.source for one in findings if one.field == field)


class TestMariaDB(unittest.TestCase):
    def test_a_standalone_server_reads_as_standalone(self):
        reading = mariadb_reading(MARIADB_STANDALONE, SOCKETS)
        self.assertEqual(reading.role.value, "standalone")
        self.assertIn("is empty", reading.role.source)

    def test_the_grants_of_this_machine_authorize_nobody_else(self):
        reading = mariadb_reading(MARIADB_STANDALONE, SOCKETS)
        self.assertEqual(reading.allowed_from.value, [])

    def test_a_grant_from_a_prefix_makes_it_a_primary(self):
        answered = dict(MARIADB_STANDALONE, grants="2001:db8:1:%\nlocalhost\n")
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "primary")
        self.assertEqual(reading.allowed_from.value, ["2001:db8:1:%"])
        self.assertIn("replication is granted", reading.role.source)

    def test_a_connected_replica_makes_it_a_primary(self):
        answered = dict(
            MARIADB_STANDALONE, replicas="2\t2001:db8:1::20\t3306\t1\n"
        )
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "primary")
        self.assertIn("1 replica(s) connected", reading.role.source)

    def test_a_replica_status_row_makes_it_a_replica(self):
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "replica")
        self.assertEqual(
            reading.primary.value, {"host": "2001:db8:1::10", "port": 3306}
        )

    def test_the_new_column_names_are_read_as_well(self):
        answered = dict(
            MARIADB_STANDALONE,
            status="  Source_Host: 2001:db8:1::10\n  Source_Port: 3307\n",
        )
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(
            reading.primary.value, {"host": "2001:db8:1::10", "port": 3307}
        )

    def test_a_status_row_without_a_port_still_names_the_primary(self):
        answered = dict(
            MARIADB_STANDALONE, status="  Master_Host: 2001:db8:1::10\n"
        )
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.primary.value, {"host": "2001:db8:1::10"})

    def test_the_status_question_keeps_its_column_names(self):
        """`\\G` names each field and --skip-column-names takes that away

        Measured on the bench: with the names gone, the primary's address
        arrived as a bare line and the reading found no primary at all on a
        machine that was plainly replicating.
        """
        engine = next(one for one in ENGINES if one.name == "mariadb")
        self.assertNotIn(
            "--skip-column-names", engine.questions["status"]
        )
        self.assertIn(
            "--skip-column-names", engine.questions["variables"]
        )

    def test_a_status_row_with_no_colon_in_it_is_still_a_replica(self):
        answered = dict(MARIADB_STANDALONE, status="1 row\n")
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "replica")
        self.assertIsNone(reading.primary.value)

    def test_a_galera_node_has_no_role_in_the_spec_yet(self):
        answered = dict(
            MARIADB_STANDALONE,
            variables="wsrep_on\tON\nport\t3306\n",
        )
        reading = mariadb_reading(answered, SOCKETS)
        self.assertIsNone(reading.role.value)
        self.assertIn("Galera", reading.role.problem)
        self.assertIn("no role in the spec yet", reading.role.problem)

    def test_a_server_that_cannot_be_asked_reports_the_command(self):
        reading = mariadb_reading(MARIADB_STANDALONE, SOCKETS,
                                  problem="exited 1")
        self.assertIsNone(reading.role.value)
        self.assertIn("exited 1", reading.role.problem)

    def test_a_port_the_server_does_not_name_falls_back_to_the_default(self):
        answered = dict(MARIADB_STANDALONE, variables="log_bin\tOFF\n")
        reading = mariadb_reading(answered, SOCKETS)
        self.assertEqual(reading.listen.value, ["127.0.0.1", "::1"])


class TestPostgreSQL(unittest.TestCase):
    def test_a_standalone_server_reads_as_standalone(self):
        reading = postgresql_reading(PG_STANDALONE, SOCKETS)
        self.assertEqual(reading.role.value, "standalone")
        self.assertIn("not in recovery", reading.role.source)

    def test_recovery_makes_it_a_replica(self):
        answered = dict(
            PG_STANDALONE,
            state="t\t0\t5432\n",
            receiver="user=repl host=2001:db8:1::10 port=5432"
                     " password=******** sslmode=prefer\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "replica")
        self.assertEqual(
            reading.primary.value, {"host": "2001:db8:1::10", "port": 5432}
        )

    def test_a_standby_that_is_not_streaming_falls_back_to_the_setting(self):
        answered = dict(
            PG_STANDALONE,
            state="t\t0\t5432\n",
            standby="host=2001:db8:1::10 port=5433 password=secret\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(
            reading.primary.value, {"host": "2001:db8:1::10", "port": 5433}
        )

    def test_only_the_host_and_the_port_are_taken_from_a_conninfo(self):
        answered = dict(
            PG_STANDALONE,
            state="t\t0\t5432\n",
            standby="host=2001:db8:1::10 password=secret user=repl\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.primary.value, {"host": "2001:db8:1::10"})

    def test_a_streaming_replica_makes_it_a_primary(self):
        answered = dict(PG_STANDALONE, state="f\t1\t5432\n")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "primary")
        self.assertIn("pg_stat_replication has 1 row(s)",
                      reading.role.source)

    def test_an_hba_rule_becomes_a_prefix_and_makes_it_a_primary(self):
        answered = dict(
            PG_STANDALONE,
            hba="local\t\t\nhost\t2001:db8:1::\tffff:ffff:ffff:ffff::\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, ["2001:db8:1::/64"])
        self.assertEqual(reading.role.value, "primary")

    def test_a_keyword_or_a_name_is_kept_as_written(self):
        answered = dict(
            PG_STANDALONE, hba="host\tsamenet\t\nhost\treplica.example.org\t\n"
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(
            reading.allowed_from.value, ["samenet", "replica.example.org"]
        )

    def test_a_netmask_that_is_not_one_keeps_the_address(self):
        answered = dict(PG_STANDALONE, hba="host\t2001:db8::\tnonsense\n")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, ["2001:db8::"])

    def test_a_loopback_host_prefix_authorizes_nobody_else(self):
        answered = dict(
            PG_STANDALONE,
            hba="host\t127.0.0.1\t255.255.255.255\nhost\t::1\tffff:"
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, [])
        self.assertEqual(reading.role.value, "standalone")

    def test_a_local_rule_names_no_origin(self):
        answered = dict(PG_STANDALONE, hba="local\t\t\n")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, [])

    def test_a_server_that_answers_nothing_is_not_inferred(self):
        answered = dict(PG_STANDALONE, state="")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertIsNone(reading.role.value)
        self.assertIn("answered nothing", reading.role.problem)


class TestRedis(unittest.TestCase):
    def test_a_master_with_no_replica_reads_as_standalone(self):
        reading = redis_reading(REDIS_MASTER, SOCKETS)
        self.assertEqual(reading.role.value, "standalone")
        self.assertIn("connected_slaves:0", reading.role.source)
        self.assertIn("keeps no record", reading.role.source)

    def test_a_master_with_a_replica_reads_as_primary(self):
        answered = dict(
            REDIS_MASTER,
            replication="role:master\nconnected_slaves:1\n"
                        "slave0:ip=2001:db8:1::20,port=6379,state=online\n",
        )
        reading = redis_reading(answered, SOCKETS)
        self.assertEqual(reading.role.value, "primary")
        self.assertIn("connected_slaves:1", reading.role.source)

    def test_a_slave_reads_as_replica_with_its_primary(self):
        reading = redis_reading(REDIS_REPLICA, SOCKETS)
        self.assertEqual(reading.role.value, "replica")
        self.assertEqual(
            reading.primary.value, {"host": "2001:db8:1::10", "port": 6379}
        )

    def test_a_cluster_node_has_no_role_in_the_spec_yet(self):
        answered = dict(REDIS_MASTER, cluster="cluster_enabled:1\n")
        reading = redis_reading(answered, SOCKETS)
        self.assertIsNone(reading.role.value)
        self.assertIn("Redis Cluster", reading.role.problem)

    def test_redis_holds_no_list_of_origins_and_says_so(self):
        reading = redis_reading(REDIS_MASTER, SOCKETS)
        self.assertIsNone(reading.allowed_from.value)
        self.assertIn("requirepass", reading.allowed_from.problem)

    def test_an_info_section_without_a_role_is_not_inferred(self):
        answered = dict(REDIS_MASTER, replication="# Replication\n")
        reading = redis_reading(answered, SOCKETS)
        self.assertIsNone(reading.role.value)
        self.assertIn("reports no role", reading.role.problem)

    def test_an_unauthenticated_client_reports_what_the_server_said(self):
        reading = redis_reading(REDIS_MASTER, SOCKETS, problem="exited 1")
        self.assertIsNone(reading.role.value)
        self.assertIn("exited 1", reading.role.problem)


class TestListening(unittest.TestCase):
    def test_the_addresses_of_one_port_are_read_from_the_sockets(self):
        value = listening_on(File("ss -lntH", SOCKETS), 3306)
        self.assertEqual(value.value, ["127.0.0.1", "::1"])

    def test_a_port_nothing_listens_on_is_not_inferred(self):
        value = listening_on(File("ss -lntH", SOCKETS), 5432)
        self.assertIsNone(value.value)
        self.assertIn("nothing listening on port 5432", value.problem)

    def test_a_command_that_did_not_run_is_not_inferred(self):
        value = listening_on(File("ss -lntH", problem="not run"), 3306)
        self.assertIsNone(value.value)
        self.assertIn("not run", value.problem)

    def test_a_line_too_short_to_hold_an_address_is_skipped(self):
        value = listening_on(File("ss -lntH", "LISTEN 0 80\n"), 3306)
        self.assertIsNone(value.value)

    def test_an_address_without_a_port_is_skipped(self):
        value = listening_on(File("ss -lntH", "LISTEN 0 80 socket peer\n"), 1)
        self.assertIsNone(value.value)


class TestServerSection(unittest.TestCase):
    def one(self, engine_name: str, answered: dict, sockets: str = SOCKETS):
        engine = next(e for e in ENGINES if e.name == engine_name)
        return Installed(
            engine, f"/usr/sbin/{engine_name}d",
            answers(engine, answered), File("ss -lntH", sockets),
        )

    def test_no_server_installed_reports_nothing_at_all(self):
        section, findings = probe_server(())
        self.assertIsNone(section)
        self.assertEqual(findings, [])

    def test_a_standalone_server_reports_engine_role_and_listen(self):
        section, findings = probe_server(
            (self.one("mariadb", MARIADB_STANDALONE),)
        )
        self.assertEqual(section["engine"], "mariadb")
        self.assertEqual(section["role"], "standalone")
        self.assertEqual(section["listen"], ["127.0.0.1", "::1"])
        self.assertEqual(
            statuses(findings, "database.server.role"), [INFERRED]
        )

    def test_a_standalone_server_reports_no_replication_fields(self):
        section, findings = probe_server(
            (self.one("mariadb", MARIADB_STANDALONE),)
        )
        self.assertNotIn("replication", section)
        self.assertEqual(statuses(findings, "database.server.replication"), [])

    def test_a_replica_reports_the_primary_and_not_the_authorizations(self):
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        section, findings = probe_server((self.one("mariadb", answered),))
        self.assertEqual(section["role"], "replica")
        self.assertEqual(
            section["replication"]["primary"],
            {"host": "2001:db8:1::10", "port": 3306},
        )
        self.assertNotIn("allowed_from", section["replication"])
        reason = reason_of(
            findings, "database.server.replication.allowed_from"
        )
        self.assertIn("the server is a replica", reason)

    def test_a_primary_reports_the_authorizations_and_not_a_primary(self):
        answered = dict(MARIADB_STANDALONE, grants="2001:db8:1:%\n")
        section, findings = probe_server((self.one("mariadb", answered),))
        self.assertEqual(section["role"], "primary")
        self.assertEqual(
            section["replication"]["allowed_from"], ["2001:db8:1:%"]
        )
        self.assertNotIn("primary", section["replication"])
        self.assertEqual(
            statuses(findings, "database.server.replication.primary"),
            [NOT_INFERRED],
        )

    def test_a_standalone_says_why_neither_field_was_read(self):
        _, findings = probe_server(
            (self.one("mariadb", MARIADB_STANDALONE),)
        )
        for name in ("primary", "allowed_from"):
            with self.subTest(field=name):
                reason = reason_of(
                    findings, f"database.server.replication.{name}"
                )
                self.assertIn("the server is a standalone", reason)

    def test_a_galera_node_writes_no_section_and_names_the_mode(self):
        answered = dict(MARIADB_STANDALONE, variables="wsrep_on\tON\n")
        section, findings = probe_server((self.one("mariadb", answered),))
        self.assertIsNone(section)
        reason = reason_of(findings, "database.server")
        self.assertIn("Galera", reason)
        self.assertIn("no role in the spec yet", reason)

    def test_a_server_that_cannot_say_what_it_is_writes_no_section(self):
        """The whole section is unknown, so no field of it can be drift"""
        installed = self.one("redis", REDIS_MASTER)
        broken = Installed(
            installed.engine, installed.binary,
            answers(installed.engine, REDIS_MASTER, problem="exited 1"),
            File("ss -lntH", SOCKETS),
        )
        section, findings = probe_server((broken,))
        self.assertIsNone(section)
        self.assertEqual(statuses(findings, "database.server"),
                         [NOT_INFERRED])
        reason = reason_of(findings, "database.server")
        self.assertIn("redis server is installed", reason)
        self.assertIn("exited 1", reason)

    def test_two_servers_on_one_machine_are_not_describable_yet(self):
        section, findings = probe_server((
            self.one("mariadb", MARIADB_STANDALONE),
            self.one("redis", REDIS_MASTER),
        ))
        self.assertIsNone(section)
        reason = reason_of(findings, "database.server")
        self.assertIn("2 database servers", reason)
        self.assertIn("mariadb, redis", reason)


class TestClientSection(unittest.TestCase):
    def reader(self, application: str):
        return next(r for r in READERS if r.application == application)

    def test_no_application_reports_nothing_at_all(self):
        section, findings = probe_client(())
        self.assertIsNone(section)
        self.assertEqual(findings, [])

    def test_wordpress_names_its_engine_host_port_name_and_user(self):
        section, findings = probe_client((
            (self.reader("wordpress"), File("/wp-config.php", WP_CONFIG)),
        ))
        self.assertEqual(section, {
            "engine": "mariadb",
            "primary": {
                "host": "2001:db8:1::10", "port": 3306,
                "name": "wordpress", "user": "wpuser",
            },
        })
        self.assertEqual(
            statuses(findings, "database.client.replicas"), [NOT_INFERRED]
        )

    def test_nodebb_names_the_engine_it_was_configured_with(self):
        section, _ = probe_client((
            (self.reader("nodebb"), File("/config.json", NODEBB_CONFIG)),
        ))
        self.assertEqual(section["engine"], "redis")
        self.assertEqual(section["primary"]["host"], "::1")
        self.assertEqual(section["primary"]["port"], 6379)
        self.assertEqual(section["primary"]["name"], "0")

    def test_no_password_reaches_the_section_or_the_report(self):
        section, findings = probe_client((
            (self.reader("wordpress"), File("/wp-config.php", WP_CONFIG)),
            (self.reader("nodebb"), File("/config.json", NODEBB_CONFIG)),
        ))
        printed = repr(section) + " ".join(one.line() for one in findings)
        self.assertNotIn("never read", printed)

    def test_a_configuration_that_cannot_be_read_is_not_inferred(self):
        section, findings = probe_client((
            (self.reader("wordpress"),
             File("/wp-config.php", problem="permission denied (root only)")),
        ))
        self.assertIsNone(section)
        self.assertIn(
            "permission denied", reason_of(findings, "database.client.primary")
        )

    def test_a_configuration_without_a_host_is_not_inferred(self):
        section, findings = probe_client((
            (self.reader("wordpress"), File("/wp-config.php", "<?php\n")),
        ))
        self.assertIsNone(section)
        self.assertIn(
            "defines no DB_HOST",
            reason_of(findings, "database.client.primary"),
        )

    def test_an_empty_host_is_not_inferred(self):
        section, findings = probe_client((
            (self.reader("wordpress"),
             File("/wp-config.php", "define('DB_HOST', '');")),
        ))
        self.assertIsNone(section)
        self.assertIn("empty DB_HOST",
                     reason_of(findings, "database.client.primary"))

    def test_the_next_reader_is_tried_when_the_first_says_nothing(self):
        section, _ = probe_client((
            (self.reader("wordpress"), File("/wp-config.php", "<?php\n")),
            (self.reader("nodebb"), File("/config.json", NODEBB_CONFIG)),
        ))
        self.assertEqual(section["engine"], "redis")

    def test_malformed_json_is_not_inferred(self):
        endpoint, reason = read_nodebb(File("/config.json", "{"))
        self.assertIsNone(endpoint)
        self.assertIn("not valid JSON", reason)

    def test_json_that_is_not_an_object_is_not_inferred(self):
        endpoint, reason = read_nodebb(File("/config.json", "[]"))
        self.assertIsNone(endpoint)
        self.assertIn("does not hold a JSON object", reason)

    def test_an_engine_the_spec_does_not_know_is_not_inferred(self):
        endpoint, reason = read_nodebb(
            File("/config.json", '{"database": "mongo"}')
        )
        self.assertIsNone(endpoint)
        self.assertIn("mongo", reason)

    def test_settings_without_a_host_are_not_inferred(self):
        endpoint, reason = read_nodebb(
            File("/config.json", '{"database": "redis", "redis": {}}')
        )
        self.assertIsNone(endpoint)
        self.assertIn("gives no host", reason)

    def test_a_port_in_the_host_is_used_when_no_port_is_given(self):
        endpoint, _ = read_nodebb(File(
            "/config.json",
            '{"database": "postgres", "postgres": {"host": "[::1]:5433"}}',
        ))
        self.assertEqual(endpoint.engine, "postgresql")
        self.assertEqual(endpoint.port, 5433)

    def test_a_bare_ipv6_host_keeps_all_of_its_colons(self):
        self.assertEqual(split_host("2001:db8:1::10"), ("2001:db8:1::10", None))

    def test_a_bracketed_host_without_a_port_is_read(self):
        self.assertEqual(split_host("[::1]"), ("::1", None))

    def test_a_port_that_is_not_a_number_is_left_out(self):
        self.assertEqual(split_host("[::1]:mysql"), ("::1", None))
        self.assertEqual(split_host("192.0.2.1:mysql"), ("192.0.2.1", None))

    def test_a_socket_path_is_read_as_a_host_and_refused_by_the_schema(self):
        endpoint, _ = read_wordpress(
            File("/wp-config.php", "define('DB_HOST', '/run/mysqld.sock');")
        )
        self.assertEqual(endpoint.host, "/run/mysqld.sock")


class TestBothSubjects(unittest.TestCase):
    """A machine can run a server and use one, and each is read alone"""

    def installed(self):
        engine = next(e for e in ENGINES if e.name == "mariadb")
        return Installed(
            engine, "/usr/sbin/mariadbd",
            answers(engine, MARIADB_STANDALONE), File("ss -lntH", SOCKETS),
        )

    def reader(self):
        return next(r for r in READERS if r.application == "wordpress")

    def test_a_machine_with_both_reports_both(self):
        section, _ = probe_database(
            (self.installed(),),
            ((self.reader(), File("/wp-config.php", WP_CONFIG)),),
        )
        self.assertEqual(sorted(section), ["client", "server"])

    def test_a_machine_with_a_server_only_reports_the_server(self):
        section, _ = probe_database((self.installed(),), ())
        self.assertEqual(list(section), ["server"])

    def test_a_machine_with_an_application_only_reports_the_client(self):
        section, _ = probe_database(
            (), ((self.reader(), File("/wp-config.php", WP_CONFIG)),)
        )
        self.assertEqual(list(section), ["client"])

    def test_a_machine_with_neither_reports_no_section(self):
        section, findings = probe_database((), ())
        self.assertIsNone(section)
        self.assertEqual(findings, [])


class TestCollectorBranches(unittest.TestCase):
    """The collector's own search, without touching a real filesystem"""

    def engine(self, name: str):
        return next(one for one in ENGINES if one.name == name)

    def test_postgresql_is_found_under_the_major_version_it_ships(self):
        found = self.engine("postgresql").installed(
            lambda pattern: (
                ["usr/lib/postgresql/17/bin/postgres"]
                if "postgres" in pattern else []
            )
        )
        self.assertEqual(found, "usr/lib/postgresql/17/bin/postgres")

    def test_the_second_pattern_is_tried_when_the_first_matches_nothing(self):
        found = self.engine("postgresql").installed(
            lambda pattern: (
                ["usr/lib/postgresql/17/bin/pg_ctl"]
                if "pg_ctl" in pattern else []
            )
        )
        self.assertEqual(found, "usr/lib/postgresql/17/bin/pg_ctl")

    def test_a_machine_without_the_server_binary_finds_nothing(self):
        self.assertIsNone(
            self.engine("mariadb").installed(lambda pattern: [])
        )

    def test_a_prefix_length_that_is_not_a_netmask_is_passed_through(self):
        answered = dict(PG_STANDALONE, hba="host\t2001:db8::\t64\n")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, ["2001:db8::/64"])

    def test_an_hba_view_that_cannot_be_read_is_not_inferred(self):
        reading = postgresql_reading(PG_STANDALONE, SOCKETS,
                                     problem="exited 2")
        self.assertIsNone(reading.allowed_from.value)
        self.assertIn("exited 2", reading.allowed_from.problem)

    def test_a_row_with_no_address_names_no_origin(self):
        answered = dict(PG_STANDALONE, hba="host\n")
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.allowed_from.value, [])

    def test_an_endpoint_with_neither_name_nor_user_carries_neither(self):
        section, _ = probe_client((
            (next(r for r in READERS if r.application == "wordpress"),
             File("/wp-config.php", "define('DB_HOST', '2001:db8::10');")),
        ))
        self.assertEqual(
            section["primary"], {"host": "2001:db8::10"}
        )

    def one(self, engine_name: str, answered: dict, sockets: str = SOCKETS):
        engine = next(e for e in ENGINES if e.name == engine_name)
        return Installed(
            engine, f"/usr/sbin/{engine_name}d",
            answers(engine, answered), File("ss -lntH", sockets),
        )

    def test_a_field_of_a_known_role_that_cannot_be_read_is_not_inferred(self):
        section, findings = probe_server((
            self.one("mariadb", MARIADB_STANDALONE, sockets="LISTEN 0 80\n"),
        ))
        self.assertEqual(section["role"], "standalone")
        self.assertNotIn("listen", section)
        self.assertEqual(
            statuses(findings, "database.server.listen"), [NOT_INFERRED]
        )

    def test_a_conninfo_without_a_host_is_passed_over(self):
        answered = dict(
            PG_STANDALONE,
            state="t\t0\t5432\n",
            receiver="user=repl sslmode=prefer\n",
            standby="host=2001:db8:1::10\n",
        )
        reading = postgresql_reading(answered, SOCKETS)
        self.assertEqual(reading.primary.value, {"host": "2001:db8:1::10"})


class TestWhatInspectWritesValidates(unittest.TestCase):
    """Every section the reading can produce is one the schema accepts

    The round trip rests on this: inspect writes a description an operator
    edits and applies, so a value the server holds and the schema refuses is
    a defect in the vocabulary. The MariaDB host pattern was exactly that,
    found on a primary authorized from a /64.
    """

    def validate(self, section: dict) -> list[str]:
        from keel import spec

        return spec.validate(
            {"version": 1, "database": section}, check_secret_files=False
        )

    def one(self, engine_name: str, answered: dict):
        engine = next(e for e in ENGINES if e.name == engine_name)
        return Installed(
            engine, f"/usr/sbin/{engine_name}d",
            answers(engine, answered), File("ss -lntH", SOCKETS),
        )

    def test_a_mariadb_primary_authorized_from_a_prefix_validates(self):
        answered = dict(MARIADB_STANDALONE, grants="2804:710:d0:5:%\n")
        section, _ = probe_server((self.one("mariadb", answered),))
        self.assertEqual(
            section["replication"]["allowed_from"], ["2804:710:d0:5:%"]
        )
        self.assertEqual(self.validate({"server": section}), [])

    def test_a_postgresql_primary_with_an_hba_prefix_validates(self):
        answered = dict(
            PG_STANDALONE,
            hba="host\t2001:db8:1::\tffff:ffff:ffff:ffff::\n",
        )
        section, _ = probe_server((self.one("postgresql", answered),))
        self.assertEqual(self.validate({"server": section}), [])

    def test_a_replica_naming_its_primary_validates(self):
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        section, _ = probe_server((self.one("mariadb", answered),))
        self.assertEqual(self.validate({"server": section}), [])

    def test_a_standalone_validates(self):
        section, _ = probe_server((self.one("redis", REDIS_MASTER),))
        self.assertEqual(self.validate({"server": section}), [])

    def test_what_the_client_reader_writes_validates(self):
        section, _ = probe_client((
            (next(r for r in READERS if r.application == "wordpress"),
             File("/wp-config.php", WP_CONFIG)),
        ))
        self.assertEqual(self.validate({"client": section}), [])
