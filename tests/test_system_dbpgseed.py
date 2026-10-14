# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL seed (keel.system.dbpgseed), against fake runners

Every test here is Arrange-Act-Assert against a scratch root and a
runner that answers what a primary would: no server, no network, no
real command run anywhere.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from keel.system import dbpgseed, dbpostgres

HOST = "2001:db8:1::10"
PORT = 5432
PASSWORD = "a-replication-password"
WHERE = {"host": HOST, "port": PORT}


def answer(stdout: str = "", returncode: int = 0,
           stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout.encode(),
                                       stderr.encode())


class SeedAction:
    """The SeedReplica attributes dbpgseed reads, without a plan"""

    def __init__(self, host=HOST, port=PORT, password=PASSWORD,
                 tls=""):
        self.host = host
        self.port = port
        self.password = password
        self.tls = tls


class TestPgpass(unittest.TestCase):
    def test_the_line_escapes_colons_for_ipv6_and_the_password(self):
        line = dbpgseed.pgpass_line("2001:db8:1::10", 5432, "a:b\\c")
        self.assertEqual(
            line,
            "2001\\:db8\\:1\\:\\:10:5432:postgres:repl:a\\:b\\\\c\n")

    def test_the_file_is_created_exclusively_at_mode_0600(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = dbpgseed.write_pgpass(directory, HOST, PORT, PASSWORD)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as fob:
            self.assertIn("repl", fob.read())

    def test_the_file_and_its_directory_are_the_server_users(self):
        """The clients run as postgres (dbpostgres.CLIENT, AS_POSTGRES):
        a root-owned pgpass in a root-owned spool is unreadable to them,
        libpq ignores it, and the probe answers the server's password
        challenge with nothing ("no password supplied" — found by the
        pair's network-namespace test of this release)"""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        with mock.patch.object(dbpgseed.pwd, "getpwnam") as getpwnam, \
                mock.patch.object(dbpgseed.os, "chown") as chown:
            getpwnam.return_value.pw_uid = 999
            path = dbpgseed.write_pgpass(directory, HOST, PORT, PASSWORD)
        getpwnam.assert_called_once_with("postgres")
        self.assertEqual(
            [one.args for one in chown.call_args_list],
            [(directory, 999, -1), (path, 999, -1)])

    def test_a_dev_host_without_the_user_keeps_root_ownership(self):
        """best effort, the way dbpgseed._as_postgres has it: the file
        is written all the same and nothing is raised"""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        with mock.patch.object(dbpgseed.pwd, "getpwnam",
                               side_effect=KeyError("postgres")):
            path = dbpgseed.write_pgpass(directory, HOST, PORT, PASSWORD)
        self.assertTrue(os.path.exists(path))

    def test_the_conninfo_names_the_pgpass_file_not_the_password(self):
        found = dbpgseed.conninfo(HOST, PORT, "/tmp/x/pgpass")
        self.assertIn("passfile=/tmp/x/pgpass", found)
        self.assertIn(f"host={HOST}", found)
        self.assertNotIn(PASSWORD, found)

    def test_the_conninfo_carries_the_pair_tls_when_given(self):
        """The replication protocol authenticates with the pair's
        certificate (the hba line's cert method, 0054), so the copy and
        the timeline asks reach the primary with no certificate at all
        without it: pg_basebackup answers "connection requires a valid
        client certificate", falls back to no TLS, and finds no line
        (found by the pair's network-namespace test of this release)"""
        tls = "sslmode=verify-full\nsslrootcert=/x/ca.pem" \
            "\nsslcert=/x/server.pem\nsslkey=/x/server.key\n"
        found = dbpgseed.conninfo(HOST, PORT, "/tmp/x/pgpass", tls)
        self.assertIn("sslmode=verify-full", found)
        self.assertIn("sslrootcert=/x/ca.pem", found)
        self.assertIn("sslcert=/x/server.pem", found)
        self.assertIn("sslkey=/x/server.key", found)


class TestReach(unittest.TestCase):
    def root(self) -> str:
        found = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, found)
        os.makedirs(os.path.join(found, "var/tmp"))
        return found

    def test_an_answering_primary_has_no_problem(self):
        ran = []
        found = dbpgseed.reach(self.root(), HOST, PORT, PASSWORD,
                               runner=self.recording(ran, "f\t2\t100\n"))
        self.assertEqual(found.problem, "")
        self.assertEqual(found.shared, ())

    def test_an_unreachable_primary_is_the_problem(self):
        def runner(argv, **kwargs):
            return answer("", returncode=1, stderr="connection refused")
        found = dbpgseed.reach(self.root(), HOST, PORT, PASSWORD,
                               runner=runner)
        self.assertIn(HOST, found.problem)
        self.assertIn("connection refused", found.problem)

    def test_a_standby_is_refused_as_a_copy_source(self):
        found = dbpgseed.reach(self.root(), HOST, PORT, PASSWORD,
                               runner=lambda a, **k: answer("t\t2\t100\n"))
        self.assertIn("itself a standby", found.problem)

    def recording(self, ran, stdout):
        def runner(argv, **kwargs):
            ran.append(list(argv))
            return answer(stdout)
        return runner


class TestSeed(unittest.TestCase):
    """The order of the steps, and what each failure leaves behind"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        confd = os.path.join(
            self.root, "etc/postgresql/17/main/conf.d")
        os.makedirs(confd)
        os.makedirs(os.path.join(self.root, "var/tmp"))
        self.datadir = os.path.join(self.root, "var/lib/postgresql/17/main")
        os.makedirs(self.datadir)
        with open(os.path.join(self.datadir, "PG_VERSION"), "w") as fob:
            fob.write("17\n")
        self.ran = []
        self.clock_at = [0.0]

    def clock(self):
        return self.clock_at[0]

    def runner(self, argv, **kwargs):
        """Answers as the primary, carries out pg_basebackup locally,
        and streams on the first ask after the start"""
        self.ran.append(list(argv))
        if "pg_basebackup" in argv:
            target = next(a.split("=", 1)[1] for a in argv
                          if a.startswith("--pgdata="))
            os.makedirs(target)
            return answer()
        if "--command" in argv:
            sql = argv[argv.index("--command") + 1]
            if sql == dbpgseed.PROBE_SQL:
                return answer("f\t2\t100\n")
            if sql == dbpgseed.STREAMING_QUESTION:
                return answer("streaming\n")
        return answer()

    def test_the_happy_path_stops_swaps_starts_and_streams(self):
        self.assertIsNone(dbpgseed.seed(self.root, SeedAction(),
                                        runner=self.runner,
                                        clock=self.clock))
        self.assertEqual(self.commands(),
                         ["pg_basebackup", "systemctl stop postgresql",
                          "systemctl start postgresql"])
        self.assertFalse(os.path.isdir(self.datadir
                                       + dbpgseed.ASIDE_SUFFIX))
        self.assertTrue(os.path.isfile(os.path.join(
            self.datadir, dbpostgres.STANDBY_SIGNAL)))
        follow = os.path.join(
            self.root, "etc/postgresql/17/main/conf.d",
            dbpostgres.FOLLOW_DROPIN_NAME)
        with open(follow) as fob:
            self.assertIn("primary_conninfo", fob.read())
        self.assertEqual(os.stat(follow).st_mode & 0o777, 0o600)
        self.assertNotIn(PASSWORD, " ".join(
            " ".join(str(a) for a in argv) for argv in self.ran))

    def test_the_copy_is_compressed_by_the_primary(self):
        """The design case's link carries about 50 kB/s: a 40 MB raw
        copy took minutes, under 3 MB compressed takes seconds (found
        by the pair's network-namespace test of this release)"""
        self.assertIsNone(dbpgseed.seed(self.root, SeedAction(),
                                        runner=self.runner,
                                        clock=self.clock))
        copy = next(argv for argv in self.ran if "pg_basebackup" in argv)
        self.assertIn("--compress=server-zstd", copy)
        self.assertIn("--format=plain", copy)

    def test_the_copy_is_never_the_pair_s_synchronous_standby(self):
        """The base backup's WAL stream reports what it flushed: under
        the standby's name `keel` the primary acknowledged commits that
        only the half-made copy held (found by the pair's
        network-namespace test, case (d))"""
        self.assertIsNone(dbpgseed.seed(self.root, SeedAction(),
                                        runner=self.runner,
                                        clock=self.clock))
        copy = " ".join(next(argv for argv in self.ran
                             if "pg_basebackup" in argv))
        self.assertIn("application_name=keel-seed", copy)
        self.assertNotIn(f"application_name={dbpostgres.SLOT} ", copy)

    def test_the_pair_streams_from_its_slot(self):
        action = SeedAction()
        action.slot = "keel"
        self.assertIsNone(dbpgseed.seed(self.root, action,
                                        runner=self.runner,
                                        clock=self.clock))
        follow = os.path.join(
            self.root, "etc/postgresql/17/main/conf.d",
            dbpostgres.FOLLOW_DROPIN_NAME)
        with open(follow) as fob:
            self.assertIn("primary_slot_name = 'keel'\n", fob.read())

    def test_the_copy_and_the_probe_carry_the_pair_tls(self):
        """Without the client certificate the primary's cert method
        refuses the replication connection (found by the pair's
        network-namespace test of this release)"""
        action = SeedAction(tls="sslmode=verify-full sslcert=/x/server.pem")
        self.assertIsNone(dbpgseed.seed(self.root, action,
                                        runner=self.runner,
                                        clock=self.clock))
        asked = " ".join(" ".join(str(a) for a in argv) for argv in self.ran)
        for keyword in ("sslmode=verify-full", "sslcert=/x/server.pem"):
            self.assertIn(keyword, asked)
        follow = os.path.join(
            self.root, "etc/postgresql/17/main/conf.d",
            dbpostgres.FOLLOW_DROPIN_NAME)
        with open(follow) as fob:
            self.assertIn("sslmode=verify-full", fob.read())

    def test_an_unreachable_primary_stops_before_anything_moves(self):
        def runner(argv, **kwargs):
            return answer("", 1, "no route")
        problem = dbpgseed.seed(self.root, SeedAction(), runner=runner,
                                clock=self.clock)
        self.assertIn("no route", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertTrue(os.path.isfile(os.path.join(
            self.datadir, "PG_VERSION")))
        self.assertEqual(self.commands(), [])

    def test_a_failed_basebackup_keeps_the_running_server(self):
        def runner(argv, **kwargs):
            if "pg_basebackup" in argv:
                return answer("", 1, "the primary closed the connection")
            return self.runner(argv, **kwargs)
        problem = dbpgseed.seed(self.root, SeedAction(), runner=runner,
                                clock=self.clock)
        self.assertIn("pg_basebackup", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertTrue(os.path.isfile(os.path.join(
            self.datadir, "PG_VERSION")))

    def test_a_swap_failure_restores_the_old_data_directory(self):
        def runner(argv, **kwargs):
            self.ran.append(list(argv))
            if "pg_basebackup" in argv:
                target = [a.split("=", 1)[1] for a in argv
                          if a.startswith("--pgdata=")][0]
                os.makedirs(target)
                return answer()
            if argv[:2] == ["systemctl", "start"]:
                return answer("", 1, "unit not found")
            return answer()
        # the follow drop-in cannot be written: conf.d replaced by a file
        confd = os.path.join(self.root, "etc/postgresql/17/main/conf.d")
        os.rmdir(confd)
        with open(confd, "w") as fob:
            fob.write("not a directory")
        problem = dbpgseed.seed(self.root, SeedAction(), runner=runner,
                                clock=self.clock)
        self.assertIn("standby files", problem)
        self.assertIn("the server is as it was", problem)
        self.assertTrue(os.path.isfile(os.path.join(
            self.datadir, "PG_VERSION")))
        self.assertFalse(os.path.isdir(self.datadir
                                       + dbpgseed.ASIDE_SUFFIX))
        self.assertIn(["systemctl", "start", "postgresql"], self.ran)

    def test_a_server_that_does_not_start_reports_the_copy_in_place(self):
        def runner(argv, **kwargs):
            if argv[:2] == ["systemctl", "start"]:
                return answer("", 1, "boom")
            return self.runner(argv, **kwargs)
        problem = dbpgseed.seed(self.root, SeedAction(), runner=runner,
                                clock=self.clock)
        self.assertIn("in place", problem)
        self.assertIn("boom", problem)
        self.assertFalse(os.path.isdir(self.datadir
                                       + dbpgseed.ASIDE_SUFFIX))

    def test_a_walreceiver_that_never_streams_is_reported(self):
        def runner(argv, **kwargs):
            if "--command" in argv and \
                    argv[argv.index("--command") + 1] == \
                    dbpgseed.STREAMING_QUESTION:
                return answer("\n")
            return self.runner(argv, **kwargs)

        def sleep(seconds):
            self.clock_at[0] += seconds

        problem = dbpgseed.seed(self.root, SeedAction(), runner=runner,
                                clock=self.clock, sleep=sleep)
        self.assertIn("walreceiver", problem)
        self.assertGreater(self.clock_at[0], 0)
        self.assertIn("in place", problem)

    def commands(self):
        found = []
        for argv in self.ran:
            if argv[:2] == ["systemctl", "stop"]:
                found.append("systemctl stop postgresql")
            elif argv[:2] == ["systemctl", "start"]:
                found.append("systemctl start postgresql")
            elif "pg_basebackup" in argv:
                found.append("pg_basebackup")
        return found


if __name__ == "__main__":
    unittest.main()
