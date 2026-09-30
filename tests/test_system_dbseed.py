# Copyright (c) 2026 KeelLinux maintainers
"""Seeding a new replica with a copy of its primary

keel.system.dbseed is the part of the replica step that talks to another
machine. The commands are replaced at the subprocess boundary by a runner
that records what it was given and answers as the measured client did, so
nothing here needs a server; the real run is in the pull request that
brought it (two containers, WordPress on the primary).
"""

import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from helpers import spec  # noqa: F401

from keel.system import dbseed
from keel.system.actions import SeedReplica
from keel.system.effects import Effects

HOST = "fd42:b2:0:1:2c2d:1cff:feeb:8756"
PASSWORD = 'pa"ss\\word#1 x'
POSITION = "0-1112879276-117"
GRANTED = "SELECT\nREPLICATION SLAVE\nSHOW VIEW\nEVENT\nTRIGGER\n"
DUMP = (
    "-- MariaDB dump 10.19-11.8.6-MariaDB, for debian-linux-gnu (x86_64)\n"
    "-- CHANGE MASTER TO MASTER_USE_GTID=slave_pos;\n"
    "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `wordpress`;\n"
    "INSERT INTO `wp_posts` VALUES (4,'Seed post 1');\n"
    "-- The deferred gtid setting for slave corresponding to the"
    " master-data CHANGE-MASTER follows\n"
    "-- Preferably use GTID to start replication from GTID position:\n"
    f"-- SET GLOBAL gtid_slave_pos='{POSITION}';\n"
    "-- Dump completed on 2026-09-30 10:00:00\n"
)


class Runner:
    """subprocess.run as the client answered it, recording every call

    `answers` maps the program and, for the local client, what it was fed
    to a (code, stdout, stderr) triple; a missing entry succeeds silently.
    The options file is read while the command runs, which is the only
    moment it exists.
    """

    def __init__(self, answers: dict | None = None, dump: str = DUMP):
        self.answers = answers or {}
        self.dump = dump
        self.calls: list[dict] = []

    def __call__(self, argv, **kwargs):
        options = [one for one in argv if one.startswith("--defaults-")]
        call = {"argv": list(argv), "kwargs": kwargs, "options": ""}
        if options:
            path = options[0].split("=", 1)[1]
            call["options"] = open(path).read()
            call["mode"] = stat.S_IMODE(os.stat(path).st_mode)
            call["directory_mode"] = stat.S_IMODE(
                os.stat(os.path.dirname(path)).st_mode
            )
        stdin = kwargs.get("stdin")
        if stdin is not None:
            call["stdin"] = stdin.read().decode()
        elif kwargs.get("input") is not None:
            call["stdin"] = kwargs["input"].decode()
        self.calls.append(call)
        key = self.key(argv, call.get("stdin", ""))
        code, out, err = self.answers.get(key, (0, b"", b""))
        if key == "probe" and not code and not out:
            out = GRANTED.encode()
        if key == "dump" and not code:
            kwargs["stdout"].write(self.dump.encode())
            out = b""
        return subprocess.CompletedProcess(argv, code, out, err)

    @staticmethod
    def key(argv, stdin: str) -> str:
        if argv[0] == "mariadb-dump":
            return "dump"
        if any(one.startswith("--defaults-") for one in argv):
            return "probe"
        if "Seed post" in stdin:
            return "load"
        if "CHANGE MASTER" in stdin:
            return "start"
        return "stop"

    def named(self, key: str) -> list[dict]:
        return [one for one in self.calls
                if self.key(one["argv"], one.get("stdin", "")) == key]


class SeedTestCase(unittest.TestCase):
    def setUp(self):
        self.root = self.enterContext(tempfile.TemporaryDirectory())
        os.makedirs(os.path.join(self.root, "var/tmp"))

    def seed(self, runner, drop=("wordpress",), port=3306):
        action = SeedReplica(HOST, port, PASSWORD, tuple(drop))
        return dbseed.seed(self.root, action, runner)

    def leftovers(self) -> list[str]:
        return os.listdir(os.path.join(self.root, "var/tmp"))


class TestTheCopy(SeedTestCase):
    def test_a_reachable_primary_is_copied_then_replicated_from(self):
        runner = Runner()
        self.assertIsNone(self.seed(runner))
        order = [Runner.key(one["argv"], one.get("stdin", ""))
                 for one in runner.calls]
        self.assertEqual(order, ["probe", "dump", "stop", "load", "start"])

    def test_the_dump_is_one_consistent_snapshot_with_its_gtid(self):
        runner = Runner()
        self.seed(runner)
        argv = runner.named("dump")[0]["argv"]
        for option in ("--single-transaction", "--gtid", "--master-data=2",
                       "--all-databases", "--ignore-database=mysql",
                       "--ignore-database=sys", "--routines", "--events",
                       "--triggers"):
            self.assertIn(option, argv)
        # mariadb-dump 11.8 refuses the run over an option it lacks.
        self.assertNotIn("--connect-timeout=10", argv)

    def test_replication_starts_at_the_position_of_the_dump(self):
        runner = Runner()
        self.seed(runner)
        start = runner.named("start")[0]["stdin"]
        self.assertIn(f"SET GLOBAL gtid_slave_pos = '{POSITION}'", start)
        self.assertIn("MASTER_USE_GTID=slave_pos", start)
        self.assertIn(f"MASTER_HOST='{HOST}'", start)
        self.assertLess(start.index("gtid_slave_pos"),
                        start.index("START SLAVE"))

    def test_local_data_is_dropped_only_after_the_copy_is_in_hand(self):
        runner = Runner()
        self.seed(runner)
        stop = runner.named("stop")[0]["stdin"]
        self.assertIn("STOP SLAVE", stop)
        self.assertIn("RESET SLAVE ALL", stop)
        self.assertIn("DROP DATABASE IF EXISTS `wordpress`", stop)

    def test_nothing_is_dropped_when_nothing_was_held(self):
        runner = Runner()
        self.seed(runner, drop=())
        self.assertNotIn("DROP DATABASE", runner.named("stop")[0]["stdin"])

    def test_the_copy_is_loaded_from_the_file_through_the_local_client(self):
        runner = Runner()
        self.seed(runner)
        load = runner.named("load")[0]
        self.assertEqual(load["argv"], ["mariadb", "--batch"])
        self.assertIn("Seed post 1", load["stdin"])

    def test_the_declared_port_is_the_one_dialled(self):
        runner = Runner()
        self.seed(runner, port=3307)
        self.assertIn("port=3307", runner.named("dump")[0]["options"])
        self.assertIn("MASTER_PORT=3307", runner.named("start")[0]["stdin"])


class TestNoSecretInArgvOrLogs(SeedTestCase):
    def test_the_password_is_in_an_options_file_and_never_in_argv(self):
        runner = Runner()
        self.seed(runner)
        for call in runner.calls:
            self.assertNotIn(PASSWORD, " ".join(call["argv"]))
        self.assertIn("user=repl", runner.named("dump")[0]["options"])

    def test_the_options_file_is_private_and_removed_afterwards(self):
        runner = Runner()
        self.seed(runner)
        for call in runner.named("probe") + runner.named("dump"):
            self.assertEqual(call["mode"], 0o600)
            self.assertEqual(call["directory_mode"], 0o700)
        self.assertEqual(self.leftovers(), [])

    def test_the_options_file_comes_first_as_the_client_requires(self):
        runner = Runner()
        self.seed(runner)
        for call in runner.named("probe") + runner.named("dump"):
            self.assertTrue(call["argv"][1].startswith(
                "--defaults-extra-file="
            ))

    def test_the_description_of_the_action_holds_no_password(self):
        action = SeedReplica(HOST, 3306, PASSWORD, ("wordpress",))
        self.assertNotIn(PASSWORD, action.describe())
        self.assertNotIn(PASSWORD, repr(action))
        self.assertIn("wordpress", action.describe())

    def test_a_failure_reports_the_client_and_not_the_statements(self):
        runner = Runner({"start": (1, b"", b"ERROR 1198 (HY000): no")})
        problem = self.seed(runner)
        self.assertIn("ERROR 1198", problem)
        self.assertNotIn(PASSWORD, problem)
        self.assertEqual(self.leftovers(), [])


class TestItRefusesBeforeDroppingAnything(SeedTestCase):
    def assert_nothing_dropped(self, runner, problem):
        self.assertIn("nothing was dropped", problem)
        self.assertEqual(runner.named("stop"), [])
        self.assertEqual(runner.named("start"), [])
        self.assertEqual(self.leftovers(), [])

    def test_an_unreachable_primary_is_named_and_nothing_is_dropped(self):
        runner = Runner({"probe": (
            1, b"", b"ERROR 2002 (HY000): Can't connect to server",
        )})
        problem = self.seed(runner)
        self.assertIn(f"[{HOST}]:3306", problem)
        self.assertIn("Can't connect", problem)
        self.assertEqual(runner.named("dump"), [])
        self.assert_nothing_dropped(runner, problem)

    def test_a_primary_that_grants_replication_alone_is_named(self):
        runner = Runner({"probe": (0, b"REPLICATION SLAVE\n", b"")})
        problem = self.seed(runner)
        self.assertIn("SELECT, SHOW VIEW, TRIGGER, EVENT", problem)
        self.assertIn("on the primary", problem)
        self.assert_nothing_dropped(runner, problem)

    def test_a_failed_dump_drops_nothing(self):
        runner = Runner({"dump": (2, b"", b"Got error: 1044")})
        problem = self.seed(runner)
        self.assertIn("1044", problem)
        self.assert_nothing_dropped(runner, problem)

    def test_a_dump_with_no_gtid_position_drops_nothing(self):
        runner = Runner(dump="CREATE DATABASE `wordpress`;\n")
        problem = self.seed(runner)
        self.assertIn("no GTID position", problem)
        self.assert_nothing_dropped(runner, problem)

    def test_a_missing_client_is_reported(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory")
        problem = self.seed(missing)
        self.assertIn("cannot run mariadb", problem)
        self.assertEqual(self.leftovers(), [])

    def test_no_private_directory_is_reported_and_not_raised(self):
        os.rmdir(os.path.join(self.root, "var/tmp"))
        problem = self.seed(Runner())
        self.assertIn("No such file or directory", problem)


class TestAfterTheDrop(SeedTestCase):
    def test_a_failed_stop_says_what_was_left(self):
        runner = Runner({"stop": (1, b"", b"ERROR 1008")})
        problem = self.seed(runner)
        self.assertIn("ERROR 1008", problem)
        self.assertEqual(runner.named("load"), [])

    def test_a_failed_load_says_the_copy_is_incomplete(self):
        runner = Runner({"load": (1, b"", b"ERROR 1064 at line 3")})
        problem = self.seed(runner)
        self.assertIn("incomplete", problem)
        self.assertIn("--destroy-local-database", problem)
        self.assertEqual(runner.named("start"), [])
        self.assertEqual(self.leftovers(), [])


class TestReach(SeedTestCase):
    def test_a_primary_granting_the_copy_is_reachable(self):
        runner = Runner()
        self.assertEqual(
            dbseed.reach(self.root, HOST, 3306, PASSWORD, runner), ""
        )
        self.assertIn("CURRENT_USER()", runner.calls[0]["argv"][-1])
        self.assertEqual(self.leftovers(), [])

    def test_an_unreachable_primary_says_why(self):
        runner = Runner({"probe": (1, b"", b"ERROR 2002 (HY000): refused")})
        problem = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("did not answer", problem)
        self.assertIn("refused", problem)

    def test_a_failure_with_nothing_on_stderr_names_the_code(self):
        runner = Runner({"probe": (1, b"", b"")})
        problem = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("exited 1", problem)

    def test_no_private_directory_is_a_reason_too(self):
        os.rmdir(os.path.join(self.root, "var/tmp"))
        problem = dbseed.reach(self.root, HOST, 3306, PASSWORD, Runner())
        self.assertIn("No such file or directory", problem)


class TestPureParts(unittest.TestCase):
    def test_an_option_value_is_quoted_and_escaped(self):
        self.assertEqual(dbseed.option_value('a"b\\c#d'),
                         '"a\\"b\\\\c#d"')
        self.assertEqual(dbseed.option_value("x\ny\tz\r"),
                         '"x\\ny\\tz\\r"')

    def test_the_options_file_names_the_account_and_the_endpoint(self):
        text = dbseed.options_text(HOST, 3306, "pw")
        self.assertEqual(text, (
            "[client]\nuser=repl\npassword=\"pw\"\n"
            f"host=\"{HOST}\"\nport=3306\n"
        ))

    def test_the_last_gtid_line_of_the_dump_is_the_position(self):
        self.assertEqual(dbseed.gtid_position(DUMP), POSITION)

    def test_a_multi_domain_position_is_kept_whole(self):
        text = "-- SET GLOBAL gtid_slave_pos='0-1-5,1-2-9';\n"
        self.assertEqual(dbseed.gtid_position(text), "0-1-5,1-2-9")

    def test_an_empty_position_is_a_primary_that_logged_nothing_yet(self):
        text = "-- SET GLOBAL gtid_slave_pos='';\n"
        self.assertEqual(dbseed.gtid_position(text), "")

    def test_no_line_or_a_malformed_one_is_no_position(self):
        self.assertIsNone(dbseed.gtid_position("nothing here\n"))
        self.assertIsNone(dbseed.gtid_position(
            "-- SET GLOBAL gtid_slave_pos='0-1-5'; DROP x';\n"
        ))

    def test_missing_privileges_are_named_in_a_fixed_order(self):
        self.assertEqual(
            dbseed.missing_privileges("REPLICATION SLAVE\nEVENT\n"),
            ["SELECT", "SHOW VIEW", "TRIGGER"],
        )
        self.assertEqual(dbseed.missing_privileges(GRANTED), [])


class TestTheEffect(SeedTestCase):
    def test_effects_hand_the_action_to_the_seeding_module(self):
        action = SeedReplica(HOST, 3306, PASSWORD, ())
        effects = Effects(self.root)
        with mock.patch.object(dbseed, "seed",
                               return_value="it failed") as seed:
            problem = effects.apply(action)
        self.assertEqual(problem, "it failed")
        seed.assert_called_once_with(effects.tree.root, action)


if __name__ == "__main__":
    unittest.main()
