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
# The accounts of the primary: the application's own, the server's, the
# replication account and one the replica already holds.
PRIMARY_ACCOUNTS = (
    "wp\t%\tN\nroot\tlocalhost\tN\nmysql\tlocalhost\tN\n"
    "mariadb.sys\tlocalhost\tN\ndebian-sys-maint\tlocalhost\tN\n"
    "repl\tfd42:b2:0:1:%\tN\nwordpress\tlocalhost\tN\n\tlocalhost\tN\n"
)
# Host names compare without case, as MariaDB compares them; users do not.
REPLICA_ACCOUNTS = (
    "root\tlocalhost\tN\nmysql\tlocalhost\tN\nwordpress\tLOCALHOST\tN\n"
)
DEFINITIONS = (
    "keel:account\n"
    "CREATE USER `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B'\n"
    "GRANT USAGE ON *.* TO `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wp`@`%`\n"
    "keel:account\n"
    "CREATE USER `wordpress`@`localhost` IDENTIFIED BY PASSWORD '*P'\n"
    "GRANT USAGE ON *.* TO `wordpress`@`localhost` IDENTIFIED BY"
    " PASSWORD '*P'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wordpress`@`localhost`\n"
    "keel:account\n"
)
LOCAL_GRANTS = (
    "keel:account\n"
    "GRANT USAGE ON *.* TO `wordpress`@`localhost` IDENTIFIED BY"
    " PASSWORD '*R'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wordpress`@`localhost`\n"
)
ANSWERS = {
    "probe": GRANTED,
    "accounts": PRIMARY_ACCOUNTS,
    "local-accounts": REPLICA_ACCOUNTS,
    "definitions": DEFINITIONS,
    "local-grants": LOCAL_GRANTS,
}


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
        default = (0, ANSWERS.get(key, "").encode(), b"")
        answer = self.answers.get(key, default)
        if isinstance(answer, list):
            # One answer per call, the last one repeated.
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        code, out, err = answer
        if key == "dump" and not code:
            kwargs["stdout"].write(self.dump.encode())
            out = b""
        return subprocess.CompletedProcess(argv, code, out, err)

    @staticmethod
    def key(argv, stdin: str) -> str:
        if argv[0] == "mariadb-dump":
            return "dump"
        asked = argv[-1] if "--execute" in argv else ""
        if any(one.startswith("--defaults-") for one in argv):
            if "USER_PRIVILEGES" in asked:
                return "probe"
            if "mysql.user" in asked:
                return "accounts"
            return "definitions"
        if "mysql.user" in asked:
            return "local-accounts"
        if "SHOW GRANTS" in stdin:
            return "local-grants"
        if "Seed post" in stdin:
            return "load"
        if "sql_log_bin" in stdin:
            return "copy"
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
        os.makedirs(os.path.join(self.root, "var/lib/mysql"))

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
        # The accounts are read before the dump and again after it: the
        # copy is the first reading, and it is used only if nothing about
        # an account changed while the dump was taken.
        self.assertEqual(order, [
            "probe", "accounts", "definitions", "dump",
            "accounts", "definitions", "local-accounts", "local-grants",
            "stop", "load", "copy", "start",
        ])

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
        # as the server's mysql account (decision 0049), and outside the
        # binary log: a pair has one on both nodes, and the copy's rows
        # are the primary's transactions, not this node's
        self.assertEqual(load["argv"], [
            "runuser", "-u", "mysql", "--", "mariadb", "--batch",
            "--init-command=SET SESSION sql_log_bin=0"])
        self.assertIn("Seed post 1", load["stdin"])

    def test_the_declared_port_is_the_one_dialled(self):
        runner = Runner()
        self.seed(runner, port=3307)
        self.assertIn("port=3307", runner.named("dump")[0]["options"])
        self.assertIn("MASTER_PORT=3307", runner.named("start")[0]["stdin"])


class TestTheAccounts(SeedTestCase):
    """The primary's accounts come with the copy, or its first ALTER USER
    stops the replica: they live in the mysql schema, which the dump
    leaves out, and the binary log only carries later changes"""

    def test_the_applications_accounts_are_asked_for(self):
        runner = Runner()
        self.seed(runner)
        # Not root, mysql, mariadb.sys, debian-sys-maint or repl, which
        # are the server's and keel's own; not the anonymous account.
        asked = runner.named("definitions")[0]["stdin"]
        self.assertIn("SHOW CREATE USER 'wp'@'%'", asked)
        self.assertIn("SHOW CREATE USER 'wordpress'@'localhost'", asked)
        self.assertEqual(asked.count("SHOW CREATE USER"), 2)
        self.assertEqual(
            runner.named("local-grants")[0]["stdin"],
            "SELECT 'keel:account';\n"
            "SHOW GRANTS FOR 'wordpress'@'LOCALHOST';\n",
        )

    def test_an_account_made_while_the_dump_ran_is_refused(self):
        # Read after the dump, a CREATE USER in the gap was applied twice
        # and stopped the replica; read before, it was never applied.
        late = DEFINITIONS.replace(
            "keel:account\nCREATE USER `wordpress`",
            "keel:account\nCREATE USER `late`@`%`\n"
            "GRANT USAGE ON *.* TO `late`@`%`\n"
            "keel:account\nCREATE USER `wordpress`",
        )
        runner = Runner({
            "accounts": [
                (0, PRIMARY_ACCOUNTS.encode(), b""),
                (0, PRIMARY_ACCOUNTS.replace(
                    "wordpress\t", "late\t%\tN\nwordpress\t"
                ).encode(), b""),
            ],
            "definitions": [
                (0, DEFINITIONS.encode(), b""),
                (0, late.encode(), b""),
            ],
        })
        problem = self.seed(runner)
        self.assertIn("changed while", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertEqual(runner.named("stop"), [])

    def test_a_grant_changed_while_the_dump_ran_is_refused(self):
        runner = Runner({"definitions": [
            (0, DEFINITIONS.encode(), b""),
            (0, DEFINITIONS.replace("ALL PRIVILEGES", "SELECT").encode(),
             b""),
        ]})
        problem = self.seed(runner)
        self.assertIn("changed while", problem)
        self.assertEqual(runner.named("stop"), [])

    def test_a_second_reading_that_fails_drops_nothing(self):
        runner = Runner({"accounts": [
            (0, PRIMARY_ACCOUNTS.encode(), b""),
            (1, b"", b"ERROR 2013 lost connection"),
        ]})
        problem = self.seed(runner)
        self.assertIn("ERROR 2013", problem)
        self.assertEqual(runner.named("stop"), [])

    def test_local_grants_that_do_not_match_the_question_drop_nothing(self):
        runner = Runner({"local-grants": (0, b"", b"")})
        problem = self.seed(runner)
        self.assertIn("0 account(s)", problem)
        self.assertEqual(runner.named("stop"), [])

    def test_a_primary_with_roles_is_refused_before_the_dump(self):
        runner = Runner({"accounts": (
            0, (PRIMARY_ACCOUNTS + "editor\t\tY\n").encode(), b"",
        )})
        problem = self.seed(runner)
        self.assertIn("editor", problem)
        self.assertIn("roles", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertEqual(runner.named("dump"), [])

    def test_reach_refuses_roles_before_anything_is_written(self):
        runner = Runner({"accounts": (
            0, (PRIMARY_ACCOUNTS + "editor\t\tY\n").encode(), b"",
        )})
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("editor", found.problem)

    def test_a_held_account_with_other_grants_is_aligned(self):
        runner = Runner({"local-grants": (0, (
            LOCAL_GRANTS
            + "GRANT SELECT ON `other`.* TO `wordpress`@`localhost`\n"
        ).encode(), b"")})
        self.assertIsNone(self.seed(runner))
        copy = runner.named("copy")[0]["stdin"]
        self.assertIn("REVOKE ALL PRIVILEGES, GRANT OPTION FROM"
                      " 'wordpress'@'localhost';\n", copy)
        self.assertNotIn("CREATE USER `wordpress`", copy)
        self.assertNotIn("'*P'", copy)

    def test_they_are_created_outside_the_binary_log_before_it_starts(self):
        runner = Runner()
        self.seed(runner)
        copy = runner.named("copy")[0]["stdin"]
        self.assertTrue(copy.startswith("SET SESSION sql_log_bin = 0;\n"))
        self.assertIn(
            "CREATE USER `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B';\n", copy
        )
        self.assertIn(
            "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wp`@`%`;\n", copy
        )
        # Held with the same grants, under its own password: left alone.
        self.assertNotIn("`wordpress`@`localhost`", copy)

    def test_an_account_the_replica_holds_alike_is_left_as_it_is(self):
        runner = Runner({
            "local-accounts": (
                0, (REPLICA_ACCOUNTS + "wp\t%\tN\n").encode(), b"",
            ),
            "local-grants": (0, (
                LOCAL_GRANTS + "keel:account\n"
                "GRANT USAGE ON *.* TO `wp`@`%` IDENTIFIED BY PASSWORD 'x'\n"
                "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wp`@`%`\n"
            ).encode(), b""),
        })
        self.assertIsNone(self.seed(runner))
        self.assertEqual(runner.named("copy"), [])

    def test_a_primary_with_no_account_of_its_own_copies_none(self):
        runner = Runner({
            "accounts": (0, b"root\tlocalhost\tN\n", b""),
            "definitions": (0, b"keel:account\n", b""),
        })
        self.assertIsNone(self.seed(runner))
        self.assertEqual(runner.named("local-grants"), [])
        self.assertEqual(runner.named("copy"), [])

    def test_the_accounts_are_read_raw_and_without_names(self):
        runner = Runner()
        self.seed(runner)
        for key in ("accounts", "definitions", "local-accounts",
                    "local-grants"):
            argv = runner.named(key)[0]["argv"]
            self.assertIn("--raw", argv)
            self.assertIn("--skip-column-names", argv)

    def test_a_statement_that_is_not_an_account_is_refused(self):
        runner = Runner({"definitions": (
            0, DEFINITIONS.encode() + b"DROP DATABASE wordpress\n", b"",
        )})
        problem = self.seed(runner)
        self.assertIn("DROP DATABASE wordpress", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertEqual(runner.named("stop"), [])

    def test_accounts_that_cannot_be_read_drop_nothing(self):
        for key in ("accounts", "local-accounts", "definitions",
                    "local-grants"):
            runner = Runner({key: (1, b"", b"ERROR 1142 denied")})
            problem = self.seed(runner)
            self.assertIn("ERROR 1142 denied", problem)
            self.assertIn("nothing was dropped", problem)
            self.assertEqual(runner.named("stop"), [])

    def test_a_failed_copy_of_the_accounts_starts_nothing(self):
        runner = Runner({"copy": (1, b"", b"ERROR 1396")})
        problem = self.seed(runner)
        self.assertIn("ERROR 1396", problem)
        self.assertIn("--destroy-local-database", problem)
        self.assertEqual(runner.named("start"), [])


class TestDiskSpace(SeedTestCase):
    def test_too_little_room_for_the_copy_drops_nothing(self):
        small = os.statvfs_result((4096, 4096, 10, 0, 0, 10, 1, 1, 0, 255))
        runner = Runner()
        with mock.patch.object(dbseed.os, "statvfs", return_value=small):
            problem = self.seed(runner)
        self.assertIn("free", problem)
        self.assertIn("nothing was dropped", problem)
        self.assertEqual(runner.named("stop"), [])
        self.assertEqual(self.leftovers(), [])

    def test_the_room_is_measured_where_the_server_keeps_its_data(self):
        runner = Runner()
        real = os.statvfs
        with mock.patch.object(dbseed.os, "statvfs",
                               side_effect=real) as measured:
            self.assertIsNone(self.seed(runner))
        self.assertEqual(measured.call_args[0][0],
                         os.path.join(self.root, "var/lib/mysql"))

    def test_no_data_directory_is_reported(self):
        os.rmdir(os.path.join(self.root, "var/lib/mysql"))
        problem = self.seed(Runner())
        self.assertIn("var/lib/mysql", problem)
        self.assertIn("nothing was dropped", problem)


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
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertEqual(found.problem, "")
        self.assertIn("CURRENT_USER()", runner.calls[0]["argv"][-1])
        self.assertEqual(self.leftovers(), [])

    def test_the_accounts_both_hold_are_named(self):
        # Their authentication stays the replica's, until the primary's
        # next ALTER USER of them replicates.
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, Runner())
        self.assertEqual(found.shared, ("'wordpress'@'LOCALHOST'",))

    def test_accounts_this_server_cannot_list_are_a_reason(self):
        runner = Runner({"local-accounts": (1, b"", b"ERROR 1045")})
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("ERROR 1045", found.problem)

    def test_an_unreachable_primary_says_why(self):
        runner = Runner({"probe": (1, b"", b"ERROR 2002 (HY000): refused")})
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("did not answer", found.problem)
        self.assertIn("refused", found.problem)
        self.assertEqual(found.shared, ())

    def test_a_failure_with_nothing_on_stderr_names_the_code(self):
        runner = Runner({"probe": (1, b"", b"")})
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, runner)
        self.assertIn("exited 1", found.problem)

    def test_no_private_directory_is_a_reason_too(self):
        os.rmdir(os.path.join(self.root, "var/tmp"))
        found = dbseed.reach(self.root, HOST, 3306, PASSWORD, Runner())
        self.assertIn("No such file or directory", found.problem)


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
