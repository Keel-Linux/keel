# Copyright (c) 2026 KeelLinux maintainers
"""What keeps a replica read only, and what promoting one waits for

keel.system.dbreadonly runs the local client. It is replaced here at the
subprocess boundary by a runner that answers as MariaDB 11.8 did on the
bench, so nothing needs a server; the real run is in keel#55.
"""

import os
import subprocess
import tempfile
import unittest

from helpers import spec  # noqa: F401

from keel.system import dbreadonly
from keel.system.actions import LockReplica, PromoteReplica, UnlockAccounts
from keel.system.effects import Effects

BYPASS = (
    "'root'@'localhost'\n'mysql'@'localhost'\n'admin'@'localhost'\n"
    "'admin'@'::1'\n'root'@'%'\n'adminer'@'localhost'\n"
)
ACCOUNTS = (
    "root\tlocalhost\nadmin\tlocalhost\nadmin\t::1\nroot\t%\n"
    "adminer\tlocalhost\n"
)


def status(sql: str = "Yes", read: int = 900, executed: int = 900,
           read_file: str = "mariadb-bin.000002",
           executed_file: str = "mariadb-bin.000002",
           error: str = "", io: str | None = None) -> str:
    """SHOW REPLICA STATUS\\G as the server prints it, the fields read"""
    return (
        "*************************** 1. row ***************************\n"
        + (f"             Slave_IO_Running: {io}\n" if io else "")
        +
        f"              Master_Log_File: {read_file}\n"
        f"          Read_Master_Log_Pos: {read}\n"
        f"        Relay_Master_Log_File: {executed_file}\n"
        f"         Slave_SQL_Running: {sql}\n"
        f"          Exec_Master_Log_Pos: {executed}\n"
        f"               Last_SQL_Error: {error}\n"
    )


class Runner:
    """subprocess.run answering by what was asked, recording every call

    `answers` maps a key (see `key`) to a (code, stdout, stderr) triple
    or to a list of them, one per call, the last repeated.
    """

    def __init__(self, answers: dict | None = None):
        self.answers = {"bypass": (0, BYPASS, ""),
                        "accounts": (0, ACCOUNTS, "")}
        self.answers.update(answers or {})
        self.calls: list[tuple[str, str]] = []
        self.argv: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        stdin = kwargs.get("input") or ""
        key = self.key(argv, stdin)
        self.calls.append((key, stdin))
        self.argv.append(list(argv))
        answer = self.answers.get(key, (0, "", ""))
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        code, out, err = answer
        return subprocess.CompletedProcess(argv, code, out, err)

    @staticmethod
    def key(argv, stdin: str) -> str:
        asked = argv[-1] if "--execute" in argv else ""
        if "PROCESSLIST" in asked:
            return "stopping"
        if asked == "STOP SLAVE IO_THREAD":
            return "stop-io"
        if "READ_ONLY ADMIN" in asked:
            return "bypass"
        if "mysql.user" in asked:
            return "accounts"
        if "SHOW REPLICA STATUS" in asked:
            return "status"
        if "REVOKE" in stdin:
            return "revoke"
        if "GRANT" in stdin:
            return "grant"
        if "RESET SLAVE ALL" in stdin:
            return "promote"
        if "STOP SLAVE SQL_THREAD" in stdin:
            return "sql-stop"
        if "read_only = OFF" in stdin:
            return "writable"
        if "START SLAVE IO_THREAD" in stdin:
            return "resume"
        if "STOP SLAVE IO_THREAD" in stdin:
            return "stop-io"
        return "other"

    def keys(self) -> list[str]:
        return [key for key, _ in self.calls]

    def sent(self, key: str) -> str:
        return "".join(stdin for one, stdin in self.calls if one == key)


class Clock:
    """A clock that moves only when the code under test sleeps"""

    def __init__(self):
        self.now = 0.0
        self.slept = 0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += 1


class ReadOnlyTestCase(unittest.TestCase):
    def setUp(self):
        self.root = self.enterContext(tempfile.TemporaryDirectory())

    def record(self) -> str | None:
        path = os.path.join(self.root, dbreadonly.RECORD)
        if not os.path.exists(path):
            return None
        with open(path) as fob:
            return fob.read()

    def write_record(self, text: str) -> None:
        path = os.path.join(self.root, dbreadonly.RECORD)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)


class TestLock(ReadOnlyTestCase):
    """READ_ONLY ADMIN is taken from every account but the server's own

    The image's `admin` and Adminer's `adminer` hold ALL ON *.*, so
    Adminer on port 12322 could write to the replica through them.
    """

    def test_the_accounts_that_write_through_it_lose_the_privilege(self):
        runner = Runner()
        self.assertIsNone(dbreadonly.lock(self.root, runner))
        sent = runner.sent("revoke")
        self.assertIn(
            "REVOKE READ_ONLY ADMIN ON *.* FROM 'admin'@'localhost';", sent
        )
        self.assertIn("FROM 'admin'@'::1';", sent)
        self.assertIn("FROM 'adminer'@'localhost';", sent)

    def test_binary_logging_is_off_before_the_first_revoke(self):
        runner = Runner()
        dbreadonly.lock(self.root, runner)
        sent = runner.sent("revoke")
        self.assertTrue(sent.startswith("SET SESSION sql_log_bin = 0;\n"))

    def test_the_servers_own_socket_account_keeps_it_and_root_loses_it(self):
        """0049, second round, point 1: root loses READ_ONLY ADMIN on a
        replica too; 'mysql'@'localhost', which only the system's mysql
        user reaches, keeps it, and keel's statements go through it"""
        runner = Runner()
        dbreadonly.lock(self.root, runner)
        sent = runner.sent("revoke")
        self.assertIn("FROM 'root'@'localhost';", sent)
        self.assertNotIn("'mysql'@'localhost'", sent)
        self.assertEqual(runner.argv[0][:4], ["runuser", "-u", "mysql", "--"])

    def test_root_from_anywhere_is_not_the_servers_own(self):
        runner = Runner()
        dbreadonly.lock(self.root, runner)
        self.assertIn("FROM 'root'@'%';", runner.sent("revoke"))

    def test_what_was_taken_is_recorded_before_it_is_taken(self):
        runner = Runner({"revoke": (1, "", "ERROR 1045")})
        problem = dbreadonly.lock(self.root, runner)
        self.assertIn("ERROR 1045", problem)
        self.assertEqual(
            self.record(),
            "root\tlocalhost\nadmin\tlocalhost\nadmin\t::1\nroot\t%\n"
            "adminer\tlocalhost\n",
        )

    def test_an_earlier_record_is_kept_and_added_to(self):
        self.write_record("wp\tlocalhost\nadmin\tlocalhost\n")
        dbreadonly.lock(self.root, Runner())
        self.assertEqual(
            self.record(),
            "wp\tlocalhost\nadmin\tlocalhost\nroot\tlocalhost\nadmin\t::1\n"
            "root\t%\nadminer\tlocalhost\n",
        )

    def test_nothing_to_take_sends_nothing_and_records_nothing(self):
        runner = Runner({"bypass": (0, "'mysql'@'localhost'\n", "")})
        self.assertIsNone(dbreadonly.lock(self.root, runner))
        self.assertEqual(runner.keys(), ["bypass"])
        self.assertIsNone(self.record())

    def test_a_server_that_cannot_say_who_bypasses_it_is_an_error(self):
        runner = Runner({"bypass": (1, "", "ERROR 2002 no socket")})
        problem = dbreadonly.lock(self.root, runner)
        self.assertIn("ERROR 2002", problem)
        self.assertNotIn("revoke", runner.keys())

    def test_a_quote_in_an_account_name_is_escaped(self):
        runner = Runner({"bypass": (0, "'o'k'@'localhost'\n", "")})
        dbreadonly.lock(self.root, runner)
        self.assertIn("FROM 'o\\'k'@'localhost';", runner.sent("revoke"))

    def test_a_line_that_is_not_an_account_is_passed_over(self):
        runner = Runner({"bypass": (0, "garbage\n", "")})
        self.assertIsNone(dbreadonly.lock(self.root, runner))
        self.assertNotIn("revoke", runner.keys())


class TestUnlock(ReadOnlyTestCase):
    """Only what a replica took is given back, and only once"""

    def test_the_recorded_accounts_get_it_back_and_the_record_goes(self):
        self.write_record("admin\tlocalhost\nadminer\tlocalhost\n")
        runner = Runner()
        self.assertIsNone(dbreadonly.unlock(self.root, runner))
        sent = runner.sent("grant")
        self.assertTrue(sent.startswith("SET SESSION sql_log_bin = 0;\n"))
        self.assertIn(
            "GRANT READ_ONLY ADMIN ON *.* TO 'admin'@'localhost';", sent
        )
        self.assertIn("TO 'adminer'@'localhost';", sent)
        self.assertNotIn("'admin'@'::1'", sent)
        self.assertIsNone(self.record())

    def test_an_account_dropped_since_is_not_created_again(self):
        self.write_record("gone\tlocalhost\nadmin\tlocalhost\n")
        runner = Runner()
        dbreadonly.unlock(self.root, runner)
        self.assertNotIn("'gone'", runner.sent("grant"))

    def test_no_record_sends_nothing(self):
        runner = Runner()
        self.assertIsNone(dbreadonly.unlock(self.root, runner))
        self.assertEqual(runner.keys(), [])

    def test_a_record_of_accounts_all_gone_is_removed(self):
        self.write_record("gone\tlocalhost\n")
        runner = Runner()
        self.assertIsNone(dbreadonly.unlock(self.root, runner))
        self.assertNotIn("grant", runner.keys())
        self.assertIsNone(self.record())

    def test_a_failed_grant_keeps_the_record(self):
        self.write_record("admin\tlocalhost\n")
        runner = Runner({"grant": (1, "", "ERROR 1133")})
        self.assertIn("ERROR 1133", dbreadonly.unlock(self.root, runner))
        self.assertEqual(self.record(), "admin\tlocalhost\n")

    def test_accounts_that_cannot_be_listed_keep_the_record(self):
        self.write_record("admin\tlocalhost\n")
        runner = Runner({"accounts": (1, "", "ERROR 2002")})
        self.assertIn("ERROR 2002", dbreadonly.unlock(self.root, runner))
        self.assertEqual(self.record(), "admin\tlocalhost\n")


class TestPromote(ReadOnlyTestCase):
    """Nothing the replica received is thrown away by promoting it

    STOP SLAVE then RESET SLAVE ALL discards the relay log, and with it
    what the I/O thread received and the SQL thread had not applied yet.
    So the I/O thread stops first and the SQL thread drains, bounded.
    """

    def promote(self, runner: Runner, clock: Clock | None = None):
        clock = clock or Clock()
        return dbreadonly.promote(
            self.root, PromoteReplica(60), runner, clock, clock.sleep
        )

    def spawned(self, events: list[str], code: int = 0):
        """STOP SLAVE IO_THREAD in a client of its own that is still
        running (a primary that is gone) until it is waited for"""
        test = self

        class Stopping:
            returncode = None
            stderr = __import__("io").StringIO("ERROR 1198 stuck")

            def __init__(self, argv, **kwargs):
                test.assertEqual(argv[-1], "STOP SLAVE IO_THREAD")
                events.append("stop-io started")

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.returncode is None:
                    events.append("stop-io ended")
                    self.returncode = code
                return self.returncode
        return Stopping

    def recorded(self, runner: Runner, events: list[str]) -> Runner:
        real = runner.__call__

        def call(argv, **kwargs):
            done = real(argv, **kwargs)
            events.append(runner.calls[-1][0])
            return done
        runner.__call__ = call
        return runner

    def promote_spawned(self, answers: dict, code: int = 0):
        events: list[str] = []
        runner = Runner(answers)
        recording = self.recorded(runner, events)
        clock = Clock()
        problem = dbreadonly.promote(
            self.root, PromoteReplica(60), recording.__call__, clock,
            clock.sleep, self.spawned(events, code))
        return problem, events, runner

    def test_writes_do_not_wait_for_the_io_thread_to_end(self):
        """keel#118: the stop waits seconds for a dead primary (10 s
        connecting, 5 s for the semi-synchronous kill, measured on
        11.8), while the thread receives nothing from the moment the
        server shows the stop. So the server takes writes before the
        stop ends, and forgets the primary after"""
        problem, events, _ = self.promote_spawned({
            "status": (0, status(io="Connecting"), ""),
            "stopping": (0, "Killing slave\n", "")})
        self.assertIsNone(problem, events)
        self.assertEqual(events[:3], ["status", "stop-io started",
                                      "stopping"])
        self.assertNotIn("sql-stop", events)
        self.assertLess(events.index("writable"),
                        events.index("stop-io ended"))
        self.assertLess(events.index("writable"), events.index("promote"))

    def test_anything_received_after_the_drain_takes_the_old_order(self):
        """The safety review of keel#118: a thread that connects again
        (MASTER_CONNECT_RETRY 2) could receive; when the position moved
        after the drain, the stop is waited for, the SQL thread drains
        again, and only then does the server take writes"""
        problem, events, runner = self.promote_spawned({
            "status": [(0, status(io="Yes", read=900, executed=900), ""),
                       (0, status(io="Yes", read=900, executed=900), ""),
                       (0, status(io="Yes", read=950, executed=900), ""),
                       (0, status(io="No", read=950, executed=950), "")],
            "stopping": (0, "Killing slave\n", "")})
        self.assertIsNone(problem, events)
        self.assertNotIn("writable", events)
        self.assertLess(events.index("stop-io ended"),
                        events.index("promote"))
        self.assertEqual(runner.sent("promote"),
                         "STOP SLAVE;\nRESET SLAVE ALL;\n"
                         "SET GLOBAL read_only = OFF;\n")

    def test_a_stop_the_server_does_not_show_is_waited_for_first(self):
        problem, events, _ = self.promote_spawned({
            "status": (0, status(io="Connecting"), ""),
            "stopping": (0, "starting\n", "")})
        self.assertIsNone(problem, events)
        self.assertLess(events.index("stop-io ended"),
                        events.index("writable"))

    def test_a_stop_not_yet_killing_after_the_drain_takes_the_old_order(
            self):
        """The re-review of keel#118: INFO is set when the statement is
        dispatched, before the stop takes its lock; only the killing
        phase, before and after the drain, lets writes come first"""
        problem, events, runner = self.promote_spawned({
            "status": (0, status(io="Connecting"), ""),
            "stopping": [(0, "Killing slave\n", ""),
                         (0, "Waiting for the stop lock\n", "")]})
        self.assertIsNone(problem, events)
        self.assertNotIn("writable", events)
        self.assertLess(events.index("stop-io ended"),
                        events.index("promote"))
        self.assertEqual(runner.sent("promote"),
                         "STOP SLAVE;\nRESET SLAVE ALL;\n"
                         "SET GLOBAL read_only = OFF;\n")

    def test_a_stop_that_fails_promotes_nothing_and_resumes(self):
        problem, events, _ = self.promote_spawned({
            "status": (0, status(io="Connecting"), ""),
            "stopping": (0, "starting\n", "")}, code=1)
        self.assertIn("ERROR 1198 stuck", problem)
        self.assertIn("Nothing was promoted", problem)
        # the server may have taken the stop before its client died
        self.assertIn("The I/O thread was started again", problem)
        self.assertIn("resume", events)
        self.assertNotIn("writable", events)

    def test_failures_after_the_stop_are_said(self):
        for key, said in (("writable", "set read_only OFF"),):
            with self.subTest(key=key):
                problem, events, runner = self.promote_spawned({
                    "status": (0, status(io="Connecting"), ""),
                    "stopping": (0, "Killing slave\n", ""),
                    key: (1, "", "ERROR 1290")})
                self.assertIn("ERROR 1290", problem)
                self.assertIn(said, problem)
                self.assertIn("stop-io ended", events)
                self.assertNotIn("promote", events)
        problem, events, _ = self.promote_spawned({
            "status": (0, status(io="Connecting"), ""),
            "stopping": (0, "Killing slave\n", ""),
            "promote": (1, "", "ERROR 2013")})
        self.assertIn("takes writes", problem)
        self.assertIn("ERROR 2013", problem)

    def test_a_status_lost_after_the_sql_thread_stopped_takes_the_old_order(
            self):
        problem, events, runner = self.promote_spawned({
            "status": [(0, status(io="Connecting"), ""),
                       (0, status(io="Connecting"), ""),
                       (1, "", "ERROR 2013"),
                       (0, status(io="No"), "")],
            "stopping": (0, "Killing slave\n", "")})
        self.assertIsNone(problem, events)
        self.assertNotIn("writable", events)
        self.assertIn("promote", events)

    def test_a_client_that_cannot_start_the_stop(self):
        def broken(argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory")
        clock = Clock()
        problem = dbreadonly.promote(
            self.root, PromoteReplica(60), Runner({"status": (
                0, status(), "")}), clock, clock.sleep, broken)
        self.assertIn("cannot run runuser", problem)

    def test_the_io_thread_stops_before_anything_else(self):
        runner = Runner({"status": (0, status(), "")})
        self.assertIsNone(self.promote(runner))
        keys = runner.keys()
        self.assertEqual(keys[1], "stop-io")
        self.assertLess(keys.index("stop-io"), keys.index("writable"))
        self.assertLess(keys.index("writable"), keys.index("promote"))

    def test_it_waits_for_the_sql_thread_to_apply_the_backlog(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(read=900, executed=300), ""),
            (0, status(read=900, executed=600), ""),
            (0, status(read=900, executed=900), ""),
        ]})
        clock = Clock()
        self.assertIsNone(self.promote(runner, clock))
        self.assertEqual(clock.slept, 2)
        keys = runner.keys()
        # the drain's four, and one more after the SQL thread stopped
        self.assertEqual(keys.count("status"), 5)
        self.assertGreater(keys.index("writable"),
                           len(keys) - 1 - keys[::-1].index("status"))

    def test_a_backlog_in_an_older_binary_log_file_is_not_drained(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(executed_file="mariadb-bin.000001"), ""),
            (0, status(), ""),
        ]})
        clock = Clock()
        self.assertIsNone(self.promote(runner, clock))
        self.assertEqual(clock.slept, 1)

    def test_then_it_forgets_the_primary_and_takes_writes(self):
        runner = Runner({"status": (0, status(), "")})
        self.promote(runner)
        self.assertEqual(runner.sent("writable"),
                         "SET GLOBAL read_only = OFF;\n")
        self.assertEqual(
            runner.sent("promote"),
            "STOP SLAVE;\nRESET SLAVE ALL;\n",
        )

    def test_giving_the_privilege_back_is_not_its_business(self):
        """UnlockAccounts is its own action, planned after the drop-in
        loses read_only, so a failed GRANT cannot keep the file from
        being rewritten (keel.system.database)"""
        self.write_record("admin\tlocalhost\n")
        runner = Runner({"status": (0, status(), "")})
        self.assertIsNone(self.promote(runner))
        self.assertNotIn("grant", runner.keys())
        self.assertEqual(self.record(), "admin\tlocalhost\n")

    def test_a_stopped_sql_thread_is_refused_before_anything_changes(self):
        runner = Runner({"status": (0, status(
            sql="No", error="Duplicate entry '7' for key 'PRIMARY'"), "")})
        problem = self.promote(runner)
        self.assertIn("Duplicate entry '7'", problem)
        self.assertIn("Nothing was changed", problem)
        self.assertEqual(runner.keys(), ["status"])

    def test_an_sql_thread_that_stops_while_draining_resumes_the_io(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(sql="No", executed=300, error="Error 1062"), ""),
        ]})
        problem = self.promote(runner)
        self.assertIn("Error 1062", problem)
        self.assertIn("START SLAVE IO_THREAD", runner.sent("resume"))
        self.assertNotIn("promote", runner.keys())

    def test_a_backlog_that_does_not_drain_in_time_is_not_promoted(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(read=900, executed=300), ""),
        ]})
        problem = self.promote(runner)
        self.assertIn("did not apply", problem)
        self.assertIn("60 s", problem)
        self.assertIn("The I/O thread was started again", problem)
        self.assertIn("resume", runner.keys())
        self.assertNotIn("promote", runner.keys())

    def test_an_io_thread_that_does_not_start_again_is_said(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(read=900, executed=300), ""),
        ], "resume": (1, "", "ERROR 1201 no master info")})
        problem = self.promote(runner)
        self.assertIn("did not apply", problem)
        self.assertNotIn("was started again", problem)
        self.assertIn("ERROR 1201", problem)
        self.assertIn("START SLAVE IO_THREAD", problem)
        self.assertNotIn("promote", runner.keys())

    def test_an_io_thread_that_does_not_start_after_an_error_is_said(self):
        runner = Runner({"status": [
            (0, status(), ""),
            (0, status(sql="No", error="Error 1062"), ""),
        ], "resume": (1, "", "ERROR 1201")})
        problem = self.promote(runner)
        self.assertIn("Error 1062", problem)
        self.assertNotIn("was started again", problem)
        self.assertIn("ERROR 1201", problem)

    def test_a_status_that_cannot_be_read_is_refused(self):
        runner = Runner({"status": (1, "", "ERROR 2002")})
        self.assertIn("ERROR 2002", self.promote(runner))
        self.assertEqual(runner.keys(), ["status"])

    def test_a_status_lost_while_draining_resumes_the_io(self):
        runner = Runner({"status": [(0, status(), ""), (1, "", "ERROR 2013")]})
        self.assertIn("ERROR 2013", self.promote(runner))
        self.assertIn("resume", runner.keys())

    def test_a_node_that_replicates_from_nowhere_is_refused(self):
        runner = Runner({"status": (0, "", "")})
        self.assertIn("replicates from nowhere", self.promote(runner))
        self.assertEqual(runner.keys(), ["status"])

    def test_a_failure_to_stop_the_io_thread_changes_nothing(self):
        runner = Runner({"status": (0, status(), ""),
                         "stop-io": (1, "", "ERROR 1198")})
        self.assertIn("ERROR 1198", self.promote(runner))
        self.assertNotIn("promote", runner.keys())

    def test_a_failure_to_forget_the_primary_is_said(self):
        runner = Runner({"status": (0, status(), ""),
                         "promote": (1, "", "ERROR 1198")})
        self.assertIn("ERROR 1198", self.promote(runner))
        self.assertNotIn("grant", runner.keys())

    def test_a_client_that_cannot_run_is_an_error(self):
        def missing(argv, **kwargs):
            raise FileNotFoundError(2, "No such file or directory")
        problem = dbreadonly.promote(
            self.root, PromoteReplica(60), missing, Clock(), Clock().sleep
        )
        self.assertIn("cannot run runuser", problem)


class TestEffects(ReadOnlyTestCase):
    """The three actions reach this module through keel.system.effects"""

    def test_each_action_is_carried_out_here(self):
        calls = []
        for name in ("lock", "unlock", "promote"):
            setattr(self, name, getattr(dbreadonly, name))
        try:
            dbreadonly.lock = lambda root: calls.append("lock")
            dbreadonly.unlock = lambda root: calls.append("unlock")
            dbreadonly.promote = lambda root, action: calls.append("promote")
            effects = Effects(self.root)
            effects.apply(LockReplica(()))
            effects.apply(UnlockAccounts())
            effects.apply(PromoteReplica(60))
        finally:
            for name in ("lock", "unlock", "promote"):
                setattr(dbreadonly, name, getattr(self, name))
        self.assertEqual(calls, ["lock", "unlock", "promote"])

    def test_the_actions_say_what_they_do(self):
        self.assertIn("'admin'@'localhost'",
                      LockReplica(("'admin'@'localhost'",)).describe())
        self.assertIn(dbreadonly.RECORD, LockReplica(()).describe())
        self.assertIn("READ_ONLY ADMIN back", UnlockAccounts().describe())
        self.assertIn("wait up to 60 s", PromoteReplica(60).describe())
