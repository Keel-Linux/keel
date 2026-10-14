# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL promotion (keel.system.dbpgpromote), against fake
runners: no server, no clock but a fake one, no sleep but a counter"""

import subprocess
import unittest

from keel.system import dbpostgres, dbpgpromote


def answer(stdout: str = "", returncode: int = 0,
           stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout.encode(),
                                       stderr.encode())


class PromoteAction:
    """The PromoteReplica attributes dbpgpromote reads, without a plan"""

    def __init__(self, timeout=30):
        self.timeout = timeout


class TestLsn(unittest.TestCase):
    def test_the_pair_of_numbers_compares_in_order(self):
        self.assertLess(dbpgpromote.lsn("0/A"), dbpgpromote.lsn("0/1000"))
        self.assertEqual(dbpgpromote.lsn("1/0"), (1, 0))
        self.assertEqual(dbpgpromote.lsn("0/3A0F1C"), (0, 0x3A0F1C))

    def test_what_is_not_an_lsn_is_none(self):
        self.assertIsNone(dbpgpromote.lsn(""))
        self.assertIsNone(dbpgpromote.lsn("nothing"))
        self.assertIsNone(dbpgpromote.lsn("0/zz"))


class TestPromote(unittest.TestCase):
    def setUp(self):
        self.ran = []
        self.now = [0.0]
        self.slept = 0.0

    def clock(self):
        return self.now[0]

    def sleep(self, seconds):
        self.slept += seconds
        self.now[0] += seconds

    def runner(self, rows):
        rows = list(rows)

        def run(argv, **kwargs):
            self.ran.append(list(argv))
            if "text" in kwargs and kwargs["text"] is not None:
                return answer()
            row = rows.pop(0) if len(rows) > 1 else rows[0]
            return answer(row)
        return run

    def test_a_drained_standby_is_promoted_with_one_statement(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["t\t0/1000\t0/1000\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIsNone(problem)
        question = list(dbpostgres.CLIENT
                        + ("--command", dbpgpromote.POSITIONS))
        self.assertEqual(self.ran, [question, list(dbpostgres.CLIENT)])
        self.assertEqual(self.slept, 0.0)

    def test_a_standbehind_waits_until_replay_reaches_receive(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(timeout=10),
            runner=self.runner([
                "t\t0/A\t0/1000\n",
                "t\t0/500\t0/1000\n",
                "t\t0/1000\t0/1000\n",
            ]),
            clock=self.clock, sleep=self.sleep)
        self.assertIsNone(problem)
        self.assertEqual(self.slept, 2.0)

    def test_a_standby_that_receives_nothing_is_refused(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["t\t0/1000\t\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIn("receives nothing", problem)
        self.assertIn("Nothing was changed", problem)

    def test_a_standby_not_in_recovery_is_refused(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["f\t\t\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIn("not in recovery", problem)

    def test_a_drain_that_never_finishes_times_out_writing_nothing(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(timeout=5),
            runner=self.runner(["t\t0/A\t0/1000\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIn("did not replay everything", problem)
        self.assertIn("5 s", problem)
        question = list(dbpostgres.CLIENT
                        + ("--command", dbpgpromote.POSITIONS))
        self.assertEqual(self.ran, [question] * len(self.ran))

    def test_a_failed_question_changes_nothing(self):
        def run(argv, **kwargs):
            self.ran.append(list(argv))
            return answer("", 1, "the socket refused")
        problem = dbpgpromote.promote(
            "/", PromoteAction(), runner=run,
            clock=self.clock, sleep=self.sleep)
        self.assertIn("the socket refused", problem)
        self.assertIn("Nothing was changed", problem)

    def test_the_promote_statement_is_what_goes_last(self):
        sent = []

        def run(argv, **kwargs):
            sent.append(kwargs.get("input"))
            return answer("t\t0/1000\t0/1000\n")
        self.assertIsNone(dbpgpromote.promote(
            "/", PromoteAction(), runner=run,
            clock=self.clock, sleep=self.sleep))
        self.assertEqual(sent[-1],
                         dbpostgres.promote().text.encode())

    def test_unpadded_hex_never_says_drained_too_early(self):
        # text comparison would call 0/A >= 0/1000 drained; numbers do not
        problem = dbpgpromote.promote(
            "/", PromoteAction(timeout=2),
            runner=self.runner(["t\t0/A\t0/1000\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIn("did not replay everything", problem)


if __name__ == "__main__":
    unittest.main()
