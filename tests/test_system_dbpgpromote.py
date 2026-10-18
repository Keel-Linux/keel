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

    def test_the_client_s_answer_splits_on_the_tab(self):
        """psql pads its aligned default with spaces and a bar; the
        client asks for one tab between the columns, so the standby's
        row reads as a standby (found when the pair's cases (b) to (e)
        were built: every promote read "not in recovery")"""
        def psql(argv, **kwargs):
            self.ran.append(list(argv))
            if "text" in kwargs and kwargs["text"] is not None:
                return answer()
            if "--no-align" in argv and "--field-separator=\t" in argv:
                return answer("t\t0/1000\t0/1000\n")
            return answer(" t                 | 0/1000 | 0/1000\n")
        problem = dbpgpromote.promote(
            "/", PromoteAction(), runner=psql,
            clock=self.clock, sleep=self.sleep)
        self.assertIsNone(problem)
        self.assertIn("--tuples-only", dbpostgres.CLIENT)

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

    def test_a_fenced_standby_is_promoted_without_a_drain(self):
        """keel#152: a standby that follows nobody receives nothing and
        has nothing to drain; the caller decided that it may take
        writes (keel.system.dbpgfollow)"""
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["t\t0/1000\t\n"]),
            clock=self.clock, sleep=self.sleep, drain=False)
        self.assertIsNone(problem)
        self.assertEqual(self.ran[-1], list(dbpostgres.CLIENT))

    def test_without_a_drain_a_primary_is_still_refused(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["f\t\t\n"]),
            clock=self.clock, sleep=self.sleep, drain=False)
        self.assertIn("not in recovery", problem)

    def test_a_standby_not_in_recovery_is_refused(self):
        problem = dbpgpromote.promote(
            "/", PromoteAction(),
            runner=self.runner(["f\t\t\n"]),
            clock=self.clock, sleep=self.sleep)
        self.assertIn("not in recovery", problem)

    def test_a_drain_that_never_finishes_times_out_writing_nothing(self):
        """the positions move but never meet: replay creeps behind the
        stream, so the standby is not stalled and not drained"""
        creeping = [f"t\t0/{0x1000 + n:X}\t0/{0x9000 + n:X}\n"
                    for n in range(40)]
        problem = dbpgpromote.promote(
            "/", PromoteAction(timeout=5),
            runner=self.runner(creeping),
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


class TestIncompleteRecord(unittest.TestCase):
    """keel#215: the walreceiver flushes the bytes that arrived, and a cut
    can end the stream inside a record. Replay cannot apply the first
    bytes of a record, so it stands at the end of the last whole record
    and replay never reaches the received position. Measured on a real
    pair: received 0/7EC8000, replayed 0/7EC7A58 (1448 bytes, one TCP
    segment), both still for 417 s. pg_promote() replays every whole
    record that is in pg_wal before it ends recovery, so a standby whose
    two positions stand still needs no more wait."""

    def setUp(self):
        self.ran = []
        self.now = [0.0]
        self.slept = 0.0
        self.said = []

    def clock(self):
        return self.now[0]

    def sleep(self, seconds):
        self.slept += seconds
        self.now[0] += seconds

    def runner(self, rows):
        rows = list(rows)

        def run(argv, **kwargs):
            self.ran.append(list(argv))
            if kwargs.get("text") is not None:
                return answer()
            return answer(rows.pop(0) if len(rows) > 1 else rows[0])
        return run

    def promote(self, rows, timeout=600):
        return dbpgpromote.promote(
            "/", PromoteAction(timeout=timeout), runner=self.runner(rows),
            clock=self.clock, sleep=self.sleep, say=self.said.append)

    def test_positions_that_stand_still_are_promoted_after_the_stall(self):
        problem = self.promote(["t\t0/7EC7A58\t0/7EC8000\n"])
        self.assertIsNone(problem)
        self.assertEqual(self.slept, dbpgpromote.STALL_SECONDS)
        self.assertEqual(self.ran[-1], list(dbpostgres.CLIENT))
        self.assertEqual(len(self.said), 1)
        self.assertIn("1448 bytes", self.said[0])
        self.assertIn("incomplete record", self.said[0])

    def test_a_received_position_that_moves_starts_the_stall_again(self):
        moving = [f"t\t0/1000\t0/{0x2000 + n:X}\n" for n in range(8)]
        problem = self.promote(moving + ["t\t0/1000\t0/2007\n"])
        self.assertIsNone(problem)
        self.assertEqual(self.slept, 7 + dbpgpromote.STALL_SECONDS)

    def test_a_replay_position_that_moves_starts_the_stall_again(self):
        moving = [f"t\t0/{0x1000 + n:X}\t0/9000\n" for n in range(6)]
        problem = self.promote(moving + ["t\t0/1005\t0/9000\n"])
        self.assertIsNone(problem)
        self.assertEqual(self.slept, 5 + dbpgpromote.STALL_SECONDS)

    def test_a_stall_shorter_than_the_limit_is_not_enough(self):
        rows = ["t\t0/1000\t0/2000\n"] * 3 + ["t\t0/1001\t0/2000\n"]
        problem = self.promote(rows, timeout=4)
        self.assertIn("did not replay everything", problem)
        self.assertEqual(self.said, [])

    def test_a_drained_standby_says_nothing_about_a_record(self):
        self.assertIsNone(self.promote(["t\t0/1000\t0/1000\n"]))
        self.assertEqual(self.said, [])

    def test_the_stall_never_promotes_a_standby_that_receives_nothing(self):
        problem = self.promote(["t\t0/1000\t\n"])
        self.assertIn("receives nothing", problem)


if __name__ == "__main__":
    unittest.main()
