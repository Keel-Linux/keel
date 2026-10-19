# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL promotion (keel.system.dbpgpromote), against fake
runners: no server, no clock but a fake one, no sleep but a counter"""

import subprocess
import unittest
from unittest import mock

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
            "/", PromoteAction(timeout=1),
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
        same = int(dbpgpromote.STALL_SECONDS)
        rows = ["t\t0/1000\t0/2000\n"] * same + ["t\t0/1001\t0/2000\n"]
        problem = self.promote(rows, timeout=same + 1)
        self.assertIn("did not replay everything", problem)
        self.assertEqual(self.said, [])

    def test_a_drained_standby_says_nothing_about_a_record(self):
        self.assertIsNone(self.promote(["t\t0/1000\t0/1000\n"]))
        self.assertEqual(self.said, [])

    def test_the_stall_never_promotes_a_standby_that_receives_nothing(self):
        problem = self.promote(["t\t0/1000\t\n"])
        self.assertIn("receives nothing", problem)


class TestTheStallNeverEndsWhileReplayMoves(unittest.TestCase):
    """The coordinator's condition for a stall shorter than 5 s: the drain
    ends by stall only when replay stood still for the whole stall. Replay
    is local, so the received position is the one that can stall for a
    reason of the network, and a stall of the received position alone
    never ends the drain. Each test runs with the limits of 5 s and 2 s."""

    LIMITS = (5.0, 2.0)

    def run_drain(self, rows, limit, timeout=600):
        """Run promote over `rows`, one row a poll; the rows' last one
        repeats. Returns (problem, the rows that were read, the times)"""
        read, times = [], []
        now = [0.0]

        def clock():
            return now[0]

        def sleep(seconds):
            now[0] += seconds
        pending = list(rows)

        def run(argv, **kwargs):
            if kwargs.get("input") is not None:  # the promote statement
                return answer()
            row = pending.pop(0) if len(pending) > 1 else pending[0]
            read.append(row)
            times.append(now[0])
            return answer(row)
        with mock.patch.object(dbpgpromote, "STALL_SECONDS", limit):
            problem = dbpgpromote.promote(
                "/", PromoteAction(timeout=timeout), runner=run,
                clock=clock, sleep=sleep, say=lambda line: None)
        return problem, read, times

    @staticmethod
    def row(replayed, received):
        return f"t\t0/{replayed:X}\t0/{received:X}\n"

    def test_a_received_position_that_stands_still_does_not_end_the_drain_while_replay_moves(self):
        for limit in self.LIMITS:
            with self.subTest(limit=limit):
                rows = [self.row(0x1000 + n * 8, 0x9000)
                        for n in range(200)]
                problem, read, _times = self.run_drain(rows, limit,
                                                       timeout=150)
                self.assertIn("did not replay everything", problem)
                self.assertEqual(len(read), 151)

    def test_replay_that_moves_within_every_stall_never_ends_it(self):
        for limit in self.LIMITS:
            with self.subTest(limit=limit):
                # one step every second poll: the quiet time is 1 s
                rows = []
                for n in range(100):
                    rows += [self.row(0x1000 + n * 8, 0x9000)] * 2
                problem, _read, _times = self.run_drain(rows, limit,
                                                        timeout=120)
                self.assertIn("did not replay everything", problem)

    def test_replay_that_stands_still_for_the_whole_stall_ends_it(self):
        for limit in self.LIMITS:
            with self.subTest(limit=limit):
                rows = [self.row(0x1000 + n * 8, 0x9000)
                        for n in range(10)]
                rows += [self.row(0x1000 + 9 * 8, 0x9000)]
                problem, _read, times = self.run_drain(rows, limit)
                self.assertIsNone(problem)
                self.assertEqual(times[-1] - 9, limit)

    def test_random_polls_never_end_the_drain_inside_a_moving_window(self):
        """seeded random positions: whenever the drain ends with replay
        behind the received position, both positions stood still for the
        whole stall before, and replay moved never in that window"""
        import random
        for limit in self.LIMITS:
            for seed in range(300):
                rng = random.Random(seed)
                replayed, received = 0x1000, 0x1000
                rows = []
                for _ in range(80):
                    if rng.random() < 0.5:
                        received += rng.choice((0, 0, 8, 64, 1448))
                    if rng.random() < 0.5 and replayed < received:
                        replayed = min(received,
                                       replayed + rng.choice((8, 64, 700)))
                    rows.append(self.row(replayed, received))
                problem, read, times = self.run_drain(rows, limit,
                                                      timeout=79)
                if problem is not None:
                    continue
                last = read[-1]
                behind = last.split("\t")[1] != last.split("\t")[2].strip()
                if not behind:
                    continue
                window = [row for row, at in zip(read, times)
                          if at >= times[-1] - limit]
                self.assertEqual(
                    len(set(window)), 1,
                    f"limit {limit} seed {seed}: the drain ended with the"
                    f" positions moving: {window}")
                self.assertGreaterEqual(times[-1] - times[0], limit)


if __name__ == "__main__":
    unittest.main()
