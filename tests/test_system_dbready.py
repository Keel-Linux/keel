# Copyright (c) 2026 KeelLinux maintainers
"""The database server apply converges is up before it is asked anything

Measured on a first boot (Template B3, node b3-a, and again in a container
built from Template B2): inithooks.service is not ordered after
mariadb.service, so the hook 10keel-system asked the server what it was
while it was still starting, was refused, and left server_id = 1 until an
operator ran apply a second time. keel.system.dbready waits for a server
that is starting, starts one that is stopped when the run may change the
machine, and says why when it gives up, within a bound.
"""

import subprocess
import unittest
from unittest import mock

from helpers import spec  # noqa: F401

from keel.system import dbmariadb, dbready

PING = dbmariadb.PING
START = ("systemctl", "start", "mariadb")
IS_ACTIVE = ("systemctl", "is-active", "mariadb")
REFUSED = (
    "ERROR 2002 (HY000): Can't connect to local server through socket"
    " '/run/mysqld/mysqld.sock' (2)\n"
)


def done(code: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class Machine:
    """A server that answers after `pings` failed attempts

    `units` are what `systemctl is-active` prints, one per call, the last
    repeated. `start` is what `systemctl start` does: a CompletedProcess,
    or an exception to raise.
    """

    def __init__(self, pings: int = 0, units=("active",), start=None):
        self.pings = pings
        self.units = list(units)
        self.start = start if start is not None else done()
        self.calls: list[tuple] = []
        self.kwargs: list[dict] = []

    def __call__(self, argv, **kwargs):
        argv = tuple(argv)
        self.calls.append(argv)
        self.kwargs.append(kwargs)
        if argv == PING:
            if self.pings:
                self.pings -= 1
                return done(1, stderr=REFUSED)
            return done(0, "1\n")
        if argv == IS_ACTIVE:
            unit = self.units.pop(0) if len(self.units) > 1 else self.units[0]
            return done(0 if unit == "active" else 3, unit + "\n")
        if argv == START:
            if isinstance(self.start, BaseException):
                raise self.start
            return self.start
        raise AssertionError(f"unexpected command {argv}")


class Clock:
    """time.monotonic and time.sleep, where sleeping moves the clock"""

    def __init__(self):
        self.now = 1000.0
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += seconds


def ready(machine: Machine, start: bool, timeout: int = 300):
    clock = Clock()
    with mock.patch.object(subprocess, "run", side_effect=machine), \
            mock.patch.object(dbready.time, "monotonic", clock.monotonic), \
            mock.patch.object(dbready.time, "sleep", clock.sleep):
        problem = dbready.ready("mariadb", PING, start, timeout)
    return problem, clock


class TestTheQuestion(unittest.TestCase):
    def test_it_is_the_cheapest_one_the_client_can_put(self):
        self.assertEqual(PING, (
            "mariadb", "--batch", "--skip-column-names",
            "--execute", "SELECT 1",
        ))


class TestARunningServerCostsOneQuestion(unittest.TestCase):
    def test_a_server_that_answers_is_neither_started_nor_waited_for(self):
        machine = Machine()
        problem, clock = ready(machine, start=True)
        self.assertEqual(problem, "")
        self.assertEqual(machine.calls, [PING])
        self.assertEqual(clock.slept, 0)

    def test_the_question_is_asked_with_a_bound_of_its_own(self):
        # A client that hangs on a wedged server must not hang apply.
        machine = Machine()
        ready(machine, start=True)
        self.assertEqual(machine.kwargs[0]["timeout"], dbready.ASK_TIMEOUT)


class TestAServerThatIsStartingIsWaitedFor(unittest.TestCase):
    """The first boot race: mariadb.service activating beside inithooks"""

    def test_a_run_that_may_change_the_machine_joins_the_start(self):
        # systemctl start on a unit that is activating waits for the job
        # already queued, which is exactly the wait that was missing.
        machine = Machine(pings=1, units=("active",))
        problem, _ = ready(machine, start=True)
        self.assertEqual(problem, "")
        self.assertEqual(machine.calls, [PING, START, PING])

    def test_the_start_is_bounded_by_the_timeout(self):
        machine = Machine(pings=1)
        ready(machine, start=True, timeout=42)
        self.assertEqual(machine.kwargs[1]["timeout"], 42)

    def test_a_dry_run_waits_while_the_unit_is_activating_and_starts_none(
        self,
    ):
        machine = Machine(pings=2, units=("activating", "activating",
                                          "active"))
        problem, clock = ready(machine, start=False)
        self.assertEqual(problem, "")
        self.assertNotIn(START, machine.calls)
        self.assertEqual(machine.calls.count(PING), 3)
        self.assertEqual(clock.slept, 2 * dbready.POLL_INTERVAL)

    def test_the_socket_may_come_a_moment_after_the_unit_is_active(self):
        # Type=notify says ready before the client is let in, rarely, and
        # a unit that went on activating a poll later is still waited for.
        machine = Machine(pings=2, units=("activating", "active"))
        problem, _ = ready(machine, start=True)
        self.assertEqual(problem, "")


class TestAServerThatIsStoppedIsStartedOrNamed(unittest.TestCase):
    def test_a_stopped_server_is_started_when_the_run_may_change_things(
        self,
    ):
        machine = Machine(pings=1)
        problem, _ = ready(machine, start=True)
        self.assertEqual(problem, "")
        self.assertIn(START, machine.calls)

    def test_a_dry_run_does_not_start_a_stopped_server_and_says_so(self):
        machine = Machine(pings=1, units=("inactive",))
        problem, clock = ready(machine, start=False)
        self.assertNotIn(START, machine.calls)
        self.assertIn("mariadb is inactive", problem)
        self.assertIn("a dry run does not start it", problem)
        self.assertIn("Can't connect to local server", problem)
        self.assertEqual(clock.slept, 0)


class TestGivingUpIsBoundedAndSaysWhy(unittest.TestCase):
    def test_a_start_that_fails_is_the_reason(self):
        machine = Machine(pings=1, start=done(
            1, stderr="Job for mariadb.service failed.\n"
        ))
        problem, _ = ready(machine, start=True)
        self.assertIn("systemctl start mariadb exited 1", problem)
        self.assertIn("Job for mariadb.service failed.", problem)
        self.assertEqual(machine.calls, [PING, START])

    def test_a_start_that_outlasts_the_bound_is_the_reason(self):
        machine = Machine(pings=1, start=subprocess.TimeoutExpired(
            list(START), 300,
        ))
        problem, _ = ready(machine, start=True)
        self.assertIn("did not finish within 300 s", problem)

    def test_a_machine_without_systemctl_is_the_reason(self):
        machine = Machine(pings=1, start=FileNotFoundError(
            2, "No such file or directory",
        ))
        problem, _ = ready(machine, start=True)
        self.assertIn("systemctl start mariadb failed", problem)
        self.assertIn("No such file or directory", problem)

    def test_an_active_server_that_refuses_the_client_is_not_waited_for(
        self,
    ):
        # Access denied does not get better by waiting: once the unit is
        # active the client's own error is the answer, at once.
        machine = Machine(pings=99, units=("active",))
        problem, clock = ready(machine, start=True)
        self.assertIn("mariadb is active and does not answer", problem)
        self.assertIn("Can't connect to local server", problem)
        self.assertEqual(clock.slept, 0)

    def test_a_server_that_stopped_again_after_its_start_is_named(self):
        machine = Machine(pings=99, units=("failed",))
        problem, clock = ready(machine, start=True)
        self.assertIn(
            "mariadb is failed after systemctl start mariadb and does not"
            " answer", problem,
        )
        self.assertEqual(clock.slept, 0)

    def test_a_unit_that_never_finishes_activating_is_given_up_on(self):
        machine = Machine(pings=10**6, units=("activating",))
        problem, clock = ready(machine, start=False, timeout=30)
        self.assertIn("still activating after 30 s", problem)
        self.assertLessEqual(clock.slept, 30)
        self.assertGreaterEqual(clock.slept, 30 - dbready.POLL_INTERVAL)

    def test_the_start_counts_against_the_same_bound(self):
        # The bound is one, not one for the start and another for the
        # wait after it.
        clock_box = {}

        def slow_start(argv, **kwargs):
            if tuple(argv) == START:
                clock_box["clock"].now += 25
                return done()
            return machine(argv, **kwargs)

        machine = Machine(pings=10**6, units=("activating",))
        clock = Clock()
        clock_box["clock"] = clock
        with mock.patch.object(subprocess, "run", side_effect=slow_start), \
                mock.patch.object(dbready.time, "monotonic",
                                  clock.monotonic), \
                mock.patch.object(dbready.time, "sleep", clock.sleep):
            problem = dbready.ready("mariadb", PING, True, 30)
        self.assertIn("still activating after 30 s", problem)
        self.assertLessEqual(clock.slept, 5)

    def test_a_client_that_hangs_is_an_answer_not_a_hang(self):
        machine = Machine(units=("inactive",))

        def hanging(argv, **kwargs):
            if tuple(argv) == PING:
                raise subprocess.TimeoutExpired(list(PING), 10)
            return machine(argv, **kwargs)

        clock = Clock()
        with mock.patch.object(subprocess, "run", side_effect=hanging), \
                mock.patch.object(dbready.time, "monotonic",
                                  clock.monotonic), \
                mock.patch.object(dbready.time, "sleep", clock.sleep):
            problem = dbready.ready("mariadb", PING, False, 30)
        self.assertIn(f"did not finish within {dbready.ASK_TIMEOUT} s",
                      problem)

    def test_a_client_that_is_not_installed_is_an_answer(self):
        machine = Machine(units=("inactive",))

        def missing(argv, **kwargs):
            if tuple(argv) == PING:
                raise FileNotFoundError(2, "No such file or directory")
            return machine(argv, **kwargs)

        with mock.patch.object(subprocess, "run", side_effect=missing):
            problem = dbready.ready("mariadb", PING, False, 30)
        self.assertIn("mariadb --batch", problem)
        self.assertIn("No such file or directory", problem)

    def test_a_unit_state_that_cannot_be_read_is_named_unknown(self):
        machine = Machine(pings=1)

        def no_systemctl(argv, **kwargs):
            if tuple(argv) == IS_ACTIVE:
                raise FileNotFoundError(2, "No such file or directory")
            return machine(argv, **kwargs)

        with mock.patch.object(subprocess, "run", side_effect=no_systemctl):
            problem = dbready.ready("mariadb", PING, False, 30)
        self.assertIn("mariadb is unknown", problem)


if __name__ == "__main__":
    unittest.main()
