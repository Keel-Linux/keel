# Copyright (c) 2026 KeelLinux maintainers
"""keel database dump (keel.system.dbdump): the dump on the standby

The dump and the pack here are real processes: a fake of subprocess
would hide the pipe, the file's mode and the kernel's file size limit.
The files and the mode are read from the real file system.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import namedtuple
from types import SimpleNamespace
from unittest import mock

from keel import exits
from keel.mesh.node import NodeError
from keel.system import dbdump, dbpair

VIP = "fd00:6b65:f1b::ffff:100"
REPLICA = dbpair.PairState(VIP, "own", "peer", "fd00::2", dbpair.REPLICA)
PRIMARY = dbpair.PairState(VIP, "own", "peer", "fd00::2", dbpair.PRIMARY)
HOUR = 3600
NOW = 2_000_000_000.0
Vfs = namedtuple("Vfs", "f_frsize f_blocks f_bavail")
MIB = 1024 * 1024


def doc(engine="mariadb", **dump):
    server = {"engine": engine, "role": "replica"}
    if dump:
        server["dump"] = dump
    return {"database": {"server": server}}


def wide_open(_path):
    """A disk of 100 GiB with 50 GiB free"""
    return Vfs(MIB, 100 * 1024, 50 * 1024)


def emit(text: str) -> tuple[str, ...]:
    return (sys.executable, "-c", f"import sys; sys.stdout.write({text!r})")


def fails(code: int) -> tuple[str, ...]:
    return (sys.executable, "-c",
            f"import sys; sys.stderr.write('server gone'); sys.exit({code})")


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.lines: list[str] = []
        for patcher in (
            mock.patch.object(dbdump, "PACK", ("cat",)),
            mock.patch.dict(dbdump.COMMANDS,
                            {"mariadb": emit("-- dump\n"),
                             "postgresql": emit("-- dump\n")}),
            mock.patch.object(dbdump, "_replicating", return_value=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    @property
    def directory(self):
        return os.path.join(self.root, dbdump.BACKUPS["mariadb"])

    def seed(self, name: str, age_hours: float = 1, size: int = 3) -> str:
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        path = os.path.join(self.directory, name)
        with open(path, "wb") as fob:
            fob.write(b"x" * size)
        os.utime(path, (NOW - age_hours * HOUR, NOW - age_hours * HOUR))
        return path

    def run_dump(self, document=None, pair=REPLICA, due_only=False,
                 statvfs=wide_open):
        with mock.patch.object(dbdump, "_document",
                               return_value=document or doc()), \
                mock.patch.object(dbdump.dbpair, "observe_pair",
                                  return_value=pair):
            return dbdump.run(self.root, "spec.yaml", self.lines.append,
                              self.lines.append, due_only=due_only,
                              now=NOW, statvfs=statvfs)

    def state(self):
        return dbdump.read_state(self.root)

    def names(self):
        return sorted(os.listdir(self.directory))


class TestSettings(unittest.TestCase):
    def test_a_pair_with_no_dump_section_has_the_daily_seven(self):
        found = dbdump.settings(doc())
        self.assertEqual(
            (found.enabled, found.every_hours, found.keep,
             found.min_free_percent), (True, 24, 7, 10))

    def test_the_spec_sets_each_value(self):
        found = dbdump.settings(doc(enabled=False, every_hours=6, keep=2,
                                    min_free_percent=30))
        self.assertEqual(
            (found.enabled, found.every_hours, found.keep,
             found.min_free_percent), (False, 6, 2, 30))


class TestRun(Base):
    def test_a_replica_writes_one_dump_of_mode_0600_in_a_0700_directory(self):
        self.assertEqual(self.run_dump(), exits.OK)
        names = self.names()
        self.assertEqual(len(names), 1, names)
        self.assertRegex(names[0], dbdump.NAME)
        path = os.path.join(self.directory, names[0])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.directory).st_mode), 0o700)
        with open(path) as fob:
            self.assertEqual(fob.read(), "-- dump\n")
        self.assertEqual(self.state().get("problem"), "")

    def test_an_open_directory_is_closed(self):
        os.makedirs(self.directory, mode=0o755)
        os.chmod(self.directory, 0o755)
        self.run_dump()
        self.assertEqual(stat.S_IMODE(os.stat(self.directory).st_mode), 0o700)

    def test_the_primary_does_not_dump_and_records_that(self):
        self.assertEqual(self.run_dump(pair=PRIMARY), exits.OK)
        self.assertFalse(os.path.exists(self.directory))
        self.assertEqual(self.state()["not_replica_at"], NOW)
        self.assertIn("only while", "\n".join(self.lines))

    def test_a_node_with_no_vip_has_nothing_to_dump(self):
        self.assertEqual(self.run_dump(pair=None), exits.OK)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIn("no appliance.vip", "\n".join(self.lines))

    def test_the_spec_turns_it_off(self):
        self.assertEqual(self.run_dump(doc(enabled=False)), exits.OK)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIn("enabled: false", "\n".join(self.lines))

    def test_an_engine_with_no_dump_is_not_dumped(self):
        self.assertEqual(self.run_dump(doc("redis")), exits.OK)
        self.assertIn("no dump for redis", "\n".join(self.lines))

    def test_a_node_with_no_server_section_is_not_dumped(self):
        self.assertEqual(self.run_dump({"database": {}}), exits.OK)
        self.assertIn("no dump for none", "\n".join(self.lines))

    def test_a_spec_that_cannot_be_read_fails(self):
        with mock.patch.object(dbdump, "_document",
                               side_effect=NodeError("no spec")):
            code = dbdump.run(self.root, "s", self.lines.append,
                              self.lines.append)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("no spec", "\n".join(self.lines))

    def test_postgresql_goes_to_its_own_directory(self):
        self.assertEqual(self.run_dump(doc("postgresql")), exits.OK)
        where = os.path.join(self.root, dbdump.BACKUPS["postgresql"])
        self.assertEqual(len(os.listdir(where)), 1)

    def test_the_timer_tick_dumps_only_when_it_is_due(self):
        kept = self.seed("dump-20330101T000000Z.sql.zst", age_hours=1)
        self.assertEqual(self.run_dump(due_only=True), exits.OK)
        self.assertEqual(self.names(), [os.path.basename(kept)])
        self.assertIn("not due", "\n".join(self.lines))

    def test_the_timer_tick_dumps_when_the_interval_is_over(self):
        self.seed("dump-20330101T000000Z.sql.zst", age_hours=24)
        self.run_dump(due_only=True)
        self.assertEqual(len(self.names()), 2)

    def test_the_first_tick_after_the_interval_is_not_lost_to_a_drift(self):
        # an hourly tick that fires seconds early does not push a daily
        # dump to 25 hours
        self.seed("dump-20330101T000000Z.sql.zst", age_hours=23.9)
        self.run_dump(due_only=True)
        self.assertEqual(len(self.names()), 2)

    def waiting(self):
        """A clock that the waits of the run move on, and what it slept"""
        slept = []
        clock = [0.0]

        def sleep(seconds):
            slept.append(seconds)
            clock[0] += seconds
        return slept, mock.patch.multiple(
            dbdump, _sleep=sleep, _clock=lambda: clock[0])

    def test_a_server_that_does_not_replicate_is_a_problem_and_no_dump(self):
        # an empty server that was not seeded would push the good dumps
        # out of the retention; it is waited for first, up to
        # REPLICATION_WAIT, and a lasting fault fails the run
        slept, patched = self.waiting()
        with mock.patch.object(dbdump, "_replicating", return_value=False), \
                patched:
            self.assertEqual(self.run_dump(), exits.APPLY_FAILED)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIn("does not replicate", self.state()["problem"])
        self.assertGreaterEqual(sum(slept), dbdump.REPLICATION_WAIT)
        self.assertTrue(all(one <= dbdump.REPLICATION_POLL for one in slept))

    def test_a_replica_that_replicates_after_a_wait_is_dumped(self):
        """The failback window (release A, laravel cloud_simple,
        2026-11-09): the claim says replica, and the server replicates
        some seconds later. The hourly run fell in that window, failed,
        and left keel-database-dump.service failed on both nodes"""
        slept, patched = self.waiting()
        with mock.patch.object(dbdump, "_replicating",
                               side_effect=[False, False, True]), patched:
            self.assertEqual(self.run_dump(), exits.OK)
        self.assertEqual(len(self.names()), 1)
        self.assertEqual(self.state()["problem"], "")
        self.assertEqual(slept, [dbdump.REPLICATION_POLL] * 2)
        self.assertTrue(any("waits for the server to replicate" in one
                            for one in self.lines), self.lines)

    def test_a_node_whose_claim_turns_primary_while_it_waits_dumps_nothing(
            self):
        slept, patched = self.waiting()
        with mock.patch.object(dbdump, "_replicating", return_value=False), \
                mock.patch.object(dbdump.dbpair, "observe_pair",
                                  side_effect=[REPLICA, REPLICA, PRIMARY]), \
                mock.patch.object(dbdump, "_document", return_value=doc()), \
                patched:
            found = dbdump.run(self.root, "spec.yaml", self.lines.append,
                               self.lines.append, now=NOW,
                               statvfs=wide_open)
        self.assertEqual(found, exits.OK)
        self.assertFalse(os.path.exists(self.directory))
        self.assertEqual(self.state()["problem"], "")
        self.assertEqual(self.state()["not_replica_at"], NOW)

    def test_a_diverged_node_is_a_problem_and_no_dump(self):
        with mock.patch.object(dbdump.dbfollow, "diverged",
                               return_value={"errant": ["0-1-1"]}):
            self.assertEqual(self.run_dump(), exits.APPLY_FAILED)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIn("diverged", self.state()["problem"])

    def test_a_second_run_at_the_same_time_leaves_the_first_alone(self):
        with dbdump.locked(self.root) as first:
            self.assertTrue(first)
            self.assertEqual(self.run_dump(), exits.OK)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIn("already runs", "\n".join(self.lines))


class TestFailure(Base):
    def assert_failed_clean(self, code, *words):
        self.assertEqual(code, exits.APPLY_FAILED)
        problem = self.state()["problem"]
        for word in words:
            self.assertIn(word, problem)
        leftovers = [one for one in os.listdir(self.directory)
                     if dbdump.NAME.match(one) or "partial" in one]
        return leftovers, problem

    def test_a_failed_dump_leaves_no_file_and_says_why(self):
        with mock.patch.dict(dbdump.COMMANDS, {"mariadb": fails(2)}):
            leftovers, _ = self.assert_failed_clean(
                self.run_dump(), "exited 2", "server gone")
        self.assertEqual(leftovers, [])

    def test_a_dump_that_writes_and_then_fails_is_no_backup(self):
        partly = (sys.executable, "-c",
                  "import sys; print('-- half'); sys.stdout.flush();"
                  " sys.exit(3)")
        with mock.patch.dict(dbdump.COMMANDS, {"mariadb": partly}):
            leftovers, _ = self.assert_failed_clean(self.run_dump(),
                                                    "exited 3")
        self.assertEqual(leftovers, [])

    def test_a_failed_pack_leaves_no_file(self):
        with mock.patch.object(dbdump, "PACK", fails(4)):
            leftovers, _ = self.assert_failed_clean(self.run_dump(),
                                                    "exited 4")
        self.assertEqual(leftovers, [])

    def test_a_pack_that_fails_is_named_when_the_dump_dies_of_it(self):
        """A pack that ends breaks the dump's pipe, and the dump then dies
        too (EPIPE, or SIGPIPE for mariadb-dump). Which of the two ended
        first was a race, and the message named the dump: the cause, the
        pack, was lost (test_a_failed_pack_leaves_no_file failed so on
        CI). A dump larger than the pipe's buffer always hits it"""
        big = (sys.executable, "-c",
               "import sys; sys.stdout.write('x' * 4000000)")
        with mock.patch.object(dbdump, "PACK", fails(4)), \
                mock.patch.dict(dbdump.COMMANDS, {"mariadb": big}):
            leftovers, _ = self.assert_failed_clean(
                self.run_dump(), "exited 4", "server gone")
        self.assertEqual(leftovers, [])

    def test_an_empty_dump_is_no_backup(self):
        with mock.patch.dict(dbdump.COMMANDS,
                             {"mariadb": (sys.executable, "-c", "pass")}):
            leftovers, _ = self.assert_failed_clean(self.run_dump(), "empty")
        self.assertEqual(leftovers, [])

    def test_a_tool_that_is_missing_is_reported(self):
        with mock.patch.dict(dbdump.COMMANDS,
                             {"mariadb": ("/nonexistent/dump",)}):
            leftovers, _ = self.assert_failed_clean(self.run_dump(),
                                                    "cannot run")
        self.assertEqual(leftovers, [])

    def test_a_failed_dump_leaves_the_older_dumps(self):
        names = [self.seed(f"dump-2033010{day}T000000Z.sql.zst", day)
                 for day in range(1, 4)]
        with mock.patch.dict(dbdump.COMMANDS, {"mariadb": fails(2)}):
            self.run_dump(doc(keep=1))
        for name in names:
            self.assertTrue(os.path.exists(name))

    def test_a_partial_file_of_a_killed_run_is_removed(self):
        self.seed(".dump-20330101T000000Z.partial")
        self.run_dump()
        self.assertEqual(len(self.names()), 1, self.names())
        self.assertRegex(self.names()[0], dbdump.NAME)

    def test_a_directory_that_cannot_be_made_is_a_problem(self):
        with mock.patch.object(dbdump.os, "makedirs",
                               side_effect=OSError(13, "Permission denied")):
            code = self.run_dump()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("Permission denied", "\n".join(self.lines))

    def test_a_state_that_cannot_be_written_does_not_hide_the_result(self):
        with mock.patch.object(dbdump, "_save",
                               side_effect=OSError(28, "No space left")):
            self.assertEqual(self.run_dump(), exits.OK)
        self.assertIn("No space left", "\n".join(self.lines))


class TestSpace(Base):
    def test_no_room_above_the_floor_refuses_before_the_dump(self):
        # 100 GiB, 10 percent is the floor, and only 9 GiB are free
        def tight(_path):
            return Vfs(MIB, 100 * 1024, 9 * 1024)
        self.assertEqual(self.run_dump(statvfs=tight), exits.APPLY_FAILED)
        self.assertIn("no room", self.state()["problem"])
        self.assertEqual(self.names(), [])

    def test_the_floor_comes_from_the_spec(self):
        def half(_path):
            return Vfs(MIB, 100 * 1024, 50 * 1024)
        code = self.run_dump(doc(min_free_percent=60), statvfs=half)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("60%", self.state()["problem"])

    def test_room_under_the_last_dump_size_refuses(self):
        self.seed("dump-20330101T000000Z.sql.zst", size=2 * MIB)

        def tight(_path):
            # the floor is 10 MiB of 100, 11 MiB free: 1 MiB of room
            return Vfs(MIB, 100, 11)
        self.assertEqual(self.run_dump(statvfs=tight), exits.APPLY_FAILED)
        self.assertIn("no room", self.state()["problem"])
        self.assertEqual(len(self.names()), 1)

    def test_a_dump_larger_than_the_room_is_stopped_by_the_kernel(self):
        # real processes and the real RLIMIT_FSIZE: the disk keeps its floor
        big = (sys.executable, "-c",
               "import sys\n"
               "for _ in range(64):\n"
               "    sys.stdout.buffer.write(b'x' * 1048576)\n")

        def tight(_path):
            # the floor is 10 MiB of 100, 12 MiB free: 2 MiB of room
            return Vfs(MIB, 100, 12)
        with mock.patch.dict(dbdump.COMMANDS, {"mariadb": big}):
            code = self.run_dump(statvfs=tight)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("free-space limit", self.state()["problem"])
        self.assertEqual(self.names(), [])

    def test_room_is_what_is_free_above_the_floor(self):
        self.assertEqual(dbdump.room("/x", 10, statvfs=lambda _p: Vfs(
            MIB, 100, 25)), 15 * MIB)

    def test_rejoin_guard_refuses_a_disk_at_its_floor(self):
        problem, limit = dbdump.rejoin_guard(
            self.root, statvfs=lambda _p: Vfs(MIB, 100, 5))
        self.assertIn("no room", problem)
        self.assertIsNone(limit)

    def test_rejoin_guard_limits_the_plain_file_to_half_the_room(self):
        # the plain file and its compressed copy are on the disk together
        with mock.patch.object(dbdump.resource, "setrlimit") as setter:
            problem, limit = dbdump.rejoin_guard(
                self.root, statvfs=lambda _p: Vfs(MIB, 100, 25))
            limit()
        self.assertEqual(problem, "")
        setter.assert_called_once_with(
            dbdump.resource.RLIMIT_FSIZE, (10 * MIB, 10 * MIB))


class TestRetention(Base):
    def test_only_the_newest_keep_stay_after_a_good_dump(self):
        for day in range(1, 5):
            self.seed(f"dump-2033010{day}T000000Z.sql.zst", 10 - day)
        self.run_dump(doc(keep=2))
        names = self.names()
        self.assertEqual(len(names), 2, names)
        self.assertIn("dump-20330104T000000Z.sql.zst", names)

    def test_a_rejoin_dump_is_never_removed(self):
        # it holds the only copy of a diverged node's writes
        rejoin = self.seed("rejoin-20200101T000000Z.sql.zst", 9000)
        other = self.seed("rejoin-20200102T000000Z.sql", 9000)
        self.seed("dump-20330101T000000Z.sql.zst", 2)
        self.run_dump(doc(keep=1))
        self.assertTrue(os.path.exists(rejoin))
        self.assertTrue(os.path.exists(other))
        self.assertEqual(sum(bool(dbdump.NAME.match(one))
                             for one in self.names()), 1)

    def test_a_file_that_cannot_be_removed_is_said_and_the_run_is_good(self):
        self.seed("dump-20200101T000000Z.sql.zst", 100)
        real = os.remove

        def refuse(path):
            if "20200101" in str(path):
                raise OSError(1, "Operation not permitted")
            real(path)
        with mock.patch.object(dbdump.os, "remove", refuse):
            code = self.run_dump(doc(keep=1))
        self.assertEqual(code, exits.OK)
        self.assertIn("Operation not permitted", "\n".join(self.lines))


class TestNoCredentials(unittest.TestCase):
    def test_no_command_line_carries_a_credential(self):
        for argv in dbdump.COMMANDS.values():
            joined = " ".join(argv).lower()
            for word in ("password", "--defaults", " -p", "pgpass"):
                self.assertNotIn(word, joined)

    def test_mariadb_dump_is_one_snapshot_with_its_position(self):
        argv = dbdump.COMMANDS["mariadb"]
        for option in ("--single-transaction", "--gtid", "--master-data=2",
                       "--all-databases", "--routines", "--events",
                       "--triggers"):
            self.assertIn(option, argv)

    def test_the_replica_is_never_stopped_for_the_dump(self):
        self.assertFalse(any(one.startswith("--dump-slave")
                             for one in dbdump.COMMANDS["mariadb"]))

    def test_postgresql_dumps_as_its_own_user(self):
        argv = dbdump.COMMANDS["postgresql"]
        self.assertEqual(argv[:4], ("runuser", "-u", "postgres", "--"))
        self.assertEqual(argv[4], "pg_dumpall")


class TestReplicating(unittest.TestCase):
    def ask(self, engine, servers):
        with mock.patch.object(dbdump, "database_servers",
                               return_value=servers):
            return dbdump._replicating("/", engine)

    def server(self, name, role):
        one = mock.Mock()
        one.engine.name = name
        one.reading.return_value = SimpleNamespace(
            role=SimpleNamespace(value=role))
        return one

    def test_a_replica_replicates(self):
        self.assertTrue(self.ask("mariadb", [self.server("mariadb",
                                                         "replica")]))

    def test_a_primary_does_not(self):
        self.assertFalse(self.ask("mariadb", [self.server("mariadb",
                                                          "primary")]))

    def test_no_such_server_does_not(self):
        self.assertFalse(self.ask("postgresql",
                                  [self.server("mariadb", "replica")]))


class TestWatch(Base):
    def setUp(self):
        super().setUp()
        self.sent: list[tuple[str, str, str, str]] = []
        self.takes = True

    def deliver(self, _root, _err, title, text, check, level="critical"):
        self.sent.append((title, text, check, level))
        return self.takes

    def watch(self, pair=REPLICA, document=None, now=NOW):
        with mock.patch.object(dbdump.alerting, "alert", self.deliver):
            dbdump.watch(self.root, document or doc(), pair,
                         self.lines.append, now=now)

    def good(self, age_hours=1):
        return self.seed("dump-20330101T000000Z.sql.zst", age_hours)

    def test_a_recent_dump_says_nothing(self):
        self.good()
        self.watch()
        self.assertEqual(self.sent, [])

    def test_a_stale_dump_alerts_once(self):
        self.good(age_hours=60)
        self.watch()
        self.watch()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0][2], dbdump.CHECK)
        self.assertEqual(self.sent[0][3], "critical")
        self.assertIn("60", self.sent[0][1])

    def test_the_limit_is_two_intervals_and_one_tick(self):
        self.good(age_hours=48.5)
        self.watch()
        self.assertEqual(self.sent, [])
        self.watch(now=NOW + HOUR)
        self.assertEqual(len(self.sent), 1)

    def test_a_shorter_interval_is_stale_sooner(self):
        self.good(age_hours=8)
        self.watch(document=doc(every_hours=2))
        self.assertEqual(len(self.sent), 1)

    def test_a_failed_dump_alerts_once_with_the_reason(self):
        self.good()
        dbdump._save_state(self.root, {"problem": "mariadb-dump exited 2"})
        self.watch()
        self.watch()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("mariadb-dump exited 2", self.sent[0][1])

    def test_a_second_kind_of_problem_alerts_again(self):
        self.good(age_hours=60)
        self.watch()
        dbdump._save_state(self.root, {"problem": "no room"})
        self.watch()
        self.assertEqual(len(self.sent), 2)

    def test_recovery_alerts_once(self):
        dbdump._save_state(self.root, {"problem": "no room"})
        self.good()
        self.watch()
        dbdump._save_state(self.root, {"problem": ""})
        self.watch()
        self.watch()
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[1][3], "recovery")

    def test_an_alert_no_channel_took_is_sent_again(self):
        self.good(age_hours=60)
        self.takes = False
        self.watch()
        self.takes = True
        self.watch()
        self.watch()
        self.assertEqual(len(self.sent), 2)

    def test_a_new_node_has_the_interval_before_it_is_stale(self):
        self.watch()
        self.assertEqual(self.sent, [])
        self.watch(now=NOW + 60 * HOUR)
        self.assertEqual(len(self.sent), 1)

    def test_a_primary_is_never_stale(self):
        self.good(age_hours=900)
        self.watch(pair=PRIMARY)
        self.assertEqual(self.sent, [])

    def test_a_node_that_was_primary_until_now_is_not_stale_at_once(self):
        self.good(age_hours=900)
        dbdump._save_state(self.root, {"problem": "",
                                       "not_replica_at": NOW - HOUR})
        self.watch()
        self.assertEqual(self.sent, [])

    def test_the_role_change_to_primary_clears_a_problem(self):
        self.good(age_hours=60)
        self.watch()
        self.watch(pair=PRIMARY)
        self.assertEqual([one[3] for one in self.sent],
                         ["critical", "recovery"])

    def test_turned_off_in_the_spec_is_silent(self):
        self.good(age_hours=900)
        self.watch(document=doc(enabled=False))
        self.assertEqual(self.sent, [])

    def test_turned_off_clears_the_alert_without_a_message(self):
        self.good(age_hours=60)
        self.watch()
        self.watch(document=doc(enabled=False))
        self.watch()
        self.assertEqual(len(self.sent), 2)
        self.assertEqual({one[3] for one in self.sent}, {"critical"})

    def test_another_engine_is_silent(self):
        self.watch(document=doc("redis"))
        self.assertEqual(self.sent, [])

    def test_a_state_that_cannot_be_kept_is_said(self):
        self.good()
        with mock.patch.object(dbdump, "_save",
                               side_effect=OSError(28, "No space left")):
            self.watch()
        self.assertIn("No space left", "\n".join(self.lines))

    def test_files_of_unreadable_state_read_as_nothing(self):
        path = os.path.join(self.root, dbdump.STATE)
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fob:
            fob.write("not json")
        self.assertEqual(dbdump.read_state(self.root), {})
        with open(path, "w") as fob:
            json.dump([1], fob)
        self.assertEqual(dbdump.read_state(self.root), {})


class TestStatus(Base):
    def test_no_dump_is_said(self):
        lines = dbdump.status_lines(self.root, doc(), now=NOW)
        self.assertIn("none", lines[0])

    def test_the_newest_and_a_problem_are_said(self):
        self.seed("dump-20330101T000000Z.sql.zst", 3)
        dbdump._save_state(self.root, {"problem": "no room"})
        lines = "\n".join(dbdump.status_lines(self.root, doc(), now=NOW))
        self.assertIn("dump-20330101T000000Z.sql.zst", lines)
        self.assertIn("3.0 h", lines)
        self.assertIn("no room", lines)

    def test_off_is_said(self):
        lines = dbdump.status_lines(self.root, doc(enabled=False), now=NOW)
        self.assertIn("off", lines[0])

    def test_another_engine_has_no_line(self):
        self.assertEqual(dbdump.status_lines(self.root, doc("redis")), [])


class TestMain(Base):
    def test_main_runs_with_the_flag_of_the_timer(self):
        args = SimpleNamespace(root=self.root, spec="s", if_due=True)
        with mock.patch.object(dbdump, "run", return_value=0) as run:
            self.assertEqual(dbdump.main(args), 0)
        self.assertTrue(run.call_args.kwargs["due_only"])


class TestRealZstd(Base):
    @unittest.skipUnless(subprocess.run(
        ["sh", "-c", "command -v zstd"], capture_output=True).returncode == 0,
        "zstd is not installed")
    def test_the_file_is_a_real_zstd_stream_of_the_dump(self):
        with mock.patch.object(dbdump, "PACK", dbdump.REAL_PACK):
            self.assertEqual(self.run_dump(), exits.OK)
        path = os.path.join(self.directory, self.names()[0])
        out = subprocess.run(["zstd", "-dc", path], capture_output=True,
                             check=True)
        self.assertEqual(out.stdout, b"-- dump\n")
