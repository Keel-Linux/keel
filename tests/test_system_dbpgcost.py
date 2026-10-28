# Copyright (c) 2026 KeelLinux maintainers
"""The estimate of the rejoin, and the copy that a reseed keeps
(decision 0054, second amendment of 2026-10-18)"""

import os
import tempfile
import unittest
from unittest import mock

from keel.system import dbpgcost, dbpgkeep

MB = 1024 * 1024
HISTORY = "1\t0/3000148\tno recovery target specified\n\n"
SLOW = "3\t0/3000148\tx\n"
LISTING = "".join(f"{name}\t{16 * 1024 * 1024}\n" for name in (
    "000000030000000000000002", "000000030000000000000003",
    "000000040000000000000003", "000000040000000000000004"))


class TestTheForkAndTheWal(unittest.TestCase):
    def test_the_fork_is_where_the_history_leaves_the_own_timeline(self):
        text = "1\t0/3000148\tx\n2\t0/5000060\ty\n"
        self.assertEqual(dbpgcost.fork_lsn(text, 1), 0x3000148)
        self.assertEqual(dbpgcost.fork_lsn(text, 2), 0x5000060)

    def test_a_history_without_the_timeline_has_no_fork(self):
        self.assertIsNone(dbpgcost.fork_lsn(HISTORY, 7))
        self.assertIsNone(dbpgcost.fork_lsn("", 1))
        self.assertIsNone(dbpgcost.fork_lsn("1\tnonsense\tx\n", 1))

    def test_the_wal_is_the_files_from_the_segment_of_the_fork(self):
        files = [("000000010000000000000002", 16 * MB),
                 ("000000010000000000000003", 16 * MB),
                 ("000000020000000000000003", 16 * MB),
                 ("000000020000000000000004", 16 * MB)]
        # the fork 0/3000148 is in segment 3: files 3 and 4 count
        self.assertEqual(dbpgcost.wal_bytes(files, 0x3000148), 48 * MB)

    def test_the_segment_number_crosses_the_high_word(self):
        files = [("0000000100000001000000FF", 16 * MB),
                 ("000000010000000200000000", 16 * MB)]
        self.assertEqual(dbpgcost.wal_bytes(files, 0x1FF000000), 32 * MB)
        self.assertEqual(dbpgcost.wal_bytes(files, 0x200000000), 16 * MB)

    def test_the_lines_of_the_listing_are_read(self):
        text = "000000010000000000000002\t16777216\nbad\n" \
               "000000010000000000000003\tx\n"
        self.assertEqual(dbpgcost.parse_wal(text),
                         [("000000010000000000000002", 16777216)])


class TestTheChoice(unittest.TestCase):
    def test_a_quick_rewind_is_taken_whatever_the_reseed_costs(self):
        # 48 MB at 1 MB/s is 48 s
        self.assertEqual(dbpgcost.choose(48 * MB, 1 * MB, 1 * MB), "rewind")

    def test_the_smaller_estimate_wins_when_the_rewind_is_slow(self):
        # 48 MB at 47 kB/s is 1000 s; 12 MB is 260 s
        self.assertEqual(dbpgcost.choose(48 * MB, 12 * MB, 47000), "reseed")
        self.assertEqual(dbpgcost.choose(48 * MB, 400 * MB, 47000),
                         "rewind")

    def test_no_speed_means_the_rewind(self):
        self.assertEqual(dbpgcost.choose(48 * MB, 1, 0), "rewind")
        self.assertEqual(dbpgcost.choose(48 * MB, 1, None), "rewind")

    def test_the_databases_are_counted_compressed(self):
        self.assertEqual(dbpgcost.reseed_bytes(100 * MB),
                         int(100 * MB * dbpgcost.COMPRESSION))


class Answers:
    """A psql that answers by the text of the statement"""

    def __init__(self, **by):
        self.by = by

    def __call__(self, argv, **kwargs):
        sql = argv[argv.index("--command") + 1] if "--command" in argv \
            else ""
        for key, value in self.by.items():
            if key in sql:
                if value is None:
                    return mock.Mock(returncode=1, stdout=b"", stderr=b"no")
                return mock.Mock(returncode=0, stdout=value.encode(),
                                 stderr=b"")
        return mock.Mock(returncode=0, stdout=b"f\t0\t100\n", stderr=b"")


class TestTheMeasure(unittest.TestCase):
    def measure(self, **by):
        base = {"convert_from": SLOW, "pg_ls_dir": LISTING,
                "pg_last_wal_replay_lsn": "0/3000200\n",
                "length(pg_read_binary_file": "262144\n"}
        base.update(by)
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "var/tmp"))
            with mock.patch("keel.system.dbpgcost._clock",
                            side_effect=iter([0.0, 5.0])):
                return dbpgcost.measure(root, "h", 5432, "pw", "", 3, "4",
                                        Answers(**base))

    def test_the_estimate_has_both_costs_and_the_speed(self):
        found = self.measure()
        self.assertEqual(found.wal, 48 * MB)
        self.assertEqual(found.changed, 0x3000200 - 0x3000148)
        self.assertAlmostEqual(found.speed, 262144 / 5.0)
        self.assertEqual(found.databases, 100)

    def test_each_question_that_fails_gives_no_estimate(self):
        for key in ("convert_from", "pg_ls_dir"):
            self.assertIsNone(self.measure(**{key: None}), key)

    def test_a_history_without_the_fork_gives_no_estimate(self):
        self.assertIsNone(self.measure(convert_from="9\t0/1\tx\n"))
        self.assertIsNone(self.measure(pg_ls_dir=""))

    def test_a_holder_that_is_a_standby_gives_no_estimate(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "var/tmp"))
            run = Answers(convert_from=SLOW, pg_ls_dir=LISTING,
                          pg_database_size="t\t0\t100\n")
            self.assertIsNone(dbpgcost.measure(
                root, "h", 5432, "pw", "", 3, "4", run))

    def test_a_probe_that_gives_no_bytes_leaves_the_speed_open(self):
        found = self.measure(**{"length(pg_read_binary_file": None})
        self.assertIsNone(found.speed)

    def test_a_replay_position_that_cannot_be_read_counts_no_change(self):
        self.assertEqual(
            self.measure(pg_last_wal_replay_lsn=None).changed, 0)

    def test_a_spool_that_cannot_be_made_gives_no_estimate(self):
        self.assertIsNone(dbpgcost.measure(
            "/nonexistent-root", "h", 5432, "pw", "", 3, "4", Answers()))

    def test_the_clock_is_the_monotonic_one(self):
        self.assertIsInstance(dbpgcost._clock(), float)

    def test_a_listing_with_no_files_has_no_wal(self):
        self.assertEqual(dbpgcost.wal_bytes([], 5), 0)
        self.assertIsNone(dbpgcost.lsn_value("0/zz"))


class TestTheKeptCopy(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.data = os.path.join(self.dir.name, "main")

    def kept(self, stamp: str, age_days: float = 0) -> str:
        path = f"{self.data}{dbpgkeep.SUFFIX}{stamp}"
        os.makedirs(path)
        with open(os.path.join(path, "PG_VERSION"), "w") as fob:
            fob.write("17\n")
        when = 1_800_000_000 - age_days * 86400
        os.utime(path, (when, when))
        return path

    def test_the_name_is_dated(self):
        name = dbpgkeep.kept_name(self.data, 1_800_000_000)
        self.assertTrue(name.startswith(self.data + ".keel-kept-2027"), name)

    def test_there_is_room_when_the_free_space_covers_the_copy_and_the_floor(
            self):
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        return_value=10 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3):
            self.assertTrue(dbpgkeep.can_keep(self.data, 1024 ** 3))
            self.assertFalse(dbpgkeep.can_keep(self.data, 8 * 1024 ** 3))

    def test_the_floor_is_the_larger_of_1_gib_and_5_percent(self):
        with mock.patch("keel.system.dbpgkeep.total_bytes",
                        return_value=100 * 1024 ** 3):
            self.assertEqual(dbpgkeep.floor_bytes(self.data), 5 * 1024 ** 3)
        with mock.patch("keel.system.dbpgkeep.total_bytes",
                        return_value=10 * 1024 ** 3):
            self.assertEqual(dbpgkeep.floor_bytes(self.data), 1024 ** 3)

    def test_old_copies_go_and_the_newest_stays(self):
        old = self.kept("20270101T000000Z", age_days=30)
        older = self.kept("20261201T000000Z", age_days=60)
        new = self.kept("20270110T000000Z", age_days=1)
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        return_value=50 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3):
            gone = dbpgkeep.prune(self.data, now=1_800_000_000)
        self.assertEqual(sorted(gone), sorted([old, older]))
        self.assertTrue(os.path.isdir(new))
        self.assertFalse(os.path.exists(old))

    def test_the_only_copy_stays_even_when_it_is_old(self):
        only = self.kept("20261201T000000Z", age_days=90)
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        return_value=50 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3):
            self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])
        self.assertTrue(os.path.isdir(only))

    def test_low_space_deletes_the_oldest_first_but_not_the_newest(self):
        a = self.kept("20270108T000000Z", age_days=3)
        b = self.kept("20270109T000000Z", age_days=2)
        c = self.kept("20270110T000000Z", age_days=1)
        free = iter([1, 1, 50 * 1024 ** 3, 50 * 1024 ** 3])
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        side_effect=lambda _: next(free)), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3):
            gone = dbpgkeep.prune(self.data, now=1_800_000_000)
        self.assertEqual(gone, [a, b])
        self.assertTrue(os.path.isdir(c))

    def test_a_pruned_directory_that_cannot_go_is_skipped(self):
        self.kept("20261201T000000Z", age_days=60)
        self.kept("20270110T000000Z", age_days=1)
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        return_value=50 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.shutil.rmtree",
                           side_effect=OSError(13, "no")):
            self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])

    def test_a_file_system_that_cannot_be_asked_keeps_nothing(self):
        with mock.patch("keel.system.dbpgkeep.free_bytes",
                        side_effect=OSError(5, "io")):
            self.assertFalse(dbpgkeep.can_keep(self.data, 1))
            self.kept("20270110T000000Z", age_days=1)
            self.kept("20270111T000000Z", age_days=1)
            self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])

    def test_a_copy_that_vanished_is_skipped(self):
        self.kept("20261201T000000Z", age_days=60)
        self.kept("20270110T000000Z", age_days=1)
        with mock.patch("keel.system.dbpgkeep.os.path.getmtime",
                        side_effect=OSError(2, "gone")), \
                mock.patch("keel.system.dbpgkeep.free_bytes",
                           return_value=50 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3):
            self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])

    def test_the_real_file_system_is_asked(self):
        self.assertGreater(dbpgkeep.free_bytes(self.data), 0)
        self.assertGreater(dbpgkeep.total_bytes(self.data), 0)

    def test_a_copy_that_cannot_be_deleted_for_space_is_skipped(self):
        self.kept("20270108T000000Z", age_days=3)
        self.kept("20270110T000000Z", age_days=1)
        with mock.patch("keel.system.dbpgkeep.free_bytes", return_value=1), \
                mock.patch("keel.system.dbpgkeep.total_bytes",
                           return_value=100 * 1024 ** 3), \
                mock.patch("keel.system.dbpgkeep.shutil.rmtree",
                           side_effect=OSError(13, "no")):
            self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])

    def test_nothing_kept_prunes_nothing(self):
        self.assertEqual(dbpgkeep.prune(self.data, 1_800_000_000), [])


if __name__ == "__main__":
    unittest.main()
