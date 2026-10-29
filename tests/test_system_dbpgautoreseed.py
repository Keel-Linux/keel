# Copyright (c) 2026 KeelLinux maintainers
"""The old primary takes the cheaper rejoin, and a reseed keeps the old
data (decision 0054, second amendment of 2026-10-18)"""

import os
from unittest import mock

from test_system_dbpgfollow import DATADIR, UNIT, FollowTestCase
from test_system_dbpgrewind import old_primary

from keel.system import dbfollow, dbpgcost, dbpgkeep, dbpgrewind

MB = 1024 * 1024
HISTORY = "1\t0/3000148\tno recovery target specified\n\n"
# the fork of the old primary (timeline 3) is in segment 3 of the holder's
# history: 3 files from it on, 48 MB
LISTING = "".join(f"{name}\t{16 * MB}\n" for name in (
    "000000030000000000000002", "000000030000000000000003",
    "000000040000000000000003", "000000040000000000000004"))
SLOW_HISTORY = "3\t0/3000148\tx\n"


def holder(**more):
    options = {"history": SLOW_HISTORY, "wal_listing": LISTING}
    options.update(more)
    return old_primary(**options)


def clock(seconds: float):
    """dbpgcost._clock: the probe of the speed takes `seconds`"""
    ticks = iter([0.0, seconds])
    return mock.patch("keel.system.dbpgcost._clock",
                      side_effect=lambda: next(ticks))


class TestTheChoice(FollowTestCase):
    def run_follow(self, server, seconds, **kwargs):
        self.pair_nodes()
        with clock(seconds), mock.patch("keel.monitor.alerting.alert",
                                        return_value=True) as alerted:
            found = self.follow(1, server, **kwargs)
        return found, alerted

    def test_a_fast_link_rewinds(self):
        server = holder()
        found, _ = self.run_follow(server, 0.01)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.ran(server, "pg_rewind"))
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_a_slow_link_reseeds_with_no_flag(self):
        server = holder()
        found, alerted = self.run_follow(server, 5.0)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(self.ran(server, "pg_rewind"))
        self.assertTrue(self.ran(server, "pg_basebackup"))
        joined = "\n".join(found.lines)
        self.assertIn("reseed is cheaper than the rewind", joined)
        self.assertIsNone(dbfollow.diverged(self.all[1].root))

    def test_the_old_data_is_kept_and_the_path_is_said_and_alerted(self):
        server = holder()
        found, alerted = self.run_follow(server, 5.0)
        data = os.path.join(self.all[1].root, DATADIR)
        kept = dbpgkeep.kept_dirs(data)
        self.assertEqual(len(kept), 1, os.listdir(os.path.dirname(data)))
        self.assertIn(kept[0], "\n".join(found.lines))
        titles = [call.args[2] for call in alerted.call_args_list]
        self.assertTrue(any("kept" in one for one in titles), titles)
        texts = " ".join(call.args[3] for call in alerted.call_args_list)
        self.assertIn(kept[0], texts)

    def test_a_reseed_with_no_room_for_a_copy_needs_the_flag(self):
        server = holder()
        self.pair_nodes()
        with clock(5.0), mock.patch("keel.system.dbpgkeep.can_keep",
                                    return_value=False), \
                mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, server)
        self.assertIn("diverged", found.problem)
        self.assertIn("no room to keep", "\n".join(found.lines))
        self.assertFalse(self.ran(server, "pg_basebackup"))
        self.assertFalse(self.ran(server, "pg_rewind"))

    def test_a_holder_with_no_claim_needs_the_flag(self):
        """The proof is the claim of the VIP: without it keel asks"""
        server = holder()
        self.pair_nodes()
        with clock(5.0), mock.patch(
                "keel.system.dbpair.PairState.claimed",
                new_callable=mock.PropertyMock, return_value=False), \
                mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, server)
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_no_estimate_rewinds_as_before(self):
        server = old_primary()
        found, _ = self.run_follow(server, 5.0)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.ran(server, "pg_rewind"))

    def test_the_flag_reseeds_and_keeps_the_old_data_too(self):
        server = holder()
        found, _ = self.run_follow(server, 0.01, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        data = os.path.join(self.all[1].root, DATADIR)
        self.assertEqual(len(dbpgkeep.kept_dirs(data)), 1)

    def test_the_flag_reseed_deletes_the_old_data_when_there_is_no_room(self):
        server = holder()
        self.pair_nodes()
        with mock.patch("keel.system.dbpgkeep.can_keep",
                        return_value=False), \
                mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, server, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        data = os.path.join(self.all[1].root, DATADIR)
        self.assertEqual(dbpgkeep.kept_dirs(data), [])

    def test_a_standby_of_the_holder_prunes_the_old_copies(self):
        self.pair_nodes()
        data = os.path.join(self.all[1].root, DATADIR)
        old = f"{data}{dbpgkeep.SUFFIX}20260101T000000Z"
        new = f"{data}{dbpgkeep.SUFFIX}20261010T000000Z"
        for path, age in ((old, 40), (new, 1)):
            os.makedirs(path)
            when = __import__("time").time() - age * 86400
            os.utime(path, (when, when))
        from test_system_dbpgfollow import Server, address
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        found = self.follow(1, Server(in_recovery=True, receiver=receiver))
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))
        self.assertIn(old, "\n".join(found.lines))


class TestTheDeathOfTheCopy(FollowTestCase):
    def test_an_unusable_copy_is_alerted_once(self):
        """keel#214"""
        self.pair_nodes()
        server = old_primary(rewind="halfway")
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=True) as alerted:
            found = self.follow(1, server)
        self.assertIn("failed halfway", found.problem)
        titles = [call.args[2] for call in alerted.call_args_list]
        self.assertEqual(sum("unusable" in one for one in titles), 1, titles)
        text = " ".join(call.args[3] for call in alerted.call_args_list)
        self.assertIn("--destroy-local-database", text)
        # the next run says the same and does not alert again
        with mock.patch("keel.monitor.alerting.alert") as again:
            self.follow(1, server)
        again.assert_not_called()
