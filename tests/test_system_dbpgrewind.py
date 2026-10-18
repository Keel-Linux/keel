# Copyright (c) 2026 KeelLinux maintainers
"""An old PostgreSQL primary rejoins with pg_rewind when it can
(decision 0054, amendment of 2026-10-18)

The follow of tests/test_system_dbpgfollow.py with a server that answers
as 17 does: the settings pg_rewind needs, the dry run, the run, and the
walreceiver. The real run is tests/postgres_netns.py.
"""

import os
import unittest
from unittest import mock

from test_system_dbpgfollow import (
    DATADIR, FOLLOW_DROPIN, STANDBY_SIGNAL, UNIT, FollowTestCase, Server)
from vip_helpers import VIP, address

from keel.mesh import vip as vipstate
from keel.mesh import vipnode
from keel.system import dbfollow, dbpgfollow, dbpgrewind, dbpostgres

ON = "on\toff\ton\n"
CHECKSUMS = "off\ton\ton\n"


def old_primary(**more) -> Server:
    """An old primary that came back writable: timeline 3 against the
    holder's 4, wal_log_hints on, and a pg_rewind that works"""
    options = {"timeline": "3", "holder_timeline": "4", "settings": ON,
               "rewind": "ok"}
    options.update(more)
    return Server(**options)


def index_of(server: Server, word: str, after: int = 0) -> int:
    return next(n for n, argv in enumerate(server.argv)
                if n >= after and any(word in one for one in argv))


class TestTheRewind(FollowTestCase):
    def follow_old_primary(self, server: Server | None = None, **kwargs):
        self.pair_nodes()
        server = server or old_primary()
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=True) as alerted:
            found = self.follow(1, server, **kwargs)
        return server, found, alerted

    def test_an_old_primary_is_rewound_and_follows_the_new_timeline(self):
        server, found, alerted = self.follow_old_primary()
        self.assertIsNone(found.problem, found.lines)
        root = self.all[1].root
        joined = "\n".join(found.lines)
        self.assertIn("rewound against", joined)
        self.assertIn(f"[{address(0)}]:5432", joined)
        # fenced, then dumped, then stopped, rewound, started
        fence = server.argv.index(["systemctl", "restart", UNIT])
        dump = index_of(server, "pg_dumpall")
        stop = server.argv.index(["systemctl", "stop", UNIT])
        dry = next(n for n, argv in enumerate(server.argv)
                   if "--dry-run" in argv)
        run = next(n for n, argv in enumerate(server.argv)
                   if argv[-1:] != ["--dry-run"] and any(
                       one.endswith("/pg_rewind") for one in argv)
                   and "--dry-run" not in argv)
        start = server.argv.index(["systemctl", "start", UNIT])
        self.assertLess(fence, dump)
        self.assertLess(dump, stop)
        self.assertLess(stop, dry)
        self.assertLess(dry, run)
        self.assertLess(run, start)
        # no copy of the holder, no divergence, no alert
        self.assertFalse(self.ran(server, "pg_basebackup"))
        self.assertIsNone(dbfollow.diverged(root))
        alerted.assert_not_called()
        # a standby of the holder on the pair's slot
        self.assertTrue(os.path.exists(os.path.join(root, STANDBY_SIGNAL)))
        with open(os.path.join(root, FOLLOW_DROPIN)) as fob:
            dropin = fob.read()
        self.assertIn(f"host={address(0)}", dropin)
        self.assertIn(f"primary_slot_name = '{dbpostgres.SLOT}'", dropin)
        self.assertIn("role=replica", self.role_file(1))

    def test_the_dry_run_comes_first_and_changes_nothing(self):
        server, found, _ = self.follow_old_primary()
        calls = [argv for argv in server.argv
                 if any(one.endswith("/pg_rewind") for one in argv)]
        self.assertEqual(len(calls), 2)
        self.assertIn("--dry-run", calls[0])
        self.assertNotIn("--dry-run", calls[1])

    def test_pg_rewind_gets_the_cluster_the_holder_and_the_tls(self):
        server, found, _ = self.follow_old_primary()
        call = next(argv for argv in server.argv
                    if any(one.endswith("/pg_rewind") for one in argv))
        self.assertEqual(call[:4], ["runuser", "-u", "postgres", "--"])
        text = " ".join(call)
        self.assertIn(f"--target-pgdata={self.all[1].root}/{DATADIR}", text)
        self.assertIn("--config-file=", text)
        self.assertIn("postgresql.conf", text)
        source = next(one for one in call
                      if one.startswith("--source-server="))
        self.assertIn(f"host={address(0)}", source)
        self.assertIn("dbname=postgres", source)
        self.assertIn("user=repl", source)
        self.assertIn("passfile=", source)
        self.assertIn("sslmode=verify-full", source)
        # the password is in the pgpass file, never in an argument
        self.assertNotIn("pw", source.replace("passfile", ""))

    def test_a_standby_that_follows_nobody_is_rewound_without_a_fence(self):
        self.pair_nodes()
        server = old_primary(in_recovery=True)
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertNotIn(["systemctl", "restart", UNIT], server.argv)
        self.assertIn(["systemctl", "start", UNIT], server.argv)

    def test_data_checksums_are_enough(self):
        server, found, _ = self.follow_old_primary(
            old_primary(settings=CHECKSUMS))
        self.assertIsNone(found.problem, found.lines)

    def test_without_wal_log_hints_or_checksums_the_fallback_applies(self):
        server, found, alerted = self.follow_old_primary(
            old_primary(settings="off\toff\ton\n"))
        self.assertIn("diverged", found.problem)
        self.assertIn("wal_log_hints", " ".join(found.lines))
        # the server is not stopped for a rewind that cannot work
        self.assertNotIn(["systemctl", "stop", UNIT], server.argv)
        self.assertFalse(self.ran(server, "pg_rewind"))
        self.assertEqual(alerted.call_count, 1)

    def test_without_full_page_writes_the_fallback_applies(self):
        server, found, _ = self.follow_old_primary(
            old_primary(settings="on\toff\toff\n"))
        self.assertIn("diverged", found.problem)
        self.assertIn("full_page_writes", " ".join(found.lines))

    def test_unknown_settings_keep_the_fallback(self):
        server, found, _ = self.follow_old_primary(
            old_primary(settings=""))
        self.assertIn("diverged", found.problem)
        self.assertIn("did not say", " ".join(found.lines))
        self.assertFalse(self.ran(server, "pg_rewind"))

    def test_a_missing_pg_rewind_keeps_the_fallback(self):
        self.pair_nodes()
        os.remove(os.path.join(self.all[1].root, "usr/lib/postgresql/17"
                               "/bin/pg_rewind"))
        found = self.follow(1, old_primary())
        self.assertIn("diverged", found.problem)
        self.assertIn("pg_rewind is not installed", " ".join(found.lines))

    def test_a_holder_that_is_a_standby_keeps_the_fallback(self):
        server, found, _ = self.follow_old_primary(
            old_primary(holder_standby=True))
        self.assertIn("diverged", found.problem)
        self.assertIn("is itself a standby", " ".join(found.lines))
        self.assertNotIn(["systemctl", "stop", UNIT], server.argv)

    def test_a_dry_run_that_fails_leaves_the_node_as_it_was(self):
        server, found, alerted = self.follow_old_primary(
            old_primary(rewind="refused"))
        self.assertIn("diverged", found.problem)
        self.assertIn("pg_rewind cannot rewind", " ".join(found.lines))
        self.assertIn("wal_log_hints", " ".join(found.lines))
        calls = [argv for argv in server.argv
                 if any(one.endswith("/pg_rewind") for one in argv)]
        self.assertEqual(len(calls), 1)
        # stopped for the dry run, started again as the fenced standby
        stop = server.argv.index(["systemctl", "stop", UNIT])
        start = server.argv.index(["systemctl", "start", UNIT])
        self.assertLess(stop, start)
        root = self.all[1].root
        self.assertTrue(os.path.exists(os.path.join(root, STANDBY_SIGNAL)))
        self.assertFalse(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))
        self.assertFalse(os.path.exists(
            os.path.join(root, dbpgrewind.FAILED)))
        self.assertEqual(dbfollow.diverged(root)["holder"], address(0))
        self.assertEqual(alerted.call_count, 1)

    def test_a_dry_run_that_fails_is_asked_again_by_the_next_follow(self):
        server, found, _ = self.follow_old_primary(
            old_primary(rewind="refused"))
        server.rewind = "ok"
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIsNone(dbfollow.diverged(self.all[1].root))

    def test_a_node_that_cannot_stop_is_not_changed(self):
        self.pair_nodes()
        server = old_primary()
        real = server.__call__

        def stop_fails(argv, **kwargs):
            if list(argv)[:2] == ["systemctl", "stop"]:
                return mock.Mock(returncode=1, stdout=b"",
                                 stderr=b"unit is masked")
            return real(argv, **kwargs)

        with mock.patch("keel.monitor.alerting.alert"):
            found = self.follow(1, mock.Mock(side_effect=stop_fails))
        self.assertIn("cannot stop", found.problem)
        self.assertIn("unit is masked", found.problem)

    def test_a_run_that_fails_halfway_makes_the_copy_unusable(self):
        server, found, _ = self.follow_old_primary(
            old_primary(rewind="halfway"))
        root = self.all[1].root
        self.assertIn("failed halfway", found.problem)
        self.assertIn("--destroy-local-database", found.problem)
        self.assertTrue(os.path.exists(os.path.join(root, dbpgrewind.FAILED)))
        self.assertFalse(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))
        self.assertFalse(self.ran(server, "pg_basebackup"))
        # started again, a standby that follows nobody
        self.assertIn(["systemctl", "start", UNIT], server.argv)
        # the next follow runs no pg_rewind, and says the same
        before = sum(any(one.endswith("/pg_rewind") for one in argv)
                     for argv in server.argv)
        found = self.follow(1, server)
        after = sum(any(one.endswith("/pg_rewind") for one in argv)
                    for argv in server.argv)
        self.assertEqual(before, after)
        self.assertIn("failed halfway", found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_the_confirmed_reseed_replaces_an_unusable_copy(self):
        server, found, _ = self.follow_old_primary(
            old_primary(rewind="halfway"))
        found = self.follow(1, server, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.ran(server, "pg_basebackup"))
        self.assertFalse(os.path.exists(
            os.path.join(self.all[1].root, dbpgrewind.FAILED)))

    def test_confirming_the_reseed_skips_the_rewind(self):
        server, found, _ = self.follow_old_primary(
            old_primary(), confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(self.ran(server, "pg_rewind"))
        self.assertTrue(self.ran(server, "pg_basebackup"))

    def test_a_standby_that_does_not_stream_goes_back_to_the_fence(self):
        server, found, _ = self.follow_old_primary(
            old_primary(streams=False))
        root = self.all[1].root
        self.assertIn("does not stream", found.problem)
        self.assertFalse(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))
        self.assertTrue(os.path.exists(os.path.join(root, STANDBY_SIGNAL)))
        self.assertFalse(os.path.exists(
            os.path.join(root, dbpgrewind.FAILED)))
        restarts = server.argv.count(["systemctl", "restart", UNIT])
        self.assertEqual(restarts, 2)

    def test_a_rewound_standby_that_caught_up_is_unfenced(self):
        self.pair_nodes()
        self.fence_vip(1)
        server = old_primary(positions="t\t0/4000098\t0/4000098\n")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(vipnode.current(self.all[1], VIP).fenced)
        self.assertIn(dbpgfollow.UNFENCED_SAID, found.lines)

    def fence_vip(self, index: int) -> None:
        from dataclasses import replace
        held = vipnode.current(self.all[index], VIP)
        vipstate.write(self.all[index].root, replace(held, fenced=True))


class Failing:
    """A server that fails one command: the first argument of the
    command that matches, and the nth time it runs (1 for the first)"""

    def __init__(self, server: Server, word, nth: int = 1,
                 detail: bytes = b"it failed"):
        self.server = server
        self.word = word
        self.nth = nth
        self.detail = detail
        self.seen = 0

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if (argv[:len(self.word)] == list(self.word)
                if isinstance(self.word, tuple)
                else any(self.word in one for one in argv)):
            self.seen += 1
            if self.seen == self.nth:
                return mock.Mock(returncode=1, stdout=b"",
                                 stderr=self.detail)
        return self.server(argv, **kwargs)

    def __getattr__(self, name):
        return getattr(self.server, name)


class TestWhatCanGoWrong(FollowTestCase):
    def run_follow(self, wrapper, **kwargs):
        self.pair_nodes()
        server = old_primary(**kwargs)
        failing = wrapper(server)
        with mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, failing)
        return server, failing, found

    def test_settings_that_cannot_be_asked_keep_the_fallback(self):
        server, _, found = self.run_follow(
            lambda one: Failing(one, "current_setting('wal_log_hints')"))
        self.assertIn("diverged", found.problem)
        self.assertIn("did not say its settings", " ".join(found.lines))

    def test_a_pgpass_that_cannot_be_written_keeps_the_fallback(self):
        self.pair_nodes()
        real = dbpgrewind.dbpgseed.write_pgpass
        calls = []

        def refuse(*args, **kwargs):
            # the timeline ask comes first and the rewind asks after it
            calls.append(args)
            if len(calls) > 1:
                raise OSError(13, "Permission denied")
            return real(*args, **kwargs)

        with mock.patch("keel.system.dbpgrewind.dbpgseed.write_pgpass",
                        side_effect=refuse), \
                mock.patch("keel.monitor.alerting.alert"):
            found = self.follow(1, old_primary())
        self.assertIn("diverged", found.problem)
        self.assertIn("Permission denied", " ".join(found.lines))

    def test_a_standby_signal_that_cannot_be_written_stops_the_rejoin(self):
        self.pair_nodes()
        with mock.patch("keel.system.dbpgrewind.dbpgseed.write_follow",
                        return_value="cannot write the standby files: no"):
            found = self.follow(1, old_primary())
        self.assertIn("rewound and could not start", found.problem)
        self.assertIn("cannot write the standby files", found.problem)

    def test_a_server_that_does_not_start_after_the_rewind_is_said(self):
        server, _, found = self.run_follow(
            lambda one: Failing(one, ("systemctl", "start", UNIT),
                            detail=b"no memory"))
        self.assertIn("rewound and could not start", found.problem)
        self.assertIn("no memory", found.problem)

    def test_a_server_that_does_not_start_after_a_dry_run_is_said(self):
        server, _, found = self.run_follow(
            lambda one: Failing(one, ("systemctl", "start", UNIT),
                            detail=b"no memory"),
            rewind="refused")
        self.assertIn("could not be started again", found.problem)

    def test_a_standby_signal_in_a_missing_directory_is_said(self):
        self.pair_nodes()
        real = os.open

        def refuse(path, *args, **kwargs):
            if str(path).endswith(dbpostgres.STANDBY_SIGNAL):
                raise OSError(13, "Permission denied")
            return real(path, *args, **kwargs)

        with mock.patch("keel.system.dbpgrewind.os.open", side_effect=refuse):
            found = self.follow(1, old_primary(in_recovery=True))
        self.assertIn("cannot write standby.signal", found.problem)

    def test_the_mark_that_cannot_be_written_still_stops_the_rewind(self):
        self.pair_nodes()
        server = old_primary(rewind="halfway")
        real = open

        def refuse(path, *args, **kwargs):
            if str(path).endswith(dbpgrewind.FAILED):
                raise OSError(13, "Permission denied")
            return real(path, *args, **kwargs)

        with mock.patch("keel.system.dbpgrewind.open", side_effect=refuse,
                        create=True):
            found = self.follow(1, server)
        self.assertIn("failed halfway", found.problem)

    def test_a_follow_drop_in_that_cannot_be_removed_is_not_an_error(self):
        self.pair_nodes()
        real = os.remove

        def refuse(path, *args, **kwargs):
            if str(path).endswith(dbpostgres.FOLLOW_DROPIN_NAME) and \
                    os.path.exists(path):
                raise OSError(13, "Permission denied")
            return real(path, *args, **kwargs)

        with mock.patch("keel.system.dbpgrewind.os.remove",
                        side_effect=refuse):
            found = self.follow(1, old_primary(streams=False))
        self.assertIn("does not stream", found.problem)

    def test_a_missing_mark_text_reads_as_no_detail(self):
        self.pair_nodes()
        text = dbpgrewind.unusable(self.all[1].root)
        self.assertIn("no detail", text)


class TestTheHolderGrants(FollowTestCase):
    def test_the_holder_grants_the_four_functions_on_each_follow(self):
        self.pair_nodes()
        server = Server(in_recovery=False)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        sent = "\n".join(server.sent)
        for name in dbpostgres.REWIND_FUNCTIONS:
            self.assertIn(f"GRANT EXECUTE ON FUNCTION {name}", sent)


class TestTheSettings(unittest.TestCase):
    def test_the_question_names_the_three_settings(self):
        for name in ("wal_log_hints", "data_checksums", "full_page_writes"):
            self.assertIn(name, dbpgrewind.SETTINGS_SQL)

    def test_the_reasons(self):
        self.assertEqual(dbpgrewind.unfit("on\toff\ton"), "")
        self.assertEqual(dbpgrewind.unfit("off\ton\ton"), "")
        self.assertIn("wal_log_hints", dbpgrewind.unfit("off\toff\ton"))
        self.assertIn("full_page_writes", dbpgrewind.unfit("on\ton\toff"))
        self.assertIn("did not say", dbpgrewind.unfit(""))
        self.assertIn("did not say", dbpgrewind.unfit("on"))


if __name__ == "__main__":
    unittest.main()
