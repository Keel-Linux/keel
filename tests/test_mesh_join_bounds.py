# Copyright (c) 2026 KeelLinux maintainers
"""A mesh join cannot wait for ever (keel#276)

The cycle that real tests found: `keel mesh members` applies a spec while
it holds the sync lock, and the plan starts keel-vip.service before it adds
the WireGuard peers. keel-vip.service is ordered after etcd.service, and
etcd says that it started only when a majority runs. On a node that needs
the new peer for its majority, the peer waits for the start, and the start
waits for the peer.
"""

import fcntl
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import exits
from keel.inspect.tree import File
from keel.mesh import bridge, memberd, sync
from keel.network import live, render, wgkeys
from keel.system import dbreadonly, dbseed, effects
from keel.system.actions import Attempt, Run, RunSql
from keel.system.appliance import plan_overlay
from keel.system.appstate import MANIFEST_MONIT, ApplianceState
from keel.inspect.monitor import Cycle
from keel.inspect.units import UnitState

JOBS = ("12 keel-vip.service start waiting\n"
        "\twaiting for job 11 (etcd.service/start)\n"
        "11 etcd.service start running\n")
FAKE_SYSTEMCTL = f"""#!/bin/sh
if [ "$1" = list-jobs ]; then
    cat <<'JOBS'
{JOBS}JOBS
    exit 0
fi
exec sleep 30
"""


class TestTheStartIsNotWaitedFor(unittest.TestCase):
    """The root cause: nothing in an apply waits for etcd's majority"""

    def vip_runs(self, waits: bool = False):
        unit = "keel-vip.service"
        state = ApplianceState(
            resolved=None, problems=(),
            units={unit: UnitState(unit, "enabled", "inactive")},
            monit_file=File("/r/" + MANIFEST_MONIT, problem="not present"),
            monit_link=None, monit_link_present=False,
            cycle=Cycle(30, "set daemon 30"), crowdsec=None, root="/",
            vip_waits=waits)
        step = plan_overlay("vip", "enabled", (unit,), state, True,
                            frozenset(("systemctl",)))
        return [action for action in step.actions if isinstance(action, Run)]

    def test_keel_vip_is_queued_once_the_cluster_exists(self):
        found = [run.argv for run in self.vip_runs()
                 if "start" in run.argv]
        self.assertEqual(found, [("systemctl", "start", "--no-block",
                                  "keel-vip.service")])

    def test_the_line_says_what_the_job_waits_for(self):
        started = [run for run in self.vip_runs() if "start" in run.argv]
        self.assertIn("etcd", started[0].summary)
        self.assertIn("majority", started[0].summary)

    def test_a_node_with_no_cluster_still_starts_nothing(self):
        self.assertEqual([run for run in self.vip_runs(waits=True)
                          if "start" in run.argv], [])

    def test_the_peers_come_after_the_overlays_so_the_order_matters(self):
        # why a blocking start stops the peer: plan_appliance is before
        # plan_overlay. A failed step does not stop the next step.
        with open(sys.modules["keel.system.plan"].__file__) as fob:
            text = fob.read()
        self.assertLess(text.index("plan_appliance(doc"),
                        text.index("plan_overlay(state.overlay"))


class StubbedPath(unittest.TestCase):
    def setUp(self):
        self.bin = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.bin)
        self.stub("systemctl", FAKE_SYSTEMCTL)
        path = mock.patch.dict(os.environ, {
            "PATH": f"{self.bin}:{os.environ['PATH']}"})
        path.start()
        self.addCleanup(path.stop)

    def stub(self, name: str, text: str) -> None:
        where = os.path.join(self.bin, name)
        with open(where, "w") as fob:
            fob.write(text)
        os.chmod(where, os.stat(where).st_mode | stat.S_IXUSR)


class TestEveryCommandHasABound(StubbedPath):
    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.effects = effects.Effects(self.root)

    def within(self, seconds: float, action):
        began = time.monotonic()
        found = self.effects.apply(action)
        self.assertLess(time.monotonic() - began, seconds)
        return found

    def test_a_start_stops_at_its_bound_and_names_the_job_it_waits_for(self):
        with mock.patch.object(effects, "UNIT_WAIT", 0.3):
            found = self.within(10, Run(
                ("systemctl", "start", "keel-vip.service"), "start"))
        self.assertIn("did not finish within 0.3 s", found)
        self.assertIn("etcd.service/start", found)
        self.assertIn("stays queued", found)

    def test_a_long_start_says_what_it_waits_for_while_it_waits(self):
        with mock.patch.object(effects, "UNIT_WAIT", 0.6), \
                mock.patch.object(effects, "NOTICE_AFTER", 0.1), \
                mock.patch("sys.stderr") as err:
            self.within(10, Run(("systemctl", "start", "keel-vip.service"),
                                "start"))
        said = "".join(call.args[0] for call in err.write.call_args_list)
        self.assertIn("keel-vip.service", said)
        self.assertIn("etcd.service/start", said)

    def test_a_database_unit_may_recover_for_longer(self):
        self.assertEqual(effects.bound(("systemctl", "restart",
                                        "postgresql@17-main.service")),
                         effects.DATABASE_UNIT_WAIT)
        self.assertEqual(effects.bound(("systemctl", "restart",
                                        "mariadb.service")),
                         effects.DATABASE_UNIT_WAIT)
        self.assertEqual(effects.bound(("systemctl", "start",
                                        "keel-vip.service")),
                         effects.UNIT_WAIT)

    def test_a_timeout_the_action_gives_stays_in_force(self):
        found = self.within(10, Run(("sleep", "30"), "wait", timeout=0.2))
        self.assertIn("within 0.2 s", found)

    def test_a_command_that_is_no_unit_has_a_bound_too(self):
        with mock.patch.object(effects, "COMMAND_WAIT", 0.2):
            found = self.within(10, Run(("sleep", "30"), "wait"))
        self.assertIn("did not finish within 0.2 s", found)

    def test_an_attempt_has_a_bound(self):
        with mock.patch.object(effects, "COMMAND_WAIT", 0.2):
            found = self.within(10, Attempt(("sleep", "30"), "wait", "then"))
        self.assertIn("did not finish", found)

    def test_statements_have_a_bound_and_are_not_said(self):
        with mock.patch.object(effects, "COMMAND_WAIT", 0.2):
            found = self.within(10, RunSql(("sleep", "30"), "SECRET;",
                                           "wait"))
        self.assertIn("did not finish", found)
        self.assertNotIn("SECRET", found)

    def test_no_block_needs_no_notice_and_works(self):
        self.stub("systemctl", "#!/bin/sh\nexit 0\n")
        self.assertIsNone(self.effects.apply(Run(
            ("systemctl", "start", "--no-block", "keel-vip.service"),
            "queue")))


class TestLiveHasABound(StubbedPath):
    def test_run_says_that_it_stopped(self):
        with mock.patch.object(live, "RUN_WAIT", 0.2):
            found = live.run(("sleep", "30"))
        self.assertIn("did not finish within 0.2 s", found)

    def test_output_is_no_answer(self):
        with mock.patch.object(live, "OUTPUT_WAIT", 0.2):
            self.assertIsNone(live.output(("sleep", "30")))


class TestSmallCommandsHaveABound(unittest.TestCase):
    def expired(self, *args, **kwargs):
        raise subprocess.TimeoutExpired("x", kwargs["timeout"])

    def test_the_render_of_an_interface(self):
        with tempfile.NamedTemporaryFile() as library, mock.patch(
                "keel.network.render.subprocess.run", self.expired):
            found = render.render(library.name, "eth0", "host", {})
        self.assertIn("did not finish", found.problem)

    def test_wg_writing_a_key(self):
        with tempfile.TemporaryFile("w") as fob, mock.patch(
                "keel.network.wgkeys.subprocess.run", self.expired):
            self.assertIn("did not finish",
                          wgkeys.run_to(("wg", "genkey"), fob))

    def test_wg_reading_a_public_key(self):
        with tempfile.NamedTemporaryFile() as key, mock.patch(
                "keel.network.wgkeys.secret_file_error", return_value=None), \
                mock.patch("keel.network.wgkeys.subprocess.run", self.expired):
            found = wgkeys.public(key.name)
        self.assertIsNone(found[0])
        self.assertIn("did not finish", found[1])


class TestTheLock(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.said = []

    def syncer(self, node=None):
        return sync.Syncer(node or mock.Mock(root=self.root),
                           lambda: datetime.now(timezone.utc),
                           self.said.append)

    def test_a_wait_ends_at_its_bound(self):
        with sync.sync_lock(self.root, 0, "the holder") as first:
            self.assertTrue(first)
            began = time.monotonic()
            with sync.sync_lock(self.root, 0.3, "the other") as second:
                self.assertFalse(second)
            self.assertLess(time.monotonic() - began, 5)

    def test_a_free_lock_is_taken_after_it_is_released(self):
        def holder():
            with sync.sync_lock(self.root, 0, "a holder"):
                time.sleep(0.3)
        thread = threading.Thread(target=holder)
        thread.start()
        time.sleep(0.05)
        with sync.sync_lock(self.root, 5, "the other") as held:
            self.assertTrue(held)
        thread.join()

    def test_the_lock_says_who_holds_it(self):
        with sync.sync_lock(self.root, 0, "keel mesh sync"):
            found = sync.holder(self.root)
        self.assertIn("keel mesh sync", found)
        self.assertIn(str(os.getpid()), found)

    def test_an_announcement_does_not_wait_for_ever(self):
        node = mock.Mock(root=self.root)
        node.public_key.return_value = ("key", "")
        with sync.sync_lock(self.root, 0, "the stuck holder"), \
                mock.patch.object(sync, "LOCK_WAIT", 0.3), \
                mock.patch.object(sync, "absorb") as absorbed:
            found = sync.announced(self.syncer(node), [])
        self.assertEqual(found, exits.MESH_REFUSED)
        absorbed.assert_not_called()
        said = "\n".join(self.said)
        self.assertIn("the stuck holder", said)
        self.assertIn("next keel mesh sync", said)


class TestTheBridge(unittest.TestCase):
    def test_half_a_message_does_not_hold_the_root_side(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        theirs.sendall(b"{half")
        with mock.patch.object(memberd, "MESSAGE_WAIT", 0.2), \
                self.assertRaises(OSError):
            memberd.message(ours, threading.Event(), poll=0.1)


class TestTheDatabasePath(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def test_a_held_replication_lock_ends_as_an_os_error(self):
        path = os.path.join(self.root, dbreadonly.REPLICATION_LOCK)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        results = []

        def waiter():
            try:
                with dbreadonly.replication_locked(self.root):
                    results.append("held")
            except OSError as e:
                results.append(str(e))
        with mock.patch.object(dbreadonly, "REPLICATION_WAIT", 0.2):
            thread = threading.Thread(target=waiter)
            thread.start()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertIn("replication", results[0])
        self.assertIn("0.2 s", results[0])

    def test_a_client_of_a_seed_stops_at_its_bound(self):
        with mock.patch.object(dbseed, "SEED_WAIT", 0.2):
            found = dbseed._run(subprocess.run, ("sleep", "30"))
        self.assertIn("did not finish within 0.2 s", found)


if __name__ == "__main__":
    unittest.main()
