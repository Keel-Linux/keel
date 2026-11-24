# Copyright (c) 2026 KeelLinux maintainers
"""One lock for the apply and the firewall's repair (decision 0097)

The sixth real test: a person's apply and the watch's repair ran at the
same moment, and the apply failed (`write ...: failed`). Both take
/run/keel/firewall.lock now: the apply waits for a repair (which holds
it a few seconds), the repair waits a short time for an apply and then
skips this run, so a repair never makes an apply fail.
"""

import os
import tempfile
import threading
import unittest
from unittest import mock

from keel import commands, exits
from keel.system import fwlock, fwrepair


class LockCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.root = self.tmp.name
        self.addCleanup(self.tmp.cleanup)

    def holding(self):
        taken, release = threading.Event(), threading.Event()

        def holder():
            with fwlock.held(self.root, 0) as held:
                assert held
                taken.set()
                release.wait(30)
        thread = threading.Thread(target=holder)
        thread.start()
        taken.wait(5)
        return thread, release


class TestLock(LockCase):
    def test_one_holder_at_a_time(self):
        thread, release = self.holding()
        try:
            with fwlock.held(self.root, 0.2) as held:
                self.assertFalse(held)
        finally:
            release.set()
            thread.join()
        with fwlock.held(self.root, 0) as held:
            self.assertTrue(held)

    def test_the_repair_skips_while_an_apply_holds_it(self):
        thread, release = self.holding()
        try:
            with mock.patch("keel.system.fwrepair.LOCK_WAIT", 0.2), \
                    mock.patch("keel.system.fwrepair.attempt") as attempt:
                code, lines = fwrepair.repair(self.root, live=False,
                                              lock=True)
        finally:
            release.set()
            thread.join()
        self.assertEqual(code, exits.OK)
        self.assertIn("an apply holds", lines[0])
        attempt.assert_not_called()

    def test_the_live_apply_runs_its_plan_under_the_lock(self):
        seen = {}

        def execute(*args, **kwargs):
            with fwlock.held(self.root, 0) as free:
                seen["free"] = free
            return mock.Mock(lines=(), failed=0, summary=lambda: "ok")
        with mock.patch("keel.commands.manifest_facts", return_value=None), \
                mock.patch("keel.system.filesync.undeclared_problem",
                           return_value=None), \
                mock.patch("keel.system.observe"), \
                mock.patch("keel.system.plan") as plan, \
                mock.patch("keel.system.execute", side_effect=execute), \
                mock.patch("keel.commands.ROOT_DEFAULT", self.root), \
                mock.patch("keel.commands.record_overlays"):
            plan.return_value.steps = (1,)
            code = commands.apply_system({"version": 1}, self.root, False)
        self.assertEqual(code, exits.OK)
        self.assertEqual(seen, {"free": False})


if __name__ == "__main__":
    unittest.main()
