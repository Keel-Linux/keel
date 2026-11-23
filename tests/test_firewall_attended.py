# Copyright (c) 2026 KeelLinux maintainers
"""Who may begin enforcement (decision 0097, section 5)

`keel spec apply --system` is an apply a person runs (the first boot
hook and confconsole run the same command for the person who installs or
configures the node). keel mesh applies the whole spec with no person:
keel-mesh-sync.timer every 15 minutes, and keel-mesh-members on a path.
So the flag that lets rule B begin enforcement comes from the command
line only, and the mesh's apply never passes it.
"""

import argparse
import contextlib
import inspect
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from keel import commands, exits
from keel.mesh import node
from keel.system.plan import plan


class TestAttended(unittest.TestCase):
    def test_keel_mesh_applies_unattended(self):
        with mock.patch("keel.mesh.node.apply_system",
                        return_value=0) as apply:
            node.live_apply({"version": 1}, "/r", 60)
        self.assertIs(apply.call_args.kwargs["attended"], False)

    def test_keel_spec_apply_is_attended(self):
        args = argparse.Namespace(spec="/r/i.yaml", conf="/r/c",
                                  system_only=True, root="/r")
        with mock.patch("keel.commands.read_spec",
                        return_value=({"version": 1}, 0)), \
                mock.patch("keel.commands.apply_system",
                           return_value=1) as apply:
            commands.spec_apply(args)
        self.assertIs(apply.call_args.kwargs["attended"], True)

    def test_apply_system_hands_the_flag_to_the_plan(self):
        for attended in (True, False):
            with mock.patch("keel.commands.manifest_facts",
                            return_value=None), \
                    mock.patch("keel.system.filesync.undeclared_problem",
                               return_value=None), \
                    mock.patch("keel.system.observe"), \
                    mock.patch("keel.system.plan") as planned:
                planned.return_value.steps = ()
                commands.apply_system({"version": 1}, "/r", True,
                                      attended=attended)
            self.assertIs(planned.call_args.kwargs["attended"], attended)

    def test_the_plan_is_unattended_unless_told(self):
        for function in (plan, commands.apply_system):
            self.assertIs(inspect.signature(function).parameters[
                "attended"].default, False)


class TestOneApplyAtATime(unittest.TestCase):
    """The review of 86370ed: a person's apply and keel mesh's apply
    could interleave, and the mesh could write report over the enforce
    the person just wrote. keel spec apply on the live system takes the
    lock keel mesh sync and the members' channel take."""

    def args(self, root="/", dry_run=False):
        return argparse.Namespace(spec="/r/i.yaml", conf="/r/c",
                                  system_only=True, root=root,
                                  dry_run=dry_run)

    def run_apply(self, args, held=True):
        seen = {}

        @contextlib.contextmanager
        def lock(root, wait, what="", say=None):
            seen["lock"] = (root, what)
            seen["inside"] = True
            yield held
            seen["inside"] = False

        def apply(*a, **k):
            seen["applied_inside"] = seen.get("inside", False)
            return 0
        with mock.patch("keel.commands.read_spec",
                        return_value=({"version": 1}, 0)), \
                mock.patch("keel.mesh.sync.sync_lock", lock), \
                mock.patch("keel.system.needs_root", return_value=None), \
                mock.patch("keel.commands.apply_system", side_effect=apply), \
                mock.patch("keel.system.bootrefusal.clear"):
            code = commands.spec_apply(args)
        return code, seen

    def test_the_live_apply_runs_under_the_sync_lock(self):
        with mock.patch("keel.commands.os.path.isdir", return_value=True):
            code, seen = self.run_apply(self.args())
        self.assertEqual(code, 0)
        self.assertEqual(seen["lock"], ("/", "keel spec apply"))
        self.assertTrue(seen["applied_inside"])

    def test_a_lock_that_does_not_come_fails_and_applies_nothing(self):
        with mock.patch("keel.commands.os.path.isdir", return_value=True):
            code, seen = self.run_apply(self.args(), held=False)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertNotIn("applied_inside", seen)

    def test_no_mesh_directory_takes_no_lock_and_makes_none(self):
        """the second review (N9): every apply created /var/lib/keel/mesh
        on nodes with no mesh; with no mesh no mesh apply can run"""
        with tempfile.TemporaryDirectory(
                dir=os.environ.get("TMPDIR")) as root:
            with mock.patch("keel.commands.ROOT_DEFAULT", root):
                with commands.apply_lock(root, False) as held:
                    self.assertTrue(held)
            self.assertFalse(os.path.exists(os.path.join(
                root, "var/lib/keel/mesh")))

    def test_a_lock_that_cannot_be_opened_says_why(self):
        with tempfile.TemporaryDirectory(
                dir=os.environ.get("TMPDIR")) as root:
            os.makedirs(os.path.join(root, "var/lib/keel/mesh"))

            def broken(*args, **kwargs):
                raise PermissionError(13, "Permission denied")
            with mock.patch("keel.commands.ROOT_DEFAULT", root), \
                    mock.patch("keel.mesh.sync.sync_lock", broken), \
                    self.assertRaisesRegex(commands.LockError,
                                           "Permission denied"):
                with commands.apply_lock(root, False):
                    pass

    def test_a_root_or_a_dry_run_takes_no_lock(self):
        for args in (self.args(root="/srv/image"), self.args(dry_run=True)):
            code, seen = self.run_apply(args)
            self.assertNotIn("lock", seen)
            self.assertTrue("applied_inside" in seen)


class TestMeshChangesUnderTheLock(unittest.TestCase):
    """The second review (N7): invite admission, join, create and the
    etcd start apply through Node.change without the sync lock, so one
    could write report over a person's enforce. Node.change now holds
    it; inside keel mesh sync, which holds it already in the same
    thread, it does not wait for itself."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def node(self, seen):
        from keel.mesh import sync

        def apply(doc, root, window):
            # another thread may not take the lock while this applies
            result = {}

            def other():
                with sync.sync_lock(root, 0, "other") as held:
                    result["held"] = held
            thread = threading.Thread(target=other)
            thread.start()
            thread.join()
            seen.append(result["held"])
            return 0
        found = node.Node(self.root, os.path.join(self.root, "i.yaml"),
                          apply=apply)
        found.write = lambda doc: None
        return found

    def test_a_change_applies_under_the_lock(self):
        seen = []
        self.node(seen).change({"version": 1})
        self.assertEqual(seen, [False])

    def test_inside_sync_s_own_lock_it_does_not_wait(self):
        from keel.mesh import sync
        seen = []
        began = time.monotonic()
        with sync.sync_lock(self.root, 0, "keel mesh sync") as held:
            self.assertTrue(held)
            self.node(seen).change({"version": 1})
        self.assertLess(time.monotonic() - began, 5)
        self.assertEqual(seen, [False])

    def test_the_lock_stays_one_per_process_elsewhere(self):
        from keel.mesh import sync
        with sync.sync_lock(self.root, 0, "first") as first:
            with sync.sync_lock(self.root, 0, "second") as second:
                self.assertEqual((first, second), (True, False))


class TestImports(unittest.TestCase):
    """keel.manifest imports keel.spec while it loads: the firewall's
    modules must import alone, in a fresh interpreter, whatever comes
    first (the database guard's ExecStartPre imports keel.manifest
    first, and a cycle failed the server's start)"""

    def test_each_firewall_module_imports_alone(self):
        import subprocess
        import sys
        for name in ("keel.manifest.monit", "keel.manifest.firewall",
                     "keel.spec.validate_firewall", "keel.system.firewall",
                     "keel.system.listeners", "keel.system.fwcheck",
                     "keel.diff.appliance", "keel.manifest"):
            with self.subTest(module=name):
                done = subprocess.run([sys.executable, "-c",
                                       f"import {name}"],
                                      capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
