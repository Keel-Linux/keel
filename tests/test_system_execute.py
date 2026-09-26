# Copyright (c) 2026 KeelLinux maintainers
"""The effects module and the executor, against a scratch tree

Effects are the only code of apply --system with side effects; here they
run against a temporary root, with subprocess.run replaced so that no
command touches the machine. The executor is tested with a fake effects
object, one branch each: done, failed, skipped after a failure, dry run.
"""

import os
import subprocess
import tempfile
import unittest
from os.path import join, lexists
from unittest import mock

from helpers import spec  # noqa: F401

from keel.system import Effects, execute
from keel.system.actions import (
    MakeDir,
    Note,
    Plan,
    Run,
    Step,
    Symlink,
    WriteFile,
)

PASSWD = f"bob:x:{os.getuid()}:{os.getgid()}::/home/bob:/bin/sh\n"


def completed(code: int, out: str = "", err: str = ""):
    return subprocess.CompletedProcess(["x"], code, out, err)


class EffectsTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(join(self.root, "etc"))
        with open(join(self.root, "etc", "passwd"), "w") as fob:
            fob.write(PASSWD)
        self.effects = Effects(self.root)


class TestEffects(EffectsTestCase):
    def test_run_reports_exit_codes_and_missing_commands(self):
        with mock.patch.object(subprocess, "run", return_value=completed(0)):
            self.assertIsNone(self.effects.apply(Run(("true",), "ok")))
        with mock.patch.object(subprocess, "run",
                               return_value=completed(9, "", "bad\n")):
            self.assertEqual(self.effects.apply(Run(("useradd", "x"), "c")),
                             "useradd exited 9: bad")
        with mock.patch.object(subprocess, "run",
                               return_value=completed(1, "on stdout\n", "")):
            self.assertEqual(self.effects.apply(Run(("t",), "c")),
                             "t exited 1: on stdout")
        with mock.patch.object(subprocess, "run",
                               side_effect=OSError(2, "No such file")):
            self.assertEqual(self.effects.apply(Run(("nope",), "c")),
                             "cannot run nope: No such file")

    def test_run_passes_the_argv_list_and_no_shell(self):
        with mock.patch.object(subprocess, "run",
                               return_value=completed(0)) as run:
            self.effects.apply(Run(("useradd", "--create-home", "a"), "c"))
        self.assertEqual(run.call_args.args, (["useradd", "--create-home",
                                               "a"],))
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_write_sets_content_mode_and_owner(self):
        os.makedirs(join(self.root, "home", "bob", ".ssh"))
        action = WriteFile("home/bob/.ssh/authorized_keys", "k\n", 0o600,
                           "bob", "write")
        self.assertIsNone(self.effects.apply(action))
        path = join(self.root, "home", "bob", ".ssh", "authorized_keys")
        with open(path) as fob:
            self.assertEqual(fob.read(), "k\n")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(path).st_uid, os.getuid())

    def test_write_tightens_the_mode_of_an_existing_file(self):
        path = join(self.root, "etc", "timezone")
        with open(path, "w") as fob:
            fob.write("Etc/UTC\n")
        os.chmod(path, 0o666)
        self.effects.apply(WriteFile("etc/timezone", "Europe/Lisbon\n", 0o644,
                                     None, "write"))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        with open(path) as fob:
            self.assertEqual(fob.read(), "Europe/Lisbon\n")

    def test_an_unknown_owner_is_a_failure_after_the_write(self):
        action = WriteFile("etc/x", "", 0o644, "ghost", "write")
        self.assertEqual(
            self.effects.apply(action),
            f"owner not set: ghost has no entry in {self.root}/etc/passwd",
        )
        self.assertTrue(lexists(join(self.root, "etc", "x")))

    def test_make_dir_is_idempotent_and_owned(self):
        action = MakeDir("home/bob/.ssh", 0o700, "bob", "ensure")
        self.assertIsNone(self.effects.apply(action))
        self.assertIsNone(self.effects.apply(action))
        path = join(self.root, "home", "bob", ".ssh")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)

    def test_symlink_replaces_a_file_or_an_old_link(self):
        path = join(self.root, "etc", "localtime")
        with open(path, "w") as fob:
            fob.write("binary\n")
        action = Symlink("etc/localtime", "/usr/share/zoneinfo/Etc/UTC", "l")
        self.assertIsNone(self.effects.apply(action))
        self.assertEqual(os.readlink(path), "/usr/share/zoneinfo/Etc/UTC")
        again = Symlink("etc/localtime", "/usr/share/zoneinfo/Europe/Lisbon",
                        "l")
        self.assertIsNone(self.effects.apply(again))
        self.assertEqual(os.readlink(path), "/usr/share/zoneinfo/Europe/Lisbon")

    def test_write_makes_a_missing_parent_directory(self):
        action = WriteFile("etc/default/locale", "LANG=C\n", 0o644, None, "w")
        self.assertIsNone(self.effects.apply(action))
        with open(join(self.root, "etc", "default", "locale")) as fob:
            self.assertEqual(fob.read(), "LANG=C\n")

    def test_os_errors_are_returned_not_raised(self):
        with open(join(self.root, "etc", "blocker"), "w") as fob:
            fob.write("a file where a directory is needed\n")
        under_file = WriteFile("etc/blocker/file", "", 0o644, None, "w")
        self.assertIn("File exists", self.effects.apply(under_file))
        with mock.patch("os.chown", side_effect=PermissionError(1, "Denied")):
            action = MakeDir("home/bob", 0o755, "bob", "ensure")
            self.assertEqual(self.effects.apply(action), "Denied")
        with mock.patch("os.symlink", side_effect=OSError("plain")):
            self.assertEqual(self.effects.apply(Symlink("etc/l", "t", "l")),
                             "plain")


class FakeEffects:
    """Records actions; fails the ones whose summary says so"""

    def __init__(self):
        self.applied = []

    def apply(self, action):
        self.applied.append(action)
        return "boom" if "fail" in action.summary else None


class TestExecute(unittest.TestCase):
    PLAN = Plan((
        Step("users.bob", (Run(("useradd", "bob"), "create user bob"),)),
        Step("users.bob.authorized_keys", (
            MakeDir("home/bob/.ssh", 0o700, "bob", "ensure /home/bob/.ssh"),
            WriteFile("home/bob/.ssh/authorized_keys", "", 0o600, "bob",
                      "write keys"),
        )),
        Step("locale.timezone", (Note("unchanged (Etc/UTC)"),)),
    ))

    def test_every_action_is_applied_and_reported(self):
        effects = FakeEffects()
        outcome = execute(self.PLAN, effects)
        self.assertEqual(len(effects.applied), 3)
        self.assertEqual((outcome.changed, outcome.failed), (3, 0))
        self.assertEqual(outcome.lines, (
            "users.bob: create user bob (useradd bob): done",
            "users.bob.authorized_keys: ensure /home/bob/.ssh (mode 0700,"
            " owner bob): done",
            "users.bob.authorized_keys: write keys (mode 0600, owner bob):"
            " done",
            "locale.timezone: unchanged (Etc/UTC)",
        ))
        self.assertEqual(outcome.summary(),
                         "apply --system: 3 change(s), 0 failed")

    def test_a_failure_skips_the_rest_of_its_step_only(self):
        broken = Plan((
            Step("users.bob.authorized_keys", (
                MakeDir("home/bob/.ssh", 0o700, "bob", "fail here"),
                WriteFile("home/bob/.ssh/authorized_keys", "", 0o600, "bob",
                          "write keys"),
            )),
            Step("locale.timezone", (WriteFile("etc/timezone", "", 0o644,
                                               None, "write tz"),)),
        ))
        effects = FakeEffects()
        outcome = execute(broken, effects)
        self.assertEqual(len(effects.applied), 2)
        self.assertEqual((outcome.changed, outcome.failed), (1, 1))
        self.assertEqual(outcome.lines[0], (
            "users.bob.authorized_keys: fail here (mode 0700, owner bob):"
            " failed: boom"
        ))
        self.assertTrue(outcome.lines[1].startswith(
            "users.bob.authorized_keys: skipped: write keys"
        ))
        self.assertTrue(outcome.lines[2].endswith(": done"))

    def test_a_dry_run_applies_nothing_and_counts_the_plan(self):
        effects = FakeEffects()
        outcome = execute(self.PLAN, effects, dry_run=True)
        self.assertEqual(effects.applied, [])
        self.assertEqual(outcome.changed, 3)
        self.assertEqual(outcome.lines[0],
                         "users.bob: would create user bob (useradd bob)")
        self.assertEqual(outcome.lines[-1],
                         "locale.timezone: unchanged (Etc/UTC)")
        self.assertEqual(outcome.summary(),
                         "dry run: 3 change(s) planned, nothing written")


if __name__ == "__main__":
    unittest.main()
