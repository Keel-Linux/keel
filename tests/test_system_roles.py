# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.roles: the hooks an application ships for the pair's flip

After keel flips the database's role it runs each executable of
/usr/lib/keel/roles.d/ with `primary` or `replica` (0050's amendment,
point 7). They run as root, so a directory or an entry that is not
root's, is writable by group or others, or is a link outside
/usr/lib/keel is not run and the reason is said; what dpkg leaves behind
(.dpkg-old) is not a hook, by run-parts(8)'s naming.
"""

import os
import subprocess
import unittest
from unittest import mock

from manifest_helpers import ManifestCase

from keel.system import roles


class RoleCase(ManifestCase):
    def setUp(self):
        super().setUp()
        self.full = os.path.join(self.root, roles.DIR.lstrip("/"))
        os.makedirs(self.full)
        os.chmod(self.full, 0o755)
        self.said = []

    def hook(self, name: str, text: str = "#!/bin/sh\n",
             mode: int = 0o755) -> str:
        path = os.path.join(self.full, name)
        with open(path, "w") as fob:
            fob.write(text)
        os.chmod(path, mode)
        return f"{roles.DIR}/{name}"

    def ran_hooks(self, role: str = "primary"):
        with mock.patch("keel.system.roles.subprocess.run") as ran:
            roles.run(self.root, role, None, self.said.append)
        return [call.args[0] for call in ran.call_args_list]


class TestTheHooks(RoleCase):
    def test_no_directory_is_no_hook(self):
        os.rmdir(self.full)
        found, problems = roles.hooks(self.root)
        self.assertEqual(found, ())
        self.assertEqual(problems, ())

    def test_a_safe_executable_is_a_hook(self):
        path = self.hook("10scan")
        found, problems = roles.hooks(self.root)
        self.assertEqual(problems, ())
        self.assertEqual([one.path for one in found], [path])
        self.assertEqual(found[0].timeout, roles.TIMEOUT)

    def test_what_dpkg_leaves_behind_is_not_a_hook(self):
        self.hook("10scan.dpkg-old")
        self.hook("20scan.dpkg-new")
        self.hook("30scan~")
        found, _ = roles.hooks(self.root)
        self.assertEqual(found, ())

    def test_a_directory_entry_is_not_a_hook(self):
        os.makedirs(os.path.join(self.full, "adir"))
        self.assertEqual(roles.hooks(self.root), ((), ()))

    def test_a_group_writable_hook_is_refused(self):
        path = self.hook("10scan")
        os.chmod(os.path.join(self.full, "10scan"), 0o775)
        found, problems = roles.hooks(self.root)
        self.assertEqual(found, ())
        self.assertTrue(any("writable by group or others" in one
                            for one in problems))
        self.assertIn(path, problems[0])

    def test_a_link_outside_keel_is_refused(self):
        outside = os.path.join(self.root, "etc", "evil")
        os.makedirs(os.path.dirname(outside))
        with open(outside, "w") as fob:
            fob.write("#!/bin/sh\n")
        os.symlink("../../../../etc/evil",
                   os.path.join(self.full, "10scan"))
        found, problems = roles.hooks(self.root)
        self.assertEqual(found, ())
        self.assertTrue(any("outside" in one for one in problems))

    def test_a_link_inside_keel_is_a_hook(self):
        target = os.path.join(self.root, "usr", "lib", "keel", "scan")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fob:
            fob.write("#!/bin/sh\n")
        os.chmod(target, 0o755)
        os.symlink("../scan", os.path.join(self.full, "10scan"))
        found, problems = roles.hooks(self.root)
        self.assertEqual(problems, ())
        self.assertEqual([one.path for one in found],
                         [f"{roles.DIR}/10scan"])

    def test_a_non_executable_is_not_a_hook_but_is_no_problem(self):
        self.hook("10scan", mode=0o644)
        found, problems = roles.hooks(self.root)
        self.assertEqual((found, problems), ((), ()))

    def test_an_entry_gone_mid_read_is_refused_never_a_crash(self):
        os.symlink("../gone", os.path.join(self.full, "10scan"))
        found, problems = roles.hooks(self.root)
        self.assertEqual(found, ())
        self.assertTrue(any("cannot be read" in one for one in problems))


class TestTheRun(RoleCase):
    def ran_with(self, role="primary", done=None):
        calls = []

        def runner(argv, **kwargs):
            calls.append((list(argv), kwargs))
            return done or subprocess.CompletedProcess(argv, 0, "", "")

        roles.run(self.root, role, runner, self.said.append)
        return calls

    def test_every_hook_runs_with_the_role_in_name_order(self):
        first = self.hook("10first")
        second = self.hook("20second")
        calls = self.ran_with("replica")
        self.assertEqual([one[0] for one in calls],
                         [[first, "replica"], [second, "replica"]])

    def test_a_failing_hook_is_said_with_its_tail(self):
        self.hook("10scan")
        done = subprocess.CompletedProcess([], 1, "", "boom: no scan\n")
        self.ran_with(done=done)
        self.assertTrue(any("10scan primary: failed (1)" in one
                            for one in self.said))
        self.assertTrue(any("boom: no scan" in one for one in self.said))

    def test_an_unsafe_directory_is_said_and_nothing_runs(self):
        os.chmod(self.full, 0o777)
        self.hook("10scan")
        self.assertEqual(self.ran_with(), [])
        self.assertTrue(any("writable by group or others" in one
                            for one in self.said))

    def test_the_runner_gets_the_timeout_and_the_capture(self):
        self.hook("10scan")
        calls = self.ran_with()
        self.assertEqual(calls[0][1]["timeout"], roles.TIMEOUT)
        self.assertTrue(calls[0][1]["capture_output"])
        self.assertFalse(calls[0][1]["check"])

    def test_a_hook_runs_with_a_minimal_environment_in_its_own_session(
            self):
        self.hook("10scan")
        calls = self.ran_with()
        kwargs = calls[0][1]
        self.assertEqual(kwargs["env"], roles.ENV)
        self.assertEqual(set(kwargs["env"]), {"PATH", "LANG"})
        self.assertEqual(kwargs["cwd"], "/")
        self.assertTrue(kwargs["start_new_session"])

    def test_the_failed_hooks_are_named_in_the_result(self):
        first = self.hook("10scan")
        self.hook("20ok")
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv[0])
            return subprocess.CompletedProcess(
                argv, 1 if argv[0] == first else 0, "", "")

        failed = roles.run(self.root, "primary", runner, self.said.append)
        self.assertEqual(failed, [first])
        self.assertEqual(len(calls), 2)

    def test_a_hook_that_succeeds_fails_nothing(self):
        self.hook("10scan")
        failed = roles.run(self.root, "primary", lambda argv, **kw:
                           subprocess.CompletedProcess(argv, 0, "", ""),
                           self.said.append)
        self.assertEqual(failed, [])

    def test_a_hook_that_takes_too_long_is_a_failure_not_a_crash(self):
        path = self.hook("10scan")
        later = self.hook("20next")
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv[0])
            if argv[0] == path:
                raise subprocess.TimeoutExpired(argv, 120)
            return subprocess.CompletedProcess(argv, 0, "", "")

        failed = roles.run(self.root, "primary", runner, self.said.append)
        self.assertEqual(failed, [path])
        self.assertEqual(calls, [path, later])
        self.assertTrue(any("stopped after 120 s" in one
                            for one in self.said))

    def test_a_hook_that_cannot_be_started_is_a_failure(self):
        path = self.hook("10scan")

        def runner(argv, **kwargs):
            raise PermissionError(13, "Permission denied")

        failed = roles.run(self.root, "primary", runner, self.said.append)
        self.assertEqual(failed, [path])
        self.assertTrue(any("cannot be run" in one for one in self.said))


if __name__ == "__main__":
    unittest.main()
