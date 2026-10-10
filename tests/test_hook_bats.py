# Copyright (c) 2026 KeelLinux maintainers
"""Run the bats suite of the firstboot hook inside the one gate job

The hook is shell, so it is tested with bats (tests/hook.bats). The
repository has a single required check, "tests / coverage", so the suite
runs from pytest instead of a second job that nothing requires: a failing
hook test fails the gate the same way a failing Python test does.

bats and shellcheck are installed by the workflow (apt-packages). On a
workstation without bats the test skips, but never in CI, where a silent
skip would mean the hook is not tested at all.
"""

import os
import shutil
import subprocess
import unittest
from os.path import abspath, dirname, join

HERE = dirname(abspath(__file__))
SUITE = join(HERE, "hook.bats")
# the package's postinst (keel#139)
POSTINST_SUITE = join(HERE, "postinst.bats")
HOOK = join(dirname(HERE), "firstboot.d", "10keel-system")


class TestHookSuite(unittest.TestCase):
    def test_the_hook_is_executable_and_its_suite_is_there(self):
        self.assertTrue(os.access(HOOK, os.X_OK), HOOK)
        self.assertTrue(os.path.exists(SUITE), SUITE)

    def test_bats_reports_every_hook_test_passing(self):
        bats = shutil.which("bats")
        if bats is None:
            if os.environ.get("CI"):
                self.fail("bats is not installed in CI: the hook suite"
                          " would not run, see .github/workflows/tests.yml")
            self.skipTest("bats is not installed")
        done = subprocess.run(
            [bats, SUITE], capture_output=True, text=True, check=False,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ok 1 ", done.stdout)

    def test_bats_reports_every_postinst_test_passing(self):
        bats = shutil.which("bats")
        if bats is None:
            if os.environ.get("CI"):
                self.fail("bats is not installed in CI: the postinst suite"
                          " would not run, see .github/workflows/tests.yml")
            self.skipTest("bats is not installed")
        done = subprocess.run([bats, POSTINST_SUITE], capture_output=True,
                              text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("ok 3 ", done.stdout)
