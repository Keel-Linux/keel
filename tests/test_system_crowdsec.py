# Copyright (c) 2026 KeelLinux maintainers
"""CrowdSec's identity on the first enable (tracker#47), and Attempt

add_bouncer runs cscli with subprocess, which is replaced here, so the
key it prints can be followed: into the `.local` file, mode 0600, and
nowhere else. The executor's Attempt is a command whose failure the run
survives.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.system import Effects, execute
from keel.system.actions import AddBouncer, Attempt, Plan, Run, Step
from keel.system.crowdsec import (
    BOUNCER,
    BOUNCER_ID,
    PENDING,
    add_bouncer,
    value_of,
)

KEY = "c2VjcmV0LWJvdW5jZXIta2V5"


class Cscli:
    """subprocess.run for cscli: records argv, answers `bouncers add`"""

    def __init__(self, code: int = 0, out: str = f"{KEY}\n",
                 err: str = ""):
        self.calls = []
        self.code, self.out, self.err = code, out, err

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if "add" in argv:
            return subprocess.CompletedProcess(argv, self.code, self.out,
                                               self.err)
        return subprocess.CompletedProcess(argv, 1, "", "not found\n")


class TestAddBouncer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def add(self, cscli: Cscli, old_id: str | None = None,
            mode: str = "nftables") -> str | None:
        action = AddBouncer(BOUNCER, BOUNCER_ID, mode, old_id)
        with mock.patch("keel.system.crowdsec.subprocess.run", cscli):
            return Effects(self.root).apply(action)

    def read(self, path: str) -> str:
        with open(join(self.root, path)) as fob:
            return fob.read()

    def test_the_key_goes_to_the_local_file_only(self):
        cscli = Cscli()
        self.assertIsNone(self.add(cscli))
        name = cscli.calls[0][-1]
        self.assertTrue(name.startswith("FirewallBouncer-"))
        self.assertEqual(cscli.calls, [
            ("cscli", "--error", "-oraw", "bouncers", "add", name)])
        self.assertEqual(self.read(BOUNCER),
                         f"mode: nftables\napi_key: {KEY}\n")
        info = os.stat(join(self.root, BOUNCER))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(self.read(BOUNCER_ID), f"{name}\n")
        self.assertNotIn(KEY, AddBouncer(BOUNCER, BOUNCER_ID, "nftables",
                                         None).describe())

    def test_the_old_bouncer_goes_and_other_settings_stay(self):
        os.makedirs(os.path.dirname(join(self.root, BOUNCER)))
        with open(join(self.root, BOUNCER), "w") as fob:
            fob.write("mode: iptables\napi_key: old\nlog_level: debug\n")
        cscli = Cscli()
        self.assertIsNone(self.add(cscli, "FirewallBouncer-old", "iptables"))
        self.assertEqual(cscli.calls[0], ("cscli", "--error", "bouncers",
                                          "delete", "FirewallBouncer-old"))
        self.assertEqual(self.read(BOUNCER), (
            f"mode: iptables\napi_key: {KEY}\nlog_level: debug\n"))

    def test_a_pending_registration_goes_once_the_key_is_stored(self):
        pending = join(self.root, PENDING)
        os.makedirs(os.path.dirname(pending))
        with open(pending, "w") as fob:
            fob.write("crowdsec-firewall-bouncer FB-2 stale\n")
        action = AddBouncer(BOUNCER, BOUNCER_ID, "nftables", None, PENDING)
        with mock.patch("keel.system.crowdsec.subprocess.run", Cscli()):
            self.assertIsNone(Effects(self.root).apply(action))
        self.assertFalse(os.path.exists(pending))
        with mock.patch("keel.system.crowdsec.subprocess.run",
                        Cscli(1, "", "locked\n")):
            with open(pending, "w") as fob:
                fob.write("x\n")
            self.assertIsNotNone(Effects(self.root).apply(action))
        self.assertTrue(os.path.exists(pending))

    def test_a_failure_says_why_and_never_the_key(self):
        problem = self.add(Cscli(1, "", "LAPI database locked\n"))
        self.assertEqual(problem, "cscli bouncers add exited 1: LAPI"
                                  " database locked")
        self.assertFalse(os.path.exists(join(self.root, BOUNCER)))
        self.assertEqual(self.add(Cscli(0, "\n")),
                         "cscli bouncers add printed no key")
        self.assertEqual(self.add(Cscli(0, "two words\n")),
                         "cscli bouncers add printed no key")

    def test_no_cscli(self):
        def missing(argv, **kwargs):
            raise OSError(2, "No such file or directory")
        with mock.patch("keel.system.crowdsec.subprocess.run", missing):
            found = add_bouncer(self.root, AddBouncer(BOUNCER, BOUNCER_ID,
                                                      "nftables", None))
        self.assertEqual(found, "cannot run cscli: No such file or"
                                " directory")

    def test_value_of(self):
        self.assertEqual(value_of("login: x\npassword: y\n", "password"),
                         "y")
        self.assertIsNone(value_of("password:\n", "password"))
        self.assertIsNone(value_of(None, "password"))


class FakeEffects:
    def __init__(self, problems: dict):
        self.problems = problems

    def apply(self, action):
        return self.problems.get(action.argv)


class TestAttempt(unittest.TestCase):
    CAPI = Attempt(("cscli", "capi", "register"), "register with CAPI",
                   "the local API runs without it")
    AFTER = Run(("systemctl", "start", "crowdsec.service"), "start it")

    def test_a_failure_is_said_and_the_step_goes_on(self):
        effects = FakeEffects({self.CAPI.argv: "cscli exited 1: offline"})
        outcome = execute(Plan((Step("overlays.crowdsec",
                                     (self.CAPI, self.AFTER)),)), effects)
        self.assertEqual(outcome.lines, (
            "overlays.crowdsec: register with CAPI (cscli capi register):"
            " not done: cscli exited 1: offline; the local API runs"
            " without it",
            "overlays.crowdsec: start it (systemctl start crowdsec.service):"
            " done"))
        self.assertEqual((outcome.changed, outcome.failed), (1, 0))

    def test_done_and_dry_run_count_as_changes(self):
        effects = FakeEffects({})
        plan = Plan((Step("overlays.crowdsec", (self.CAPI,)),))
        self.assertEqual(execute(plan, effects).changed, 1)
        dry = execute(plan, effects, dry_run=True)
        self.assertEqual(dry.lines, (
            "overlays.crowdsec: would register with CAPI (cscli capi"
            " register)",))

    def test_the_effect_runs_the_command(self):
        with mock.patch.object(subprocess, "run", return_value=(
                subprocess.CompletedProcess([], 0, "", ""))) as run:
            self.assertIsNone(Effects("/").apply(self.CAPI))
        self.assertEqual(run.call_args[0][0], list(self.CAPI.argv))


if __name__ == "__main__":
    unittest.main()
