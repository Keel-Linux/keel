# Copyright (c) 2026 KeelLinux maintainers
"""apply --system runs an overlay's state hooks (decision 0041, keel#62)

An overlay with no unit, Coraza for one, declares in its manifest the
executable /usr/lib/keel/overlays/<name>/state that turns it on and off
(`hooks.state`), and another package may react to an overlay's state
with an executable in /usr/lib/keel/overlays/<name>/state.d/. keel runs
them with `enabled` or `disabled` on the live system, each within its
timeout, when what it recorded under /var/lib/keel/overlays/ (the state
and a digest of the hooks) differs, after the units come up and before
they go down, and records both once they all passed. A hook that is not
root's, is writable by others, or is a link out of
/usr/lib/keel/overlays is refused, and so is its directory.
"""

import dataclasses
import os
import unittest
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase

from keel.inspect.monitor import Cycle
from keel.inspect.tree import File
from keel.inspect.units import UnitState
from keel.manifest.facts import gather
from keel.system.actions import Note, Plan, Refuse, Run, WriteFile
from keel.system.appliance import MANIFEST_MONIT, plan_appliance
from keel.system.appstate import (
    ApplianceState,
    CrowdsecState,
    observe_appliance,
)
from keel.system.effects import Effects
from keel.system.execute import execute
from keel.system.hooks import (
    RECORD,
    Hook,
    OverlayHooks,
    observe_hooks,
)

LIVE = frozenset(("systemctl", "monit", "cscli"))
CYCLE = Cycle(30, "set daemon 30 in /etc/monit/monitrc")
CORE = {"installer": "enabled", "wireguard": "disabled", "etcd": "disabled",
        "crowdsec": "disabled"}
SIMPLE = {**CORE, "nginx": "enabled", "coraza": "disabled",
          "anubis": "disabled"}
ADVANCED = {**SIMPLE, "coraza": "enabled", "anubis": "enabled"}
CORAZA = "/usr/lib/keel/overlays/coraza/state"
FRONT = "/usr/lib/keel/overlays/anubis/state.d/50keel-web"
DIGEST = "d" * 64
UNITS = ("etcd.service", "crowdsec.service",
         "crowdsec-firewall-bouncer.service", "nginx.service",
         "anubis.service")
DECLARED = ("requires: [nginx]\n",
            f"requires: [nginx]\nhooks:\n  state: {{path: {CORAZA}}}\n")


def units(nginx: str = "active", anubis: str = "inactive") -> dict:
    found = {unit: UnitState(unit, "disabled", "inactive") for unit in UNITS}
    found["nginx.service"] = UnitState("nginx.service", "enabled", nginx)
    found["anubis.service"] = UnitState(
        "anubis.service", "enabled" if anubis == "active" else "disabled",
        anubis)
    return found


def hooks(*paths: str, recorded=None, timeout: int = 120,
          **fields) -> OverlayHooks:
    return OverlayHooks(hooks=tuple(Hook(path, timeout) for path in paths),
                        digest=DIGEST, recorded=recorded, **fields)


def executable(root: str, path: str, mode: int = 0o755,
               text: str = "#!/bin/sh\n") -> str:
    full = join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fob:
        fob.write(text)
    os.chmod(full, mode)
    return full


class HookCase(ManifestCase):
    def state(self, **fields) -> ApplianceState:
        base = ApplianceState(
            resolved=gather(self.root, "web").resolved, problems=(),
            units=units(), monit_file=File("/r/" + MANIFEST_MONIT,
                                           problem="not present"),
            monit_link=None, monit_link_present=False, cycle=CYCLE,
            crowdsec=CrowdsecState(lapi=False, capi="absent",
                                   bouncer_key=False, bouncer_mode=None,
                                   bouncer_id=None),
            root="/", hooks={"coraza": hooks(CORAZA),
                             "anubis": hooks(FRONT)})
        return dataclasses.replace(base, **fields)

    def plan(self, overlays: dict, state: ApplianceState | None = None,
             live: bool = True, available=LIVE) -> Plan:
        doc = {"version": 1, "appliance": {"name": "web"},
               "overlays": overlays}
        return Plan(tuple(plan_appliance(doc, state or self.state(), live,
                                         available)))

    def steps(self, *args, **kwargs) -> dict:
        return {step.field: step.actions
                for step in self.plan(*args, **kwargs).steps}


class TestPlan(HookCase):
    def test_an_overlay_without_units_gets_a_step_for_its_hook(self):
        found = self.steps(ADVANCED)["overlays.coraza"]
        self.assertEqual(found, (
            Run((CORAZA, "enabled"),
                f"run {CORAZA}: the overlay is enabled", timeout=120),
            WriteFile(RECORD.format(name="coraza"),
                      f"enabled\nsha256:{DIGEST}\n", 0o644, None,
                      "record enabled and the hooks' digest in"
                      " /var/lib/keel/overlays/coraza"),
        ))

    def test_the_manifest_s_timeout_is_the_hook_s(self):
        state = self.state(hooks={"coraza": hooks(CORAZA, timeout=300)})
        self.assertEqual(self.steps(ADVANCED, state)["overlays.coraza"][0]
                         .timeout, 300)

    def test_a_first_apply_runs_the_hook_for_disabled_too(self):
        found = self.steps(SIMPLE)["overlays.coraza"]
        self.assertEqual(found[0].argv, (CORAZA, "disabled"))
        self.assertEqual(found[1].content, f"disabled\nsha256:{DIGEST}\n")

    def test_the_state_and_hooks_recorded_are_not_run_again(self):
        state = self.state(hooks={"coraza": hooks(
            CORAZA, recorded=("enabled", DIGEST))})
        found = self.steps(ADVANCED, state)["overlays.coraza"]
        self.assertEqual([a.describe() for a in found], [
            f"unchanged (enabled: {CORAZA})"])

    def test_a_hook_installed_after_the_record_runs_them_again(self):
        # keel-web's state.d hook arrives on a machine already enabled
        state = self.state(hooks={"anubis": hooks(
            FRONT, recorded=("enabled", "e" * 64))},
            units=units(anubis="active"))
        found = self.steps(ADVANCED, state)["overlays.anubis"]
        self.assertEqual([a.argv for a in found if isinstance(a, Run)],
                         [(FRONT, "enabled")])

    def test_a_hook_after_the_units_come_up(self):
        found = self.steps(ADVANCED)["overlays.anubis"]
        self.assertEqual([a.argv for a in found if isinstance(a, Run)], [
            ("systemctl", "enable", "anubis.service"),
            ("systemctl", "start", "anubis.service"),
            (FRONT, "enabled"),
        ])
        self.assertIsInstance(found[-1], WriteFile)

    def test_a_hook_before_the_units_go_down(self):
        state = self.state(units=units(anubis="active"), hooks={
            "anubis": hooks(FRONT, recorded=("enabled", DIGEST))})
        found = self.steps(SIMPLE, state)["overlays.anubis"]
        self.assertEqual([a.argv for a in found if isinstance(a, Run)], [
            (FRONT, "disabled"),
            ("systemctl", "stop", "anubis.service"),
            ("systemctl", "disable", "anubis.service"),
        ])
        self.assertIsInstance(found[1], WriteFile)

    def test_every_hook_runs_in_order_and_the_record_comes_last(self):
        paths = (CORAZA, CORAZA + ".d/10first", CORAZA + ".d/20second")
        found = self.steps(ADVANCED, self.state(
            hooks={"coraza": hooks(*paths)}))["overlays.coraza"]
        self.assertEqual([a.argv[0] for a in found[:3]], list(paths))
        self.assertIsInstance(found[3], WriteFile)

    def test_requires_come_up_first(self):
        fields = [field for field in self.steps(ADVANCED)
                  if field.startswith("overlays.")]
        self.assertLess(fields.index("overlays.nginx"),
                        fields.index("overlays.coraza"))
        self.assertLess(fields.index("overlays.nginx"),
                        fields.index("overlays.anubis"))

    def test_an_overlay_with_neither_units_nor_hooks_has_no_step(self):
        self.assertNotIn("overlays.coraza",
                         self.steps(ADVANCED, self.state(hooks={})))

    def test_a_refused_hook_refuses_the_step_before_anything_runs(self):
        state = self.state(hooks={"anubis": hooks(
            FRONT, problems=(f"{FRONT} is writable by group or others",))})
        found = self.steps(ADVANCED, state)["overlays.anubis"]
        self.assertEqual(found, (Refuse(
            f"{FRONT} is writable by group or others"),))

    def test_a_note_of_the_hooks_is_said(self):
        state = self.state(hooks={"coraza": OverlayHooks(
            notes=(f"not run: {CORAZA} is not declared",))})
        found = self.steps(ADVANCED, state)["overlays.coraza"]
        self.assertEqual([a.describe() for a in found], [
            f"not run: {CORAZA} is not declared", "unchanged (enabled)"])

    def test_under_a_root_the_hooks_are_said_not_run_and_nothing_else(self):
        state = self.state(root="/srv/tree",
                           units={u: dataclasses.replace(s, active=None)
                                  for u, s in units().items()})
        found = self.steps(ADVANCED, state, live=False,
                           available=frozenset())
        self.assertEqual([a.describe() for a in found["overlays.coraza"]], [
            f"not run under --root: {CORAZA} runs on the live system"])
        anubis = [a.describe() for a in found["overlays.anubis"]]
        self.assertIn(f"not run under --root: {FRONT} runs on the live"
                      " system", anubis)
        self.assertFalse(any("unchanged" in line for line in anubis))

    def test_hooks_alone_need_no_systemctl(self):
        found = self.steps(ADVANCED, available=frozenset())
        self.assertIsInstance(found["overlays.coraza"][0], Run)
        self.assertIsInstance(found["overlays.nginx"][0], Refuse)


class FailingRuns(Effects):
    def apply(self, action):
        if isinstance(action, Run):
            return f"{action.argv[0]} exited 1: coraza: rolled back"
        return super().apply(action)


class TestExecute(HookCase):
    def test_a_failing_hook_fails_the_step_and_leaves_no_record(self):
        outcome = execute(self.plan(ADVANCED), FailingRuns(self.tmpdir))
        lines = [line for line in outcome.lines
                 if line.startswith("overlays.coraza")]
        self.assertIn("failed: /usr/lib/keel/overlays/coraza/state exited 1:"
                      " coraza: rolled back", lines[0])
        self.assertTrue(lines[1].startswith("overlays.coraza: skipped:"
                                            " record enabled"))
        self.assertFalse(os.path.exists(
            join(self.tmpdir, RECORD.format(name="coraza"))))

    def test_a_dry_run_says_what_it_would_run_and_record(self):
        outcome = execute(self.plan(ADVANCED), FailingRuns(self.tmpdir),
                          dry_run=True)
        self.assertIn(
            f"overlays.coraza: would run {CORAZA}: the overlay is enabled"
            f" ({CORAZA} enabled)", outcome.lines)
        self.assertIn(
            "overlays.coraza: would record enabled and the hooks' digest in"
            " /var/lib/keel/overlays/coraza (mode 0644)", outcome.lines)

    def test_a_hook_that_runs_past_its_timeout_is_killed_and_fails(self):
        script = executable(self.tmpdir, "/slow", text="#!/bin/sh\nsleep 5\n")
        found = Effects(self.tmpdir).apply(
            Run((script, "enabled"), "run it", timeout=0.5))
        self.assertEqual(found, f"{script} did not finish within 0.5 s and"
                         " was killed")

    def test_a_hook_within_its_timeout_passes(self):
        script = executable(self.tmpdir, "/quick")
        self.assertIsNone(Effects(self.tmpdir).apply(
            Run((script, "enabled"), "run it", timeout=5)))


class TestObserve(ManifestCase):
    def setUp(self):
        # the directories the tests make are root's 0755 on a machine; a
        # umask of 002 would make them writable by the group
        umask = os.umask(0o022)
        self.addCleanup(os.umask, umask)
        super().setUp()
        self.manifest = {"hooks": {"state": {"path": CORAZA}}}

    def observe(self, manifest=None, name="coraza") -> OverlayHooks | None:
        return observe_hooks(self.root, name, self.manifest
                             if manifest is None else manifest)

    def test_the_declared_hook_first_then_state_d_by_name(self):
        executable(self.root, CORAZA)
        executable(self.root, CORAZA + ".d/20b")
        executable(self.root, CORAZA + ".d/10a")
        found = self.observe({"hooks": {"state": {"path": CORAZA,
                                                  "timeout": 300}}})
        self.assertEqual(found.hooks, (
            Hook(CORAZA, 300), Hook(CORAZA + ".d/10a", 120),
            Hook(CORAZA + ".d/20b", 120)))
        self.assertEqual(found.problems, ())

    def test_what_run_parts_would_skip_is_skipped(self):
        executable(self.root, CORAZA + ".d/10a.dpkg-old")
        executable(self.root, CORAZA + ".d/.hidden")
        executable(self.root, CORAZA + ".d/30c", mode=0o644)
        os.makedirs(join(self.root, CORAZA.lstrip("/") + ".d", "40dir"))
        self.assertIsNone(self.observe({}))

    def test_an_overlay_with_nothing_has_no_hooks(self):
        self.assertIsNone(self.observe({}, name="nginx"))

    def test_a_state_hook_the_manifest_does_not_declare_is_not_run(self):
        executable(self.root, CORAZA)
        found = self.observe({})
        self.assertEqual(found.hooks, ())
        self.assertEqual(found.notes, (
            f"not run: {CORAZA} is not declared in the overlay manifest's"
            " hooks.state",))

    def test_a_declared_hook_that_is_missing_is_refused(self):
        self.assertEqual(self.observe().problems, (
            f"{CORAZA}: declared in hooks.state and not there",))

    def test_a_hook_writable_by_others_is_refused(self):
        executable(self.root, CORAZA, mode=0o757)
        self.assertEqual(self.observe().problems, (
            f"{CORAZA} is writable by group or others: it is not run",))

    def test_a_hook_not_owned_by_root_is_refused(self):
        executable(self.root, CORAZA)
        with mock.patch("keel.manifest.machine.ROOT_UID", os.getuid() + 1):
            found = self.observe()
        self.assertIn(f"{CORAZA} is not owned by root: it is not run",
                      found.problems)
        self.assertIn("/usr/lib/keel/overlays/coraza is not owned by root:"
                      " it is not run", found.problems)

    def test_a_directory_writable_by_others_is_refused(self):
        executable(self.root, FRONT)
        os.chmod(join(self.root, FRONT.lstrip("/")[:-len("/50keel-web")]),
                 0o777)
        self.assertEqual(self.observe({}, name="anubis").problems, (
            "/usr/lib/keel/overlays/anubis/state.d is writable by group or"
            " others: it is not run",))

    def test_a_link_out_of_the_overlays_directory_is_refused(self):
        target = executable(self.root, "/tmp/elsewhere")
        os.makedirs(join(self.root, "usr/lib/keel/overlays/anubis/state.d"))
        os.symlink(target, join(self.root, FRONT.lstrip("/")))
        found = self.observe({}, name="anubis")
        self.assertEqual(found.problems, (
            f"{FRONT} is a link to /tmp/elsewhere, outside"
            " /usr/lib/keel/overlays: it is not run",))

    def test_a_dangling_link_is_refused_not_a_crash(self):
        os.makedirs(join(self.root, "usr/lib/keel/overlays/anubis/state.d"))
        os.symlink(join(self.root, "usr/lib/keel/overlays/anubis/gone"),
                   join(self.root, FRONT.lstrip("/")))
        found = self.observe({}, name="anubis")
        self.assertEqual(found.problems, (
            f"{FRONT} cannot be read: No such file or directory: it is not"
            " run",))

    def test_a_link_inside_the_overlays_directory_is_followed(self):
        target = executable(self.root, "/usr/lib/keel/overlays/anubis/real")
        os.makedirs(join(self.root, "usr/lib/keel/overlays/anubis/state.d"))
        os.symlink(target, join(self.root, FRONT.lstrip("/")))
        found = self.observe({}, name="anubis")
        self.assertEqual((found.problems, found.hooks),
                         ((), (Hook(FRONT, 120),)))

    def test_the_digest_follows_the_paths_and_the_content(self):
        executable(self.root, CORAZA)
        first = self.observe().digest
        self.assertEqual(self.observe().digest, first)
        executable(self.root, CORAZA, text="#!/bin/sh\nexit 0\n")
        second = self.observe().digest
        self.assertNotEqual(second, first)
        executable(self.root, CORAZA + ".d/50keel-web")
        self.assertNotEqual(self.observe().digest, second)

    def test_a_declared_hook_that_is_not_a_file_is_refused(self):
        os.makedirs(join(self.root, CORAZA.lstrip("/")))
        self.assertIn(f"{CORAZA} is not a regular file: it is not run",
                      self.observe().problems)

    def test_a_hook_keel_cannot_read_still_has_a_digest(self):
        full = executable(self.root, CORAZA, mode=0o311)
        self.addCleanup(os.chmod, full, 0o755)
        if os.access(full, os.R_OK):
            self.skipTest("running as root: every file is readable")
        unreadable = self.observe().digest
        os.chmod(full, 0o755)
        self.assertNotEqual(self.observe().digest, unreadable)

    def test_the_record_is_read_back(self):
        executable(self.root, CORAZA)
        record = join(self.root, RECORD.format(name="coraza"))
        os.makedirs(os.path.dirname(record))
        for text, wanted in (
                (f"enabled\nsha256:{DIGEST}\n", ("enabled", DIGEST)),
                ("enabled\n", None), ("maybe\nsha256:x\n", None)):
            with self.subTest(text=text):
                with open(record, "w") as fob:
                    fob.write(text)
                self.assertEqual(self.observe().recorded, wanted)
        os.remove(record)
        self.assertIsNone(self.observe().recorded)

    def test_the_appliance_state_holds_each_overlay_s_hooks(self):
        executable(self.root, CORAZA)
        self.edit("overlays", "coraza", *DECLARED)
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "web"}})
        self.assertEqual(list(found.hooks), ["coraza"])
        self.assertEqual(found.hooks["coraza"].hooks, (Hook(CORAZA, 120),))


class TestRunsForReal(ManifestCase):
    """The run of a plan through the effects, with a hook under the root
    and the Run pointed at it"""

    def test_the_hook_gets_the_state_word(self):
        out = join(self.tmpdir, "out")
        script = executable(self.tmpdir, "/hook",
                            text=f"#!/bin/sh\necho \"$1\" > {out}\n")
        self.assertIsNone(Effects(self.tmpdir).apply(
            Run((script, "disabled"), "run it", timeout=5)))
        with open(out) as fob:
            self.assertEqual(fob.read(), "disabled\n")

    def test_a_hook_that_fails_within_its_timeout_says_why(self):
        script = executable(self.tmpdir, "/fails",
                            text="#!/bin/sh\necho rolled back >&2\nexit 1\n")
        self.assertEqual(Effects(self.tmpdir).apply(
            Run((script, "enabled"), "run it", timeout=5)),
            f"{script} exited 1: rolled back")

    def test_a_command_that_cannot_start_is_said(self):
        self.assertIn("cannot run", Effects(self.tmpdir).apply(
            Run(("/nonexistent/hook", "enabled"), "run it", timeout=5)))


if __name__ == "__main__":
    unittest.main()
