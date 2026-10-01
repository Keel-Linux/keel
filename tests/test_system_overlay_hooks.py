# Copyright (c) 2026 KeelLinux maintainers
"""apply --system runs an overlay's state hooks (decision 0041, keel#62)

An overlay with no unit, Coraza for one, is turned on and off by the
executable /usr/lib/keel/overlays/<name>/state its package ships, and
another package may react to an overlay's state with an executable in
/usr/lib/keel/overlays/<name>/state.d/. keel runs them with `enabled` or
`disabled` on the live system when the state it last recorded under
/var/lib/keel/overlays/ differs from the spec's, after the units come up
and before they go down, and records the state once they all passed.
"""

import dataclasses
import os
import unittest
from os.path import join

from manifest_helpers import ManifestCase

from keel.inspect.monitor import Cycle
from keel.inspect.tree import File
from keel.inspect.units import UnitState
from keel.manifest.facts import gather
from keel.system.actions import Note, Refuse, Run, WriteFile
from keel.system.appliance import MANIFEST_MONIT, plan_appliance
from keel.system.appstate import (
    ApplianceState,
    CrowdsecState,
    hook_paths,
    observe_appliance,
)
from keel.system.hooks import RECORD

LIVE = frozenset(("systemctl", "monit", "cscli"))
CYCLE = Cycle(30, "set daemon 30 in /etc/monit/monitrc")
CORE = {"installer": "enabled", "wireguard": "disabled", "etcd": "disabled",
        "crowdsec": "disabled"}
SIMPLE = {**CORE, "nginx": "enabled", "coraza": "disabled",
          "anubis": "disabled"}
ADVANCED = {**SIMPLE, "coraza": "enabled", "anubis": "enabled"}
CORAZA = "/usr/lib/keel/overlays/coraza/state"
FRONT = "/usr/lib/keel/overlays/anubis/state.d/50keel-web"
UNITS = ("etcd.service", "crowdsec.service",
         "crowdsec-firewall-bouncer.service", "nginx.service",
         "anubis.service")


def units(nginx: str = "active", anubis: str = "inactive") -> dict:
    found = {unit: UnitState(unit, "disabled", "inactive") for unit in UNITS}
    found["nginx.service"] = UnitState("nginx.service", "enabled", nginx)
    found["anubis.service"] = UnitState(
        "anubis.service", "enabled" if anubis == "active" else "disabled",
        anubis)
    return found


def executable(root: str, path: str, mode: int = 0o755) -> None:
    full = join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fob:
        fob.write("#!/bin/sh\n")
    os.chmod(full, mode)


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
            root="/", hooks={"coraza": (CORAZA,), "anubis": (FRONT,)},
            recorded={})
        return dataclasses.replace(base, **fields)

    def steps(self, overlays: dict, state: ApplianceState | None = None,
              live: bool = True, available=LIVE) -> dict:
        doc = {"version": 1, "appliance": {"name": "web"},
               "overlays": overlays}
        return {step.field: step.actions for step in plan_appliance(
            doc, state or self.state(), live, available)}


class TestPlan(HookCase):
    def test_an_overlay_without_units_gets_a_step_for_its_hook(self):
        found = self.steps(ADVANCED)["overlays.coraza"]
        self.assertEqual(found, (
            Run((CORAZA, "enabled"),
                f"run {CORAZA}: the overlay is enabled"),
            WriteFile(RECORD.format(name="coraza"), "enabled\n", 0o644,
                      None, "record enabled in"
                      " /var/lib/keel/overlays/coraza"),
        ))

    def test_a_first_apply_runs_the_hook_for_disabled_too(self):
        found = self.steps(SIMPLE)["overlays.coraza"]
        self.assertEqual(found[0], Run((CORAZA, "disabled"),
                                       f"run {CORAZA}: the overlay is"
                                       " disabled"))
        self.assertEqual(found[1].content, "disabled\n")

    def test_the_state_recorded_is_not_run_again(self):
        state = self.state(recorded={"coraza": "enabled"})
        found = self.steps(ADVANCED, state)["overlays.coraza"]
        self.assertEqual([a.describe() for a in found], [
            f"unchanged (enabled: {CORAZA})"])

    def test_a_hook_after_the_units_come_up(self):
        found = self.steps(ADVANCED)["overlays.anubis"]
        self.assertEqual([a.argv for a in found if isinstance(a, Run)], [
            ("systemctl", "enable", "anubis.service"),
            ("systemctl", "start", "anubis.service"),
            (FRONT, "enabled"),
        ])
        self.assertIsInstance(found[-1], WriteFile)

    def test_a_hook_before_the_units_go_down(self):
        state = self.state(units=units(anubis="active"),
                           recorded={"anubis": "enabled"})
        found = self.steps(SIMPLE, state)["overlays.anubis"]
        self.assertEqual([a.argv for a in found if isinstance(a, Run)], [
            (FRONT, "disabled"),
            ("systemctl", "stop", "anubis.service"),
            ("systemctl", "disable", "anubis.service"),
        ])
        self.assertEqual(found[1], WriteFile(
            RECORD.format(name="anubis"), "disabled\n", 0o644, None,
            "record disabled in /var/lib/keel/overlays/anubis"))

    def test_every_hook_runs_in_order_and_the_record_comes_last(self):
        hooks = (CORAZA, CORAZA + ".d/10first", CORAZA + ".d/20second")
        found = self.steps(ADVANCED, self.state(hooks={"coraza": hooks}))[
            "overlays.coraza"]
        self.assertEqual([a.argv[0] for a in found[:3]], list(hooks))
        self.assertIsInstance(found[3], WriteFile)

    def test_requires_come_up_first(self):
        fields = [field for field in self.steps(ADVANCED)
                  if field.startswith("overlays.")]
        self.assertLess(fields.index("overlays.nginx"),
                        fields.index("overlays.coraza"))
        self.assertLess(fields.index("overlays.nginx"),
                        fields.index("overlays.anubis"))

    def test_an_overlay_with_neither_units_nor_hooks_has_no_step(self):
        found = self.steps(ADVANCED, self.state(hooks={}))
        self.assertNotIn("overlays.coraza", found)

    def test_under_a_root_the_hooks_are_not_run_nor_recorded(self):
        state = self.state(root="/srv/tree",
                           units={u: dataclasses.replace(s, active=None)
                                  for u, s in units().items()})
        found = self.steps(ADVANCED, state, live=False,
                           available=frozenset())["overlays.coraza"]
        self.assertEqual([a.describe() for a in found], [
            f"not run under --root: {CORAZA} runs on the live system",
            f"unchanged (enabled: {CORAZA})"])
        self.assertTrue(all(isinstance(a, Note) for a in found))

    def test_hooks_alone_need_no_systemctl(self):
        found = self.steps(ADVANCED, available=frozenset())
        self.assertIsInstance(found["overlays.coraza"][0], Run)
        self.assertIsInstance(found["overlays.nginx"][0], Refuse)


class TestObserve(ManifestCase):
    def test_the_state_hook_first_then_state_d_by_name(self):
        executable(self.root, CORAZA)
        executable(self.root, CORAZA + ".d/20b")
        executable(self.root, CORAZA + ".d/10a")
        self.assertEqual(hook_paths(self.root, "coraza"), (
            CORAZA, CORAZA + ".d/10a", CORAZA + ".d/20b"))

    def test_what_is_not_an_executable_with_a_plain_name_is_skipped(self):
        executable(self.root, CORAZA, mode=0o644)
        executable(self.root, CORAZA + ".d/10a.dpkg-old")
        executable(self.root, CORAZA + ".d/.hidden")
        executable(self.root, CORAZA + ".d/30c", mode=0o644)
        os.makedirs(join(self.root, CORAZA.lstrip("/") + ".d", "40dir"))
        self.assertEqual(hook_paths(self.root, "coraza"), ())

    def test_an_overlay_without_hooks_has_none(self):
        self.assertEqual(hook_paths(self.root, "nginx"), ())

    def test_the_appliance_state_holds_hooks_and_records(self):
        executable(self.root, CORAZA)
        record = join(self.root, RECORD.format(name="coraza"))
        os.makedirs(os.path.dirname(record))
        with open(record, "w") as fob:
            fob.write("enabled\n")
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "web"}})
        self.assertEqual(found.hooks, {"coraza": (CORAZA,)})
        self.assertEqual(found.recorded, {"coraza": "enabled"})

    def test_no_record_is_none(self):
        executable(self.root, CORAZA)
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "web"}})
        self.assertEqual(found.recorded, {"coraza": None})

    def test_a_record_that_is_not_a_state_is_none(self):
        executable(self.root, CORAZA)
        record = join(self.root, RECORD.format(name="coraza"))
        os.makedirs(os.path.dirname(record))
        with open(record, "w") as fob:
            fob.write("maybe\n")
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "web"}})
        self.assertEqual(found.recorded, {"coraza": None})


if __name__ == "__main__":
    unittest.main()
