# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: the overlays' units and Monit's file (decision 0041)

The planner is a pure function of the spec and an ApplianceState, so the
live branches are checked with hand built states over the format's
manifests; the state reader against a temporary root, and the whole run
through the CLI under --root, where systemctl is replaced at the
subprocess boundary.
"""

import dataclasses
import os
import subprocess
import unittest
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase

from keel.inspect.monitor import Cycle
from keel.inspect.tree import File
from keel.inspect.units import UnitState
from keel.manifest.facts import gather
from keel.system.actions import (
    AddBouncer,
    Attempt,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Symlink,
    WriteFile,
)
from keel.system.appliance import (
    MANIFEST_MONIT,
    MONIT_LINK,
    plan_appliance,
)
from keel.system.appstate import (
    ApplianceState,
    CrowdsecState,
    observe_appliance,
)
from keel.system.crowdsec import BOUNCER, BOUNCER_ID, CAPI, PENDING

LIVE = frozenset(("systemctl", "monit", "cscli"))
CYCLE = Cycle(30, "set daemon 30 in /etc/monit/monitrc")
OFF = {"installer": "enabled", "wireguard": "disabled", "etcd": "disabled",
       "crowdsec": "disabled"}
ON = {**OFF, "crowdsec": "enabled"}
UNITS = ("etcd.service", "crowdsec.service",
         "crowdsec-firewall-bouncer.service")
REGISTERED = CrowdsecState(lapi=True, capi="present", bouncer_key=True,
                           bouncer_mode="nftables", bouncer_id="FB-1",
                           iptables=None)


def units(enabled: str = "disabled", active: str | None = "inactive",
          **overrides) -> dict:
    found = {unit: UnitState(unit, enabled, active) for unit in UNITS}
    for unit, state in overrides.items():
        found[unit] = state
    return found


class PlanCase(ManifestCase):
    def state(self, **fields) -> ApplianceState:
        base = ApplianceState(
            resolved=gather(self.root, "core").resolved, problems=(),
            units=units(), monit_file=File("/r/" + MANIFEST_MONIT,
                                           problem="not present"),
            monit_link=None, monit_link_present=False, cycle=CYCLE,
            crowdsec=REGISTERED, root="/")
        return dataclasses.replace(base, **fields)

    def doc(self, overlays: dict, monitor: dict | None = None) -> dict:
        found = {"version": 1, "appliance": {"name": "core"},
                 "overlays": overlays}
        if monitor is not None:
            found["monitor"] = monitor
        return found

    def plan(self, overlays: dict, state: ApplianceState | None = None,
             live: bool = True, available=LIVE, monitor=None):
        return plan_appliance(self.doc(overlays, monitor),
                              state or self.state(), live, available)

    def actions(self, *args, field: str | None = None, **kwargs):
        return [action for step in self.plan(*args, **kwargs)
                for action in step.actions
                if field is None or step.field == field]

    def runs(self, *args, **kwargs):
        return [action.argv for action in self.actions(*args, **kwargs)
                if isinstance(action, Run)]


class TestUnits(PlanCase):
    def test_no_appliance_is_no_step(self):
        self.assertEqual(plan_appliance({"version": 1}, None, True, LIVE),
                         [])

    def test_disabled_and_stopped_is_unchanged(self):
        found = self.actions(OFF, field="overlays.crowdsec")
        self.assertEqual([a.describe() for a in found], [
            "unchanged (disabled: crowdsec.service,"
            " crowdsec-firewall-bouncer.service)"])
        self.assertEqual(self.runs(OFF), [])

    def test_enabled_enables_then_starts_each_unit_in_order(self):
        self.assertEqual(self.runs(ON, field="overlays.crowdsec"), [
            ("systemctl", "enable", "crowdsec.service"),
            ("systemctl", "start", "crowdsec.service"),
            ("systemctl", "enable", "crowdsec-firewall-bouncer.service"),
            ("systemctl", "start", "crowdsec-firewall-bouncer.service"),
        ])

    def test_enabled_and_running_is_unchanged(self):
        state = self.state(units=units("enabled", "active"))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertEqual([a.describe() for a in found], [
            "unchanged (enabled: crowdsec.service,"
            " crowdsec-firewall-bouncer.service)"])

    def test_disabled_stops_and_disables_in_reverse_order(self):
        state = self.state(units=units("enabled", "active"))
        self.assertEqual(self.runs(OFF, state, field="overlays.crowdsec"), [
            ("systemctl", "stop", "crowdsec-firewall-bouncer.service"),
            ("systemctl", "disable", "crowdsec-firewall-bouncer.service"),
            ("systemctl", "stop", "crowdsec.service"),
            ("systemctl", "disable", "crowdsec.service"),
        ])

    def test_only_what_differs_is_done(self):
        state = self.state(units=units(
            "enabled", "active", **{"crowdsec.service": UnitState(
                "crowdsec.service", "enabled", "failed")}))
        self.assertEqual(self.runs(ON, state, field="overlays.crowdsec"), [
            ("systemctl", "start", "crowdsec.service")])

    def test_a_masked_unit_is_refused_and_never_unmasked(self):
        state = self.state(units=units(**{"crowdsec.service": UnitState(
            "crowdsec.service", "masked", "inactive")}))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertIsInstance(found[0], Refuse)
        self.assertEqual(found[0].describe(),
                         "crowdsec.service is masked, and keel never"
                         " unmasks a unit: systemctl unmask"
                         " crowdsec.service, then apply again")
        self.assertEqual(self.runs(OFF, state, field="overlays.crowdsec"),
                         [])

    def test_a_masked_unit_makes_no_identity(self):
        state = self.state(
            units=units(**{"crowdsec.service": UnitState(
                "crowdsec.service", "masked", "inactive")}),
            crowdsec=TestCrowdsecIdentity.NONE)
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertEqual([type(a).__name__ for a in found], ["Refuse"])

    def test_a_requires_cycle_does_not_recurse(self):
        resolved = gather(self.root, "core").resolved
        looped = dataclasses.replace(resolved, overlays=tuple(
            dataclasses.replace(state, manifest={
                **state.manifest, "requires": ["crowdsec"]})
            if state.name == "etcd" else
            dataclasses.replace(state, manifest={
                **state.manifest, "requires": ["etcd"]})
            if state.name == "crowdsec" else state
            for state in resolved.overlays))
        fields = [step.field for step in self.plan(
            OFF, self.state(resolved=looped))]
        self.assertEqual(sorted(fields), ["derived.monit", "overlays.crowdsec",
                                          "overlays.etcd"])

    def test_a_static_unit_is_started_and_never_enabled(self):
        state = self.state(units=units(**{"crowdsec.service": UnitState(
            "crowdsec.service", "static", "inactive")}))
        runs = self.runs(ON, state, field="overlays.crowdsec")
        self.assertNotIn(("systemctl", "enable", "crowdsec.service"), runs)
        self.assertIn(("systemctl", "start", "crowdsec.service"), runs)

    def test_under_a_root_the_links_are_made_and_nothing_started(self):
        state = self.state(units=units(active=None), root="/srv/tree")
        self.assertEqual(
            self.runs(ON, state, live=False, available=frozenset(),
                      field="overlays.crowdsec"), [
                ("systemctl", "--root=/srv/tree", "enable",
                 "crowdsec.service"),
                ("systemctl", "--root=/srv/tree", "enable",
                 "crowdsec-firewall-bouncer.service")])

    def test_live_without_systemctl_is_refused(self):
        found = self.actions(ON, available=frozenset(("cscli",)),
                             field="overlays.crowdsec")
        self.assertEqual([a.describe() for a in found], [
            "systemctl not found: the units cannot be converged"])

    def test_requires_come_up_first_and_go_down_last(self):
        wanted = {**OFF, "wireguard": "enabled", "etcd": "enabled"}
        fields = [step.field for step in self.plan(wanted)]
        # what goes down goes first, then what comes up
        self.assertEqual(fields, ["derived.monit", "overlays.crowdsec",
                                  "overlays.etcd"])
        self.edit("overlays", "crowdsec", "title: CrowdSec",
                  "title: CrowdSec\nrequires: [etcd]")
        self.edit("appliances", "core", "crowdsec:  {simple: disabled,"
                  " cloud_simple: enabled", "crowdsec:  {simple: disabled,"
                  " cloud_simple: disabled")
        state = self.state(resolved=gather(self.root, "core").resolved,
                           units=units("enabled", "active"))
        fields = [step.field for step in self.plan(
            {**OFF, "wireguard": "enabled", "etcd": "disabled"}, state)
            if step.field.startswith("overlays.")]
        self.assertEqual(fields, ["overlays.crowdsec", "overlays.etcd"])

    def test_manifests_that_cannot_be_used_are_refused(self):
        state = self.state(resolved=None, problems=("core: gone",))
        found = self.plan(ON, state)
        self.assertEqual([(s.field, a.describe()) for s in found
                          for a in s.actions],
                         [("appliance", "core: gone")])
        self.assertIsInstance(found[0].actions[0], Refuse)


class TestCrowdsecIdentity(PlanCase):
    NONE = CrowdsecState(lapi=False, capi="absent", bouncer_key=False,
                         bouncer_mode=None, bouncer_id=None,
                         iptables="/usr/sbin/iptables-legacy")

    def test_a_first_enable_makes_the_identity_before_the_units(self):
        found = self.actions(ON, self.state(crowdsec=self.NONE),
                             field="overlays.crowdsec")
        # the empty CAPI file only once the machine is registered: a
        # registration that fails leaves it absent, so the next run
        # still registers with the central API
        self.assertEqual(found[0].argv, ("cscli", "--error", "machines",
                                         "add", "--auto", "--force"))
        self.assertIsInstance(found[1], WriteFile)
        self.assertEqual((found[1].path, found[1].content, found[1].mode),
                         (CAPI, "", 0o600))
        self.assertIsInstance(found[2], Attempt)
        self.assertEqual(found[2].argv, ("cscli", "--error", "capi",
                                         "register"))
        self.assertIsInstance(found[3], AddBouncer)
        self.assertEqual((found[3].mode, found[3].old_id),
                         ("iptables", None))
        self.assertEqual(found[4].argv,
                         ("systemctl", "enable", "crowdsec.service"))

    def test_nothing_is_made_twice_and_running_units_restart(self):
        state = self.state(crowdsec=dataclasses.replace(
            REGISTERED, bouncer_key=False), units=units("enabled", "active"))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertEqual([type(a).__name__ for a in found],
                         ["AddBouncer", "Run", "Run"])
        self.assertEqual((found[0].mode, found[0].old_id),
                         ("nftables", "FB-1"))
        self.assertEqual([a.argv for a in found[1:]], [
            ("systemctl", "restart", "crowdsec.service"),
            ("systemctl", "restart", "crowdsec-firewall-bouncer.service")])

    def test_a_bouncer_that_has_its_key_is_left_alone(self):
        state = self.state(crowdsec=dataclasses.replace(REGISTERED,
                                                        lapi=False))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertEqual(found[0].argv[:4], ("cscli", "--error", "machines",
                                             "add"))
        self.assertFalse([a for a in found if isinstance(a, AddBouncer)])

    def test_a_registration_debian_left_pending_is_replaced(self):
        """crowdsec's postinst exits before its pending registrations
        when its unit is not active, and the bouncer's unit does not
        start while the file is there"""
        state = self.state(crowdsec=dataclasses.replace(REGISTERED,
                                                        pending=True))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertIsInstance(found[0], AddBouncer)
        self.assertEqual(found[0].pending, PENDING)
        self.assertIn(f"remove /{PENDING}", found[0].describe())

    def test_the_mode_follows_the_iptables_alternative(self):
        state = self.state(crowdsec=dataclasses.replace(
            self.NONE, iptables="/usr/sbin/iptables-nft"))
        bouncer = [a for a in self.actions(ON, state)
                   if isinstance(a, AddBouncer)][0]
        self.assertEqual(bouncer.mode, "nftables")

    def test_an_empty_capi_file_is_left_to_the_operator(self):
        state = self.state(crowdsec=dataclasses.replace(REGISTERED,
                                                        capi="empty"))
        found = self.actions(ON, state, field="overlays.crowdsec")
        self.assertIsInstance(found[0], Note)
        self.assertIn("cscli capi register", found[0].describe())
        self.assertFalse([a for a in found if isinstance(a, Attempt)])

    def test_disabling_leaves_the_identity(self):
        state = self.state(crowdsec=self.NONE)
        self.assertEqual(self.actions(OFF, state, field="overlays.crowdsec")
                         [0].describe()[:9], "unchanged")

    def test_under_a_root_no_identity_is_made(self):
        state = self.state(crowdsec=self.NONE, units=units(active=None),
                           root="/srv/tree")
        found = self.actions(ON, state, live=False, available=frozenset(),
                             field="overlays.crowdsec")
        self.assertEqual(found[0].describe(), (
            "CrowdSec's identity is not made under --root: an image would"
            " give every machine made from it the same one (tracker#47);"
            " apply on the machine makes it"))
        self.assertFalse([a for a in found
                          if isinstance(a, (AddBouncer, Attempt))])

    def test_live_without_cscli_is_refused(self):
        found = self.actions(ON, self.state(crowdsec=self.NONE),
                             available=frozenset(("systemctl",)),
                             field="overlays.crowdsec")
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("cscli not found", found[0].describe())

    def test_the_actions_say_where_and_never_a_key(self):
        found = self.actions(ON, self.state(crowdsec=self.NONE))
        text = " ".join(a.describe() for a in found)
        self.assertIn(f"/{BOUNCER}", text)
        self.assertIn(f"/{BOUNCER_ID}", text)
        self.assertIn("never printed", text)


class TestMonit(PlanCase):
    def monit(self, overlays=OFF, state=None, monitor=None, live=True,
              available=LIVE):
        return self.actions(overlays, state, live, available, monitor,
                            field="derived.monit")

    def test_the_file_is_written_whatever_the_monitor_says(self):
        found = self.monit()
        write = found[0]
        self.assertIsInstance(write, WriteFile)
        self.assertEqual((write.path, write.mode), (MANIFEST_MONIT, 0o600))
        self.assertEqual(write.describe(), (
            f"write /{MANIFEST_MONIT}: 4 unit(s) and 3 probe(s) of core"
            " (mode 0600)"))
        self.assertEqual(len(found), 1)

    def test_included_and_reloaded_while_the_monitor_is_enabled(self):
        found = self.monit(monitor={"enabled": True})
        self.assertIsInstance(found[1], Symlink)
        self.assertEqual((found[1].path, found[1].target),
                         (MONIT_LINK, "/" + MANIFEST_MONIT))
        self.assertEqual([a.argv for a in found[2:]], [
            ("monit", "-t"),
            ("systemctl", "try-reload-or-restart", "monit.service")])

    def test_crowdsec_adds_its_checks_and_the_file_is_rewritten(self):
        off = self.monit()[0].content
        state = self.state(monit_file=File("/r/x", off),
                           monit_link="/" + MANIFEST_MONIT,
                           monit_link_present=True)
        found = self.monit(ON, state, {"enabled": True})
        self.assertIn("keel-check-crowdsec-lapi", found[0].content)
        self.assertEqual([a.argv for a in found[1:]], [
            ("monit", "-t"),
            ("systemctl", "try-reload-or-restart", "monit.service")])

    def test_the_same_file_included_is_unchanged(self):
        text = self.monit()[0].content
        state = self.state(monit_file=File("/r/x", text),
                           monit_link="/" + MANIFEST_MONIT,
                           monit_link_present=True)
        found = self.monit(OFF, state, {"enabled": True})
        self.assertEqual([a.describe() for a in found], [
            f"unchanged (/{MANIFEST_MONIT}, 4 unit(s) and 3 probe(s) of"
            " core, included)"])

    def test_a_monitor_turned_off_stops_including_it(self):
        text = self.monit()[0].content
        state = self.state(monit_file=File("/r/x", text),
                           monit_link="/" + MANIFEST_MONIT,
                           monit_link_present=True)
        found = self.monit(OFF, state, {"enabled": False})
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[0].path, MONIT_LINK)
        self.assertEqual(found[1].argv, ("monit", "-t"))

    def test_no_monitor_section_leaves_the_include_as_it_is(self):
        text = self.monit()[0].content
        state = self.state(monit_file=File("/r/x", text),
                           monit_link="/" + MANIFEST_MONIT,
                           monit_link_present=True)
        found = self.monit(OFF, state)
        self.assertEqual([a.describe() for a in found], [
            f"unchanged (/{MANIFEST_MONIT}, 4 unit(s) and 3 probe(s) of"
            " core, included)"])

    def test_a_changed_file_that_is_not_included_is_not_reloaded(self):
        found = self.monit(ON, monitor={"enabled": False})
        self.assertEqual([type(a).__name__ for a in found], ["WriteFile"])

    def test_someone_else_s_file_in_its_place_is_refused(self):
        state = self.state(monit_link=None, monit_link_present=True)
        found = self.monit(state=state, monitor={"enabled": True})
        self.assertIsInstance(found[-1], Refuse)
        self.assertIn(f"/{MONIT_LINK} is there and is not keel's link",
                      found[-1].describe())

    def test_the_notes_of_the_renderer_are_said(self):
        doc_overlays = {**OFF, "wireguard": "enabled", "etcd": "enabled"}
        found = self.monit(doc_overlays)
        self.assertIn("etcd-health not watched: its address is the mesh,"
                      " and the spec declares no"
                      " network.overlay.wireguard.address",
                      [a.describe() for a in found])

    def test_under_a_root_nothing_is_reloaded(self):
        found = self.monit(monitor={"enabled": True}, live=False,
                           available=frozenset())
        self.assertEqual(found[-1].describe(),
                         "monit not reloaded: not the live system")


class TestObserve(ManifestCase):
    def test_no_appliance_is_nothing_to_observe(self):
        self.assertIsNone(observe_appliance(self.root, {"version": 1}))

    def test_what_the_tree_holds(self):
        os.makedirs(join(self.root, "etc/systemd/system/"
                         "multi-user.target.wants"))
        os.symlink("/usr/lib/systemd/system/crowdsec.service",
                   join(self.root, "etc/systemd/system/multi-user.target"
                        ".wants/crowdsec.service"))
        os.makedirs(join(self.root, "etc/crowdsec/bouncers"))
        os.makedirs(join(self.root, "var/lib/crowdsec"))
        for path, text in (
                ("etc/crowdsec/local_api_credentials.yaml",
                 "url: http://127.0.0.1:8080\nlogin: x\npassword: y\n"),
                (CAPI, ""),
                (BOUNCER, "mode: iptables\napi_key: k\n"),
                (BOUNCER_ID, "FirewallBouncer-1\n"),
                (PENDING, "crowdsec-firewall-bouncer FB-2 k\n")):
            with open(join(self.root, path), "w") as fob:
                fob.write(text)
        os.makedirs(join(self.root, "etc/monit/conf.d"))
        os.symlink("/" + MANIFEST_MONIT, join(self.root, MONIT_LINK))
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "core"}})
        self.assertEqual(found.problems, ())
        self.assertEqual(found.units["crowdsec.service"].enabled, "enabled")
        self.assertEqual(found.units["etcd.service"].enabled, "disabled")
        self.assertIsNone(found.units["etcd.service"].active)
        self.assertEqual(found.crowdsec, CrowdsecState(
            lapi=True, capi="empty", bouncer_key=True,
            bouncer_mode="iptables", bouncer_id="FirewallBouncer-1",
            iptables=None, pending=True))
        self.assertEqual(found.monit_link, "/" + MANIFEST_MONIT)
        self.assertTrue(found.monit_link_present)
        self.assertFalse(found.monit_file.readable)

    def test_nothing_of_crowdsec_is_all_missing(self):
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "core"}})
        self.assertEqual(found.crowdsec, CrowdsecState(
            lapi=False, capi="absent", bouncer_key=False,
            bouncer_mode=None, bouncer_id=None, iptables=None))

    def test_manifests_that_cannot_be_used(self):
        found = observe_appliance(self.root, {
            "version": 1, "appliance": {"name": "php"}})
        self.assertIsNone(found.resolved)
        self.assertEqual(len(found.problems), 1)

    def test_live_asks_systemctl(self):
        def run(argv, **kwargs):
            word = "enabled" if argv[1] == "is-enabled" else "active"
            return subprocess.CompletedProcess(argv, 0, word + "\n", "")
        with mock.patch("keel.system.appstate.ROOT_DEFAULT", self.root), \
                mock.patch("keel.inspect.units.subprocess.run", run):
            found = observe_appliance(self.root, {
                "version": 1, "appliance": {"name": "core"}})
        self.assertEqual(found.units["etcd.service"].active, "active")


if __name__ == "__main__":
    unittest.main()
