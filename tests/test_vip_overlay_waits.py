# Copyright (c) 2026 KeelLinux maintainers
"""The VIP overlay before etcd's cluster exists (keel#106)

keel-vip.service is the VIP's controller with etcd. Its unit has
ConditionPathExists=/var/lib/keel/etcd/cluster.json, so it never runs
in cloud simple, and in cloud advanced it waits for etcd to form, as
etcd itself waits (keel.system.etcd). Before, `keel diff` reported
`overlays.vip: drift (declared enabled, observed keel-vip.service
enabled and inactive)` on every cloud simple pair, and every apply
printed "start keel-vip.service: done" for a unit that did not start.
"""

import unittest
from unittest import mock

from manifest_helpers import ManifestCase, put, unit

from keel.diff.appliance import DRIFT, NO_VIP_CLUSTER, SAME, appliance_fields
from keel.inspect.units import UnitState
from keel.mesh import etcdstate
from keel.system.actions import Note, Run
from keel.system.appliance import plan_appliance
from keel.system.appstate import observe_appliance

VIP_OVERLAY = """\
manifest_version: 1
kind: overlay
name: vip
title: Service VIP
summary: The replicated pair's VIP on the mesh (0049); moved by keel vip
requires: [wireguard]
processes:
  - name: keel-vip
    unit: keel-vip.service
"""

PAIR_APPLIANCE = """\
manifest_version: 1
kind: appliance
name: pairnode
title: A pair node
summary: Core and the VIP, for the tests of keel#106
base: core
overlays:
  vip: {simple: disabled, cloud_simple: disabled, cloud_advanced: disabled}
"""

UNIT = "keel-vip.service"
LIVE = frozenset(("systemctl", "monit", "cscli"))


def doc(vip: str = "enabled") -> dict:
    return {"version": 1, "appliance": {"name": "pairnode"},
            "installation": {"mode": "cloud_simple"},
            "overlays": {"installer": "enabled", "wireguard": "enabled",
                         "etcd": "disabled", "crowdsec": "disabled",
                         "vip": vip}}


class Case(ManifestCase):
    def setUp(self):
        super().setUp()
        put(self.root, "overlays", "vip", VIP_OVERLAY)
        put(self.root, "appliances", "pairnode", PAIR_APPLIANCE)
        unit(self.root, "keel-vip")

    def formed(self) -> None:
        etcdstate.save_cluster(self.root, etcdstate.Cluster(
            "new", (), "00" * 16))

    def units(self, enabled: str, active: str | None):
        def read(tree, names, live):
            return {name: UnitState(name, enabled if name == UNIT
                                    else "disabled",
                                    active if name == UNIT else "inactive")
                    for name in names}
        return read


class TestDiff(Case):
    def field(self, enabled: str, active: str | None, vip: str = "enabled"):
        with mock.patch("keel.diff.appliance.read_units",
                        side_effect=self.units(enabled, active)):
            found = {one.field: one
                     for one in appliance_fields(doc(vip), self.root)}
        return found["overlays.vip"]

    def test_enabled_and_waiting_for_etcd_is_no_drift(self):
        found = self.field("enabled", "inactive")
        self.assertEqual(found.status, SAME)
        self.assertEqual(found.reason, NO_VIP_CLUSTER)

    def test_a_unit_not_enabled_is_drift_while_it_waits(self):
        found = self.field("disabled", "inactive")
        self.assertEqual(found.status, DRIFT)

    def test_with_etcd_s_cluster_an_inactive_controller_is_drift(self):
        self.formed()
        found = self.field("enabled", "inactive")
        self.assertEqual(found.status, DRIFT)
        self.assertIn("inactive", str(found.observed))

    def test_disabled_is_compared_as_before(self):
        self.assertEqual(self.field("disabled", "inactive",
                                    vip="disabled").status, SAME)


class TestApply(Case):
    def plan(self, enabled: str, active: str):
        with mock.patch("keel.system.appstate.read_units",
                        side_effect=self.units(enabled, active)):
            state = observe_appliance(self.root, doc())
        steps = plan_appliance(doc(), state, True, LIVE)
        (step,) = [one for one in steps if one.field == "overlays.vip"]
        return step

    def test_the_unit_is_enabled_and_not_started_before_etcd(self):
        step = self.plan("disabled", "inactive")
        runs = [a.argv for a in step.actions if isinstance(a, Run)]
        self.assertIn(("systemctl", "enable", UNIT), runs)
        self.assertNotIn(("systemctl", "start", UNIT), runs)
        notes = [a.describe() for a in step.actions if isinstance(a, Note)]
        self.assertTrue(any("etcd" in one for one in notes), notes)

    def test_an_enabled_unit_waiting_for_etcd_is_unchanged(self):
        step = self.plan("enabled", "inactive")
        self.assertEqual([a for a in step.actions if isinstance(a, Run)], [])

    def test_with_etcd_s_cluster_the_unit_is_started(self):
        self.formed()
        step = self.plan("enabled", "inactive")
        self.assertIn(("systemctl", "start", UNIT),
                      [a.argv for a in step.actions if isinstance(a, Run)])


if __name__ == "__main__":
    unittest.main()
