# Copyright (c) 2026 KeelLinux maintainers
"""An overlay the chain gains on an upgrade (keel 0.20.0, keel-core 0.1.3)

`apt full-upgrade` brought keel-overlay-vip, and keel-core
0.1.3 added `vip` to Core's overlays: every spec written before it, which
named the seven overlays the chain had, was refused by every command.
An upgrade never breaks a working machine, so an overlay the spec leaves
out and the chain gained after the spec was last applied takes its
manifest default for the installation mode, said as a warning by
validate and as "not declared" by diff. An overlay the spec declared when
it was last applied, and leaves out now, stays an error (decisions 0027,
0041). The record of what was declared is apply's,
/var/lib/keel/spec/overlays.yaml under the root.
"""

import os
import unittest
from os.path import join

import yaml

from test_appliance_cli import DRIFT, WANTS, ApplianceCliCase, spec_text

from keel.manifest.facts import gather
from keel.spec import overlayrecord
from keel.spec.validate_appliance import (
    ManifestFacts,
    against_manifests,
    undeclared_defaults,
    with_defaults,
)

VIP = """manifest_version: 1
kind: overlay
name: vip
title: Service VIP
summary: The replicated pair's VIP on the mesh (0049)
requires: [wireguard]
processes:
  - name: keel-vip
    unit: keel-vip.service
"""
VIP_LINE = ("  vip:       {simple: disabled, cloud_simple: disabled,"
            " cloud_advanced: disabled}\n")
CROWDSEC_LINE = "  crowdsec:  {simple: disabled, cloud_simple: enabled," \
    " cloud_advanced: enabled}\n"

CORE = {"installer": (), "wireguard": (), "etcd": ("wireguard",),
        "crowdsec": ()}
STATES = {"installer": "enabled", "wireguard": "disabled",
          "etcd": "disabled", "crowdsec": "disabled"}
DEFAULTS = {name: {"simple": state, "cloud_simple": state,
                   "cloud_advanced": state}
            for name, state in STATES.items()}


def facts(recorded=frozenset(STATES), **more) -> ManifestFacts:
    """Core and a vip it gained, disabled everywhere unless MORE says"""
    vip = more.get("vip", {"simple": "disabled", "cloud_simple": "disabled",
                           "cloud_advanced": "disabled"})
    return ManifestFacts(
        appliance="core", chain=("core",),
        overlays={**CORE, "vip": more.get("requires", ("wireguard",))},
        defaults={**DEFAULTS, "vip": vip}, recorded=recorded)


def core(mode="simple", **overlays) -> dict:
    found = {"version": 1, "appliance": {"name": "core"},
             "overlays": {**STATES, **overlays}}
    if mode:
        found["installation"] = {"mode": mode}
    return found


class TestDefaults(unittest.TestCase):
    def test_a_gained_overlay_takes_its_default_and_is_no_error(self):
        self.assertEqual(against_manifests(core(), facts()), [])
        self.assertEqual(undeclared_defaults(core(), facts()),
                         {"vip": "disabled"})

    def test_the_default_is_the_column_of_the_mode(self):
        found = facts(vip={"simple": "disabled", "cloud_simple": "disabled",
                           "cloud_advanced": "enabled"}, requires=())
        self.assertEqual(undeclared_defaults(core("cloud_advanced"), found),
                         {"vip": "enabled"})

    def test_an_overlay_declared_at_the_last_apply_stays_an_error(self):
        states = dict(STATES)
        del states["crowdsec"]
        doc = {**core(), "overlays": states}
        self.assertEqual(against_manifests(doc, facts()), [
            "overlays.crowdsec: not declared; every overlay of the chain"
            " of core is written out, enabled or disabled (decisions 0027,"
            " 0041)"])
        self.assertNotIn("crowdsec", undeclared_defaults(doc, facts()))

    def test_once_declared_and_applied_it_is_held_like_the_others(self):
        recorded = frozenset(STATES) | {"vip"}
        found = against_manifests(core(), facts(recorded))
        self.assertEqual(len(found), 1)
        self.assertIn("overlays.vip: not declared", found[0])

    def test_without_a_record_a_left_out_overlay_takes_its_default(self):
        """a machine keel never applied a spec on since this fix: what it
        declared then is not known, so nothing it leaves out is refused"""
        states = dict(STATES)
        del states["crowdsec"]
        doc = {**core(), "overlays": states}
        self.assertEqual(against_manifests(doc, facts(None)), [])
        self.assertEqual(undeclared_defaults(doc, facts(None)),
                         {"crowdsec": "disabled", "vip": "disabled"})

    def test_ask_has_no_default_to_take(self):
        found = facts(vip={"simple": "ask", "cloud_simple": "disabled",
                           "cloud_advanced": "disabled"})
        errors = against_manifests(core(), found)
        self.assertEqual(len(errors), 1)
        self.assertIn("overlays.vip: not declared", errors[0])
        self.assertIn("its default in simple is ask", errors[0])

    def test_no_mode_gives_no_column_to_take_it_from(self):
        errors = against_manifests(core(mode=None), facts())
        self.assertEqual(len(errors), 1)
        self.assertIn("overlays.vip: not declared", errors[0])

    def test_requires_are_held_against_the_defaults_too(self):
        found = facts(vip={"simple": "enabled", "cloud_simple": "disabled",
                           "cloud_advanced": "disabled"})
        self.assertEqual(against_manifests(core(), found), [
            "overlays.vip: enabled, but vip requires wireguard, which is"
            " disabled"])

    def test_an_explicit_state_is_kept_and_nothing_is_defaulted(self):
        doc = core(vip="disabled")
        self.assertEqual(against_manifests(doc, facts()), [])
        self.assertEqual(undeclared_defaults(doc, facts()), {})
        self.assertIs(with_defaults(doc, facts())[0], doc)

    def test_with_defaults_copies_and_leaves_the_spec_alone(self):
        doc = core()
        filled, defaulted = with_defaults(doc, facts())
        self.assertEqual(defaulted, {"vip": "disabled"})
        self.assertEqual(filled["overlays"]["vip"], "disabled")
        self.assertNotIn("vip", doc["overlays"])

    def test_without_facts_nothing_is_defaulted(self):
        self.assertEqual(with_defaults(core(), None), (core(), {}))


class UpgradeCase(ApplianceCliCase):
    """Core as keel-core 0.1.2 had it, applied, then the upgrade"""

    def gain_vip(self) -> None:
        self.put("overlays", "vip", VIP)
        self.edit("appliances", "core", CROWDSEC_LINE,
                  CROWDSEC_LINE + VIP_LINE)
        from manifest_helpers import unit
        unit(self.root, "keel-vip")

    def validate(self) -> tuple[int, str, str]:
        return self.cli("spec", "validate", "--spec", self.spec,
                        "--no-secret-files")

    def record(self) -> dict:
        with open(join(self.root, overlayrecord.RECORD)) as fob:
            return yaml.safe_load(fob)


class TestUpgrade(UpgradeCase):
    def setUp(self):
        super().setUp()
        self.write(spec_text())
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.gain_vip()

    def test_the_spec_keeps_working_and_validate_says_why(self):
        code, out, err = self.validate()
        self.assertEqual(code, 0, err)
        self.assertIn("ok", out)
        self.assertIn(
            f"Warning: {self.spec}: overlays.vip: not declared (default:"
            " disabled): the"
            " chain of core gained it after this spec was last applied, so"
            " it takes the manifest's default for simple; write it out",
            err)

    def test_apply_converges_the_default_and_records_only_the_spec(self):
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn("overlays.vip: unchanged (disabled: keel-vip.service)",
                      out)
        self.assertIn("overlays.vip: not declared (default: disabled)", err)
        self.assertEqual(self.record(), {
            "appliance": "core",
            "overlays": ["crowdsec", "etcd", "installer", "wireguard"]})
        self.assertEqual(self.validate()[0], 0)

    def test_diff_reports_it_not_declared_with_its_default(self):
        code, out, err = self.diff()
        self.assertEqual(code, 0, out + err)
        self.assertIn("overlays.vip: not declared (default: disabled,"
                      " observed disabled)", out)

    def test_diff_is_drift_when_the_machine_is_off_the_default(self):
        os.makedirs(join(self.root, WANTS), exist_ok=True)
        os.symlink("/usr/lib/systemd/system/keel-vip.service",
                   join(self.root, WANTS, "keel-vip.service"))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT, out)
        self.assertIn("overlays.vip: drift (declared disabled, observed"
                      " enabled; not declared: the manifest's default)", out)

    def test_an_overlay_the_spec_had_and_drops_is_still_refused(self):
        self.write(spec_text().replace(", crowdsec: disabled", ""))
        code, _, err = self.validate()
        self.assertEqual(code, 3, err)
        self.assertIn("overlays.crowdsec: not declared; every overlay of the"
                      " chain of core is written out", err)

    def test_declared_explicitly_it_is_as_before(self):
        self.write(spec_text().replace("crowdsec: disabled",
                                       "crowdsec: disabled, vip: disabled"))
        code, _, err = self.validate()
        self.assertEqual(code, 0, err)
        self.assertNotIn("vip", err)
        code, out, _ = self.diff()
        self.assertIn("overlays.vip: same (disabled)", out)
        self.apply()
        self.assertIn("vip", self.record()["overlays"])
        # applied once declared, leaving it out again is the error
        self.write(spec_text())
        code, _, err = self.validate()
        self.assertEqual(code, 3, err)
        self.assertIn("overlays.vip: not declared", err)

    def test_a_gained_overlay_with_no_unit_says_its_default(self):
        self.put("overlays", "vip", VIP.split("processes:")[0])
        code, out, _ = self.diff()
        self.assertIn("overlays.vip: not compared (not declared (default:"
                      " disabled); runs no unit", out)

    def test_inspect_writes_the_new_overlay_out(self):
        _, out, err = self.cli("inspect")
        self.assertEqual(yaml.safe_load(out)["overlays"]["vip"], "disabled")
        self.assertIn("overlays.vip: disabled (from systemd", err)


class TestNeverApplied(UpgradeCase):
    def test_a_spec_never_applied_is_held_by_no_record(self):
        self.gain_vip()
        self.write(spec_text())
        code, _, err = self.validate()
        self.assertEqual(code, 0, err)
        self.assertIn("overlays.vip: not declared (default: disabled)", err)
        self.assertFalse(os.path.exists(join(self.root,
                                             overlayrecord.RECORD)))

    def test_a_dry_run_records_nothing(self):
        self.write(spec_text())
        self.cli("spec", "apply", "--spec", self.spec, "--system-only",
                 "--dry-run")
        self.assertFalse(os.path.exists(join(self.root,
                                             overlayrecord.RECORD)))


class TestRecord(UpgradeCase):
    def test_gather_reads_the_record_of_its_appliance_only(self):
        self.assertIsNone(gather(self.root, "core").recorded)
        overlayrecord.write(self.root, "core", ["installer", "etcd"])
        found = gather(self.root, "core")
        self.assertEqual(found.recorded, frozenset({"installer", "etcd"}))
        self.assertEqual(found.defaults["etcd"]["cloud_advanced"], "enabled")
        overlayrecord.write(self.root, "web", ["nginx"])
        self.assertIsNone(gather(self.root, "core").recorded)

    def test_a_record_that_cannot_be_read_is_no_record(self):
        path = join(self.root, overlayrecord.RECORD)
        os.makedirs(os.path.dirname(path))
        for text in ("{", "- a list\n", "appliance: core\noverlays: 3\n",
                     "appliance: core\noverlays: [1]\n"):
            with open(path, "w") as fob:
                fob.write(text)
            self.assertIsNone(overlayrecord.read(self.root, "core"), text)

    def test_a_spec_without_an_appliance_records_nothing(self):
        self.write("version: 1\ninstance: {hostname: core}\n")
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertFalse(os.path.exists(join(self.root,
                                             overlayrecord.RECORD)))

    def test_a_record_that_cannot_be_written_is_said_not_fatal(self):
        os.makedirs(join(self.root, "var/lib/keel"))
        with open(join(self.root, "var/lib/keel/spec"), "w") as fob:
            fob.write("in the way\n")
        self.write(spec_text())
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn(f"Warning: /{overlayrecord.RECORD} not written:", err)

    def test_the_record_is_root_s_and_world_readable(self):
        overlayrecord.write(self.root, "core", ["vip", "etcd"])
        path = join(self.root, overlayrecord.RECORD)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        self.assertEqual(self.record()["overlays"], ["etcd", "vip"])


if __name__ == "__main__":
    unittest.main()
