# Copyright (c) 2026 KeelLinux maintainers
"""apply, diff and inspect of the appliance sections, end to end (0041)

Under --root, over the format's Core: systemctl is replaced at the
subprocess boundary by a fake that makes and removes the `.wants` links
the real one would make under --root, so every run converges a real
tree, which inspect and diff then read back. The criterion of step 3 of
0041's plan, in a tree: CrowdSec disabled, enabled, disabled converges
each time, a second apply changes nothing, diff is clean, and Monit's
file gains and loses exactly CrowdSec's checks.
"""

import os
import subprocess
from os.path import join
from unittest import mock

import yaml

from manifest_helpers import ManifestCase, fixture

from keel import exits
from keel.diff.appliance import appliance_fields
from keel.system import effects
from keel.manifest.firewall import PATH as FIREWALL
from keel.manifest.firewall import loaded_digest
from keel.system.appstate import MANIFEST_MONIT, MONIT_LINK

WANTS = "etc/systemd/system/multi-user.target.wants"
DRIFT = exits.DRIFT_FOUND
REAL_RUN = subprocess.run


def spec_text(crowdsec: str = "disabled", monitor: str = "") -> str:
    return (
        "version: 1\n"
        "appliance: {name: core}\n"
        "installation: {mode: simple}\n"
        "overlays: {installer: enabled, wireguard: disabled,"
        f" etcd: disabled, crowdsec: {crowdsec}}}\n" + monitor)


class ApplianceCliCase(ManifestCase):
    def setUp(self):
        super().setUp()
        # Core alone, as a keel-core machine has it
        os.remove(self.path("appliances", "web"))
        self.spec = join(self.tmpdir, "instance.yaml")
        self.systemctl = []

    def write(self, text: str) -> None:
        with open(self.spec, "w") as fob:
            fob.write(text)

    def fake_run(self, argv, **kwargs):
        """systemctl --root=R enable|disable UNIT, as far as links go"""
        if argv[0] != "systemctl":
            return REAL_RUN(argv, **kwargs)
        self.systemctl.append(tuple(argv))
        verb, unit = argv[-2], argv[-1]
        link = join(argv[1][len("--root="):], WANTS, unit)
        if verb == "enable":
            os.makedirs(os.path.dirname(link), exist_ok=True)
            os.symlink(f"/usr/lib/systemd/system/{unit}", link)
        else:
            os.remove(link)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def apply(self) -> tuple[int, str, str]:
        with mock.patch.object(effects.subprocess, "run", self.fake_run):
            return self.cli("spec", "apply", "--spec", self.spec,
                            "--system-only")

    def diff(self) -> tuple[int, str, str]:
        return self.cli("diff", "--spec", self.spec)

    def monit_file(self) -> str:
        with open(join(self.root, MANIFEST_MONIT)) as fob:
            return fob.read()


class TestConverge(ApplianceCliCase):
    def test_disabled_enabled_disabled(self):
        self.write(spec_text("disabled"))
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn("overlays.crowdsec: unchanged (disabled:"
                      " crowdsec.service, crowdsec-firewall-bouncer.service)",
                      out)
        self.assertIn(f"derived.monit: write /{MANIFEST_MONIT}: 4 unit(s)"
                      " and 3 probe(s) of core (mode 0600): done", out)
        off = self.monit_file()
        self.assertEqual(self.diff()[0], 0, self.diff()[1])

        self.write(spec_text("enabled"))
        code, out, err = self.diff()
        self.assertEqual(code, DRIFT, out)
        self.assertIn("overlays.crowdsec: drift (declared enabled, observed"
                      " disabled)", out)
        self.assertIn("derived.monit: drift", out)
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(self.systemctl[-2:], [
            ("systemctl", f"--root={self.root}", "enable",
             "crowdsec.service"),
            ("systemctl", f"--root={self.root}", "enable",
             "crowdsec-firewall-bouncer.service")])
        self.assertIn("CrowdSec's identity is not made under --root", out)
        on = self.monit_file()
        self.assertEqual(self.checks(on) - self.checks(off), {
            "keel-unit-crowdsec", "keel-unit-firewall-bouncer",
            "keel-check-crowdsec-lapi"})
        self.assertEqual(self.checks(off) - self.checks(on), set())
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("overlays.crowdsec: same (enabled)", out)

        code, out, _ = self.apply()
        self.assertIn("apply --system-only: 0 change(s), 0 failed", out)

        self.write(spec_text("disabled"))
        code, out, _ = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.monit_file(), off)
        self.assertFalse(os.listdir(join(self.root, WANTS)))
        self.assertEqual(self.diff()[0], 0)
        code, out, _ = self.apply()
        self.assertIn("apply --system-only: 0 change(s), 0 failed", out)

    @staticmethod
    def checks(text: str) -> set[str]:
        return {line.split()[2] for line in text.splitlines()
                if line.startswith("check ")}

    def test_the_monitor_includes_it_and_diff_compares_the_include(self):
        monitor = ("security: {alerts: admin@example.org}\n"
                   "monitor:\n  enabled: true\n  notify: {email: true}\n")
        self.write(spec_text("disabled", monitor))
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(os.readlink(join(self.root, MONIT_LINK)),
                         "/" + MANIFEST_MONIT)
        code, out, _ = self.diff()
        self.assertIn("derived.monit.included: same (true)", out)
        os.remove(join(self.root, MONIT_LINK))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.monit.included: drift (declared true,"
                      " observed false)", out)

    def test_a_hand_edit_of_the_file_is_drift(self):
        self.write(spec_text())
        self.apply()
        with open(join(self.root, MANIFEST_MONIT), "a") as fob:
            fob.write("check system mine\n")
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.monit: drift (declared the file apply"
                      " renders from the manifests, observed a file that"
                      " differs from it)", out)
        os.remove(join(self.root, MANIFEST_MONIT))
        self.assertIn("observed nothing", self.diff()[1])

    def test_a_unit_turned_off_by_hand_is_drift(self):
        self.write(spec_text("enabled"))
        self.apply()
        os.remove(join(self.root, WANTS, "crowdsec-firewall-bouncer.service"))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("overlays.crowdsec: drift (declared enabled, observed"
                      " crowdsec.service enabled,"
                      " crowdsec-firewall-bouncer.service disabled)", out)

    def test_overlays_without_a_unit_and_the_mode_are_not_compared(self):
        self.write(spec_text())
        code, out, _ = self.diff()
        self.assertIn("overlays.installer: not compared (runs no unit, so"
                      " nothing in systemd says whether it is on)", out)
        self.assertIn("installation: not compared", out)
        self.assertIn("appliance.name: same (core)", out)

    def test_a_dry_run_changes_nothing(self):
        self.write(spec_text("enabled"))
        with mock.patch.object(effects.subprocess, "run", self.fake_run):
            code, out, _ = self.cli("spec", "apply", "--spec", self.spec,
                                    "--system-only", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("overlays.crowdsec: would enable crowdsec.service",
                      out)
        self.assertEqual(self.systemctl, [])
        self.assertFalse(os.path.exists(join(self.root, MANIFEST_MONIT)))


class TestFirewall(ApplianceCliCase):
    """Optional, cloud advanced only: written under --root, compared by
    diff, and removed again when the spec turns it off"""

    def setUp(self):
        super().setUp()
        # the ports sshd listens on are read, never guessed
        os.makedirs(join(self.root, "etc/ssh"))
        with open(join(self.root, "etc/ssh/sshd_config"), "w") as fob:
            fob.write("Port 22\n")
        # a host bridge, whose guests keep their DHCP and DNS
        os.makedirs(join(self.root, "sys/class/net/lxcbr0/bridge"))

    def test_without_sshd_s_config_nothing_is_written(self):
        os.remove(join(self.root, "etc/ssh/sshd_config"))
        self.write(self.firewall(True))
        code, out, _ = self.apply()
        self.assertEqual(code, 16)
        self.assertIn("the ports sshd listens on cannot be determined", out)
        self.assertFalse(os.path.exists(join(self.root, FIREWALL)))

    def firewall(self, enabled: bool, mode: str = "cloud_advanced") -> str:
        return (spec_text().replace("mode: simple", f"mode: {mode}")
                + f"firewall: {{enabled: {str(enabled).lower()}}}\n")

    def test_on_then_off(self):
        self.write(self.firewall(True))
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn(f"derived.firewall: write /{FIREWALL}: public tcp 22,"
                      " 12320, 12321, DHCP and DNS for the guests of lxcbr0"
                      " (mode 0600): done", out)
        self.assertIn("derived.firewall: not loaded: not the live system",
                      out)
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("derived.firewall: same (the ruleset apply renders"
                      " from the manifests)", out)
        self.assertIn("derived.firewall.loaded: not compared", out)
        self.assertIn("0 change(s)", self.apply()[1])

        with open(join(self.root, FIREWALL), "a") as fob:
            fob.write("# mine\n")
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.firewall: drift", out)

        self.write(self.firewall(False))
        code, out, _ = self.apply()
        self.assertIn(f"derived.firewall: remove /{FIREWALL}, which keel"
                      " wrote: the firewall is off in the spec: done", out)
        self.assertFalse(os.path.exists(join(self.root, FIREWALL)))
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("derived.firewall: same (nothing)", out)

    def test_on_the_live_system_the_kernel_s_table_is_compared(self):
        self.write(self.firewall(True))
        self.apply()
        with open(join(self.root, FIREWALL)) as fob:
            digest = loaded_digest(fob.read())
        declared = yaml.safe_load(self.firewall(True))
        for held, status in ((digest, "same"), ("0000", "drift"),
                             (None, "drift")):
            with mock.patch("keel.diff.appliance.LIVE_ROOT", self.root), \
                    mock.patch("keel.diff.appliance.table_digest",
                               return_value=held), \
                    mock.patch("keel.inspect.units.subprocess.run",
                               side_effect=OSError(2, "none")):
                found = {field.field: field for field in
                         appliance_fields(declared, self.root)}
            self.assertEqual(found["derived.firewall.loaded"].status, status)

    def test_inspect_keeps_the_opt_in(self):
        """a re-emitted spec (0027) keeps firewall.enabled"""
        self.write(self.firewall(True))
        self.apply()
        code, out, err = self.cli("inspect")
        self.assertEqual(yaml.safe_load(out)["firewall"], {"enabled": True})
        self.assertIn(f"firewall.enabled: true (from {self.root}/"
                      f"{FIREWALL}, keel's ruleset)", err)
        self.write(self.firewall(False))
        self.apply()
        code, out, err = self.cli("inspect")
        self.assertEqual(yaml.safe_load(out)["firewall"],
                         {"enabled": False})

    def test_refused_outside_cloud_advanced(self):
        self.write(self.firewall(True, "simple"))
        code, _, err = self.apply()
        self.assertEqual(code, 3)
        self.assertIn("firewall.enabled: the firewall derived from the"
                      " manifests is for cloud advanced installations only",
                      err)
        self.assertFalse(os.path.exists(join(self.root, FIREWALL)))

    def test_off_with_keel_s_file_left_behind_is_drift(self):
        self.write(self.firewall(True))
        self.apply()
        self.write(self.firewall(False))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.firewall: drift (declared nothing, observed"
                      " keel's ruleset)", out)


class TestInspect(ApplianceCliCase):
    def inspect(self) -> tuple[dict, str]:
        code, out, err = self.cli("inspect")
        return yaml.safe_load(out), err

    def test_the_appliance_and_its_units_are_read_back(self):
        self.write(spec_text("enabled"))
        self.apply()
        doc, report = self.inspect()
        self.assertEqual(doc["appliance"], {"name": "core"})
        self.assertEqual(doc["overlays"], {"etcd": "disabled",
                                           "crowdsec": "enabled"})
        self.assertIn("appliance.name: core (from the one appliance"
                      " manifest", report)
        self.assertIn("installation.mode: not inferred: a machine's units"
                      " do not say which mode chose them", report)
        self.assertIn("overlays.installer: not inferred: runs no unit",
                      report)

    def test_the_emitted_spec_gives_the_mode_and_the_rest(self):
        os.makedirs(join(self.root, "etc/keel"))
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write(spec_text())
        doc, report = self.inspect()
        self.assertEqual(doc["installation"], {"mode": "simple"})
        self.assertEqual(doc["overlays"], {
            "installer": "enabled", "wireguard": "disabled",
            "etcd": "disabled", "crowdsec": "disabled"})
        self.assertIn("installation.mode: simple (from"
                      f" {self.root}/etc/keel/instance.yaml)", report)

    def wireguard(self, enabled: bool) -> None:
        """/etc/wireguard/wg0.conf, and the unit's link when `enabled`"""
        os.makedirs(join(self.root, "etc/wireguard"))
        with open(join(self.root, "etc/wireguard/wg0.conf"), "w") as fob:
            fob.write("[Interface]\nAddress = fd00:1::1/64\n")
        if enabled:
            os.makedirs(join(self.root, WANTS))
            os.symlink("/usr/lib/systemd/system/wg-quick@.service",
                       join(self.root, WANTS, "wg-quick@wg0.service"))

    def test_wireguard_is_read_from_its_interface_s_unit(self):
        self.wireguard(enabled=True)
        doc, report = self.inspect()
        self.assertEqual(doc["overlays"]["wireguard"], "enabled")
        self.assertIn("overlays.wireguard: enabled (from"
                      " wg-quick@wg0.service enabled)", report)

    def test_wireguard_s_file_without_its_unit_is_disabled(self):
        self.wireguard(enabled=False)
        doc, report = self.inspect()
        self.assertEqual(doc["overlays"]["wireguard"], "disabled")

    def test_the_machine_says_wireguard_before_the_emitted_spec(self):
        os.makedirs(join(self.root, "etc/keel"))
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write(spec_text())
        self.wireguard(enabled=True)
        doc, _ = self.inspect()
        self.assertEqual(doc["overlays"]["wireguard"], "enabled")
        self.assertEqual(doc["overlays"]["installer"], "enabled")

    def test_wireguard_s_interface_and_unit_that_disagree(self):
        # on the live system only: wg0 up and its unit not yet enabled
        os.makedirs(join(self.root, "etc/keel"))
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write(spec_text())
        why = "wg-quick@wg0.service disabled, wg0 up"
        with mock.patch("keel.inspect.overlays.wireguard_state",
                        return_value=(None, why)):
            doc, report = self.inspect()
        self.assertNotIn("wireguard", doc["overlays"])
        self.assertIn("overlays.wireguard: not inferred: its interface and"
                      f" its unit disagree: {why}", report)

    def test_units_that_disagree_are_not_inferred(self):
        os.makedirs(join(self.root, WANTS))
        os.symlink("/x", join(self.root, WANTS, "crowdsec.service"))
        doc, report = self.inspect()
        self.assertNotIn("crowdsec", doc["overlays"])
        self.assertIn("overlays.crowdsec: not inferred: its units disagree:"
                      " crowdsec.service enabled,"
                      " crowdsec-firewall-bouncer.service disabled", report)

    def test_an_emitted_spec_that_says_nothing_usable(self):
        os.makedirs(join(self.root, "etc/keel"))
        for text in ("installation: [\n", "overlays: [installer]\n"):
            with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
                fob.write(text)
            doc, report = self.inspect()
            self.assertNotIn("installation", doc)
            self.assertIn("overlays.installer: not inferred", report)

    def test_a_chain_that_does_not_resolve(self):
        self.edit("appliances", "core", "base: none", "base: none\nbad: 1")
        doc, report = self.inspect()
        self.assertEqual(doc["appliance"], {"name": "core"})
        self.assertNotIn("overlays", doc)
        self.assertIn("overlays: not inferred:", report)
        found = appliance_fields({"appliance": {"name": "core"}}, self.root)
        self.assertEqual([(f.field, f.status) for f in found],
                         [("overlays", "unknown")])

    def test_an_unreadable_manifest_is_not_a_base(self):
        self.put("appliances", "other", "base: [\n")
        doc, report = self.inspect()
        self.assertIn("appliance.name: not inferred: core and other are"
                      " installed", report)

    def test_no_appliance_manifest_is_no_section(self):
        empty = join(self.tmpdir, "empty")
        os.makedirs(empty)
        code, out, err = self.cli("inspect", root=empty)
        self.assertNotIn("appliance", yaml.safe_load(out))
        self.assertNotIn("appliance.name", err)

    def test_two_appliances_that_do_not_build_on_each_other(self):
        self.put("appliances", "web", fixture("appliances", "web"))
        self.put("appliances", "other", (
            "manifest_version: 1\nkind: appliance\nname: other\n"
            "title: other\nsummary: x\nbase: core\n"))
        doc, report = self.inspect()
        self.assertNotIn("appliance", doc)
        self.assertIn("appliance.name: not inferred: other and web are"
                      " installed, and neither is built on the other",
                      report)
