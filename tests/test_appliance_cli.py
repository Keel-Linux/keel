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
        # keel trusts a firewall record root owns; the test's files are
        # the user's (tests/test_firewall_record.py)
        owner = mock.patch("keel.system.fwrecord.ROOT_UID", os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        # sshd's configuration, which every machine has: the firewall
        # (decision 0097, every mode) reads the ports it must keep open
        os.makedirs(join(self.root, "etc/ssh"), exist_ok=True)
        with open(join(self.root, "etc/ssh/sshd_config"), "w") as fob:
            fob.write("Port 22\n")
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
        self.assertIn(f"derived.monit: write /{MANIFEST_MONIT}: 5 unit(s)"
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

    def test_monit_missing_before_first_apply_says_why(self):
        """keel#252: when apply has not converged the appliance (no overlay
        record), a missing monit file is drift with a note that says why"""
        self.write(spec_text())
        # Before any apply, the overlay record does not exist and the
        # monit file has never been written. diff reports drift with
        # a note naming the overlay record and the log to check.
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.monit: drift", out)
        self.assertIn("no successful apply is recorded", out)
        self.assertIn("10keel-system", out)
        # After apply converges, the record exists. Deleting the file
        # is drift without the note: the record proves apply ran.
        self.apply()
        self.assertTrue(os.path.exists(join(self.root, MANIFEST_MONIT)))
        os.remove(join(self.root, MANIFEST_MONIT))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.monit: drift", out)
        self.assertIn("observed nothing", out)
        self.assertNotIn("no successful apply is recorded", out)

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
    """Every mode (decision 0097): written under --root, compared by
    diff, read back by inspect, and removed when the spec says off"""

    def setUp(self):
        super().setUp()
        # the ports sshd listens on are read, never guessed
        os.makedirs(join(self.root, "etc/ssh"), exist_ok=True)
        with open(join(self.root, "etc/ssh/sshd_config"), "w") as fob:
            fob.write("Port 22\n")
        # a host bridge, whose guests keep their DHCP and DNS
        os.makedirs(join(self.root, "sys/class/net/lxcbr0/bridge"))

    def test_without_sshd_s_config_nothing_is_written(self):
        os.remove(join(self.root, "etc/ssh/sshd_config"))
        self.write(self.firewall("enforce"))
        code, out, _ = self.apply()
        self.assertEqual(code, 16)
        self.assertIn("the ports sshd listens on cannot be determined", out)
        self.assertFalse(os.path.exists(join(self.root, FIREWALL)))

    def firewall(self, state: str | None, mode: str = "simple",
                 extra: str = "") -> str:
        text = spec_text().replace("mode: simple", f"mode: {mode}")
        if state is not None:
            text += f"firewall: {{state: {state}{extra}}}\n"
        return text

    def test_enforce_then_off_in_the_simple_mode(self):
        self.write(self.firewall("enforce"))
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn(f"derived.firewall: write /{FIREWALL} (enforce): public"
                      " tcp 22, 12320, 12321, DHCP and DNS for the guests of"
                      " lxcbr0 (mode 0600): done", out)
        self.assertIn("derived.firewall: not loaded: not the live system",
                      out)
        self.assertIn("check program keel-firewall", self.monit_file())
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("derived.firewall: same (the ruleset apply renders"
                      " from the manifests, enforce)", out)
        self.assertIn("derived.firewall.loaded: not compared", out)
        self.assertIn("0 change(s)", self.apply()[1])

        with open(join(self.root, FIREWALL), "a") as fob:
            fob.write("# mine\n")
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.firewall: drift", out)

        self.write(self.firewall("off"))
        code, out, _ = self.apply()
        self.assertIn(f"derived.firewall: remove /{FIREWALL}, which keel"
                      " wrote: the firewall is off in the spec: done", out)
        self.assertFalse(os.path.exists(join(self.root, FIREWALL)))
        self.assertNotIn("keel-firewall", self.monit_file())
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("derived.firewall: same (nothing)", out)
        self.assertIn("derived.firewall.state: not compared (warning: off"
                      " in the spec, no inbound rule of keel's protects this"
                      " node)", out)

    def test_a_spec_that_says_nothing_writes_report_under_a_root(self):
        """an image build declares enforce; with nothing said, keel
        cannot see a socket under --root, so it writes report"""
        self.write(self.firewall(None, "cloud_simple"))
        code, out, err = self.apply()
        self.assertEqual(code, 0, out + err)
        self.assertIn("derived.firewall: report: the sockets cannot be"
                      " listed (not the live system: no socket is seen)", out)
        self.assertIn(f"write /{FIREWALL} (report)", out)
        code, out, _ = self.diff()
        self.assertEqual(code, 0, out)
        self.assertIn("derived.firewall: same (the ruleset apply renders"
                      " from the manifests, report)", out)

    def test_a_node_in_the_field_before_its_apply_is_drift(self):
        self.write(self.firewall(None))
        code, out, _ = self.diff()
        self.assertEqual(code, DRIFT)
        self.assertIn("derived.firewall: drift (declared the ruleset apply"
                      " renders from the manifests, report, observed"
                      " nothing)", out)

    def test_diff_without_sshd_s_ports_is_unknown(self):
        os.remove(join(self.root, "etc/ssh/sshd_config"))
        self.write(self.firewall("enforce"))
        code, out, _ = self.diff()
        self.assertIn("derived.firewall: unknown (declared the ruleset apply"
                      " renders from the manifests, enforce; not inferred:"
                      " the ports sshd listens on cannot be determined", out)

    def test_on_the_live_system_the_kernel_s_table_is_compared(self):
        self.write(self.firewall("enforce"))
        self.apply()
        with open(join(self.root, FIREWALL)) as fob:
            digest = loaded_digest(fob.read())
        declared = yaml.safe_load(self.firewall("enforce"))
        for held, status in ((digest, "same"), ("0000", "drift"),
                             (None, "drift")):
            found = self.live_fields(declared, held, "")
            self.assertEqual(found["derived.firewall.loaded"].status, status)

    def live_fields(self, declared, held, ss: str) -> dict:
        def run(argv, **kwargs):
            """ss and sshd -T answer; systemctl and the rest are absent"""
            if argv[0] == "ss":
                return subprocess.CompletedProcess(argv, 0, ss, "")
            if argv[0] == "sshd":
                return subprocess.CompletedProcess(argv, 0, "port 22\n", "")
            raise OSError(2, "none")
        # one patch: these modules share the one subprocess module
        with mock.patch("keel.diff.appliance.LIVE_ROOT", self.root), \
                mock.patch("keel.diff.appliance.table_digest",
                           return_value=held), \
                mock.patch("keel.system.listeners.subprocess.run", run):
            return {field.field: field for field in
                    appliance_fields(declared, self.root)}

    def test_diff_lists_what_enforce_would_close(self):
        """report: each socket on an address that is not a loopback and
        that the ruleset does not open"""
        self.write(self.firewall("report"))
        self.apply()
        found = self.live_fields(yaml.safe_load(self.firewall("report")),
                                 None,
                                 "tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\n"
                                 "tcp LISTEN 0 1 [::]:9999 [::]:*\n"
                                 "tcp LISTEN 0 1 127.0.0.1:25 0.0.0.0:*\n")
        line = found["derived.firewall.listeners"].line()
        self.assertEqual(line, (
            "derived.firewall.listeners: not compared (report: enforce would"
            " close tcp [::]:9999 of no process ss could read)"))

    def test_diff_names_the_warnings_of_decision_0097(self):
        os.makedirs(join(self.root, "etc/iptables"))
        with open(join(self.root, "etc/iptables/rules.v4"), "w") as fob:
            fob.write("*filter\n")
        self.write(self.firewall("enforce", extra=", allow: [{port: 3306,"
                                 " protocol: tcp}, {port: 8080, protocol:"
                                 " tcp}]"))
        code, out, _ = self.diff()
        self.assertIn("derived.firewall.legacy: not compared (warning:"
                      " /etc/iptables/rules.v4 is there: do not install"
                      " iptables-persistent, its rules have no WireGuard"
                      " port)", out)
        self.assertIn("firewall.allow: not compared (warning: 3306/tcp opens"
                      " a database port to every address: give it `from`)",
                      out)

    def test_inspect_keeps_enforce_and_leaves_report_to_rule_b(self):
        """a re-emitted spec (0027) keeps enforce; report is left out, so
        a re-emitted spec never pins a node in report"""
        self.write(self.firewall("enforce"))
        self.apply()
        code, out, err = self.cli("inspect")
        self.assertEqual(yaml.safe_load(out)["firewall"],
                         {"state": "enforce"})
        self.assertIn(f"firewall.state: enforce (from {self.root}/"
                      f"{FIREWALL}, keel's ruleset)", err)
        self.write(self.firewall("report"))
        self.apply()
        code, out, err = self.cli("inspect")
        self.assertNotIn("firewall", yaml.safe_load(out))
        self.assertIn("firewall.state: not inferred", err)

    def test_enforce_is_valid_in_every_mode(self):
        for mode in ("simple", "cloud_simple", "cloud_advanced"):
            self.write(self.firewall("enforce", mode))
            _, _, err = self.apply()
            self.assertNotIn("firewall", err)


SS_CORE = (
    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=101,fd=3))\n'
    'tcp LISTEN 0 128 0.0.0.0:12321 0.0.0.0:*'
    ' users:(("miniserv.pl",pid=310,fd=5))\n'
    'udp UNCONN 0 0 0.0.0.0:12321 0.0.0.0:*'
    ' users:(("miniserv.pl",pid=310,fd=6))\n'
    'tcp LISTEN 0 100 127.0.0.1:25 0.0.0.0:*'
    ' users:(("master",pid=400,fd=13))\n')


class TestLiveEntry(ApplianceCliCase):
    """The whole decision from the command a person runs (decision 0097)

    The tests of keel.system.firewall build a FirewallState by hand, so
    they never saw that the observation, keel.system.appstate, listed
    the sockets and asked sshd -T only when the spec had a `firewall:`
    key, which no published spec has (the real test of PR 307). These
    go through `keel spec apply` itself, with the root taken for the
    live system, with a spec that has no firewall key in each mode."""

    def setUp(self):
        super().setUp()
        for pid, unit in ((101, "ssh.service"), (310, "webmin.service"),
                          (400, "postfix@-.service")):
            os.makedirs(join(self.root, f"proc/{pid}"))
            with open(join(self.root, f"proc/{pid}/cgroup"), "w") as fob:
                fob.write(f"0::/system.slice/{unit}\n")
        self.ss = SS_CORE
        self.asked = []
        self.shown = []

    def answer(self, argv, **kwargs):
        """ss, sshd -T and nft answer as on a node; the rest fails"""
        self.asked.append(argv[0])
        self.shown.append(tuple(argv[:3]))
        if argv[:3] == ["systemctl", "show", "--value"]:
            return subprocess.CompletedProcess(argv, 0, "101\n", "")
        answers = {"ss": (0, self.ss), "sshd": (0, "port 22\n"),
                   "nft": (1, "")}
        code, out = answers.get(argv[0], (1, ""))
        return subprocess.CompletedProcess(argv, code, out, "")

    def apply_live(self, mode: str, extra: str = "") -> str:
        self.write(spec_text().replace("mode: simple", f"mode: {mode}")
                   + extra)
        # the test's /proc files are the user's; on a node, root's
        owner = mock.patch("keel.system.listeners.ROOT_UID", os.getuid())
        with owner, mock.patch("keel.system.appstate.ROOT_DEFAULT",
                               self.root), \
                mock.patch("keel.inspect.constants.ROOT_DEFAULT",
                           self.root), \
                mock.patch("subprocess.run", self.answer), \
                mock.patch("shutil.which", return_value="/usr/sbin/x"):
            code, out, err = self.cli("spec", "apply", "--spec", self.spec,
                                      "--system-only", "--dry-run")
        return out + err

    def test_no_firewall_key_lets_rule_b_decide_in_each_mode(self):
        for mode in ("simple", "cloud_simple", "cloud_advanced"):
            with self.subTest(mode=mode):
                out = self.apply_live(mode)
                self.assertIn("derived.firewall: enforce: each socket on an"
                              " address that is not a loopback belongs to a"
                              " unit of the manifests", out)
                self.assertIn("would write /etc/keel/firewall/"
                              "keel-manifest.nft (enforce)", out)
                self.assertIn("ss", self.asked)
                self.assertIn("sshd", self.asked)
                self.assertIn(("systemctl", "show", "ssh.socket"),
                              self.shown)

    def test_an_undeclared_socket_keeps_report_from_the_command(self):
        self.ss = SS_CORE + ("tcp LISTEN 0 1 [::]:9999 [::]:*"
                             ' users:(("nc",pid=800,fd=3))\n')
        out = self.apply_live("simple")
        self.assertIn("derived.firewall: report: enforce waits, because these"
                      " sockets belong to no unit of the manifests: tcp"
                      " [::]:9999", out)

    def apply_executed(self, mode: str = "simple") -> tuple[int, str]:
        """keel spec apply --system-only, carried out: the lock, the
        writes under the root, the nft runs and the timer's start go
        through, with ss, sshd, nft and systemctl answering as on a
        node (the second review: TestLiveEntry ran --dry-run only)"""
        self.write(spec_text().replace("mode: simple", f"mode: {mode}"))
        os.makedirs(join(self.root, "var/lib/keel/mesh"), exist_ok=True)
        with mock.patch("keel.system.appstate.ROOT_DEFAULT", self.root), \
                mock.patch("keel.inspect.constants.ROOT_DEFAULT",
                           self.root), \
                mock.patch("keel.commands.ROOT_DEFAULT", self.root), \
                mock.patch("subprocess.run", self.carried), \
                mock.patch("shutil.which", return_value="/usr/sbin/x"):
            code, out, err = self.cli("spec", "apply", "--spec", self.spec,
                                      "--system-only")
        return code, out + err

    def carried(self, argv, **kwargs):
        self.ran.append(tuple(argv))
        if argv[0] == "nft" and "list" not in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["systemctl", "start"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return self.answer(argv)

    def test_an_executed_apply_writes_loads_and_starts_the_watch(self):
        self.ran = []
        code, out = self.apply_executed()
        self.assertIn(f"write /{FIREWALL} (enforce)", out)
        self.assertIn(("nft", "-f", f"/{FIREWALL}"), self.ran)
        self.assertIn(("systemctl", "start", "keel-firewall-watch.timer"),
                      self.ran)
        with open(join(self.root, FIREWALL)) as fob:
            self.assertIn("policy drop;", fob.read())
        with open(join(self.root, "var/lib/keel/mesh/sync.lock")) as fob:
            self.assertIn("keel spec apply", fob.read())

    def test_an_executed_apply_survives_a_watch_that_does_not_start(self):
        self.ran = []
        real = self.carried

        def refusing(argv, **kwargs):
            if argv[:2] == ["systemctl", "start"]:
                self.ran.append(tuple(argv))
                return subprocess.CompletedProcess(argv, 1, "",
                                                   "Unit is masked.")
            return real(argv, **kwargs)
        self.carried = refusing
        code, out = self.apply_executed()
        self.assertIn("start keel-firewall-watch.timer", out)
        self.assertIn("not done", out)
        self.assertNotIn("derived.firewall: refused", out)
        self.assertNotIn("keel-firewall-watch.timer): failed", out)

    def test_the_port_a_running_sshd_holds_stays_open(self):
        """the second review: SSHD_OPTS="-p 2200" in /etc/default/ssh,
        or a Port edited and sshd not restarted: sshd -T says 22, the
        daemon listens on 2200. Both stay open, and the plan says so"""
        self.ss = SS_CORE.replace("0.0.0.0:22 ", "0.0.0.0:2200 ")
        out = self.apply_live("simple")
        self.assertIn("would write /etc/keel/firewall/keel-manifest.nft"
                      " (enforce): public tcp 22, 2200, 12320, 12321", out)
        self.assertIn("derived.firewall: sshd listens now on tcp 2200,"
                      " which its configuration (sshd -T) does not name:"
                      " both stay open", out)

    def test_a_process_named_sshd_of_another_user_opens_nothing(self):
        """the third review (F1): www-data runs a copy named sshd on 4444"""
        os.makedirs(join(self.root, "proc/500"))
        with open(join(self.root, "proc/500/cgroup"), "w") as fob:
            fob.write("0::/system.slice/nginx.service\n")
        self.ss = SS_CORE + ('tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:*'
                             ' users:(("sshd",pid=500,fd=3))\n')
        out = self.apply_live("simple")
        self.assertNotIn("4444, 12320", out)
        self.assertNotIn("listens now on tcp 4444", out)

    def test_each_spelling_from_the_command(self):
        """the table of docs/spec.md: what each value means"""
        cases = (("", "enforce"),
                 ("firewall: {enabled: false}\n", "enforce"),
                 ("firewall: {allow: []}\n", "enforce"),
                 ("firewall: {enabled: true}\n", "enforce"),
                 ("firewall: {state: enforce}\n", "enforce"),
                 ("firewall: {state: report}\n", "report"))
        for extra, state in cases:
            with self.subTest(spec=extra):
                out = self.apply_live("simple", extra)
                self.assertIn("/etc/keel/firewall/keel-manifest.nft"
                              f" ({state})", out)
        out = self.apply_live("simple", "firewall: {state: off}\n")
        self.assertIn("derived.firewall: off in the spec", out)


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

    def test_wireguard_disagreeing_keeps_the_emitted_spec_s_value(self):
        # on the live system only: wg0 up and its unit not yet enabled,
        # inside a 0018 window. The machine says nothing settled, so the
        # spec the installer emitted still gives the key, and the emitted
        # spec keeps every overlay of the chain
        os.makedirs(join(self.root, "etc/keel"))
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write(spec_text())
        why = "wg-quick@wg0.service disabled, wg0 up"
        with mock.patch("keel.inspect.overlays.wireguard_state",
                        return_value=(None, why)):
            doc, report = self.inspect()
        self.assertEqual(doc["overlays"]["wireguard"], "disabled")
        self.assertIn("overlays.wireguard: disabled (from"
                      f" {self.root}/etc/keel/instance.yaml; its interface"
                      f" and its unit disagree: {why})", report)

    def test_wireguard_disagreeing_with_no_emitted_spec(self):
        why = "wg-quick@wg0.service disabled, wg0 up"
        with mock.patch("keel.inspect.overlays.wireguard_state",
                        return_value=(None, why)):
            doc, report = self.inspect()
        self.assertNotIn("wireguard", doc.get("overlays", {}))
        self.assertIn("overlays.wireguard: not inferred: its interface and"
                      f" its unit disagree: {why}, and no spec the installer"
                      " emitted says it at", report)

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
