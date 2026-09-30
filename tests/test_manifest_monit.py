# Copyright (c) 2026 KeelLinux maintainers
"""Monit's checks, derived from the manifests (decisions 0040, 0041)

The renderer is pure: the resolved chain of the format's Core and Web,
the spec's states and the mesh address in, the file out. When a monit
binary is at hand (on PATH, or named by KEEL_MONIT) every file rendered
here is also given to `monit -t`.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from manifest_helpers import ManifestCase, install_app

from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.monit import HEADER, render
from keel.manifest.resolve import resolve

NOTIFY = ("/usr/bin/python3", "-B", "-m", "keel", "notify")
CORE_OFF = {"installer": "enabled", "wireguard": "disabled",
            "etcd": "disabled", "crowdsec": "disabled"}
WEB_OFF = {**CORE_OFF, "nginx": "enabled", "coraza": "disabled",
           "anubis": "disabled"}
ALL_ON = {name: "enabled" for name in WEB_OFF}


def monit_binary() -> str | None:
    return os.environ.get("KEEL_MONIT") or shutil.which("monit")


def monit_check(text: str) -> subprocess.CompletedProcess:
    """monit -t on a control file that includes TEXT, as monitrc does"""
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "keel-manifest.conf")
        control = os.path.join(tmp, "monitrc")
        with open(conf, "w") as fob:
            fob.write(text)
        with open(control, "w") as fob:
            fob.write(f"set daemon 30\nset idfile {tmp}/id\n"
                      f"set statefile {tmp}/state\ninclude {conf}\n")
        os.chmod(conf, 0o600)
        os.chmod(control, 0o600)
        return subprocess.run([monit_binary(), "-t", "-c", control],
                              capture_output=True, text=True)


class RenderCase(ManifestCase):
    def resolved(self, name: str = "web"):
        catalog = Catalog(self.root)
        found, errors = resolve(catalog, catalog.read(APPLIANCE, name))
        self.assertEqual(errors, [])
        return found

    def render(self, states: dict, name: str = "web",
               mesh: str | None = None, cycle: int = 30):
        return render(self.resolved(name), states, mesh, NOTIFY, cycle)

    def assertMonitAccepts(self, text: str) -> None:
        if not monit_binary():
            return
        out = monit_check(text)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


class TestCore(RenderCase):
    def test_simple_watches_the_four_and_nothing_else(self):
        found = self.render(CORE_OFF, "core")
        self.assertTrue(found.text.startswith(HEADER))
        self.assertEqual(found.services, (
            "keel-unit-sshd", "keel-unit-webmin", "keel-unit-webshell",
            "keel-unit-postfix", "keel-check-sshd", "keel-check-webmin",
            "keel-check-postfix"))
        self.assertEqual(found.notes, ())
        self.assertNotIn("crowdsec", found.text)
        self.assertNotIn("etcd", found.text)
        self.assertMonitAccepts(found.text)

    def test_a_unit_is_watched_and_restarted_through_systemd(self):
        text = self.render(CORE_OFF, "core").text
        self.assertIn(
            'check program keel-unit-sshd with path "/usr/bin/systemctl'
            ' is-active --quiet ssh.service"\n'
            '    start program = "/usr/bin/systemctl start ssh.service"\n'
            '    restart program = "/usr/bin/systemctl restart'
            ' ssh.service"\n'
            "    if status != 0 for 2 cycles then restart\n"
            '    if status != 0 for 2 cycles then exec "/usr/bin/python3 -B'
            " -m keel notify --level critical --check service --name sshd"
            ' --unit ssh.service"\n'
            "        repeat every 120 cycles\n"
            '    else if succeeded then exec "/usr/bin/python3 -B -m keel'
            ' notify --level recovery --check service --name sshd --unit'
            ' ssh.service"\n'
            "    if 3 restarts within 5 cycles then unmonitor\n"
            '    if 3 restarts within 5 cycles then exec "/usr/bin/python3'
            " -B -m keel notify --level critical --check restarts --name"
            ' sshd --unit ssh.service"\n', text)

    def test_the_probes_of_core(self):
        text = self.render(CORE_OFF, "core").text
        self.assertIn("check host keel-check-sshd with address ::1\n", text)
        self.assertIn("    depends on keel-unit-sshd\n", text)
        self.assertIn("    if failed port 22 protocol ssh for 2 cycles then"
                      " restart\n", text)
        self.assertIn('    if failed port 12321 protocol https request "/"'
                      " status = 200 for 2 cycles then restart\n", text)
        self.assertIn("    if failed port 25 protocol smtp for 2 cycles then"
                      " restart\n", text)

    def test_the_reminder_is_hourly_at_monit_s_cycle(self):
        text = self.render(CORE_OFF, "core", cycle=120).text
        self.assertIn("        repeat every 30 cycles\n", text)


class TestCrowdsec(RenderCase):
    def test_enabled_adds_exactly_crowdsec_s_checks(self):
        off = self.render(CORE_OFF, "core")
        on = self.render({**CORE_OFF, "crowdsec": "enabled"}, "core")
        added = [name for name in on.services if name not in off.services]
        self.assertEqual(added, ["keel-unit-crowdsec",
                                 "keel-unit-firewall-bouncer",
                                 "keel-check-crowdsec-lapi"])
        self.assertEqual([name for name in off.services
                          if name not in on.services], [])
        self.assertMonitAccepts(on.text)

    def test_the_lapi_probe_uses_the_literal_crowdsec_binds(self):
        text = self.render({**CORE_OFF, "crowdsec": "enabled"}, "core").text
        self.assertIn(
            "check host keel-check-crowdsec-lapi with address 127.0.0.1\n"
            '    start program = "/usr/bin/systemctl start'
            ' crowdsec.service"\n'
            '    restart program = "/usr/bin/systemctl restart'
            ' crowdsec.service"\n'
            "    depends on keel-unit-crowdsec\n"
            "    if failed port 8080 type tcp for 2 cycles then restart\n",
            text)


class TestWeb(RenderCase):
    def test_simple_adds_nginx_and_its_health(self):
        found = self.render(WEB_OFF)
        self.assertIn("keel-check-nginx", found.services)
        self.assertIn('    if failed port 80 protocol http request'
                      ' "/keel-health" status = 204 for 2 cycles then'
                      " restart\n", found.text)
        self.assertNotIn("anubis", found.text)
        self.assertMonitAccepts(found.text)

    def test_an_alert_only_probe_every_tenth_cycle(self):
        text = self.render(ALL_ON, mesh="fd00:1::1/64").text
        block = text[text.index("check host keel-check-waf-blocks"):]
        block = block[:block.index("\n\n")]
        self.assertIn("    every 10 cycles\n", block)
        self.assertNotIn("then restart", block)
        self.assertNotIn("program =", block)
        self.assertNotIn("depends on", block)
        self.assertNotIn("unmonitor", block)
        self.assertIn('    if failed port 80 protocol http request'
                      ' "/keel-health?keel-waf-probe=%3Cscript%3Ealert(1)'
                      '%3C%2Fscript%3E" status = 403 for 2 cycles then exec'
                      ' "/usr/bin/python3 -B -m keel notify --level critical'
                      ' --check service --name waf-blocks"\n', block)

    def test_a_mesh_probe_uses_the_overlay_address(self):
        found = self.render(ALL_ON, mesh="fd00:1::1/64")
        self.assertIn("check host keel-check-etcd-health with address"
                      " fd00:1::1\n", found.text)
        self.assertMonitAccepts(found.text)

    def test_a_mesh_probe_without_an_overlay_address_is_left_out(self):
        found = self.render(ALL_ON)
        self.assertNotIn("keel-check-etcd-health", found.services)
        self.assertIn("keel-unit-etcd", found.services)
        self.assertEqual(found.notes, (
            "etcd-health not watched: its address is the mesh, and the"
            " spec declares no network.overlay.wireguard.address",))


class TestApplication(RenderCase):
    def setUp(self):
        super().setUp()
        install_app(self.root)
        self.states = {**WEB_OFF, "mariadb": "enabled"}

    def test_restart_never_alerts_and_does_not_restart(self):
        text = self.render(self.states, "blog").text
        block = text[text.index("check program keel-unit-blog "):]
        block = block[:block.index("\n\n")]
        self.assertNotIn("restart", block.replace("--check restarts", ""))
        self.assertIn('then exec "/usr/bin/python3 -B -m keel notify'
                      ' --level critical --check service --name blog --unit'
                      ' blog.service"', block)

    def test_a_restart_limit_of_its_own(self):
        text = self.render(self.states, "blog").text
        self.assertIn("    if 2 restarts within 10 cycles then unmonitor\n",
                      text)

    def test_a_command_check(self):
        text = self.render(self.states, "blog").text
        self.assertIn('check program keel-check-mariadb-ping with path'
                      ' "/usr/bin/mariadb-admin ping"\n'
                      "    depends on keel-unit-mariadb\n"
                      "    if status != 0 for 2 cycles then exec", text)

    def test_a_command_monit_cannot_quote_is_left_out(self):
        self.edit("overlays", "nginx", "checks:",
                  "checks:\n  - {name: spaced, type: command, command:"
                  " [/bin/echo, 'two words'], on_failure: alert}")
        found = self.render(WEB_OFF)
        self.assertNotIn("keel-check-spaced", found.services)
        self.assertIn("spaced not watched: monit splits its command at"
                      " spaces, and an argument holds a space or a quote",
                      found.notes)

    def test_a_check_of_a_process_that_is_not_watched_is_left_out(self):
        """blog-nginx is the blog's own check, on the nginx overlay's
        process: with nginx off, depending on it would make monit refuse
        the whole file"""
        found = self.render({**self.states, "nginx": "disabled"}, "blog")
        self.assertNotIn("keel-check-blog-nginx", found.services)
        self.assertNotIn("keel-unit-nginx", found.text)
        self.assertIn("blog-nginx not watched: its process nginx belongs"
                      " to the overlay nginx, which is disabled",
                      found.notes)

    def test_a_disabled_embedded_overlay_is_not_watched(self):
        found = self.render({**WEB_OFF, "mariadb": "disabled"}, "blog")
        self.assertNotIn("keel-unit-mariadb", found.services)
        self.assertNotIn("keel-check-mariadb", found.services)
        self.assertIn("keel-unit-blog", found.services)


if __name__ == "__main__":
    unittest.main()
