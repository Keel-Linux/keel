# Copyright (c) 2026 KeelLinux maintainers
"""keel manifest validate and keel manifest show (decision 0041, step 1)

The manifests of the format, Keel Core and Keel Web with their seven
overlays, validate; `show web --resolved` prints the tables of the
format's "Worked example: Keel Web" row for row, followed by the
processes, checks, secrets, options and hooks the chain resolves to.
"""

import os
import tempfile
import unittest
from unittest import mock

from manifest_helpers import FIXTURES, ManifestCase, fixture, hook

from keel import cli
from keel.manifest import Catalog, ManifestError, load, resolve


# The two tables of docs/manifest-v1.md, "Worked example: Keel Web",
# under "Resolved, as keel manifest show web --resolved prints it"
FORMAT_OVERLAYS = """\
| Overlay | From | simple | cloud simple | cloud advanced |
| --- | --- | --- | --- | --- |
| installer | core | enabled | enabled | enabled |
| wireguard | core | disabled | enabled | enabled |
| etcd | core | disabled | disabled | enabled |
| crowdsec | core | disabled | enabled | enabled |
| nginx | web | enabled | enabled | enabled |
| coraza | web | disabled | enabled | enabled |
| anubis | web | disabled | enabled | enabled |
"""

FORMAT_PORTS = """\
| Port | Process | From | Exposure |
| --- | --- | --- | --- |
| 22/tcp | sshd | core | public |
| 25/tcp | postfix | core | loopback, IPv4 |
| 80/tcp, 443/tcp | nginx | web (nginx) | public |
| 2379/tcp, 2380/tcp | etcd | core (etcd) | mesh |
| 6060/tcp, 8080/tcp | crowdsec | core (crowdsec) | loopback, IPv4 |
| 8923/tcp | anubis | web (anubis) | loopback |
| 12320/tcp | webshell | core | public |
| 12321/tcp | webmin | core | public |
"""

WEB_RESOLVED = (
    "Keel Web (web), resolved along core, web\n"
    "\n"
    "Overlays\n" + FORMAT_OVERLAYS + "\n"
    "Ports\n" + FORMAT_PORTS + "\n"
    """\
Processes
| Process | Unit | From | Restart |
| --- | --- | --- | --- |
| sshd | ssh.service | core | 3 restarts within 5 cycles |
| webmin | webmin.service | core | 3 restarts within 5 cycles |
| webshell | shellinabox.service | core | 3 restarts within 5 cycles |
| postfix | postfix.service | core | 3 restarts within 5 cycles |
| etcd | etcd.service | core (etcd) | 3 restarts within 5 cycles |
| crowdsec | crowdsec.service | core (crowdsec) | 3 restarts within 5 cycles |
| firewall-bouncer | crowdsec-firewall-bouncer.service | core (crowdsec) \
| 3 restarts within 5 cycles |
| nginx | nginx.service | web (nginx) | 3 restarts within 5 cycles |
| anubis | anubis.service | web (anubis) | 3 restarts within 5 cycles |

Checks
| Check | Process | From | Probe | On failure | Every |
| --- | --- | --- | --- | --- | --- |
| sshd | sshd | core | ssh loopback port 22 | restart | 1 cycle |
| webmin | webmin | core | https loopback port 12321 /, expects 200 \
| restart | 1 cycle |
| postfix | postfix | core | smtp loopback port 25 | restart | 1 cycle |
| etcd-health | etcd | core (etcd) | http mesh port 2379 /health, expects \
200 | restart | 1 cycle |
| crowdsec-lapi | crowdsec | core (crowdsec) | tcp loopback port 8080 \
| restart | 1 cycle |
| nginx | nginx | web (nginx) | http loopback port 80 /keel-health, \
expects 204 | restart | 1 cycle |
| waf-blocks | none | web (coraza) | http loopback port 80 \
/keel-health?keel-waf-probe=%3Cscript%3Ealert(1)%3C%2Fscript%3E, \
expects 403 | alert | 10 cycles |
| anubis | anubis | web (anubis) | tcp loopback port 8923 | restart \
| 1 cycle |

Secrets
| Secret | From | Generate | Shared | Description |
| --- | --- | --- | --- | --- |
| root_password | core | allowed | no | The root password, for SSH and \
Webmin |
| anubis_signing_key | web (anubis) | required | yes | The key Anubis \
signs its challenge cookies with |

Options
none

First boot hooks
| Hook | From |
| --- | --- |
| /usr/lib/inithooks/firstboot.d/00declarative | core (installer) |
| /usr/lib/inithooks/firstboot.d/10keel-system | core (installer) |
| /usr/lib/inithooks/firstboot.d/75keel-role | core (installer) |
| /usr/lib/inithooks/firstboot.d/80keel-cloud | core (installer) |

Application
none
"""
)

ALL_FILES = (
    ("overlays", "anubis"), ("overlays", "coraza"), ("overlays", "crowdsec"),
    ("overlays", "etcd"), ("overlays", "installer"), ("overlays", "nginx"),
    ("overlays", "wireguard"), ("appliances", "core"), ("appliances", "web"),
)


class TestTheFormatValidates(ManifestCase):
    def test_every_installed_manifest_and_every_chain(self):
        code, out, err = self.cli("manifest", "validate")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        for kind, name in ALL_FILES:
            self.assertIn(f"{self.path(kind, name)}: ok\n", out)
        self.assertIn("core: resolved along core\n", out)
        self.assertIn("web: resolved along core, web\n", out)

    def test_each_one_by_name(self):
        for kind, name in ALL_FILES:
            with self.subTest(name=name):
                code, out, err = self.cli("manifest", "validate", name)
                self.assertEqual(code, 0, err)
                self.assertIn(f"{self.path(kind, name)}: ok", out)

    def test_by_path_outside_the_root(self):
        path = os.path.join(FIXTURES, "appliances", "web.yaml")
        code, out, err = self.cli("manifest", "validate", path)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            out, f"{path}: ok\nweb: resolved along core, web\n")

    def test_the_library_resolves_what_the_command_prints(self):
        catalog = Catalog(self.root)
        resolved, errors = resolve(catalog, catalog.read("appliance", "web"))
        self.assertEqual(errors, [])
        self.assertEqual(resolved.chain, ("core", "web"))
        self.assertEqual(
            [item.name for item in resolved.overlays],
            ["installer", "wireguard", "etcd", "crowdsec", "nginx",
             "coraza", "anubis"])
        states = {item.name: item.states for item in resolved.overlays}
        self.assertEqual(
            states["etcd"],
            {"simple": "disabled", "cloud_simple": "disabled",
             "cloud_advanced": "enabled"})

    def test_an_empty_root_is_nothing_to_do(self):
        empty = os.path.join(self.tmpdir, "empty")
        os.mkdir(empty)
        code, out, err = self.cli("manifest", "validate", root=empty)
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("no manifest installed", err)


class TestShow(ManifestCase):
    def test_show_web_resolved_prints_the_formats_tables(self):
        code, out, err = self.cli("manifest", "show", "web", "--resolved")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, WEB_RESOLVED)

    def test_the_formats_two_tables_appear_verbatim(self):
        _, out, _ = self.cli("manifest", "show", "web", "--resolved")
        self.assertIn("Overlays\n" + FORMAT_OVERLAYS, out)
        self.assertIn("Ports\n" + FORMAT_PORTS, out)

    def test_states_are_words_never_booleans(self):
        _, out, _ = self.cli("manifest", "show", "web", "--resolved")
        for word in ("True", "False", "true", "false", " on ", " off "):
            self.assertNotIn(word, out)

    def test_show_without_resolved_prints_the_file(self):
        for kind, name in (("appliances", "core"), ("overlays", "etcd")):
            with self.subTest(name=name):
                code, out, err = self.cli("manifest", "show", name)
                self.assertEqual(code, 0, err)
                self.assertEqual(out, fixture(kind, name))

    def test_show_core_resolved_has_core_alone(self):
        code, out, _ = self.cli("manifest", "show", "core", "--resolved")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(
            "Keel Core (core), resolved along core\n"))
        self.assertNotIn("nginx", out)

    def test_an_absent_name_cannot_be_read(self):
        code, out, err = self.cli("manifest", "show", "nope")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("no manifest named nope", err)

    def test_an_overlay_is_not_resolved(self):
        code, _, err = self.cli("manifest", "show", "nginx", "--resolved")
        self.assertEqual(code, 1)
        self.assertIn("nginx is an overlay: only an appliance resolves", err)

    def test_an_invalid_manifest_is_not_shown(self):
        self.edit("appliances", "web", "base: core", "base: none")
        code, out, err = self.cli("manifest", "show", "web", "--resolved")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("base: none is for core only", err)

    def test_a_broken_chain_is_not_shown(self):
        self.edit("overlays", "nginx", "port: 443", "port: 8080")
        code, out, err = self.cli("manifest", "show", "web", "--resolved")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        self.assertIn("8080/tcp", err)

    def test_a_name_of_both_kinds_needs_kind(self):
        self.put("overlays", "web", fixture("overlays", "wireguard").replace(
            "name: wireguard", "name: web"))
        code, _, err = self.cli("manifest", "show", "web")
        self.assertEqual(code, 1)
        self.assertIn("both an overlay and an appliance are named web", err)
        code, out, _ = self.cli("manifest", "show", "web", "--kind",
                                "appliance")
        self.assertEqual(code, 0)
        self.assertEqual(out, fixture("appliances", "web"))


class TestValidateTargets(ManifestCase):
    def test_a_name_of_both_kinds_validates_both(self):
        text = fixture("overlays", "wireguard").replace(
            "name: wireguard", "name: web")
        self.put("overlays", "web", text)
        code, out, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 0, err)
        self.assertIn(f"{self.path('overlays', 'web')}: ok", out)
        self.assertIn(f"{self.path('appliances', 'web')}: ok", out)
        code, out, _ = self.cli("manifest", "validate", "web", "--kind",
                                "overlay")
        self.assertEqual(code, 0)
        self.assertNotIn("appliances", out)

    def test_an_absent_name(self):
        code, _, err = self.cli("manifest", "validate", "nope")
        self.assertEqual(code, 2)
        self.assertIn("no manifest named nope", err)

    def test_an_absent_path(self):
        code, _, err = self.cli("manifest", "validate",
                                os.path.join(self.tmpdir, "gone.yaml"))
        self.assertEqual(code, 2)
        self.assertIn("gone.yaml", err)

    def test_the_kind_of_a_path_is_its_directory(self):
        text = fixture("overlays", "wireguard").replace(
            "name: wireguard", "name: stray")
        path = self.put("appliances", "stray", text)
        err = self.refused(path)
        self.assertIn("kind: overlay, but the file is in appliances/", err)

    def test_kind_given_for_a_path_must_agree(self):
        path = self.path("overlays", "etcd")
        code, _, err = self.cli("manifest", "validate", path, "--kind",
                                "appliance")
        self.assertEqual(code, 3)
        self.assertIn("kind: overlay, but --kind says appliance", err)

    def test_unreadable_wins_over_invalid(self):
        self.put("overlays", "etcd", "manifest_version: [\n")
        self.edit("appliances", "web", "base: core", "base: nope")
        code, _, err = self.cli("manifest", "validate")
        self.assertEqual(code, 2)
        self.assertIn("not valid YAML", err)
        self.assertIn("base: nope is not an installed appliance", err)

    def test_a_base_that_cannot_be_read_fails_the_chain(self):
        self.put("appliances", "core", "- a list\n")
        code, _, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 3)
        self.assertIn("top level must be a mapping", err)
        self.assertIn("base: core cannot be used", err)

    def test_an_overlay_that_is_invalid_fails_the_chain(self):
        self.edit("overlays", "nginx", "unit: nginx.service",
                  "unit: nginx")
        code, _, err = self.cli("manifest", "validate", "web")
        self.assertEqual(code, 3)
        self.assertIn("overlays.nginx: nginx cannot be used", err)


class TestLoad(unittest.TestCase):
    def write(self, text: str) -> str:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".yaml", delete=False) as fob:
            fob.write(text)
        self.addCleanup(os.remove, fob.name)
        return fob.name

    def test_an_empty_file(self):
        with self.assertRaisesRegex(ManifestError, "file is empty"):
            load(self.write(""))

    def test_a_key_given_twice_is_refused(self):
        path = self.write("overlays:\n  nginx: {}\n  nginx: {}\n")
        with self.assertRaisesRegex(ManifestError,
                                    "line 3: nginx appears twice"):
            load(path)

    def test_the_fixtures_load(self):
        doc = load(os.path.join(FIXTURES, "appliances", "core.yaml"))
        self.assertEqual(doc["overlays"]["etcd"]["cloud_advanced"],
                         "enabled")


class TestParser(unittest.TestCase):
    def test_manifest_without_an_action_is_a_usage_error(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(cli.main(["manifest"]), 1)

    def test_show_needs_a_name(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as caught:
            cli.main(["manifest", "show"])
        self.assertEqual(caught.exception.code, 1)


class TestHookModes(ManifestCase):
    def test_a_hook_the_group_can_write_is_refused(self):
        hook(self.root, "75keel-role", 0o775)
        self.refused("installer", "writable by group or others")


if __name__ == "__main__":
    unittest.main()
