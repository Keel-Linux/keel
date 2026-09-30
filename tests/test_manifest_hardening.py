# Copyright (c) 2026 KeelLinux maintainers
"""What the review of keel#57 found a manifest could slip past the reader

A unit name that climbs out of systemd's directories with `..`, an init
script that is not an executable file inside the root, a name with a
trailing newline (which `^...$` with re.match accepts), and YAML nested
deeply enough to exhaust the recursion limit.
"""

import os
import unittest

from manifest_helpers import ManifestCase, overlay

UNIT_SHAPE = "is not a systemd unit name"


class TestUnitNames(ManifestCase):
    def test_a_unit_that_climbs_out_is_refused(self):
        escape = os.path.join(self.root, "etc", "escape.service")
        os.makedirs(os.path.dirname(escape), exist_ok=True)
        open(escape, "w").close()
        self.edit("overlays", "etcd", "unit: etcd.service",
                  "unit: ../../../../etc/escape.service")
        self.refused("etcd", f"processes[0].unit:"
                     f' "../../../../etc/escape.service" {UNIT_SHAPE}')

    def test_characters_outside_systemd_unit_names(self):
        for unit in ("et cd.service", "etcd\n.service", "e*d.service",
                     ".service", "a@b@c.service", "x" * 250 + ".service"):
            with self.subTest(unit=unit):
                self.edit("overlays", "etcd", "unit: etcd.service",
                          f"unit: {unit!r}".replace("'", '"'))
                self.refused("etcd", UNIT_SHAPE)

    def test_template_and_escaped_names_are_units(self):
        for unit in ("wg-quick@wg0.service", "a_b:c.d-e.service",
                     r"x\x2dy.service"):
            with self.subTest(unit=unit):
                with open(os.path.join(self.root, "usr/lib/systemd/system",
                                       unit), "w"):
                    pass
                self.edit("overlays", "etcd", "unit: etcd.service",
                          f"unit: '{unit}'")
                code, _, err = self.cli("manifest", "validate", "etcd")
                self.assertEqual(code, 0, err)


class TestInitScript(ManifestCase):
    def setUp(self):
        super().setUp()
        os.remove(os.path.join(self.root, "usr/lib/systemd/system",
                               "etcd.service"))
        self.script = os.path.join(self.root, "etc", "init.d", "etcd")
        os.makedirs(os.path.dirname(self.script))

    def test_an_executable_script_counts(self):
        with open(self.script, "w") as fob:
            fob.write("#!/bin/sh\n")
        os.chmod(self.script, 0o755)
        code, _, err = self.cli("manifest", "validate", "etcd")
        self.assertEqual(code, 0, err)

    def test_a_script_that_is_not_executable(self):
        open(self.script, "w").close()
        os.chmod(self.script, 0o644)
        self.refused("etcd", "etcd.service has no unit file")

    def test_a_directory_is_not_a_script(self):
        os.mkdir(self.script)
        self.refused("etcd", "etcd.service has no unit file")

    def test_a_script_outside_the_root(self):
        outside = os.path.join(self.tmpdir, "outside")
        with open(outside, "w") as fob:
            fob.write("#!/bin/sh\n")
        os.chmod(outside, 0o755)
        os.symlink(outside, self.script)
        self.refused("etcd", "etcd.service has no unit file")


class TestTrailingNewline(ManifestCase):
    def test_names_with_a_trailing_newline(self):
        cases = (
            ("overlays", "nginx", "name: nginx", 'name: "nginx\\n"',
             "name: "),
            ("overlays", "nginx", "- name: nginx", '- name: "nginx\\n"',
             "processes[0].name: "),
            ("overlays", "anubis", "name: anubis_signing_key",
             'name: "anubis_signing_key\\n"', "secrets[0].name: "),
            ("overlays", "anubis", "requires: [nginx]",
             'requires: ["nginx\\n"]', "requires[0]: "),
            ("appliances", "web", "base: core", 'base: "core\\n"', "base: "),
            ("appliances", "web", "  nginx:  {", '  "nginx\\n":  {',
             "overlays: "),
        )
        for kind, name, old, new, key in cases:
            with self.subTest(new=new):
                self.edit(kind, name, old, new)
                self.refused(name, key)

    def test_values_with_a_trailing_newline(self):
        self.edit("appliances", "web", "cloud_advanced: enabled}",
                  "cloud_advanced: enabled, version: \">= 1.26\\n\"}")
        self.refused("web", "overlays.nginx.version: must be a constraint")

    def test_a_name_on_the_command_line(self):
        code, _, err = self.cli("manifest", "show", "web\n")
        self.assertEqual(code, 2)
        self.assertIn("no manifest named web", err)


class TestDeepNesting(ManifestCase):
    def test_nesting_past_the_recursion_limit_cannot_be_read(self):
        depth = 100000
        path = self.put("overlays", "deep", overlay(
            "deep", "screen: " + "[" * depth + "]" * depth + "\n"))
        code, _, err = self.cli("manifest", "validate", path)
        self.assertEqual(code, 2)
        self.assertIn("nested too deeply", err)


if __name__ == "__main__":
    unittest.main()
