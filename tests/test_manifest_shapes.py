# Copyright (c) 2026 KeelLinux maintainers
"""Sections of the wrong shape, and fields left out

A manifest is data a person types, so every section may arrive as a
string where a list belongs, or a list where a mapping does; each is
reported under its own key and the rest of the file is still checked
(rule 2 and "every error at once"). Also the corners of the readers:
a key YAML cannot hash, a requirement graph shaped like a diamond, and
a hook whose directory is a file.
"""

import os
import unittest

from manifest_helpers import ManifestCase, appliance, overlay

O, A = "overlays", "appliances"

SHAPES = (
    # (directory, manifest text, a message it must print)
    (O, "manifest_version: 1\n", "kind: required"),
    (O, "manifest_version: 1\nkind: 3\n", "kind: must be overlay or"
     " appliance, not 3"),
    (O, overlay("s", "secrets: [{name: key, description: d}]\n"),
     "secrets[0].generate: required"),
    (O, overlay("s", "hooks: [/usr/lib/x]\n"), "hooks: must be a mapping"),
    (O, overlay("s", "hooks: {first_boot: /usr/lib/x}\n"),
     "hooks.first_boot: must be a list"),
    (O, overlay("s", "hooks: {first_boot: [x]}\n"),
     "hooks.first_boot[0]: must be an absolute path"),
    (O, overlay("s", "provides: mariadb\n"), "provides: must be a mapping"),
    (O, overlay("s", "provides: {}\n"), "provides.engine: required"),
    (O, overlay("s", "data: /var/lib/s\n"), "data: must be a list"),
    (O, overlay("s", "data: [/var/lib/s]\n"), "data[0]: must be a mapping"),
    (O, overlay("s", "processes: [{name: p}]\n"),
     "processes[0].unit: required"),
    (O, overlay("s", "processes: [{name: p, unit: p.service, listen: 80}]"
                "\n"), "processes[0].listen: must be a list"),
    (O, overlay("s", "processes: [{name: p, unit: p.service, listen:"
                " [80]}]\n"), "processes[0].listen[0]: must be a mapping"),
    (O, overlay("s", "processes: [{name: p, unit: p.service, listen:"
                " [{}]}]\n"), "processes[0].listen[0].port: required"),
    (O, overlay("s", "processes: [{name: p, unit: p.service, listen:"
                " [{port: [80], protocol: tcp, expose: public}]}]\n"),
     "processes[0].listen[0].port: must be a port number"),
    (O, overlay("s", "checks: [{name: c}]\n"), "checks[0].type: required"),
    (O, overlay("s", "checks: [{name: c, type: tcp, address: loopback,"
                " port: 1, on_failure: alert, process: [p]}]\n"),
     "checks[0].process: must be the name of a process"),
    (A, appliance("s", "[core]"), "base: must be the name of an appliance,"
     " or none"),
    (A, appliance("s", "Core"), 'base: "Core" is not an appliance name'),
    (A, appliance("s", "core", "overlays: [nginx]\n"),
     "overlays: must be a mapping"),
    (A, appliance("s", "core", "options: [{name: o}]\n"),
     "options[0].type: required"),
    (A, appliance("s", "core", "services: [database]\n"),
     "services: must be a mapping"),
    (A, appliance("s", "core", "services: {database: mariadb}\n"),
     "services.database: must be a mapping"),
    (A, appliance("s", "core", "services: {database: {engine: mariadb,"
                  " required: true, durable: true, placement: embedded}}\n"),
     "services.database.placement: must be a mapping"),
    (A, appliance("s", "core", "services: {database: {engine: mariadb,"
                  " required: true, durable: true, defaults: blog}}\n"),
     "services.database.defaults: must be a mapping"),
    (A, appliance("s", "core", "services: {database: {engine: mariadb,"
                  " required: true, durable: true, defaults: {name: ''}}}\n"),
     "services.database.defaults.name: must be a non-empty string"),
    (A, appliance("s", "core", "state: [/srv/s]\n"),
     "state: must be a mapping"),
    (A, appliance("s", "core", "state: {replicate: /srv/s}\n"),
     "state.replicate: must be a list"),
    (A, appliance("s", "core", "state: {replicate: [/srv/s], exclude:"
                  " /srv/s/x}\n"), "state.exclude: must be a list"),
    (A, appliance("s", "core", "state: {replicate: [/srv/s], exclude:"
                  " [srv]}\n"), "state.exclude[0]: must be an absolute path"),
    (A, appliance("s", "core", "state: {exclude: [/srv/x]}\n"),
     "state.exclude[0]: /srv/x is inside no replicated path"),
    (A, appliance("s", "core", "state: {replicate: [srv]}\n"),
     "state.replicate[0]: must be an absolute path"),
    (A, appliance("s", "core", "state: {replicate: [/srv/s/a, /srv/s]}\n"),
     "state.replicate[1]: /srv/s/a is inside /srv/s"),
    (A, appliance("s", "core", "workers: [{name: w, unit: w.service,"
                  " scaling: 2}]\n"), "workers[0].scaling: must be a mapping"),
    (A, appliance("s", "core", "workers: [{name: w, unit: w.service,"
                  " scaling: {}}]\n"), "workers[0].scaling.max: required"),
    (A, appliance("s", "core", "web: /var/www\n"), "web: must be a mapping"),
    (A, appliance("s", "core", "web: {root: www}\n"),
     "web.root: must be an absolute path"),
    (A, appliance("s", "core", "web: {routes: {path: /}}\n"),
     "web.routes: must be a list"),
    (A, appliance("s", "core", "web: {routes: [/]}\n"),
     "web.routes[0]: must be a mapping"),
    (A, appliance("s", "core", "web: {routes: [{}]}\n"),
     "web.routes[0].to: required"),
    (A, appliance("s", "core", "web: {health: /health}\n"),
     "web.health: must be a mapping"),
    (A, appliance("s", "core", "web: {health: {}}\n"),
     "web.health.path: required"),
    (A, appliance("s", "core", "web: {health: {path: health, expect:"
                  " 200}}\n"), "web.health.path: must start with /"),
    (A, appliance("s", "core", "hooks: {migrate: /usr/lib/m}\n"),
     "hooks.migrate: must be a mapping"),
)


class TestShapes(ManifestCase):
    def test_every_shape_is_reported_under_its_key(self):
        for directory, text, message in SHAPES:
            with self.subTest(message=message):
                path = self.put(directory, "s", text)
                self.refused(path, message)
                os.remove(path)

    def test_a_migrate_hook_without_needs(self):
        path = self.put(A, "s", appliance(
            "s", "core", "hooks: {migrate: {command: [/usr/lib/m]}}\n"))
        code, out, err = self.cli("manifest", "validate", path)
        self.assertEqual(code, 0, err)
        self.assertIn("s: resolved along core, s", out)


class TestReaders(ManifestCase):
    def test_a_key_yaml_cannot_hash(self):
        path = self.put(O, "s", "? [a, b]\n: 1\n")
        code, _, err = self.cli("manifest", "validate", path)
        self.assertEqual(code, 2)
        self.assertIn("not valid YAML", err)

    def test_requires_shaped_like_a_diamond(self):
        self.put(O, "top", overlay("top", "requires: [left, right]\n"))
        self.put(O, "left", overlay("left", "requires: [right]\n"))
        self.put(O, "right", overlay("right"))
        code, _, err = self.cli("manifest", "validate", "top")
        self.assertEqual(code, 0, err)

    def test_a_requirement_of_a_requirement_that_is_not_installed(self):
        self.put(O, "top", overlay("top", "requires: [middle]\n"))
        self.put(O, "middle", overlay("middle", "requires: [ghost]\n"))
        code, _, err = self.cli("manifest", "validate", "top")
        self.assertEqual(code, 0, err)
        self.refused("middle", "requires: ghost is not an installed overlay")

    def test_requires_of_the_wrong_shape_in_another_overlay(self):
        self.put(O, "top", overlay("top", "requires: [middle, broken]\n"))
        self.put(O, "middle", overlay("middle", "requires: ghost\n"))
        self.put(O, "broken", "manifest_version: [\n")
        code, _, err = self.cli("manifest", "validate", "top")
        self.assertEqual(code, 0, err)

    def test_a_hook_whose_directory_is_a_file(self):
        hooks = os.path.join(self.root, "usr/lib/inithooks/firstboot.d")
        for entry in os.listdir(hooks):
            os.remove(os.path.join(hooks, entry))
        os.rmdir(hooks)
        open(hooks, "w").close()
        self.refused("installer", "hooks.first_boot[0]: /usr/lib/inithooks/"
                     "firstboot.d/00declarative cannot be read under")

    def test_a_directory_of_manifests_that_is_a_file(self):
        empty = os.path.join(self.tmpdir, "flat")
        os.makedirs(os.path.join(empty, "usr/share"))
        open(os.path.join(empty, "usr/share/keel"), "w").close()
        code, _, err = self.cli("manifest", "validate", root=empty)
        self.assertEqual(code, 0)
        self.assertIn("nothing to do", err)


if __name__ == "__main__":
    unittest.main()
