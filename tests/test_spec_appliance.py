# Copyright (c) 2026 KeelLinux maintainers
"""The spec's appliance, installation and overlays (decision 0041)

The structure of the three sections is checked without a manifest; the
rules that hold the spec against the installed manifests (25 to 27 of
docs/manifest-v1.md) are checked against hand built facts here, and
against manifests on disk through `keel spec validate --root` in
TestAgainstInstalledManifests.
"""

import os
import unittest

from helpers import doc, spec
from manifest_helpers import ManifestCase, install_app

from keel.manifest.facts import gather
from keel.spec.validate_appliance import (
    ManifestFacts,
    against_manifests,
    validate_appliance,
)

CORE_OVERLAYS = {"installer": (), "wireguard": (), "etcd": ("wireguard",),
                 "crowdsec": ()}
FACTS = ManifestFacts(
    appliance="core", chain=("core",), overlays=CORE_OVERLAYS,
    secrets={"root_password": ("allowed", "core")},
)
CORE_STATES = {"installer": "enabled", "wireguard": "disabled",
               "etcd": "disabled", "crowdsec": "disabled"}


def core(**sections) -> dict:
    found = {"version": 1, "appliance": {"name": "core"},
             "installation": {"mode": "simple"},
             "overlays": dict(CORE_STATES)}
    found.update(sections)
    return found


class TestStructure(unittest.TestCase):
    def test_the_format_example_is_valid(self):
        self.assertEqual(spec.validate(core()), [])

    def test_absent_sections_are_valid(self):
        self.assertEqual(validate_appliance({"version": 1}), [])

    def test_each_section_is_a_mapping(self):
        found = validate_appliance({"appliance": "core", "installation": [],
                                    "overlays": "all"})
        self.assertEqual(found, [
            "appliance: must be a mapping",
            "installation: must be a mapping",
            "overlays: must be a mapping",
        ])

    def test_appliance_needs_a_name_of_the_manifest_shape(self):
        self.assertEqual(validate_appliance({"appliance": {}}),
                         ["appliance.name: required"])
        self.assertEqual(
            validate_appliance({"appliance": {"name": "Keel Web"}}),
            ["appliance.name: must match [a-z][a-z0-9-]*, at most 32"
             " characters (Keel Web)"])
        self.assertEqual(
            validate_appliance({"appliance": {"name": "core\n"}}),
            ["appliance.name: must match [a-z][a-z0-9-]*, at most 32"
             " characters (core\n)"])
        self.assertEqual(
            validate_appliance({"appliance": {"name": "a" * 33}}),
            [f"appliance.name: must match [a-z][a-z0-9-]*, at most 32"
             f" characters ({'a' * 33})"])

    def test_unknown_keys_are_errors(self):
        found = validate_appliance({
            "appliance": {"name": "core", "version": 2},
            "installation": {"mode": "simple", "role": "primary"},
        })
        self.assertEqual(found, ["appliance.version: unknown key",
                                 "installation.role: unknown key"])

    def test_the_mode_is_one_of_the_three(self):
        self.assertEqual(
            validate_appliance({"installation": {}}),
            ["installation.mode: required"])
        self.assertEqual(
            validate_appliance({"installation": {"mode": "advanced"}}),
            ["installation.mode: must be simple, cloud_simple or"
             " cloud_advanced"])

    def test_a_state_is_enabled_or_disabled(self):
        found = validate_appliance({"appliance": {"name": "core"},
                                    "overlays": {"etcd": "running"}})
        self.assertEqual(found, ["overlays.etcd: must be enabled or"
                                 " disabled"])

    def test_on_and_off_arrive_as_booleans_and_say_so(self):
        found = validate_appliance(doc(
            "appliance: {name: core}\noverlays:\n  etcd: on\n"
            "  crowdsec: off\n"))
        self.assertEqual(found, [
            "overlays.etcd: YAML reads on, off, yes and no as true or"
            " false; write enabled or disabled",
            "overlays.crowdsec: YAML reads on, off, yes and no as true or"
            " false; write enabled or disabled",
        ])

    def test_ask_never_reaches_a_spec(self):
        found = validate_appliance({"appliance": {"name": "core"},
                                    "overlays": {"crowdsec": "ask"}})
        self.assertEqual(found, [
            "overlays.crowdsec: ask is the manifest's: the spec records"
            " the answer, enabled or disabled"])

    def test_an_overlay_name_has_the_manifest_shape(self):
        found = validate_appliance({"appliance": {"name": "core"},
                                    "overlays": {"Etcd": "enabled"}})
        self.assertEqual(found, [
            "overlays.Etcd: not an overlay name ([a-z][a-z0-9-]*, at"
            " most 32 characters)"])

    def test_overlays_need_the_appliance_they_belong_to(self):
        found = validate_appliance({"overlays": {"etcd": "enabled"}})
        self.assertEqual(found, [
            "overlays: needs appliance.name, the appliance whose overlays"
            " these are"])

    def test_without_the_system_phase_the_overlays_are_left_alone(self):
        self.assertEqual(spec.unsupported(core()), [
            "overlays: the units and Monit's file of the appliance are"
            " converged by the system phase (--system, --system-only)"
            " only, not in this run"])
        self.assertEqual(spec.unsupported(core(), True), [])
        self.assertEqual(spec.unsupported({"version": 1}), [])

    def test_the_top_level_accepts_the_three_sections(self):
        self.assertNotIn("unknown top level key", " ".join(
            spec.validate(core())))


class TestRule25(unittest.TestCase):
    def test_every_overlay_of_the_chain_named_is_valid(self):
        self.assertEqual(against_manifests(core(), FACTS), [])

    def test_no_appliance_declared_checks_nothing(self):
        self.assertEqual(against_manifests({"version": 1}, None), [])

    def test_manifests_that_cannot_be_used_are_the_error(self):
        facts = ManifestFacts(appliance="web", problems=(
            "web is not an installed appliance under /usr/share/keel",))
        self.assertEqual(against_manifests(core(), facts), [
            "appliance.name: web is not an installed appliance under"
            " /usr/share/keel"])

    def test_an_overlay_left_out_is_an_error(self):
        states = dict(CORE_STATES)
        del states["crowdsec"]
        found = against_manifests(core(overlays=states), FACTS)
        self.assertEqual(found, [
            "overlays.crowdsec: not declared; every overlay of the chain"
            " of core is written out, enabled or disabled (decisions 0027,"
            " 0041)"])

    def test_no_overlays_section_names_every_missing_one(self):
        found = against_manifests(
            {"version": 1, "appliance": {"name": "core"}}, FACTS)
        self.assertEqual(len(found), 4)

    def test_an_overlay_the_chain_does_not_carry_is_an_error(self):
        found = against_manifests(
            core(overlays={**CORE_STATES, "nginx": "enabled"}), FACTS)
        self.assertEqual(found, [
            "overlays.nginx: not an overlay of the chain of core (core)"])

    def test_requires_of_an_enabled_overlay_are_enabled(self):
        found = against_manifests(
            core(overlays={**CORE_STATES, "etcd": "enabled"}), FACTS)
        self.assertEqual(found, [
            "overlays.etcd: enabled, but etcd requires wireguard, which is"
            " disabled"])
        self.assertEqual(against_manifests(core(overlays={
            **CORE_STATES, "etcd": "enabled", "wireguard": "enabled"}),
            FACTS), [])

    def test_a_malformed_state_is_left_to_the_structure_check(self):
        found = against_manifests(
            core(overlays={**CORE_STATES, "etcd": True}), FACTS)
        self.assertEqual(found, [])


class TestRule26(unittest.TestCase):
    FACTS = ManifestFacts(
        appliance="web", chain=("core", "web"), overlays={},
        secrets={"root_password": ("allowed", "core"),
                 "anubis_signing_key": ("required", "web (anubis)"),
                 "admin_passwd": ("never", "web")},
    )

    def test_a_declared_name_is_accepted_and_others_refused(self):
        doc = {"version": 1, "appliance": {"name": "web"}, "secrets": {
            "anubis_signing_key": {"generate": True},
            "salts": {"generate": True}}}
        found = spec.validate(doc, check_secret_files=False,
                              facts=self.FACTS)
        self.assertEqual(found, ["secrets.salts: unknown secret: neither"
                                 " root_password, db_password,"
                                 " app_password nor a name the manifests"
                                 " of web declare"])

    def test_without_facts_a_manifest_name_stays_unknown(self):
        found = spec.validate({"version": 1, "secrets": {
            "anubis_signing_key": {"generate": True}}})
        self.assertEqual(found, ["secrets.anubis_signing_key: unknown"
                                 " secret"])

    def test_generate_is_refused_where_the_manifest_says_never(self):
        doc = {"version": 1, "appliance": {"name": "web"},
               "first_login_wizard": True, "secrets": {
                   "admin_passwd": {"generate": True},
                   "root_password": {"generate": True}}}
        found = against_manifests(doc, self.FACTS)
        self.assertEqual(found, [
            "secrets.admin_passwd: generate, but the manifest of web says"
            " a person chooses it (generate: never); give a file"])

    def test_a_file_reference_is_fine_whatever_the_policy(self):
        doc = {"version": 1, "appliance": {"name": "web"}, "secrets": {
            "admin_passwd": {"file": "/etc/keel/secrets/admin"}}}
        self.assertEqual(against_manifests(doc, self.FACTS), [])


class TestManifestSecretsRender(unittest.TestCase):
    """A declared name renders as KEEL_SECRET_<NAME>, masked like the rest"""

    DOC = {"version": 1, "appliance": {"name": "web"}, "secrets": {
        "anubis_signing_key": {"generate": True},
        "root_password": {"file": "/nonexistent"}}}

    def test_resolved_under_its_variable(self):
        doc = {"version": 1, "secrets": {
            "anubis_signing_key": {"generate": True}}}
        resolved = spec.resolve_secrets(doc)
        self.assertEqual(list(resolved), ["KEEL_SECRET_ANUBIS_SIGNING_KEY"])
        self.assertGreater(len(resolved["KEEL_SECRET_ANUBIS_SIGNING_KEY"]),
                           10)

    def test_a_reference_that_is_not_a_mapping_resolves_to_nothing(self):
        self.assertEqual(spec.resolve_secrets(
            {"version": 1, "secrets": {"root_password": "hunter2"}}), {})

    def test_rendered_and_masked(self):
        rendered = spec.render_env(self.DOC, spec.masked_secrets(self.DOC))
        self.assertIn("export ROOT_PASS='[masked]'\n", rendered)
        self.assertIn("export KEEL_SECRET_ANUBIS_SIGNING_KEY='[masked]'\n",
                      rendered)
        value = spec.render_env(self.DOC, {
            "KEEL_SECRET_ANUBIS_SIGNING_KEY": "s3cret"})
        self.assertIn("KEEL_SECRET_ANUBIS_SIGNING_KEY=s3cret", value)
        self.assertNotIn("s3cret", spec.mask(value))


class TestRule27(unittest.TestCase):
    OPTIONS = (
        ({"name": "site_title", "type": "string", "default": "Blog",
          "pattern": "^.{1,80}$"}, "blog"),
        ({"name": "posts", "type": "integer", "default": 10}, "blog"),
        ({"name": "comments", "type": "boolean", "default": True}, "blog"),
        ({"name": "theme", "type": "enum", "values": ["light", "dark"],
          "default": "light"}, "blog"),
        ({"name": "domain", "type": "string"}, "blog"),
    )
    FACTS = ManifestFacts(appliance="blog", options=OPTIONS)

    def check(self, options: dict | None) -> list[str]:
        app = {} if options is None else {"app": {"options": options}}
        return against_manifests(
            {"version": 1, "appliance": {"name": "blog"}, **app},
            self.FACTS)

    def test_declared_options_of_their_type_are_valid(self):
        self.assertEqual(self.check({
            "site_title": "My blog", "posts": 5, "comments": False,
            "theme": "dark", "domain": "blog.example.org"}), [])

    def test_a_required_option_is_present(self):
        self.assertEqual(self.check(None), [
            "app.options.domain: required by blog, which gives no"
            " default"])

    def test_an_undeclared_option_is_an_error(self):
        found = self.check({"domain": "x", "colour": "red"})
        self.assertEqual(found, [
            "app.options.colour: not an option the manifests of blog"
            " declare"])

    def test_each_type_is_checked(self):
        found = self.check({
            "domain": "x", "site_title": "", "posts": "5",
            "comments": "yes", "theme": "blue"})
        self.assertEqual(found, [
            "app.options.site_title: does not match ^.{1,80}$",
            "app.options.posts: must be an integer",
            "app.options.comments: must be true or false",
            "app.options.theme: must be one of light, dark",
        ])

    def test_a_boolean_is_not_an_integer_nor_a_string(self):
        found = self.check({"domain": True, "posts": True})
        self.assertEqual(found, ["app.options.domain: must be a string",
                                 "app.options.posts: must be an integer"])

    def test_a_malformed_section_is_left_to_the_structure_check(self):
        self.assertEqual(against_manifests(
            {"version": 1, "appliance": {"name": "blog"},
             "app": {"options": ["domain"]}},
            ManifestFacts(appliance="blog")), [])


class TestGather(ManifestCase):
    def test_the_facts_of_web(self):
        facts = gather(self.root, "web")
        self.assertEqual(facts.problems, ())
        self.assertEqual(facts.chain, ("core", "web"))
        self.assertEqual(list(facts.overlays), [
            "installer", "wireguard", "etcd", "crowdsec", "nginx",
            "coraza", "anubis"])
        self.assertEqual(facts.overlays["etcd"], ("wireguard",))
        self.assertEqual(facts.secrets["anubis_signing_key"],
                         ("required", "web (anubis)"))
        self.assertIsNotNone(facts.resolved)

    def test_an_appliance_that_is_not_installed(self):
        facts = gather(self.root, "php")
        self.assertEqual(facts.problems, (
            f"php is not an installed appliance under"
            f" {self.root}/usr/share/keel",))

    def test_an_appliance_that_fails_validation(self):
        self.edit("appliances", "web", "base: core", "base: core\nbad: 1")
        facts = gather(self.root, "web")
        self.assertEqual(len(facts.problems), 1)
        self.assertIn("web.yaml fails validation", facts.problems[0])

    def test_a_chain_that_does_not_resolve(self):
        self.edit("appliances", "web", "nginx:  {simple: enabled",
                  "etcd:  {simple: enabled")
        facts = gather(self.root, "web")
        self.assertIn("overlays.etcd: already carried by core",
                      " ".join(facts.problems))

    def test_a_name_of_the_wrong_shape_is_never_looked_up(self):
        facts = gather(self.root, "../overlays/etcd")
        self.assertEqual(len(facts.problems), 1)


class TestAgainstInstalledManifests(ManifestCase):
    SPEC = (
        "version: 1\n"
        "appliance: {name: web}\n"
        "installation: {mode: simple}\n"
        "overlays: {installer: enabled, wireguard: disabled, etcd: disabled,"
        " crowdsec: disabled, nginx: enabled, coraza: disabled,"
        " anubis: disabled}\n"
    )

    def write_spec(self, text: str) -> str:
        path = os.path.join(self.tmpdir, "instance.yaml")
        with open(path, "w") as fob:
            fob.write(text)
        return path

    def test_the_format_example_validates_against_web(self):
        path = self.write_spec(self.SPEC)
        code, out, err = self.cli("spec", "validate", "--spec", path,
                                  "--no-secret-files")
        self.assertEqual(code, 0, err)
        self.assertIn("ok", out)

    def test_an_appliance_that_is_not_installed_is_refused(self):
        path = self.write_spec(self.SPEC.replace("name: web", "name: php"))
        code, _, err = self.cli("spec", "validate", "--spec", path,
                                "--no-secret-files")
        self.assertEqual(code, 3)
        self.assertIn("appliance.name: php is not an installed appliance",
                      err)

    def test_application_rules_hold_against_the_blog(self):
        install_app(self.root)
        path = self.write_spec(
            self.SPEC.replace("name: web", "name: blog").replace(
                "anubis: disabled}", "anubis: disabled, mariadb: enabled}")
            + "secrets: {app_password: {generate: true}}\n"
            "first_login_wizard: true\n")
        code, _, err = self.cli("spec", "validate", "--spec", path,
                                "--no-secret-files")
        self.assertEqual(code, 3)
        self.assertIn("secrets.app_password: generate, but the manifest of"
                      " blog says a person chooses it", err)
        self.assertIn("app.options.domain: required by blog", err)

    def test_a_spec_without_an_appliance_needs_no_manifest(self):
        path = self.write_spec("version: 1\n")
        code, _, err = self.cli("spec", "validate", "--spec", path,
                                root=os.path.join(self.tmpdir, "empty"))
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
