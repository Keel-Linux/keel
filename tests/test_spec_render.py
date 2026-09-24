# Copyright (c) 2026 KeelLinux maintainers
"""Mapping of spec fields onto the conf variables the hooks read"""

import os
import tempfile
import unittest
from os.path import join

from helpers import doc, env, errors, spec

from keel.spec.fields import is_ipv4  # noqa: E402


class TestMapping(unittest.TestCase):
    def test_maps_instance_and_app_keys_to_env_names(self):
        exported = env(
            "version: 1\n"
            "instance:\n"
            "  hostname: blog\n"
            "  fqdn: blog.example.org\n"
            "app:\n"
            "  email: admin@example.org\n"
            "  domain: blog.example.org\n"
        )
        self.assertEqual(exported["HOSTNAME"], "blog")
        self.assertEqual(exported["FQDN"], "blog.example.org")
        self.assertEqual(exported["APP_EMAIL"], "admin@example.org")
        self.assertEqual(exported["APP_DOMAIN"], "blog.example.org")

    def test_app_options_are_upper_cased_with_app_prefix(self):
        exported = env(
            "version: 1\n"
            "app:\n"
            "  options:\n"
            "    ip_bind: '[2001:db8:1::10]'\n"
            "    realm: example\n"
        )
        self.assertEqual(exported["APP_IP_BIND"], "'[2001:db8:1::10]'")
        self.assertEqual(exported["APP_REALM"], "example")

    def test_preseed_keys_pass_through_verbatim(self):
        exported = env("version: 1\npreseed:\n  AUTOGROW: ONCE\n")
        self.assertEqual(exported["AUTOGROW"], "ONCE")

    def test_hub_and_security_values_are_upper_cased(self):
        exported = env(
            "version: 1\n"
            "hub:\n"
            "  api_key: skip\n"
            "security:\n"
            "  alerts: skip\n"
            "  updates: force\n"
        )
        self.assertEqual(exported["HUB_APIKEY"], "SKIP")
        self.assertEqual(exported["SEC_ALERTS"], "SKIP")
        self.assertEqual(exported["SEC_UPDATES"], "FORCE")

    def test_security_alerts_email_is_kept_as_is(self):
        exported = env("version: 1\nsecurity:\n  alerts: A@example.org\n")
        self.assertEqual(exported["SEC_ALERTS"], "A@example.org")

    def test_rejects_security_alerts_that_is_not_an_email(self):
        self.assertTrue(errors("version: 1\nsecurity:\n  alerts: nope\n"))

    def test_first_login_wizard_true_exports_auto_run(self):
        exported = env("version: 1\nfirst_login_wizard: true\n")
        self.assertEqual(exported["AUTO_RUN"], "TRUE")

    def test_first_login_wizard_false_does_not_export_auto_run(self):
        exported = env("version: 1\nfirst_login_wizard: false\n")
        self.assertNotIn("AUTO_RUN", exported)

    def test_boolean_values_are_exported_as_the_hooks_keywords(self):
        exported = env(
            "version: 1\n"
            "app:\n  options:\n    debug: true\n"
            "preseed:\n  AUTOGROW: false\n"
        )
        self.assertEqual(exported["APP_DEBUG"], "TRUE")
        self.assertEqual(exported["AUTOGROW"], "FALSE")

    def test_hub_api_key_from_a_file_is_exported_and_masked_for_display(self):
        tmpdir = tempfile.mkdtemp()
        path = join(tmpdir, "apikey")
        with open(path, "w") as fob:
            fob.write("ABCDEF123456\n")
        os.chmod(path, 0o600)
        text = f"version: 1\nhub:\n  api_key:\n    file: {path}\n"

        self.assertEqual(env(text)["HUB_APIKEY"], "ABCDEF123456")

        document = doc(text)
        placeholders = spec.masked_secrets(document)
        self.assertEqual(placeholders, {"HUB_APIKEY": spec.MASK})
        rendered = spec.mask(spec.render_env(document, placeholders))
        self.assertIn(f"export HUB_APIKEY={spec.MASK}\n", rendered)
        self.assertNotIn("ABCDEF123456", rendered)

    def test_mask_leaves_the_skip_keyword_readable(self):
        rendered = spec.mask("export HUB_APIKEY=SKIP\nexport ROOT_PASS=x\n")
        self.assertEqual(
            rendered, f"export HUB_APIKEY=SKIP\nexport ROOT_PASS={spec.MASK}\n"
        )


class TestNetworkMapping(unittest.TestCase):
    def file_managed(self, ipv4: str) -> dict:
        return env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv4:\n"
            f"        method: {ipv4}\n"
            "      ipv6:\n"
            "        method: auto\n"
        )

    def test_ipv4_none_exports_nothing(self):
        self.assertEqual(self.file_managed("none"), {})

    def test_ipv4_dhcp_exports_only_the_method(self):
        self.assertEqual(self.file_managed("dhcp"), {"IP_CONFIG": "dhcp"})

    def test_is_ipv4_tells_the_families_apart(self):
        self.assertTrue(is_ipv4("192.0.2.53"))
        self.assertFalse(is_ipv4("2001:db8:1::53"))
        self.assertFalse(is_ipv4("ns.example.org"))


class TestDomains(unittest.TestCase):
    def test_rejects_domain_with_path(self):
        found = errors("version: 1\napp:\n  domain: example.org/blog\n")
        self.assertTrue(found)

    def test_rejects_fqdn_with_port(self):
        found = errors("version: 1\ninstance:\n  fqdn: example.org:8080\n")
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
