# Copyright (c) 2026 KeelLinux maintainers
"""Mapping of spec fields onto the conf variables the hooks read"""

import unittest

from helpers import env, errors


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


class TestDomains(unittest.TestCase):
    def test_rejects_domain_with_path(self):
        found = errors("version: 1\napp:\n  domain: example.org/blog\n")
        self.assertTrue(found)

    def test_rejects_fqdn_with_port(self):
        found = errors("version: 1\ninstance:\n  fqdn: example.org:8080\n")
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
