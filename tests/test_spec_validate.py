# Copyright (c) 2026 KeelLinux maintainers
"""Validation of every section of the spec, one error per mistake

Each section is checked for the same three things: it must be a mapping,
it accepts only its documented keys, and each key gets a message that
names the field. A file with several mistakes reports all of them.
"""

import os
import tempfile
import unittest
from os.path import join

from helpers import errors

from keel.spec.fields import MAX_DOMAIN_LENGTH  # noqa: E402

SECTIONS = (
    "instance", "secrets", "app", "hub", "security", "network", "tls",
    "preseed",
)


def messages(text: str, *fragments: str) -> None:
    """Assert that every fragment appears in exactly one error message"""
    found = errors(text)
    for fragment in fragments:
        matching = [error for error in found if fragment in error]
        if len(matching) != 1:
            raise AssertionError(
                f"expected one error mentioning {fragment!r}, got {found}"
            )


def secret_file(directory: str, content: str, name: str = "secret") -> str:
    path = join(directory, name)
    with open(path, "w") as fob:
        fob.write(content)
    os.chmod(path, 0o600)
    return path


class TestSections(unittest.TestCase):
    def test_every_section_must_be_a_mapping(self):
        for section in SECTIONS:
            with self.subTest(section=section):
                messages(
                    f"version: 1\n{section}: [one]\n",
                    f"{section}: must be a mapping",
                )

    def test_empty_sections_are_accepted(self):
        text = "version: 1\n" + "".join(
            f"{section}: {{}}\n" for section in SECTIONS
        )
        self.assertEqual(errors(text), [])

    def test_several_mistakes_are_all_reported_at_once(self):
        found = errors(
            "version: 2\n"
            "instance:\n  nonsense: 1\n"
            "app:\n  email: nope\n"
            "first_login_wizard: maybe\n"
        )
        self.assertEqual(len(found), 4)


class TestInstance(unittest.TestCase):
    def test_rejects_unknown_key(self):
        messages(
            "version: 1\ninstance:\n  colour: blue\n",
            "instance.colour: unknown key",
        )

    def test_rejects_hostname_that_is_not_a_string(self):
        messages(
            "version: 1\ninstance:\n  hostname: 42\n",
            "instance.hostname: must be a domain name",
        )

    def test_rejects_blank_hostname(self):
        messages(
            'version: 1\ninstance:\n  hostname: "  "\n',
            "instance.hostname: must be a domain name",
        )

    def test_rejects_fqdn_longer_than_the_dns_limit(self):
        fqdn = ".".join(["a" * 60] * 5)
        self.assertGreater(len(fqdn), MAX_DOMAIN_LENGTH)
        messages(
            f"version: 1\ninstance:\n  fqdn: {fqdn}\n", "instance.fqdn: domain"
        )

    def test_rejects_label_starting_with_a_hyphen(self):
        messages(
            "version: 1\ninstance:\n  fqdn: -blog.example.org\n",
            "instance.fqdn: domain",
        )

    def test_accepts_fqdn_with_a_trailing_dot(self):
        text = "version: 1\ninstance:\n  fqdn: blog.example.org.\n"
        self.assertEqual(errors(text), [])


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_rejects_unknown_secret(self):
        messages(
            "version: 1\nsecrets:\n  wifi_password:\n    generate: true\n",
            "secrets.wifi_password: unknown secret",
        )

    def test_rejects_secret_that_is_not_a_mapping(self):
        messages(
            "version: 1\nsecrets:\n  db_password: generate\n",
            "secrets.db_password: must be a mapping",
        )

    def test_rejects_unknown_backend_and_asks_for_exactly_one(self):
        messages(
            "version: 1\nsecrets:\n  db_password:\n    vault: kv/db\n",
            "secrets.db_password.vault: unknown secret backend",
            "secrets.db_password: exactly one of file, generate is required",
        )

    def test_generate_is_refused_for_root_password_without_wizard(self):
        messages(
            "version: 1\nsecrets:\n  root_password:\n    generate: true\n",
            "secrets.root_password: generate needs first_login_wizard",
        )

    def test_generate_is_allowed_for_db_password_without_wizard(self):
        text = "version: 1\nsecrets:\n  db_password:\n    generate: true\n"
        self.assertEqual(errors(text), [])

    def test_generate_false_next_to_a_file_still_counts_as_two_backends(self):
        path = secret_file(self.tmpdir, "s3cret\n")
        messages(
            "version: 1\nsecrets:\n  root_password:\n"
            f"    file: {path}\n    generate: false\n",
            "secrets.root_password: exactly one of",
        )


class TestApp(unittest.TestCase):
    def test_rejects_unknown_key(self):
        messages(
            "version: 1\napp:\n  colour: blue\n", "app.colour: unknown key"
        )

    def test_rejects_email_without_a_domain(self):
        messages(
            "version: 1\napp:\n  email: admin\n",
            "app.email: must be an email address",
        )

    def test_rejects_options_that_are_not_a_mapping(self):
        messages(
            "version: 1\napp:\n  options: [a, b]\n",
            "app.options: must be a mapping",
        )

    def test_rejects_option_that_is_not_a_variable_name(self):
        messages(
            "version: 1\napp:\n  options:\n    ip-bind: x\n",
            "app.options.ip-bind: not a valid variable name",
        )

    def test_reports_bad_email_and_bad_options_together(self):
        found = errors("version: 1\napp:\n  email: nope\n  options: yes\n")
        self.assertEqual(len(found), 2)


class TestHub(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_rejects_unknown_key(self):
        messages("version: 1\nhub:\n  token: abc\n", "hub.token: unknown key")

    def test_rejects_inline_api_key(self):
        messages(
            "version: 1\nhub:\n  api_key: ABCDEF123456\n",
            "hub.api_key: must be 'skip' or a secret mapping",
        )

    def test_accepts_skip_in_any_case(self):
        self.assertEqual(errors("version: 1\nhub:\n  api_key: SKIP\n"), [])

    def test_api_key_mapping_is_checked_like_a_secret(self):
        absent = join(self.tmpdir, "absent")
        messages(
            f"version: 1\nhub:\n  api_key:\n    file: {absent}\n",
            f"hub.api_key: {absent}: secret file not found",
        )

    def test_api_key_from_a_protected_file_is_accepted(self):
        path = secret_file(self.tmpdir, "ABCDEF123456\n", "apikey")
        text = f"version: 1\nhub:\n  api_key:\n    file: {path}\n"
        self.assertEqual(errors(text), [])


class TestSecurity(unittest.TestCase):
    def test_rejects_unknown_key(self):
        messages(
            "version: 1\nsecurity:\n  firewall: on\n",
            "security.firewall: unknown key",
        )

    def test_rejects_updates_that_is_not_skip_or_force(self):
        messages(
            "version: 1\nsecurity:\n  updates: weekly\n",
            "security.updates: must be 'skip' or 'force'",
        )

    def test_accepts_skip_and_force_in_any_case(self):
        text = "version: 1\nsecurity:\n  alerts: SKIP\n  updates: Force\n"
        self.assertEqual(errors(text), [])


class TestWizard(unittest.TestCase):
    def test_rejects_value_that_is_not_a_boolean(self):
        messages(
            "version: 1\nfirst_login_wizard: maybe\n",
            "first_login_wizard: must be true or false",
        )


class TestTLS(unittest.TestCase):
    def acme(self, body: str) -> str:
        return "version: 1\ntls:\n  acme:\n" + body

    def test_rejects_unknown_key(self):
        messages(
            "version: 1\ntls:\n  selfsigned: true\n",
            "tls.selfsigned: unknown key",
        )

    def test_rejects_acme_that_is_not_a_mapping(self):
        messages(
            "version: 1\ntls:\n  acme: yes\n", "tls.acme: must be a mapping"
        )

    def test_accepts_empty_acme(self):
        self.assertEqual(errors(self.acme("")), [])

    def test_reports_unknown_tls_key_and_bad_acme_together(self):
        found = errors("version: 1\ntls:\n  selfsigned: true\n  acme: yes\n")
        self.assertEqual(len(found), 2)

    def test_rejects_unknown_acme_key(self):
        messages(
            self.acme("    email: a@example.org\n"),
            "tls.acme.email: unknown key",
        )

    def test_rejects_unknown_challenge(self):
        messages(
            self.acme("    challenge: tls-alpn-01\n"),
            "tls.acme.challenge: must be http-01 or dns-01",
        )

    def test_rejects_domain_that_is_not_a_domain(self):
        messages(
            self.acme(
                "    domains:\n"
                "      - blog.example.org\n"
                "      - 'https://blog.example.org'\n"
            ),
            "tls.acme.domains: domain",
        )

    def test_rejects_domains_that_are_not_a_list(self):
        found = errors(self.acme("    domains: blog.example.org\n"))
        self.assertEqual(found, ["tls.acme.domains: must be a list"])

    def test_accepts_a_full_acme_section(self):
        text = self.acme(
            "    enabled: true\n"
            "    challenge: http-01\n"
            "    domains:\n"
            "      - blog.example.org\n"
        )
        self.assertEqual(errors(text), [])


class TestPreseed(unittest.TestCase):
    def test_rejects_key_that_is_not_a_variable_name(self):
        messages(
            "version: 1\npreseed:\n  auto-grow: ONCE\n",
            "preseed.auto-grow: not a valid variable name",
        )

    def test_accepts_variable_names(self):
        text = "version: 1\npreseed:\n  AUTOGROW: ONCE\n  _x1: y\n"
        self.assertEqual(errors(text), [])


if __name__ == "__main__":
    unittest.main()
