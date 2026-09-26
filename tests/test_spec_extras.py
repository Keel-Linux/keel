# Copyright (c) 2026 KeelLinux maintainers
"""The users and locale sections: validated here, converged by apply --system"""

import unittest

from helpers import doc, env, errors, spec

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog"

USERS = (
    "version: 1\n"
    "users:\n"
    "  root:\n"
    "    authorized_keys:\n"
    f"      - {KEY}\n"
    "  admin:\n"
    "    authorized_keys: []\n"
)

LOCALE = (
    "version: 1\n"
    "locale:\n"
    "  timezone: Europe/Lisbon\n"
    "  lang: en_US.UTF-8\n"
)


class TestUsers(unittest.TestCase):
    def test_public_keys_per_user_are_accepted(self):
        self.assertEqual(errors(USERS), [])

    def test_users_must_be_a_mapping(self):
        self.assertEqual(errors("version: 1\nusers: [root]\n"),
                         ["users: must be a mapping"])

    def test_each_user_must_be_a_mapping_or_empty(self):
        found = errors("version: 1\nusers:\n  root: [key]\n  admin:\n")
        self.assertEqual(found, ["users.root: must be a mapping"])

    def test_user_name_is_checked(self):
        found = errors("version: 1\nusers:\n  Root User:\n")
        self.assertEqual(found, ["users.Root User: not a valid user name"])

    def test_unknown_user_key_is_an_error(self):
        found = errors("version: 1\nusers:\n  root:\n    password: x\n")
        self.assertEqual(found, ["users.root.password: unknown key"])

    def test_shell_and_groups_are_accepted(self):
        text = (
            "version: 1\nusers:\n  admin:\n    shell: /bin/bash\n"
            "    groups: [sudo, adm]\n"
        )
        self.assertEqual(errors(text), [])

    def test_shell_must_be_an_absolute_path(self):
        for shell in ("bash", "'/bin/../bin/sh'", "'/bin/sh; rm'", "7"):
            with self.subTest(shell=shell):
                found = errors(
                    f"version: 1\nusers:\n  admin:\n    shell: {shell}\n"
                )
                self.assertEqual(found, [
                    "users.admin.shell: must be an absolute path such as"
                    " /bin/bash"
                ])

    def test_groups_must_be_a_list_of_group_names(self):
        found = errors("version: 1\nusers:\n  admin:\n    groups: sudo\n")
        self.assertEqual(found, ["users.admin.groups: must be a list"])
        found = errors(
            "version: 1\nusers:\n  admin:\n    groups: [sudo, 'Bad Group']\n"
        )
        self.assertEqual(found, [
            "users.admin.groups: not a valid group name ('Bad Group')"
        ])

    def test_authorized_keys_must_be_a_list(self):
        found = errors(
            f"version: 1\nusers:\n  root:\n    authorized_keys: {KEY}\n"
        )
        self.assertEqual(found, ["users.root.authorized_keys: must be a list"])

    def test_each_authorized_key_must_look_like_a_public_key(self):
        text = (
            "version: 1\nusers:\n  root:\n    authorized_keys:\n"
            "      - not a key\n"
            "      - ssh-rsa\n"
            "      - 42\n"
        )
        found = errors(text)
        self.assertEqual(len(found), 3)
        for message in found:
            self.assertIn("users.root.authorized_keys: not a public key line",
                          message)

    def test_users_render_nothing_and_apply_warns_without_system(self):
        self.assertNotIn("USERS", " ".join(env(USERS)))
        found = spec.unsupported(doc(USERS))
        self.assertEqual(len(found), 1)
        self.assertIn("users:", found[0])
        self.assertIn("--system", found[0])
        self.assertEqual(spec.unsupported(doc(USERS), system=True), [])


class TestLocale(unittest.TestCase):
    def test_timezone_and_lang_are_accepted(self):
        self.assertEqual(errors(LOCALE), [])

    def test_locale_must_be_a_mapping(self):
        self.assertEqual(errors("version: 1\nlocale: UTC\n"),
                         ["locale: must be a mapping"])

    def test_unknown_locale_key_is_an_error(self):
        found = errors("version: 1\nlocale:\n  keyboard: us\n")
        self.assertEqual(found, ["locale.keyboard: unknown key"])

    def test_timezone_must_be_a_zoneinfo_name(self):
        found = errors("version: 1\nlocale:\n  timezone: '../etc/passwd'\n")
        self.assertEqual(len(found), 1)
        self.assertIn("locale.timezone", found[0])

    def test_lang_must_be_a_locale_name(self):
        found = errors("version: 1\nlocale:\n  lang: 'en US'\n")
        self.assertEqual(len(found), 1)
        self.assertIn("locale.lang", found[0])

    def test_locale_renders_nothing_and_apply_warns_without_system(self):
        self.assertNotIn("LANG", env(LOCALE))
        found = spec.unsupported(doc(LOCALE))
        self.assertEqual(len(found), 1)
        self.assertIn("locale:", found[0])
        self.assertEqual(spec.unsupported(doc(LOCALE), system=True), [])

    def test_system_keeps_the_acme_warning(self):
        text = "version: 1\ntls:\n  acme:\n    enabled: true\nlocale: {}\n"
        found = spec.unsupported(doc(text), system=True)
        self.assertEqual(len(found), 1)
        self.assertIn("tls.acme", found[0])

    def test_empty_sections_warn_nothing(self):
        self.assertEqual(spec.unsupported(doc("version: 1\nusers: {}\n"
                                              "locale: {}\n")), [])


if __name__ == "__main__":
    unittest.main()
