# Copyright (c) 2026 KeelLinux maintainers
"""Secrets are referenced, never inlined, and never leak into a render"""

import os
import subprocess
import tempfile
import unittest
from os.path import join

from helpers import doc, env, errors, spec

MIN_GENERATED_LENGTH = 8


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def secret_file(self, content: str, mode: int = 0o600) -> str:
        path = join(self.tmpdir, "secret")
        with open(path, "w") as fob:
            fob.write(content)
        os.chmod(path, mode)
        return path

    def test_secret_file_is_read_and_trailing_newline_stripped(self):
        path = self.secret_file("s3cret\n")
        exported = env(
            "version: 1\n"
            "secrets:\n"
            "  app_password:\n"
            f"    file: {path}\n"
        )
        self.assertEqual(exported["APP_PASS"], "s3cret")

    def test_secret_file_with_loose_mode_is_rejected(self):
        path = self.secret_file("s3cret\n", 0o644)
        found = errors(
            "version: 1\n"
            "secrets:\n"
            "  app_password:\n"
            f"    file: {path}\n"
        )
        self.assertTrue(any("mode" in error for error in found))

    def test_missing_secret_file_is_rejected(self):
        found = errors(
            "version: 1\n"
            "secrets:\n"
            "  app_password:\n"
            f"    file: {join(self.tmpdir, 'absent')}\n"
        )
        self.assertTrue(found)

    def test_secret_with_two_backends_is_rejected(self):
        path = self.secret_file("s3cret\n")
        found = errors(
            "version: 1\n"
            "secrets:\n"
            "  db_password:\n"
            f"    file: {path}\n"
            "    generate: true\n"
        )
        self.assertTrue(found)

    def test_generate_is_refused_for_app_password_without_wizard(self):
        found = errors(
            "version: 1\nsecrets:\n  app_password:\n    generate: true\n"
        )
        self.assertTrue(any("generate" in error for error in found))

    def test_generate_is_allowed_for_app_password_with_wizard(self):
        text = (
            "version: 1\n"
            "first_login_wizard: true\n"
            "secrets:\n"
            "  app_password:\n"
            "    generate: true\n"
        )
        self.assertEqual(errors(text), [])

    def test_generated_db_password_is_not_empty(self):
        exported = env(
            "version: 1\nsecrets:\n  db_password:\n    generate: true\n"
        )
        self.assertTrue(len(exported["DB_PASS"]) > MIN_GENERATED_LENGTH)

    def test_render_for_display_masks_the_secret(self):
        path = self.secret_file("s3cret\n")
        document = doc(
            "version: 1\n"
            "secrets:\n"
            "  app_password:\n"
            f"    file: {path}\n"
        )
        rendered = spec.mask(
            spec.render_env(document, spec.masked_secrets(document))
        )
        self.assertIn("APP_PASS", rendered)
        self.assertNotIn("s3cret", rendered)

    def test_values_are_shell_quoted(self):
        password = "a b$c\"d'e"
        path = self.secret_file(password + "\n")
        document = doc(
            "version: 1\n"
            "secrets:\n"
            "  app_password:\n"
            f"    file: {path}\n"
        )
        self.assertEqual(spec.validate(document), [])
        secrets = spec.resolve_secrets(document)
        rendered = spec.render_env(document, secrets)

        conf = join(self.tmpdir, "inithooks.conf")
        spec.write_conf(rendered, conf)
        out = subprocess.run(
            ["bash", "-c", f'source {conf}; printf %s "$APP_PASS"'],
            capture_output=True,
        )
        self.assertEqual(out.stdout.decode(), password)


if __name__ == "__main__":
    unittest.main()
