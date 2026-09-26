# Copyright (c) 2026 KeelLinux maintainers
"""Deprecated field names: still accepted, warned about, canonicalised

keel.spec.compat is pure: deprecations() reports, canonical() returns a
new document and never touches the one it was given. The CLI tests check
that a spec written before the rename still validates, still renders the
same conf variable, and prints one warning naming the current name.
"""

import contextlib
import io
import os
import tempfile
import unittest

from helpers import doc, spec

from keel import exits
from keel.cli import main
from keel.spec import compat

OLD = "version: 1\nsecurity:\n  alerts: skip\n  updates: force\n"
NEW = (
    "version: 1\nsecurity:\n  alerts: skip\n"
    "  updates_at_first_boot: force\n"
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestDeprecations(unittest.TestCase):
    def test_the_old_name_is_reported_with_the_new_one_and_the_reason(self):
        found = compat.deprecations(doc(OLD))
        self.assertEqual(len(found), 1)
        self.assertIn("security.updates is deprecated, rename it to"
                      " security.updates_at_first_boot", found[0])
        self.assertIn("only ever controlled whether the first boot installs",
                      found[0])

    def test_both_names_together_say_which_value_is_used(self):
        found = compat.deprecations(doc(NEW + "  updates: skip\n"))
        self.assertIn("security.updates_at_first_boot is also set, and that"
                      " is the value being used", found[0])

    def test_a_current_document_says_nothing(self):
        self.assertEqual(compat.deprecations(doc(NEW)), [])
        self.assertEqual(compat.deprecations({"version": 1}), [])
        self.assertEqual(compat.deprecations({"security": "skip"}), [])
        self.assertEqual(compat.deprecations("not a mapping"), [])


class TestCanonical(unittest.TestCase):
    def test_the_field_moves_and_nothing_else_changes(self):
        original = doc(OLD)
        updated = compat.canonical(original)
        self.assertEqual(updated, {
            "version": 1,
            "security": {"alerts": "skip", "updates_at_first_boot": "force"},
        })
        self.assertEqual(original["security"], {"alerts": "skip",
                                                "updates": "force"})

    def test_the_current_name_wins_and_the_old_one_is_dropped(self):
        updated = compat.canonical(doc(NEW + "  updates: skip\n"))
        self.assertEqual(updated["security"],
                         {"alerts": "skip", "updates_at_first_boot": "force"})

    def test_anything_else_comes_back_as_it_came(self):
        for document in ("not a mapping", None, {"security": ["a"]},
                         {"version": 1}):
            self.assertEqual(compat.canonical(document), document)
        keyed = {"security": {1: "one", "updates": "skip"}}
        self.assertEqual(compat.canonical(keyed)["security"],
                         {1: "one", "updates_at_first_boot": "skip"})


class TestValidateAcceptsTheOldName(unittest.TestCase):
    def test_the_old_name_is_not_an_unknown_key(self):
        self.assertEqual(spec.validate(doc(OLD)), [])

    def test_a_bad_value_is_reported_under_the_current_name(self):
        found = spec.validate(doc(OLD.replace("force", "weekly")))
        self.assertEqual(
            found,
            ["security.updates_at_first_boot: must be 'skip' or 'force'"],
        )


class TestCommandsWarnOnce(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def write(self, text: str) -> str:
        path = os.path.join(self.tmpdir, "instance.yaml")
        with open(path, "w") as fob:
            fob.write(text)
        return path

    def test_validate_accepts_the_old_spec_and_names_the_new_field(self):
        path = self.write(OLD)
        code, out, err = run_cli("spec", "validate", "--spec", path)
        self.assertEqual(code, exits.OK)
        self.assertIn("ok (secret files checked)", out)
        self.assertIn(f"Warning: {path}: security.updates is deprecated,"
                      " rename it to security.updates_at_first_boot", err)

    def test_render_exports_the_same_variable_under_either_name(self):
        for text in (OLD, NEW):
            with self.subTest(text=text):
                code, out, _ = run_cli("spec", "render", "--spec",
                                       self.write(text))
                self.assertEqual(code, exits.OK)
                self.assertIn("export SEC_UPDATES=FORCE\n", out)

    def test_the_current_spec_warns_about_nothing(self):
        _, _, err = run_cli("spec", "validate", "--spec", self.write(NEW))
        self.assertNotIn("deprecated", err)
