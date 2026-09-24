# Copyright (c) 2026 KeelLinux maintainers
"""Loading and top level validation of the instance spec"""

import unittest

from helpers import doc, env, errors, spec


class TestLoad(unittest.TestCase):
    def test_loads_minimal_document(self):
        # Arrange / Act
        exported = env("version: 1\n")

        # Assert
        self.assertEqual(exported, {})

    def test_rejects_malformed_yaml(self):
        with self.assertRaises(spec.SpecError):
            doc("version: 1\ninstance: [unclosed\n")

    def test_rejects_document_that_is_not_a_mapping(self):
        with self.assertRaises(spec.SpecError):
            doc("- one\n- two\n")

    def test_rejects_empty_file(self):
        with self.assertRaises(spec.SpecError):
            doc("")

    def test_rejects_missing_or_wrong_version(self):
        self.assertTrue(errors("instance:\n  hostname: blog\n"))
        self.assertTrue(errors("version: 2\n"))

    def test_rejects_unknown_top_level_key(self):
        found = errors("version: 1\nnonsense: true\n")
        self.assertTrue(any("nonsense" in error for error in found))


if __name__ == "__main__":
    unittest.main()
