# Copyright (c) 2026 KeelLinux maintainers
"""Reading the .hash file generate-signature writes next to a tarball"""

import tempfile
import unittest
from os.path import join

from layers_helpers import fixture_fields, hash_text, read_fixture, write

from keel.layers import hashfile

SHA256 = "a" * 64
SHA512 = "b" * 128


class TestParse(unittest.TestCase):
    def test_reads_both_digests_and_the_file_name_of_the_real_files(self):
        for name in ("core", "lamp"):
            with self.subTest(layer=name):
                found = hashfile.parse(
                    "x", read_fixture(f"{name}.tar.zst.hash")
                )
                fields = fixture_fields(name)
                self.assertEqual(found.sha256, fields["sha256"])
                self.assertEqual(found.filename, fields["tarball"])
                self.assertEqual(len(found.sha512), 128)

    def test_the_real_files_carry_no_signature(self):
        found = hashfile.parse("x", read_fixture("lamp.tar.zst.hash"))
        self.assertFalse(found.signed)

    def test_a_clear_signed_file_is_reported_as_signed(self):
        found = hashfile.parse("x", hash_text("lamp", SHA256, signed=True))
        self.assertTrue(found.signed)
        self.assertEqual(found.sha256, SHA256)

    def test_one_signature_mark_alone_is_not_a_signature(self):
        text = f"-----BEGIN PGP SIGNED MESSAGE-----\n{SHA256}  a.tar.zst\n"
        self.assertFalse(hashfile.parse("x", text).signed)

    def test_prose_without_digest_lines_gives_nothing(self):
        found = hashfile.parse("x", "no digests here\n")
        self.assertEqual(
            (found.sha256, found.sha512, found.filename), (None, None, None)
        )

    def test_the_first_digest_of_each_kind_wins(self):
        text = (
            f"{SHA256}  first.tar.zst\n"
            f"{'c' * 64}  second.tar.zst\n"
            f"{SHA512}  first.tar.zst\n"
            f"{'d' * 128}  second.tar.zst\n"
        )
        found = hashfile.parse("x", text)
        self.assertEqual(found.sha256, SHA256)
        self.assertEqual(found.sha512, SHA512)
        self.assertEqual(found.filename, "first.tar.zst")

    def test_the_file_name_comes_from_the_sha512_line_when_no_sha256(self):
        found = hashfile.parse("x", f"  {SHA512}  only.tar.zst\n")
        self.assertIsNone(found.sha256)
        self.assertEqual(found.filename, "only.tar.zst")


class TestLoad(unittest.TestCase):
    def test_load_reads_the_file_and_keeps_its_path(self):
        tmpdir = tempfile.mkdtemp()
        path = write(
            join(tmpdir, "lamp.tar.zst.hash"), hash_text("lamp", SHA256)
        )
        found = hashfile.load(path)
        self.assertEqual(found.path, path)
        self.assertEqual(found.sha256, SHA256)

    def test_load_raises_oserror_for_a_missing_file(self):
        with self.assertRaises(OSError):
            hashfile.load(join(tempfile.mkdtemp(), "absent.hash"))


if __name__ == "__main__":
    unittest.main()
