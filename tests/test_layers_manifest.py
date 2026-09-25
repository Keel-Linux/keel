# Copyright (c) 2026 KeelLinux maintainers
"""Parsing and validating a layer manifest, with the real core and lamp"""

import os
import tempfile
import unittest
from os.path import join

from layers_helpers import (
    fixture_fields,
    read_fixture,
    render,
    write,
    write_manifest,
)

from keel.layers import Manifest, ManifestError, REQUIRED_KEYS, manifest


class TestParse(unittest.TestCase):
    def test_parses_the_real_lamp_manifest_into_every_required_key(self):
        fields = manifest.parse(read_fixture("lamp.manifest"))
        self.assertEqual(set(fields), set(REQUIRED_KEYS))
        self.assertEqual(fields["layer"], "lamp")
        self.assertEqual(fields["type"], "delta")
        self.assertEqual(fields["parent"], "core")

    def test_values_keep_their_inner_spaces(self):
        fields = manifest.parse(read_fixture("lamp.manifest"))
        self.assertEqual(
            fields["common_overlays"],
            "turnkey.d tkl-webcp confconsole-lamp apache php mysql adminer"
            " composer",
        )

    def test_blank_lines_are_ignored(self):
        fields = manifest.parse("\nlayer core\n\n  \ntype rootfs\n")
        self.assertEqual(fields, {"layer": "core", "type": "rootfs"})

    def test_reports_every_malformed_line(self):
        with self.assertRaises(ManifestError) as raised:
            manifest.parse("layer core\nBad key\nsize\nlayer lamp\n")
        self.assertEqual(
            raised.exception.errors,
            [
                "line 2: invalid key 'Bad'",
                "line 3: size: missing value",
                "line 4: layer: repeated key",
            ],
        )

    def test_the_sha256_file_matches_the_manifest(self):
        for name in ("core", "lamp"):
            with self.subTest(layer=name):
                digest, filename = (
                    read_fixture(f"{name}.tar.zst.sha256").split()
                )
                fields = fixture_fields(name)
                self.assertEqual(digest, fields["sha256"])
                self.assertEqual(filename, fields["tarball"])


class TestValidate(unittest.TestCase):
    def test_the_real_manifests_are_valid(self):
        for name in ("core", "lamp"):
            with self.subTest(layer=name):
                self.assertEqual(manifest.validate(fixture_fields(name)), [])

    def test_missing_keys_are_reported_together_and_first(self):
        fields = {"layer": "core", "type": "rootfs"}
        errors = manifest.validate(fields)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("missing keys: parent, "))
        self.assertIn("size", errors[0])

    def test_every_value_check(self):
        fields = fixture_fields("core")
        fields.update(
            layer="Core Layer",
            type="image",
            sha256="xyz",
            size="-1",
            source_date_epoch="yesterday",
            tarball="../core.tar.zst",
        )
        errors = manifest.validate(fields)
        self.assertEqual(
            errors,
            [
                "layer: invalid name 'Core Layer'",
                "type: must be one of rootfs, delta",
                "sha256: must be 64 lowercase hex digits",
                "size: must be a non negative integer",
                "source_date_epoch: must be a non negative integer",
                "tarball: must be a file name, not a path",
            ],
        )

    def test_rootfs_must_not_name_a_parent(self):
        fields = fixture_fields("core")
        fields.update(parent="base", parent_sha256="a" * 64)
        self.assertEqual(
            manifest.validate(fields),
            [
                "parent: a rootfs layer must have parent none",
                "parent_sha256: a rootfs layer must have parent_sha256 none",
            ],
        )

    def test_delta_must_name_a_parent_and_its_sha256(self):
        fields = fixture_fields("lamp")
        fields.update(parent="none", parent_sha256="none")
        self.assertEqual(
            manifest.validate(fields),
            [
                "parent: a delta layer must name its parent layer",
                "parent_sha256: a delta layer must record the parent sha256",
            ],
        )

    def test_delta_parent_must_be_a_layer_name(self):
        fields = fixture_fields("lamp")
        fields.update(parent="/core")
        self.assertEqual(
            manifest.validate(fields),
            ["parent: a delta layer must name its parent layer"],
        )

    def test_delta_cannot_be_its_own_parent(self):
        fields = fixture_fields("lamp")
        fields.update(parent="lamp")
        self.assertEqual(
            manifest.validate(fields),
            ["parent: a layer cannot be its own parent"],
        )


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_loads_the_real_lamp_manifest(self):
        path = write_manifest(self.tmpdir, fixture_fields("lamp"))
        loaded = manifest.load(path)
        self.assertIsInstance(loaded, Manifest)
        self.assertEqual(loaded.path, path)
        self.assertEqual(loaded.name, "lamp")
        self.assertEqual(loaded.kind, "delta")
        self.assertEqual(loaded.parent, "core")
        self.assertEqual(
            loaded.parent_sha256,
            "e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19",
        )
        self.assertEqual(loaded.tarball, "lamp.tar.zst")
        self.assertEqual(
            loaded.sha256,
            "237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae",
        )
        self.assertEqual(loaded.size, 79807121)
        self.assertEqual(loaded.source_date_epoch, 1700000000)

    def test_a_rootfs_has_no_parent(self):
        path = write_manifest(self.tmpdir, fixture_fields("core"))
        loaded = manifest.load(path)
        self.assertIsNone(loaded.parent)
        self.assertIsNone(loaded.parent_sha256)

    def test_the_fields_are_read_only(self):
        path = write_manifest(self.tmpdir, fixture_fields("core"))
        loaded = manifest.load(path)
        with self.assertRaises(TypeError):
            loaded.fields["size"] = "0"

    def test_missing_file_raises_manifest_error(self):
        path = join(self.tmpdir, "absent.manifest")
        with self.assertRaises(ManifestError) as raised:
            manifest.load(path)
        self.assertEqual(raised.exception.path, path)
        self.assertTrue(raised.exception.errors[0].startswith("cannot read"))
        self.assertIn(path, str(raised.exception))

    def test_binary_garbage_raises_manifest_error(self):
        path = write(join(self.tmpdir, "bad.manifest"), b"\xff\xfe layer\n")
        with self.assertRaises(ManifestError) as raised:
            manifest.load(path)
        self.assertTrue(raised.exception.errors[0].startswith("cannot read"))

    def test_malformed_lines_are_reported_with_the_path(self):
        path = write(join(self.tmpdir, "bad.manifest"), "layer\n")
        with self.assertRaises(ManifestError) as raised:
            manifest.load(path)
        self.assertEqual(raised.exception.path, path)
        self.assertEqual(
            raised.exception.errors, ["line 1: layer: missing value"]
        )

    def test_invalid_fields_are_reported_with_the_path(self):
        fields = fixture_fields("core")
        fields["size"] = "big"
        path = write(join(self.tmpdir, "core.manifest"), render(fields))
        with self.assertRaises(ManifestError) as raised:
            manifest.load(path)
        self.assertEqual(
            raised.exception.errors,
            ["size: must be a non negative integer"],
        )

    def tearDown(self):
        for name in os.listdir(self.tmpdir):
            os.remove(join(self.tmpdir, name))
        os.rmdir(self.tmpdir)


if __name__ == "__main__":
    unittest.main()
