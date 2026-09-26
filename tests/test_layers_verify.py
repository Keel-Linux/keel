# Copyright (c) 2026 KeelLinux maintainers
"""Verifying a directory of layers against their manifests"""

import os
import shutil
import tempfile
import unittest
from os.path import join

from layers_helpers import (
    LAMP_BYTES,
    build_tree,
    hash_text,
    sha256,
    stand_in_fields,
    to_cache_layout,
    write,
    write_manifest,
)

from keel import exits
from keel.layers import LayerResult, Report, verify, verify_layers

OTHER = "f" * 64


class VerifyTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.fields = build_tree(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def result(self, name: str, tarballs_dir=None) -> LayerResult:
        report = verify_layers(self.root, tarballs_dir)
        return next(r for r in report.results if r.name == name)

    def rewrite(self, name: str, **changes) -> None:
        write_manifest(self.root, {**self.fields[name], **changes})


class TestHappyPath(VerifyTestCase):
    def test_every_layer_is_ok_and_the_report_exits_ok(self):
        report = verify_layers(self.root)
        self.assertEqual([r.line() for r in report.results],
                         ["core: ok", "lamp: ok"])
        self.assertEqual(report.code, exits.OK)
        self.assertEqual(
            report.summary(),
            "layers: 2 checked, 2 ok, 0 unverified, 0 mismatch, 0 invalid",
        )

    def test_tarballs_can_live_in_another_directory(self):
        tarballs = join(self.root, "tarballs")
        os.mkdir(tarballs)
        for name in ("core", "lamp"):
            os.rename(join(self.root, f"{name}.tar.zst"),
                      join(tarballs, f"{name}.tar.zst"))
        self.assertEqual(verify_layers(self.root).code, exits.LAYER_MISMATCH)
        self.assertEqual(verify_layers(self.root, tarballs).code, exits.OK)

    def test_a_three_deep_chain_resolves(self):
        app = stand_in_fields(
            "lamp", b"app\n", layer="app", parent="lamp",
            parent_sha256=self.fields["lamp"]["sha256"], tarball="app.tar.zst",
        )
        write(join(self.root, "app.tar.zst"), b"app\n")
        write_manifest(self.root, app)
        self.assertEqual(self.result("app").line(), "app: ok")

    def test_manifests_are_reported_in_name_order(self):
        self.rewrite("core", size="1")
        names = [r.name for r in verify_layers(self.root).results]
        self.assertEqual(names, ["core", "lamp"])


class TestTarball(VerifyTestCase):
    def test_missing_tarball_is_a_mismatch(self):
        os.remove(join(self.root, "lamp.tar.zst"))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.code, exits.LAYER_MISMATCH)
        self.assertEqual(
            found.details, ("tarball lamp.tar.zst: No such file or directory",)
        )

    def test_wrong_size_in_the_manifest_is_a_mismatch(self):
        self.rewrite("lamp", size="1")
        found = self.result("lamp")
        self.assertEqual(
            found.details, (f"size {len(LAMP_BYTES)}, manifest says 1",)
        )

    def test_corrupted_tarball_fails_sha256_and_size(self):
        write(join(self.root, "lamp.tar.zst"), b"corrupted")
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(len(found.details), 2)
        self.assertTrue(found.details[0].startswith("size 9, manifest says"))
        self.assertTrue(found.details[1].startswith(
            f"sha256 {sha256(b'corrupted')}, manifest says"
        ))

    def test_same_size_different_content_fails_sha256_only(self):
        write(join(self.root, "lamp.tar.zst"), b"X" * len(LAMP_BYTES))
        found = self.result("lamp")
        self.assertEqual(len(found.details), 1)
        self.assertTrue(found.details[0].startswith("sha256 "))


class TestParentChain(VerifyTestCase):
    def test_parent_sha256_must_match_the_parent_manifest(self):
        self.rewrite("lamp", parent_sha256=OTHER)
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.details, (
            f"parent_sha256 {OTHER}, core manifest says "
            f"{self.fields['core']['sha256']}",
        ))

    def test_missing_parent_manifest_breaks_the_chain(self):
        os.remove(join(self.root, "core.manifest"))
        found = self.result("lamp")
        self.assertEqual(found.details, ("parent core: no valid manifest",))

    def test_invalid_parent_manifest_breaks_the_chain(self):
        self.rewrite("core", size="big")
        self.assertEqual(self.result("core").status, verify.STATUS_INVALID)
        self.assertEqual(
            self.result("lamp").details, ("parent core: no valid manifest",)
        )

    def test_a_loop_in_the_chain_is_reported(self):
        self.rewrite("core", type="delta", parent="lamp",
                     parent_sha256=self.fields["lamp"]["sha256"])
        found = self.result("lamp")
        self.assertEqual(found.details, ("parent chain loops through lamp",))


class TestHashFile(VerifyTestCase):
    def hash_path(self, name="lamp") -> str:
        return join(self.root, f"{name}.tar.zst.hash")

    def test_unsigned_hash_file_with_the_right_digest_is_unverified(self):
        write(self.hash_path(),
              hash_text("lamp", self.fields["lamp"]["sha256"]))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_UNVERIFIED)
        self.assertEqual(found.code, exits.SIGNATURE_UNVERIFIED)
        self.assertEqual(found.details, (verify.SIGNATURE_ABSENT,))

    def test_signed_hash_file_is_reported_present_and_never_verified(self):
        write(self.hash_path(),
              hash_text("lamp", self.fields["lamp"]["sha256"], signed=True))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_UNVERIFIED)
        self.assertEqual(found.details, (verify.SIGNATURE_PRESENT,))
        self.assertIn("not verified", found.line())

    def test_hash_file_with_another_digest_is_a_mismatch(self):
        write(self.hash_path(), hash_text("lamp", OTHER, signed=True))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.details, (
            f"hash file sha256 {OTHER}, manifest says "
            f"{self.fields['lamp']['sha256']}",
        ))

    def test_hash_file_naming_another_tarball_is_a_mismatch(self):
        text = hash_text("lamp", self.fields["lamp"]["sha256"])
        write(self.hash_path(), text.replace("lamp.tar.zst", "core.tar.zst"))
        found = self.result("lamp")
        self.assertEqual(found.details, (
            "hash file names core.tar.zst, manifest says lamp.tar.zst",
        ))

    def test_hash_file_without_digest_lines_is_a_mismatch(self):
        write(self.hash_path(), "nothing to see\n")
        self.assertEqual(
            self.result("lamp").details, ("hash file: no sha256 line",)
        )

    def test_unreadable_hash_file_is_a_mismatch(self):
        os.mkdir(self.hash_path())
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.details, ("hash file: Is a directory",))

    def test_the_worst_layer_decides_the_report_code(self):
        write(self.hash_path("core"),
              hash_text("core", self.fields["core"]["sha256"]))
        self.assertEqual(verify_layers(self.root).code,
                         exits.SIGNATURE_UNVERIFIED)
        self.rewrite("lamp", size="1")
        self.assertEqual(verify_layers(self.root).code, exits.LAYER_MISMATCH)
        write(join(self.root, "zzz.manifest"), "layer zzz\n")
        self.assertEqual(verify_layers(self.root).code,
                         exits.MANIFEST_INVALID)


class TestManifests(VerifyTestCase):
    def test_invalid_manifest_lists_every_error(self):
        self.rewrite("core", size="big", sha256="short")
        found = self.result("core")
        self.assertEqual(found.status, verify.STATUS_INVALID)
        self.assertEqual(found.code, exits.MANIFEST_INVALID)
        self.assertEqual(found.line(), (
            "core: invalid: sha256: must be 64 lowercase hex digits;"
            " size: must be a non negative integer"
        ))

    def test_manifest_whose_layer_field_differs_from_its_name_is_invalid(self):
        write_manifest(self.root, self.fields["core"], name="base")
        found = self.result("base")
        self.assertEqual(found.status, verify.STATUS_INVALID)
        self.assertEqual(found.details, (
            "layer: manifest names 'core', file is 'base'",
        ))

    def test_files_that_are_not_manifests_are_ignored(self):
        write(join(self.root, "core.log"), "INFO building\n")
        self.assertEqual(len(verify_layers(self.root).results), 2)


class TestCacheLayout(VerifyTestCase):
    """A directory keel pull wrote: `<name>-<sha256>.*` (docs/layers.md)"""

    def cached(self, name: str, suffix: str) -> str:
        return join(self.root, f"{name}-{self.fields[name]['sha256']}{suffix}")

    def write_hash_files(self) -> None:
        for name in ("core", "lamp"):
            write(join(self.root, f"{name}.tar.zst.hash"),
                  hash_text(name, self.fields[name]["sha256"]))

    def test_the_cache_layout_verifies_like_the_build_output(self):
        before = verify_layers(self.root)
        to_cache_layout(self.root, self.fields)
        after = verify_layers(self.root)
        self.assertEqual([r.line() for r in after.results],
                         [r.line() for r in before.results])
        self.assertEqual([r.line() for r in after.results],
                         ["core: ok", "lamp: ok"])
        self.assertEqual(after.code, exits.OK)

    def test_unsigned_hash_files_are_unverified_in_both_layouts(self):
        self.write_hash_files()
        before = verify_layers(self.root)
        to_cache_layout(self.root, self.fields)
        after = verify_layers(self.root)
        self.assertEqual([r.line() for r in before.results], [
            f"core: unverified: {verify.SIGNATURE_ABSENT}",
            f"lamp: unverified: {verify.SIGNATURE_ABSENT}",
        ])
        self.assertEqual([r.line() for r in after.results],
                         [r.line() for r in before.results])
        self.assertEqual(after.code, exits.SIGNATURE_UNVERIFIED)
        self.assertEqual(before.code, exits.SIGNATURE_UNVERIFIED)

    def test_the_sha256_in_the_file_name_must_be_the_recorded_one(self):
        to_cache_layout(self.root, self.fields)
        os.rename(self.cached("lamp", ".manifest"),
                  join(self.root, f"lamp-{OTHER}.manifest"))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.code, exits.LAYER_MISMATCH)
        self.assertEqual(found.details[0], (
            f"file name sha256 {OTHER}, manifest says "
            f"{self.fields['lamp']['sha256']}"
        ))
        self.assertEqual(self.result("core").status, verify.STATUS_OK)

    def test_the_tarball_is_looked_up_by_the_cache_name(self):
        to_cache_layout(self.root, self.fields)
        os.rename(self.cached("lamp", ".tar.zst"),
                  join(self.root, "lamp.tar.zst"))
        found = self.result("lamp")
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertEqual(found.details, (
            (f"tarball lamp-{self.fields['lamp']['sha256']}.tar.zst:"
             " No such file or directory"),
        ))

    def test_a_manifest_naming_another_layer_is_invalid(self):
        to_cache_layout(self.root, self.fields)
        stem = f"base-{self.fields['core']['sha256']}"
        os.rename(self.cached("core", ".manifest"),
                  join(self.root, f"{stem}.manifest"))
        found = self.result(stem)
        self.assertEqual(found.status, verify.STATUS_INVALID)
        self.assertEqual(found.details, (
            f"layer: manifest names 'core', file is {stem!r}",
        ))

    def test_two_versions_of_the_parent_are_both_checked(self):
        to_cache_layout(self.root, self.fields)
        other = stand_in_fields("core", b"other core\n")
        write(join(self.root, f"core-{other['sha256']}.tar.zst"),
              b"other core\n")
        write_manifest(self.root, other, name=f"core-{other['sha256']}")
        report = verify_layers(self.root)
        self.assertEqual([r.line() for r in report.results],
                         ["core: ok", "core: ok", "lamp: ok"])

    def test_a_layer_name_with_a_dash_is_not_a_digest(self):
        app = stand_in_fields(
            "lamp", b"app\n", layer="my-app", parent="lamp",
            parent_sha256=self.fields["lamp"]["sha256"],
            tarball="my-app.tar.zst",
        )
        write(join(self.root, "my-app.tar.zst"), b"app\n")
        write_manifest(self.root, app)
        self.assertEqual(self.result("my-app").line(), "my-app: ok")


class TestDirectory(unittest.TestCase):
    def test_absent_directory_gives_an_empty_ok_report(self):
        report = verify_layers(join(tempfile.mkdtemp(), "absent"))
        self.assertEqual(report.results, ())
        self.assertEqual(report.code, exits.OK)
        self.assertEqual(
            report.summary(),
            "layers: 0 checked, 0 ok, 0 unverified, 0 mismatch, 0 invalid",
        )

    def test_unlistable_directory_is_one_invalid_result(self):
        path = write(join(tempfile.mkdtemp(), "layers"), "a file\n")
        report = verify_layers(path)
        self.assertEqual(report.code, exits.MANIFEST_INVALID)
        self.assertEqual(report.results[0].name, path)
        self.assertEqual(
            report.results[0].details, ("cannot list: Not a directory",)
        )

    def test_report_is_read_only(self):
        report = Report("x", ())
        with self.assertRaises(AttributeError):
            report.results = (LayerResult("a", verify.STATUS_OK),)


if __name__ == "__main__":
    unittest.main()
