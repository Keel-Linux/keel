# Copyright (c) 2026 KeelLinux maintainers
"""Assembling a rootfs from cached layers and packing a template

The layers are synthetic (tests/layers_helpers.py), built with tarfile:
the delta carries a whiteout as a character device 0:0 and opaque
directories through the pax xattr header, exactly as tar --xattrs
stores them, so the suite exercises the overlay semantics without
overlayfs. Root is stood in with os.geteuid patched; nothing here
needs real privileges because no device node is ever created and the
overlay xattrs are never restored.
"""

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from os.path import exists, isdir, join
from unittest import mock

from layers_helpers import (
    CORE_VERSION,
    LAMP_VERSION,
    OPAQUE,
    TOOL_XATTR,
    build_source,
    member,
    sha256,
    stand_in_fields,
    tar_bytes,
    write,
    write_manifest,
    zstd,
)

from keel import exits
from keel.layers import (
    AssembleReport,
    LayerError,
    assemble,
    extract,
    pack,
    pull,
)
from keel.layers.cache import Cache

AS_ROOT = mock.patch("os.geteuid", return_value=0)
AS_USER = mock.patch("os.geteuid", return_value=1000)
EPOCH = 1700000000


def read(path: str) -> bytes:
    with open(path, "rb") as fob:
        return fob.read()


class AssembleTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.rootfs = join(self.tmpdir, "out", "rootfs")
        self.fields = build_source(self.source)
        pull("lamp", self.source, self.cache)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def assemble(self, layer="lamp", template=None, sha256=None):
        with AS_ROOT:
            return assemble(layer, self.cache, self.rootfs, template, sha256)

    def failing(self, **kwargs) -> LayerError:
        with self.assertRaises(LayerError) as raised:
            self.assemble(**kwargs)
        return raised.exception

    def work_dirs(self) -> list[str]:
        out = join(self.tmpdir, "out")
        return [e for e in os.listdir(out) if e.startswith(".keel-assemble")]

    def cached(self, name: str, suffix=".tar.zst") -> str:
        digest = self.fields[name]["sha256"]
        return join(self.cache, f"{name}-{digest}{suffix}")


class TestAssemble(AssembleTestCase):
    def test_the_chain_is_applied_with_overlay_semantics(self):
        report = self.assemble()

        self.assertEqual(read(join(self.rootfs, "etc/turnkey_version")),
                         LAMP_VERSION)
        self.assertTrue(isdir(join(self.rootfs, "etc/apt")))
        self.assertFalse(exists(join(self.rootfs, "etc/apt/01proxy")))
        self.assertEqual(read(join(self.rootfs, "etc/apache2/apache2.conf")),
                         b"ServerRoot\n")
        self.assertEqual(os.listdir(join(self.rootfs, "etc/php")),
                         ["php.ini"])
        self.assertTrue(isdir(join(self.rootfs, "var/lib")))
        self.assertFalse(exists(join(self.rootfs, "var/lib/x")))
        tool = join(self.rootfs, "usr/bin/tool")
        self.assertEqual(os.stat(tool).st_mode & 0o777, 0o755)
        self.assertEqual(os.getxattr(tool, "user.keel"), b"tool")
        self.assertEqual(os.listxattr(join(self.rootfs, "etc/php")), [])
        self.assertEqual(report.lines(), [
            "core: extracted (1 members, 0 whiteouts, 0 opaque directories)",
            "lamp: extracted (2 members, 2 whiteouts, 2 opaque directories)",
            f"rootfs: {self.rootfs}",
        ])
        self.assertIsNone(report.packed)
        self.assertEqual(self.work_dirs(), [])

    def test_core_alone_is_the_core_rootfs(self):
        self.assemble("core")
        self.assertEqual(read(join(self.rootfs, "etc/turnkey_version")),
                         CORE_VERSION)
        self.assertTrue(exists(join(self.rootfs, "etc/apt/01proxy")))

    def test_sha256_picks_a_version_when_several_are_cached(self):
        other = stand_in_fields("core", b"other", tarball="other.tar.zst")
        write(join(self.cache, f"core-{other['sha256']}.tar.zst"), b"other")
        write_manifest(self.cache, other, name=f"core-{other['sha256']}")
        error = self.failing(layer="core")
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn("several versions in cache, pass --sha256", str(error))
        self.assertIn(other["sha256"], str(error))
        self.assertIn(self.fields["core"]["sha256"], str(error))
        self.assemble("core", sha256=self.fields["core"]["sha256"])
        self.assertTrue(exists(join(self.rootfs, "etc/turnkey_version")))

    def test_rootfs_may_exist_when_empty(self):
        os.makedirs(self.rootfs)
        self.assemble()
        self.assertTrue(exists(join(self.rootfs, "etc/turnkey_version")))


class TestTemplate(AssembleTestCase):
    def setUp(self):
        super().setUp()
        self.template = join(self.tmpdir, "out", "lamp.tar.zst")

    def entries(self, path: str) -> list[tarfile.TarInfo]:
        plain = subprocess.run(
            ["zstd", "--quiet", "--decompress", "--stdout", path],
            capture_output=True, check=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
            return tar.getmembers()

    def test_the_template_is_packed_with_its_sha512(self):
        report = self.assemble(template=self.template)
        packed = report.packed
        self.assertEqual(packed.path, self.template)
        self.assertEqual(packed.size, os.path.getsize(self.template))
        self.assertEqual(packed.sha512,
                         hashlib.sha512(read(self.template)).hexdigest())
        self.assertEqual(
            read(self.template + ".sha512").decode(),
            f"{packed.sha512}  lamp.tar.zst\n",
        )
        self.assertEqual(report.lines()[-1], packed.line())
        self.assertIn(f"template: {self.template} ({packed.size} bytes,"
                      f" sha512 {packed.sha512})", packed.line())

    def test_the_tar_stream_is_deterministic(self):
        self.assemble(template=self.template)
        entries = self.entries(self.template)
        names = [entry.name for entry in entries]
        self.assertEqual(names, sorted(names))
        self.assertEqual({entry.mtime for entry in entries}, {EPOCH})
        self.assertEqual({entry.uname for entry in entries}, {""})
        tool = next(e for e in entries if e.name == "./usr/bin/tool")
        self.assertEqual(tool.pax_headers[TOOL_XATTR[0]], TOOL_XATTR[1])
        first = read(self.template)
        shutil.rmtree(self.rootfs)
        self.assemble(template=self.template)
        self.assertEqual(read(self.template), first)

    def test_a_template_that_cannot_be_written_fails_after_the_rootfs(self):
        error = self.failing(template=join(self.tmpdir, "absent", "t.tar.zst"))
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertIn("zstd exited", str(error))
        self.assertTrue(exists(join(self.rootfs, "etc/turnkey_version")))

    def test_a_rootfs_that_cannot_be_read_fails_in_tar(self):
        with self.assertRaises(LayerError) as raised:
            pack.pack(join(self.tmpdir, "absent"), self.template, EPOCH)
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_FAILED)
        self.assertIn("tar exited", str(raised.exception))


class TestRefusals(AssembleTestCase):
    def test_not_root_is_refused_before_anything_is_touched(self):
        with AS_USER:
            with self.assertRaises(LayerError) as raised:
                assemble("lamp", self.cache, self.rootfs)
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_NEEDS_ROOT)
        self.assertIn("assemble must run as root", str(raised.exception))
        self.assertIn("uid 1000", str(raised.exception))
        self.assertFalse(exists(self.rootfs))

    def test_a_layer_that_was_not_pulled_is_unavailable(self):
        error = self.failing(layer="wordpress")
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertEqual(
            str(error),
            f"wordpress: not in cache {self.cache}; run keel pull first",
        )

    def test_a_missing_parent_in_the_cache_is_unavailable(self):
        os.remove(self.cached("core", ".manifest"))
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn("core:", str(error))
        self.assertIn("run keel pull first", str(error))

    def test_a_cached_manifest_that_does_not_validate_is_invalid(self):
        write(self.cached("core", ".manifest"), "layer core\n")
        error = self.failing()
        self.assertEqual(error.code, exits.MANIFEST_INVALID)
        self.assertIn("missing keys", str(error))

    def test_a_corrupted_cached_tarball_is_a_mismatch_before_extraction(self):
        write(self.cached("lamp"), b"corrupted")
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertIn("lamp: cached tarball: size 9, manifest says",
                      str(error))
        self.assertFalse(exists(self.rootfs))

    def test_a_missing_cached_tarball_is_a_mismatch(self):
        os.remove(self.cached("core"))
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertIn("No such file or directory", str(error))

    def test_a_rootfs_that_is_not_empty_is_refused(self):
        os.makedirs(self.rootfs)
        write(join(self.rootfs, "stale"), "x")
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertEqual(str(error),
                         f"{self.rootfs}: not empty, refusing to assemble")

    def test_a_rootfs_path_that_is_a_file_fails(self):
        os.makedirs(join(self.tmpdir, "out"))
        write(self.rootfs, "x")
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertIn("File exists", str(error))


class TestBrokenTarballs(AssembleTestCase):
    """The tarball matches its manifest but cannot be applied"""

    def replace_lamp(self, data: bytes) -> None:
        shutil.rmtree(self.cache)
        build_source(self.source, lamp_data=data)
        self.fields = build_source(self.source, lamp_data=data)
        pull("lamp", self.source, self.cache)

    def test_a_tarball_that_is_not_zstd_fails_in_zstd(self):
        self.replace_lamp(b"not zstd at all")
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertIn("zstd exited", str(error))
        self.assertEqual(self.work_dirs(), [])

    def test_a_tarball_that_is_not_a_tar_fails_in_the_scan(self):
        self.replace_lamp(zstd(b"not a tar"))
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertIn("lamp.tar:", str(error))
        self.assertEqual(self.work_dirs(), [])

    def test_a_member_tar_cannot_extract_fails_in_tar(self):
        self.replace_lamp(zstd(tar_bytes([
            member("./", "dir"),
            member("./etc/hard", "link", linkname="./etc/absent"),
        ])))
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertIn("tar exited 2", str(error))

    def test_a_whiteout_that_escapes_the_rootfs_is_refused(self):
        self.replace_lamp(zstd(tar_bytes([
            member("./", "dir"),
            member("../escape", "whiteout"),
        ])))
        error = self.failing()
        self.assertEqual(error.code, exits.ASSEMBLE_FAILED)
        self.assertEqual(str(error),
                         "refusing to touch '../escape' in the rootfs")

    def test_a_tar_without_a_root_entry_is_one_member(self):
        self.replace_lamp(zstd(tar_bytes([
            member("etc", "dir"),
            member("etc/turnkey_version", data=LAMP_VERSION),
        ])))
        report = self.assemble()
        self.assertEqual(report.applied[1].groups, 1)
        self.assertEqual(read(join(self.rootfs, "etc/turnkey_version")),
                         LAMP_VERSION)


class TestExtractHelpers(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_relative_accepts_paths_under_the_root_only(self):
        self.assertEqual(extract.relative("./etc/x"), "etc/x")
        self.assertEqual(extract.relative("etc/../usr"), "usr")
        for name in (".", "./", "..", "../x", "/etc", "./../x"):
            with self.subTest(name=name):
                with self.assertRaises(LayerError):
                    extract.relative(name)

    def test_remove_path_removes_files_and_trees_and_ignores_absent(self):
        os.makedirs(join(self.tmpdir, "d/e"))
        write(join(self.tmpdir, "f"), "x")
        extract.remove_path(self.tmpdir, "./d")
        extract.remove_path(self.tmpdir, "./f")
        extract.remove_path(self.tmpdir, "./absent")
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_scan_groups_members_and_marks(self):
        plain = write(join(self.tmpdir, "t.tar"), tar_bytes([
            member("./", "dir"),
            member("./a", "whiteout"),
            member("./", "dir"),
            member("./b", "dir", xattrs=OPAQUE),
            member("./c", "dir"),
        ]))
        groups = extract.scan(plain)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].whiteouts, ["./a"])
        self.assertEqual(groups[0].opaques, [])
        self.assertEqual(groups[1].whiteouts, [])
        self.assertEqual(groups[1].opaques, ["./b"])
        self.assertEqual(groups[0].end, groups[1].start)
        self.assertEqual(groups[1].end, os.path.getsize(plain))

    def test_a_tar_that_dies_early_is_reported_not_a_broken_pipe(self):
        plain = write(join(self.tmpdir, "big.tar"), tar_bytes([
            member("./big", data=b"\0" * (4 << 20)),
        ]))
        group = extract.Group(0, os.path.getsize(plain))
        with self.assertRaises(LayerError) as raised:
            extract.extract_group(plain, group, join(self.tmpdir, "absent"))
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_FAILED)
        self.assertIn("tar exited 2", str(raised.exception))


class TestCacheHelpers(unittest.TestCase):
    def test_has_is_the_opposite_of_check(self):
        tmpdir = tempfile.mkdtemp()
        cache = Cache(tmpdir)
        data = b"layer"
        fields = stand_in_fields("core", data)
        layer = mock.Mock(name="core", sha256=fields["sha256"],
                          size=len(data))
        layer.name = "core"
        self.assertFalse(cache.has(layer))
        write(cache.tarball("core", fields["sha256"]), data)
        self.assertTrue(cache.has(layer))
        self.assertEqual(cache.check(layer), [])
        shutil.rmtree(tmpdir)

    def test_report_is_read_only(self):
        report = AssembleReport("r", (), None)
        with self.assertRaises(AttributeError):
            report.rootfs = "x"
        self.assertEqual(sha256(b""), hashlib.sha256(b"").hexdigest())


if __name__ == "__main__":
    unittest.main()
