# Copyright (c) 2026 KeelLinux maintainers
"""Pulling layers from a directory or an http source into the cache"""

import importlib
import io
import os
import shutil
import tempfile
import unittest
from os.path import exists, join
from unittest import mock

from layers_helpers import (
    Server,
    build_source,
    hash_text,
    sha256,
    write,
    write_manifest,
)

from keel import exits
from keel.layers import LayerError, PullReport, PullResult, pull, verify_layers
from keel.layers.cache import Cache
from keel.layers.pull import STATUS_CACHED, STATUS_FETCHED
from keel.layers.source import Source

# The package exports the pull function under the module's name, so the
# module itself is reached through importlib for patching.
pulling = importlib.import_module("keel.layers.pull")

OTHER = "f" * 64


class PullTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.fields = build_source(self.source)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def pull(self, layer="lamp", source=None) -> PullReport:
        return pull(layer, source or self.source, self.cache)

    def failing(self, layer="lamp", source=None) -> LayerError:
        with self.assertRaises(LayerError) as raised:
            self.pull(layer, source)
        return raised.exception

    def rewrite(self, name: str, **changes) -> None:
        write_manifest(self.source, {**self.fields[name], **changes})

    def cached(self, name: str, suffix=".tar.zst") -> str:
        digest = self.fields[name]["sha256"]
        return join(self.cache, f"{name}-{digest}{suffix}")

    def write_hash_files(self, signed=False) -> None:
        for name in ("core", "lamp"):
            write(join(self.source, f"{name}.tar.zst.hash"),
                  hash_text(name, self.fields[name]["sha256"], signed))


class TestDirectorySource(PullTestCase):
    def test_first_pull_fetches_the_whole_chain_rootfs_first(self):
        report = self.pull()
        self.assertEqual([r.line() for r in report.results], [
            f"core: fetched ({self.fields['core']['size']} bytes)",
            f"lamp: fetched ({self.fields['lamp']['size']} bytes)",
        ])
        total = sum(int(self.fields[n]["size"]) for n in ("core", "lamp"))
        self.assertEqual(report.transferred, total)
        self.assertEqual(
            report.summary(),
            f"layers: 2 resolved, 2 fetched, 0 cached, {total} bytes"
            " transferred",
        )
        for name in ("core", "lamp"):
            self.assertTrue(exists(self.cached(name)))
            self.assertTrue(exists(self.cached(name, ".manifest")))
        self.assertFalse(os.listdir(self.cache) and any(
            entry.endswith(".part") for entry in os.listdir(self.cache)
        ))

    def test_second_pull_transfers_nothing(self):
        self.pull()
        report = self.pull()
        self.assertEqual([r.status for r in report.results],
                         [STATUS_CACHED, STATUS_CACHED])
        self.assertEqual(report.transferred, 0)
        self.assertEqual(report.count(STATUS_FETCHED), 0)
        self.assertIn("2 cached, 0 bytes transferred", report.summary())

    def test_pulling_core_alone_fetches_core_alone(self):
        report = self.pull("core")
        self.assertEqual([r.name for r in report.results], ["core"])

    def test_a_corrupted_cached_tarball_is_fetched_again(self):
        self.pull()
        write(self.cached("lamp"), b"corrupted")
        report = self.pull()
        self.assertEqual([r.status for r in report.results],
                         [STATUS_CACHED, STATUS_FETCHED])
        self.assertEqual(sha256(open(self.cached("lamp"), "rb").read()),
                         self.fields["lamp"]["sha256"])

    def test_the_cached_manifest_reads_back_as_the_source_one(self):
        self.pull()
        cache = Cache(self.cache)
        found = cache.load("lamp", self.fields["lamp"]["sha256"])
        self.assertEqual(dict(found.fields), self.fields["lamp"])

    def test_the_source_may_serve_tarballs_by_hash(self):
        for name in ("core", "lamp"):
            os.rename(join(self.source, f"{name}.tar.zst"),
                      join(self.source,
                           f"{name}-{self.fields[name]['sha256']}.tar.zst"))
        report = self.pull()
        self.assertEqual(report.count(STATUS_FETCHED), 2)

    def test_the_top_layer_may_be_a_manifest_file(self):
        manifest = join(self.tmpdir, "appliance.manifest")
        shutil.copy(join(self.source, "lamp.manifest"), manifest)
        os.remove(join(self.source, "lamp.manifest"))
        report = self.pull(manifest)
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])

    def test_a_manifest_file_that_does_not_validate_is_invalid(self):
        manifest = write(join(self.tmpdir, "bad.manifest"), "layer lamp\n")
        error = self.failing(manifest)
        self.assertEqual(error.code, exits.MANIFEST_INVALID)
        self.assertIn("missing keys", str(error))

    def test_the_hash_file_is_copied_when_the_source_has_one(self):
        self.write_hash_files()
        self.pull()
        for name in ("core", "lamp"):
            with open(self.cached(name, ".tar.zst.hash")) as cached, \
                    open(join(self.source, f"{name}.tar.zst.hash")) as source:
                self.assertEqual(cached.read(), source.read())

    def test_no_hash_file_at_the_source_leaves_none_in_the_cache(self):
        self.pull()
        self.assertFalse(any(
            entry.endswith(".hash") for entry in os.listdir(self.cache)
        ))

    def test_the_hash_file_is_copied_for_a_cached_layer_too(self):
        self.pull()
        self.write_hash_files(signed=True)
        report = self.pull()
        self.assertEqual(report.count(STATUS_CACHED), 2)
        self.assertTrue(exists(self.cached("lamp", ".tar.zst.hash")))

    def test_the_source_may_serve_the_hash_file_by_hash(self):
        self.write_hash_files()
        for name in ("core", "lamp"):
            os.rename(join(self.source, f"{name}.tar.zst.hash"),
                      join(self.source,
                           f"{name}-{self.fields[name]['sha256']}"
                           ".tar.zst.hash"))
        self.pull()
        self.assertTrue(exists(self.cached("core", ".tar.zst.hash")))

    def test_the_cache_verifies_as_the_source_does(self):
        self.write_hash_files()
        self.pull()
        source = verify_layers(self.source)
        cache = verify_layers(self.cache)
        self.assertEqual([r.line() for r in cache.results],
                         [r.line() for r in source.results])
        self.assertEqual(cache.code, exits.SIGNATURE_UNVERIFIED)
        self.assertEqual(cache.count("invalid"), 0)

    def test_result_is_read_only(self):
        result = PullResult("core", OTHER, 1, STATUS_CACHED)
        with self.assertRaises(AttributeError):
            result.status = STATUS_FETCHED


class TestSourceProblems(PullTestCase):
    def test_a_layer_the_source_does_not_have_is_unavailable(self):
        error = self.failing("nonsense")
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(join(self.source, "nonsense.manifest"), str(error))

    def test_a_missing_parent_manifest_is_unavailable(self):
        os.remove(join(self.source, "core.manifest"))
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn("core.manifest", str(error))
        self.assertFalse(exists(self.cache))

    def test_a_missing_tarball_names_both_places_it_was_looked_for(self):
        os.remove(join(self.source, "core.tar.zst"))
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(f"core-{self.fields['core']['sha256']}.tar.zst",
                      str(error))
        self.assertIn("core.tar.zst:", str(error))

    def test_an_invalid_source_manifest_lists_its_errors(self):
        self.rewrite("core", size="big")
        error = self.failing()
        self.assertEqual(error.code, exits.MANIFEST_INVALID)
        self.assertIn("size: must be a non negative integer", str(error))

    def test_a_manifest_naming_another_layer_is_invalid(self):
        write_manifest(self.source, self.fields["core"], name="base")
        error = self.failing("base")
        self.assertEqual(error.code, exits.MANIFEST_INVALID)
        self.assertIn("manifest names 'core', asked for 'base'", str(error))

    def test_a_parent_that_moved_on_is_a_mismatch(self):
        self.rewrite("lamp", parent_sha256=OTHER)
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertIn(f"lamp: parent_sha256 {OTHER}, core manifest at the"
                      f" source says {self.fields['core']['sha256']}",
                      str(error))

    def test_a_loop_in_the_chain_is_a_mismatch(self):
        self.rewrite("core", type="delta", parent="lamp",
                     parent_sha256=self.fields["lamp"]["sha256"])
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertEqual(str(error), "core: parent chain loops through lamp")

    def test_a_tarball_with_another_digest_is_removed_and_a_mismatch(self):
        write(join(self.source, "lamp.tar.zst"),
              b"X" * int(self.fields["lamp"]["size"]))
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertIn("lamp: downloaded size", str(error))
        self.assertTrue(exists(self.cached("core")))
        self.assertFalse(exists(self.cached("lamp")))
        self.assertFalse(exists(self.cached("lamp") + ".part"))

    def test_a_tarball_larger_than_the_manifest_stops_early(self):
        data = open(join(self.source, "lamp.tar.zst"), "rb").read()
        write(join(self.source, "lamp.tar.zst"), data + b"\0" * 4096)
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_MISMATCH)
        self.assertFalse(exists(self.cached("lamp") + ".part"))

    def test_a_transfer_that_breaks_removes_the_part_and_is_unavailable(self):
        broken = mock.MagicMock()
        broken.__enter__.return_value.read.side_effect = OSError("reset")
        with mock.patch.object(pulling, "open_tarball", return_value=broken):
            error = self.failing("core")
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertEqual(str(error), "core: transfer failed: reset")
        self.assertFalse(exists(self.cached("core") + ".part"))

    def test_a_transfer_that_never_starts_is_unavailable(self):
        with mock.patch.object(pulling, "open_tarball",
                               side_effect=OSError("timed out")):
            error = self.failing("core")
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertEqual(str(error), "core: transfer failed: timed out")
        self.assertEqual(os.listdir(self.cache), [])

    def test_a_cache_that_cannot_be_created_is_unavailable(self):
        write(self.cache, "a file\n")
        error = self.failing()
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(f"cache {self.cache}", str(error))


class TestHttpSource(PullTestCase):
    def setUp(self):
        super().setUp()
        self.server = Server(self.source)

    def tearDown(self):
        self.server.close()
        super().tearDown()

    def test_pulls_over_ipv6_loopback(self):
        report = self.pull(source=self.server.url)
        self.assertEqual(report.count(STATUS_FETCHED), 2)
        self.assertEqual(sha256(open(self.cached("core"), "rb").read()),
                         self.fields["core"]["sha256"])

    def test_a_404_for_the_parent_is_unavailable(self):
        os.remove(join(self.source, "core.manifest"))
        error = self.failing(source=self.server.url)
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(f"{self.server.url}core.manifest: HTTP Error 404",
                      str(error))

    def test_a_refused_connection_is_unavailable(self):
        self.server.close()
        error = self.failing(source=self.server.url)
        self.assertEqual(error.code, exits.LAYER_UNAVAILABLE)
        self.assertIn("lamp.manifest", str(error))

    def test_pull_then_verify_round_trip_over_ipv6(self):
        self.write_hash_files(signed=True)
        report = self.pull(source=self.server.url)
        self.assertEqual(report.count(STATUS_FETCHED), 2)
        verified = verify_layers(self.cache)
        self.assertEqual([r.line() for r in verified.results], [
            ("core: unverified: signature present, not verified (no trusted"
             " key configured)"),
            ("lamp: unverified: signature present, not verified (no trusted"
             " key configured)"),
        ])
        self.assertEqual(verified.code, exits.SIGNATURE_UNVERIFIED)

    def test_a_trailing_slash_is_optional(self):
        report = self.pull(source=self.server.url.rstrip("/"))
        self.assertEqual(report.count(STATUS_FETCHED), 2)


class TestSource(unittest.TestCase):
    def test_a_directory_is_not_a_url(self):
        source = Source("/var/lib/layers")
        self.assertFalse(source.is_url)
        self.assertEqual(source.path("core.manifest"),
                         "/var/lib/layers/core.manifest")

    def test_an_ipv6_url_keeps_its_brackets_and_quotes_the_name(self):
        source = Source("https://[2001:db8::1]/layers/")
        self.assertTrue(source.is_url)
        self.assertEqual(source.path("core 1.manifest"),
                         "https://[2001:db8::1]/layers/core%201.manifest")

    def test_read_text_decodes_what_open_returns(self):
        source = Source("x")
        with mock.patch.object(Source, "open",
                               return_value=io.BytesIO(b"layer core\n")):
            self.assertEqual(source.read_text("core.manifest"),
                             "layer core\n")


if __name__ == "__main__":
    unittest.main()
