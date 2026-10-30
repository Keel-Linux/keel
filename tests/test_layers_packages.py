"""keel verify, the packages half (brief section 5.4, keel#239)"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from os.path import join
from unittest import mock

from layers_helpers import build_tree, sha256, write, write_manifest

from keel import exits
from keel.cli import main
from keel.layers import packages

CORE_LIST = "adduser 3.152 all\napt 3.0.3 amd64\nbash 5.2.37-2 amd64\n"
LAMP_LIST = ("adduser 3.152 all\napt 3.0.3 amd64\nbash 5.2.37-3 amd64\n"
             "nginx 1.26.3-3 amd64\n")


def status(*entries: tuple[str, str, str]) -> str:
    """A dpkg status file with each (name, version, arch) installed"""
    return "".join(
        f"Package: {name}\nStatus: install ok installed\nVersion: {version}\n"
        f"Architecture: {arch}\nMaintainer: x\nDescription: x\n\n"
        for name, version, arch in entries)


INSTALLED = (("adduser", "3.152", "all"), ("apt", "3.0.3", "amd64"),
             ("bash", "5.2.37-3", "amd64"), ("nginx", "1.26.3-3", "amd64"))


class PackagesCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.layers = join(self.tmpdir, "layers")
        self.fields = build_tree(self.layers)
        self.put_list("core", CORE_LIST)
        self.put_list("lamp", LAMP_LIST)
        self.root = join(self.tmpdir, "root")
        self.installed(*INSTALLED)

    def put_list(self, name: str, text: str, **overrides: str) -> None:
        write(join(self.layers, f"{name}.packages"), text)
        fields = {**self.fields[name],
                  "packages": str(len(text.splitlines())),
                  "packages_sha256": sha256(text.encode()), **overrides}
        self.fields[name] = fields
        write_manifest(self.layers, fields)

    def installed(self, *entries) -> None:
        admin = join(self.root, "var", "lib", "dpkg")
        os.makedirs(join(admin, "info"), exist_ok=True)
        os.makedirs(join(admin, "updates"), exist_ok=True)
        write(join(admin, "status"), status(*entries))

    def verify(self, *argv: str) -> tuple[int, list[str], str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["verify", "--layers-dir", self.layers,
                         "--non-interactive", *argv])
        return code, out.getvalue().splitlines(), err.getvalue()


class TheLists(PackagesCase):
    def test_lists_that_match_and_no_root_exit_ok(self):
        code, out, _ = self.verify()
        self.assertEqual(code, exits.OK)
        self.assertEqual(out[-3:], [
            "packages core: ok: 3 listed",
            "packages lamp: ok: 4 listed",
            "installed packages: not checked (no --root)"])

    def test_a_changed_list_is_a_mismatch(self):
        write(join(self.layers, "lamp.packages"), LAMP_LIST + "vim 9 amd64\n")
        code, out, _ = self.verify()
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        line = [text for text in out if text.startswith("packages lamp")][0]
        self.assertIn("packages lamp: mismatch: sha256 ", line)
        self.assertIn("5 lines, manifest says 4", line)

    def test_a_missing_list_is_a_mismatch(self):
        os.remove(join(self.layers, "core.packages"))
        code, out, _ = self.verify()
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertIn("packages core: mismatch: core.packages: No such file"
                      " or directory", out)

    def test_a_manifest_with_no_list_is_not_declared(self):
        write_manifest(self.layers, {
            key: value for key, value in self.fields["core"].items()
            if not key.startswith("packages")})
        code, out, _ = self.verify()
        self.assertEqual(code, exits.OK)
        self.assertIn("packages core: not declared", out)

    def test_a_layer_problem_stops_before_the_lists(self):
        os.remove(join(self.layers, "lamp.tar.zst"))
        code, out, _ = self.verify()
        self.assertEqual(code, exits.LAYER_MISMATCH)
        self.assertFalse(any(text.startswith("packages ") for text in out))


class TheRoot(PackagesCase):
    def test_a_root_that_matches_its_chain(self):
        code, out, _ = self.verify("--root", self.root, "--layer", "lamp")
        self.assertEqual(code, exits.OK)
        self.assertEqual(out[-1], f"installed packages under {self.root},"
                         " against lamp: 4 declared, 4 installed, 0 differ")

    def test_the_higher_layer_replaces_the_lower_entry(self):
        # core lists bash 5.2.37-2, lamp 5.2.37-3: the root has -3.
        code, out, _ = self.verify("--root", self.root, "--layer", "lamp")
        self.assertEqual(code, exits.OK)
        self.assertFalse(any("differs bash" in text for text in out))

    def test_each_difference_has_its_line(self):
        self.installed(("adduser", "3.152", "all"), ("apt", "3.0.4", "amd64"),
                       ("bash", "5.2.37-3", "amd64"), ("vim", "9", "amd64"))
        code, out, _ = self.verify("--root", self.root, "--layer", "lamp")
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertIn("differs apt: installed 3.0.4 amd64, declared 3.0.3"
                      " amd64", out)
        self.assertIn("missing nginx 1.26.3-3 amd64", out)
        self.assertIn("not declared vim 9 amd64", out)
        self.assertEqual(out[-1], f"installed packages under {self.root},"
                         " against lamp: 4 declared, 4 installed, 3 differ")

    def test_an_unknown_layer_is_refused(self):
        code, out, _ = self.verify("--root", self.root, "--layer", "shop")
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertIn("installed packages: shop has no complete chain in the"
                      " layers directory", out)

    def test_a_chain_whose_parent_is_missing_is_refused(self):
        found = packages.chain_of({}, "lamp")
        self.assertIsNone(found)
        lamp = packages.verify_packages_dir(self.layers).lists
        self.assertEqual([result.status for result in lamp], ["ok", "ok"])
        with mock.patch.object(packages, "find_manifests",
                               return_value=[join(self.layers,
                                                  "lamp.manifest")]):
            report = packages.verify_packages_dir(self.layers, self.root,
                                                  "lamp")
        self.assertEqual(report.code, exits.PACKAGES_MISMATCH)

    def test_an_unusable_list_in_the_chain_stops_the_comparison(self):
        write(join(self.layers, "core.packages"), "changed 1 all\n")
        code, out, _ = self.verify("--root", self.root, "--layer", "lamp")
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertIn("installed packages: not checked, the list of core"
                      " cannot be used", out)

    def test_a_root_dpkg_cannot_read(self):
        empty = join(self.tmpdir, "empty")
        os.mkdir(empty)
        code, out, _ = self.verify("--root", empty, "--layer", "lamp")
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertTrue(any(text.startswith(f"installed packages under"
                                            f" {empty}: cannot be read: ")
                            for text in out))

    def test_dpkg_query_that_fails_is_reported(self):
        failed = mock.Mock(returncode=2, stderr="", stdout="")
        with mock.patch.object(packages.subprocess, "run",
                               return_value=failed):
            code, out, _ = self.verify("--root", self.root, "--layer", "lamp")
        self.assertEqual(code, exits.PACKAGES_MISMATCH)
        self.assertIn(f"installed packages under {self.root}: cannot be"
                      " read: dpkg-query exited 2", out)

    def test_a_line_that_is_not_name_version_arch_is_skipped(self):
        self.assertEqual(packages.parse("a 1 all\n\nbroken line\n"),
                         {"a": ("1", "all")})

    def test_root_and_layer_go_together(self):
        code, _, err = self.verify("--root", self.root)
        self.assertEqual(code, exits.USAGE)
        self.assertIn("--root and --layer go together", err)

    def test_an_unreadable_layers_dir_has_no_lists(self):
        with mock.patch.object(packages, "find_manifests",
                               side_effect=OSError("denied")):
            report = packages.verify_packages_dir(self.layers)
        self.assertEqual(report.lists, ())
        self.assertEqual(report.code, exits.OK)


if __name__ == "__main__":
    unittest.main()
