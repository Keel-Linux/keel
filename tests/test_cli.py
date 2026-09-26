# Copyright (c) 2026 KeelLinux maintainers
"""CLI behaviour and exit codes

The CLI is exercised in process through keel.cli.main, and once as a
subprocess so that `python3 -m keel` is covered too.
"""

import contextlib
import importlib
import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from os.path import dirname, abspath, join
from unittest import mock

from helpers import spec  # noqa: F401
from layers_helpers import (
    LAMP_VERSION,
    build_source,
    build_tree,
    hash_text,
    write,
    write_manifest,
)

from keel.layers import CACHE_ENV, LAYERS_ENV  # noqa: E402

import keel  # noqa: E402
from keel import commands, exits  # noqa: E402
from keel.cli import main  # noqa: E402

ROOT = dirname(dirname(abspath(__file__)))

VALID = (
    "version: 1\n"
    "instance:\n"
    "  hostname: blog\n"
    "  fqdn: blog.example.org\n"
    "network:\n"
    "  managed_by: host\n"
    "  interfaces:\n"
    "    eth0:\n"
    "      ipv6:\n"
    "        method: static\n"
    "        address: 2001:db8:1::10/64\n"
    "        gateway: fe80::1\n"
)


class CLITestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.conf = join(self.tmpdir, "inithooks.conf")

    def write_spec(self, text: str, name: str = "instance.yaml") -> str:
        path = join(self.tmpdir, name)
        with open(path, "w") as fob:
            fob.write(text)
        return path

    def run_cli(self, *argv: str) -> int:
        return main(list(argv))

    def run_cli_captured(self, *argv: str) -> tuple[int, str, str]:
        """Run the CLI in process and return (code, stdout, stderr)"""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()


class TestSpecCommands(CLITestCase):
    def test_validate_of_a_good_spec_exits_ok(self):
        path = self.write_spec(VALID)
        code, out, err = self.run_cli_captured("spec", "validate", "--spec",
                                               path)
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out, f"{path}: ok (secret files checked)\n")

    def test_validate_checks_the_secret_files_by_default(self):
        path = self.write_spec(
            VALID + "secrets:\n  root_password:\n"
            f"    file: {join(self.tmpdir, 'absent')}\n"
        )
        code, out, err = self.run_cli_captured("spec", "validate", "--spec",
                                               path)
        self.assertEqual((code, out), (exits.SPEC_INVALID, ""))
        self.assertIn("secrets.root_password: ", err)
        self.assertIn("secret file not found", err)

    def test_validate_no_secret_files_accepts_a_missing_file_and_says_so(self):
        path = self.write_spec(
            VALID + "secrets:\n  root_password:\n"
            f"    file: {join(self.tmpdir, 'absent')}\n"
        )
        code, out, err = self.run_cli_captured(
            "spec", "validate", "--spec", path, "--no-secret-files"
        )
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out, f"{path}: ok (secret files not checked)\n")

    def test_validate_no_secret_files_still_checks_the_structure(self):
        path = self.write_spec(
            VALID + "secrets:\n  root_password:\n    vault: kv/root\n"
        )
        code, out, err = self.run_cli_captured(
            "spec", "validate", "--spec", path, "--no-secret-files"
        )
        self.assertEqual((code, out), (exits.SPEC_INVALID, ""))
        self.assertIn("secrets.root_password.vault: unknown secret backend",
                      err)

    def test_no_secret_files_belongs_to_validate_only(self):
        path = self.write_spec(VALID)
        for action in ("render", "apply"):
            with self.subTest(action=action):
                with self.assertRaises(SystemExit) as raised:
                    self.run_cli_captured("spec", action, "--spec", path,
                                          "--no-secret-files")
                self.assertEqual(raised.exception.code, exits.USAGE)

    def test_spec_validate_called_without_the_flag_checks_the_files(self):
        """confconsole builds a Namespace by hand, as the README shows"""
        from argparse import Namespace
        path = self.write_spec(
            VALID + "secrets:\n  root_password:\n"
            f"    file: {join(self.tmpdir, 'absent')}\n"
        )
        args = Namespace(spec=path, conf=self.conf, non_interactive=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(commands.spec_validate(args), exits.SPEC_INVALID)

    def test_absent_spec_is_a_no_op_for_every_spec_command(self):
        path = join(self.tmpdir, "absent.yaml")
        for action in ("validate", "render", "apply"):
            code = self.run_cli(
                "spec", action, "--spec", path, "--conf", self.conf
            )
            self.assertEqual(code, exits.OK)
        self.assertFalse(os.path.exists(self.conf))

    def test_malformed_yaml_exits_spec_unreadable(self):
        path = self.write_spec("version: 1\ninstance: [unclosed\n")
        code = self.run_cli("spec", "validate", "--spec", path)
        self.assertEqual(code, exits.SPEC_UNREADABLE)

    def test_spec_that_cannot_be_opened_exits_spec_unreadable(self):
        code, _, err = self.run_cli_captured(
            "spec", "validate", "--spec", self.tmpdir
        )
        self.assertEqual(code, exits.SPEC_UNREADABLE)
        self.assertIn(self.tmpdir, err)

    def test_validate_reports_every_error_with_the_spec_path(self):
        path = self.write_spec("version: 2\nnonsense: true\n")
        code, _, err = self.run_cli_captured(
            "spec", "validate", "--spec", path
        )
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn(f"Error: {path}: version: must be 1", err)
        self.assertIn(f"Error: {path}: nonsense: unknown top level key", err)

    def test_render_prints_the_conf_with_secrets_masked(self):
        secret = join(self.tmpdir, "secret")
        with open(secret, "w") as fob:
            fob.write("s3cret\n")
        os.chmod(secret, 0o600)
        path = self.write_spec(
            VALID + f"secrets:\n  root_password:\n    file: {secret}\n"
        )

        code, out, _ = self.run_cli_captured("spec", "render", "--spec", path)

        self.assertEqual(code, exits.OK)
        self.assertIn("export HOSTNAME=blog\n", out)
        self.assertIn(f"export ROOT_PASS={spec.MASK}\n", out)
        self.assertNotIn("s3cret", out)
        self.assertFalse(os.path.exists(self.conf))

    def test_invalid_spec_exits_spec_invalid(self):
        path = self.write_spec("version: 1\nnonsense: true\n")
        code = self.run_cli("spec", "validate", "--spec", path)
        self.assertEqual(code, exits.SPEC_INVALID)

    def test_apply_writes_the_conf_0600(self):
        path = self.write_spec(VALID)
        code = self.run_cli(
            "spec", "apply", "--spec", path, "--conf", self.conf,
            "--non-interactive",
        )
        self.assertEqual(code, exits.OK)
        self.assertEqual(os.stat(self.conf).st_mode & 0o777, 0o600)
        with open(self.conf) as fob:
            self.assertIn("export HOSTNAME=blog", fob.read())

    def test_existing_non_empty_conf_wins(self):
        path = self.write_spec(VALID)
        with open(self.conf, "w") as fob:
            fob.write("export ROOT_PASS=preseeded\n")

        code = self.run_cli(
            "spec", "apply", "--spec", path, "--conf", self.conf
        )

        self.assertEqual(code, exits.OK)
        with open(self.conf) as fob:
            self.assertEqual(fob.read(), "export ROOT_PASS=preseeded\n")

    def test_apply_with_an_unwritable_conf_exits_conf_error(self):
        path = self.write_spec(VALID)
        conf = join(self.tmpdir, "absent-directory", "inithooks.conf")
        code = self.run_cli("spec", "apply", "--spec", path, "--conf", conf)
        self.assertEqual(code, exits.CONF_ERROR)

    def test_apply_with_a_missing_secret_file_exits_spec_invalid(self):
        path = self.write_spec(
            "version: 1\n"
            "secrets:\n"
            "  db_password:\n"
            f"    file: {join(self.tmpdir, 'absent')}\n"
        )
        code = self.run_cli("spec", "apply", "--spec", path, "--conf",
                            self.conf)
        self.assertEqual(code, exits.SPEC_INVALID)

    def test_secret_that_disappears_after_validation_exits_secret_error(self):
        path = self.write_spec(VALID)
        with mock.patch.object(
            commands.spec,
            "resolve_secrets",
            side_effect=spec.SpecError("gone: secret file not found"),
        ):
            code = self.run_cli(
                "spec", "apply", "--spec", path, "--conf", self.conf
            )
        self.assertEqual(code, exits.SECRET_ERROR)


class TestVerify(CLITestCase):
    def setUp(self):
        super().setUp()
        self.layers = join(self.tmpdir, "layers")
        self.fields = build_tree(self.layers)

    def verify(self, *argv: str) -> tuple[int, str, str]:
        return self.run_cli_captured(
            "verify", "--layers-dir", self.layers, "--non-interactive", *argv
        )

    def test_layers_that_pass_still_exit_not_implemented_for_packages(self):
        code, out, err = self.verify()
        self.assertEqual(code, exits.NOT_IMPLEMENTED)
        self.assertEqual(out.splitlines(), [
            "core: ok",
            "lamp: ok",
            "layers: 2 checked, 2 ok, 0 unverified, 0 mismatch, 0 invalid",
        ])
        self.assertIn("verify packages: not implemented yet", err)
        self.assertIn("BRIEF.md section 5.4", err)

    def test_invalid_manifest_exits_manifest_invalid(self):
        write_manifest(self.layers, {**self.fields["core"], "size": "big"})
        code, out, _ = self.verify()
        self.assertEqual(code, exits.MANIFEST_INVALID)
        self.assertIn("core: invalid: size: must be a non negative integer",
                      out)

    def test_missing_tarball_exits_layer_mismatch(self):
        os.remove(join(self.layers, "lamp.tar.zst"))
        code, out, _ = self.verify()
        self.assertEqual(code, exits.LAYER_MISMATCH)
        self.assertIn("lamp: mismatch: tarball lamp.tar.zst:", out)
        self.assertIn("1 mismatch", out)

    def test_signed_hash_file_exits_signature_unverified(self):
        write(join(self.layers, "lamp.tar.zst.hash"),
              hash_text("lamp", self.fields["lamp"]["sha256"], signed=True))
        code, out, _ = self.verify()
        self.assertEqual(code, exits.SIGNATURE_UNVERIFIED)
        self.assertIn("lamp: unverified: signature present, not verified"
                      " (no trusted key configured)", out)

    def test_tarballs_dir_points_at_the_tarballs(self):
        tarballs = join(self.tmpdir, "tarballs")
        os.mkdir(tarballs)
        for name in ("core", "lamp"):
            os.rename(join(self.layers, f"{name}.tar.zst"),
                      join(tarballs, f"{name}.tar.zst"))
        code, _, _ = self.verify("--tarballs-dir", tarballs)
        self.assertEqual(code, exits.NOT_IMPLEMENTED)

    def test_absent_layers_dir_says_so_and_checks_nothing(self):
        absent = join(self.tmpdir, "absent")
        code, out, err = self.run_cli_captured(
            "verify", "--layers-dir", absent
        )
        self.assertEqual(code, exits.NOT_IMPLEMENTED)
        self.assertIn(f"{absent}: no layer manifests found", err)
        self.assertIn("layers: 0 checked", out)

    def test_layers_dir_defaults_to_the_environment(self):
        os.remove(join(self.layers, "core.tar.zst"))
        with mock.patch.dict(os.environ, {LAYERS_ENV: self.layers}):
            code, _, _ = self.run_cli_captured("verify")
        self.assertEqual(code, exits.LAYER_MISMATCH)


class TestPullAndAssemble(CLITestCase):
    def setUp(self):
        super().setUp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.rootfs = join(self.tmpdir, "rootfs")
        self.fields = build_source(self.source)

    def pull(self, *argv: str) -> tuple[int, str, str]:
        return self.run_cli_captured(
            "pull", "lamp", "--source", self.source, "--cache-dir",
            self.cache, "--non-interactive", *argv,
        )

    def assemble(self, *argv: str) -> tuple[int, str, str]:
        return self.run_cli_captured(
            "assemble", "lamp", "--rootfs", self.rootfs, "--cache-dir",
            self.cache, "--non-interactive", *argv,
        )

    def test_pull_reports_every_layer_and_the_bytes_transferred(self):
        code, out, _ = self.pull()
        self.assertEqual(code, exits.OK)
        self.assertEqual(out.splitlines(), [
            f"core: fetched ({self.fields['core']['size']} bytes)",
            f"lamp: fetched ({self.fields['lamp']['size']} bytes)",
            "layers: 2 resolved, 2 fetched, 0 cached,"
            f" {int(self.fields['core']['size'])
                + int(self.fields['lamp']['size'])} bytes transferred",
        ])

    def test_pull_without_a_source_exits_usage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as raised:
                self.run_cli("pull", "lamp")
        self.assertEqual(raised.exception.code, exits.USAGE)
        self.assertIn("--source", err.getvalue())

    def test_pull_failure_prints_the_reason_and_exits_with_its_code(self):
        os.remove(join(self.source, "core.tar.zst"))
        code, _, err = self.pull()
        self.assertEqual(code, exits.LAYER_UNAVAILABLE)
        self.assertIn("Error: ", err)
        self.assertIn("core.tar.zst", err)

    def test_cache_dir_defaults_to_the_environment(self):
        with mock.patch.dict(os.environ, {CACHE_ENV: self.cache}):
            code, _, _ = self.run_cli_captured(
                "pull", "core", "--source", self.source
            )
        self.assertEqual(code, exits.OK)
        self.assertTrue(os.path.exists(
            join(self.cache, f"core-{self.fields['core']['sha256']}.tar.zst")
        ))

    def test_assemble_as_a_user_exits_assemble_needs_root(self):
        self.pull()
        with mock.patch("os.geteuid", return_value=1000):
            code, _, err = self.assemble()
        self.assertEqual(code, exits.ASSEMBLE_NEEDS_ROOT)
        self.assertIn("Error: assemble must run as root", err)

    def test_assemble_as_root_extracts_and_packs(self):
        self.pull()
        template = join(self.tmpdir, "lamp.tar.zst")
        with mock.patch("os.geteuid", return_value=0):
            code, out, _ = self.assemble("--template", template)
        self.assertEqual(code, exits.OK)
        with open(join(self.rootfs, "etc", "turnkey_version"), "rb") as fob:
            self.assertEqual(fob.read(), LAMP_VERSION)
        self.assertTrue(os.path.exists(template + ".sha512"))
        lines = out.splitlines()
        self.assertEqual(lines[0], "core: extracted (1 members, 0 whiteouts,"
                         " 0 opaque directories)")
        self.assertEqual(lines[2], f"rootfs: {self.rootfs}")
        self.assertTrue(lines[3].startswith(f"template: {template} ("))

    def test_assemble_of_a_layer_not_pulled_exits_layer_unavailable(self):
        with mock.patch("os.geteuid", return_value=0):
            code, _, err = self.assemble()
        self.assertEqual(code, exits.LAYER_UNAVAILABLE)
        self.assertIn("run keel pull first", err)

    def test_assemble_reports_an_os_error_as_assemble_failed(self):
        with mock.patch.object(commands.layers, "assemble",
                               side_effect=OSError("zstd: not found")):
            code, _, err = self.assemble()
        self.assertEqual(code, exits.ASSEMBLE_FAILED)
        self.assertEqual(err, "Error: assemble: zstd: not found\n")

    def test_assemble_without_a_rootfs_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli("assemble", "lamp")
        self.assertEqual(raised.exception.code, exits.USAGE)


class TestStubs(CLITestCase):
    """The packages half of verify is the one stub left"""

    def test_stubs_exit_not_implemented(self):
        code = self.run_cli("verify", "--layers-dir", self.tmpdir)
        self.assertEqual(code, exits.NOT_IMPLEMENTED)

    def test_stub_names_the_brief_section(self):
        out = self.module_run("verify", "--layers-dir", self.tmpdir)
        self.assertEqual(out.returncode, exits.NOT_IMPLEMENTED)
        self.assertIn("not implemented yet", out.stderr.decode())
        self.assertIn("BRIEF.md section", out.stderr.decode())

    def module_run(self, *argv: str):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = ROOT
        return subprocess.run(
            [sys.executable, "-m", "keel", *argv],
            capture_output=True,
            env=environment,
        )


class TestUsage(CLITestCase):
    def test_unknown_command_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli("nonsense")
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_unknown_option_prints_usage_and_exits_usage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as raised:
                self.run_cli("spec", "validate", "--nonsense")
        self.assertEqual(raised.exception.code, exits.USAGE)
        self.assertIn("usage:", err.getvalue())
        self.assertIn("Error:", err.getvalue())

    def test_no_command_exits_usage(self):
        self.assertEqual(self.run_cli(), exits.USAGE)

    def test_spec_without_action_exits_usage(self):
        self.assertEqual(self.run_cli("spec"), exits.USAGE)

    def test_version_prints_the_package_version_and_exits_ok(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as raised:
                self.run_cli("--version")
        self.assertEqual(raised.exception.code, exits.OK)
        self.assertEqual(out.getvalue().strip(), keel.__version__)

    def test_spec_and_conf_paths_default_to_the_environment(self):
        path = self.write_spec(VALID)
        environment = {spec.SPEC_ENV: path, spec.CONF_ENV: self.conf}
        with mock.patch.dict(os.environ, environment):
            code = self.run_cli("spec", "apply")
        self.assertEqual(code, exits.OK)
        self.assertTrue(os.path.exists(self.conf))

    def test_every_exit_code_is_documented(self):
        codes = {
            value
            for name, value in vars(exits).items()
            if name.isupper() and isinstance(value, int)
        }
        self.assertEqual(codes, set(exits.DESCRIPTIONS))


class TestEntryPoints(CLITestCase):
    """The module and the script entry points hand the exit code to sys"""

    def run_as_main(self, run, *argv: str) -> int:
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["keel", *argv]):
            with contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit) as raised:
                    run()
        return raised.exception.code

    def test_importing_the_module_entry_point_does_not_run_the_cli(self):
        with mock.patch.object(sys, "argv", ["keel", "verify"]):
            importlib.import_module("keel.__main__")
        sys.modules.pop("keel.__main__", None)

    def test_python_dash_m_keel_exits_with_the_command_code(self):
        code = self.run_as_main(
            lambda: runpy.run_module("keel", run_name="__main__"),
            "verify", "--layers-dir", self.tmpdir,
        )
        self.assertEqual(code, exits.NOT_IMPLEMENTED)

    def test_cli_module_run_as_a_script_exits_with_the_command_code(self):
        script = join(ROOT, "keel", "cli.py")
        code = self.run_as_main(
            lambda: runpy.run_path(script, run_name="__main__"),
            "verify", "--layers-dir", self.tmpdir,
        )
        self.assertEqual(code, exits.NOT_IMPLEMENTED)


if __name__ == "__main__":
    unittest.main()
