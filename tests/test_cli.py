# Copyright (c) 2026 KeelLinux maintainers
"""CLI behaviour and exit codes

The CLI is exercised in process through keel.cli.main, and once as a
subprocess so that `python3 -m keel` is covered too.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from os.path import dirname, abspath, join
from unittest import mock

from helpers import spec  # noqa: F401

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


class TestSpecCommands(CLITestCase):
    def test_validate_of_a_good_spec_exits_ok(self):
        path = self.write_spec(VALID)
        code = self.run_cli("spec", "validate", "--spec", path)
        self.assertEqual(code, exits.OK)

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


class TestStubs(CLITestCase):
    def test_stubs_exit_not_implemented(self):
        for command in ("inspect", "diff", "verify"):
            self.assertEqual(self.run_cli(command), exits.NOT_IMPLEMENTED)

    def test_stub_names_the_brief_section(self):
        out = self.module_run("verify")
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

    def test_no_command_exits_usage(self):
        self.assertEqual(self.run_cli(), exits.USAGE)

    def test_every_exit_code_is_documented(self):
        codes = {
            value
            for name, value in vars(exits).items()
            if name.isupper() and isinstance(value, int)
        }
        self.assertEqual(codes, set(exits.DESCRIPTIONS))


if __name__ == "__main__":
    unittest.main()
