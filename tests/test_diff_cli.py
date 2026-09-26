# Copyright (c) 2026 KeelLinux maintainers
"""keel diff end to end: the spec side, the exit codes, JSON, the round trip

The round trip is the property that ties inspect and diff together: a
spec written by `keel inspect` from a fixture tree, diffed against the
same tree, reports no drift and exits 0, for every fixture.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from os.path import abspath, dirname, join

from helpers import spec

from keel import exits
from keel.cli import main

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "inspect")
TURNKEY = join(FIXTURES, "turnkey")
DHCP = join(FIXTURES, "dhcp")
MISSING = join(FIXTURES, "missing")

MATCHING = (
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
    "security:\n"
    "  alerts: admin@example.org\n"
    "  updates: force\n"
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class DiffTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def write_spec(self, text: str, name: str = "instance.yaml") -> str:
        path = join(self.tmpdir, name)
        with open(path, "w") as fob:
            fob.write(text)
        return path


class TestDiffCommand(DiffTestCase):
    def test_a_matching_spec_exits_ok_with_one_line_per_field(self):
        path = self.write_spec(MATCHING)
        code, out, err = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual((code, err), (exits.OK, ""))
        lines = out.splitlines()
        self.assertEqual(lines[0], "instance.hostname: same (blog)")
        self.assertIn("network.interfaces.eth0.ipv4.method: not declared"
                      " (observed dhcp)", lines)
        self.assertEqual(
            lines[-1],
            "diff: 8 same, 0 drift, 0 unknown, 14 not declared,"
            " 0 not compared; no drift",
        )

    def test_drift_exits_drift_found(self):
        path = self.write_spec(MATCHING.replace("hostname: blog",
                                                "hostname: shop"))
        code, out, _ = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("instance.hostname: drift (declared shop, observed"
                      " blog)\n", out)
        self.assertTrue(out.endswith("; drift found\n"))

    def test_unobservable_declared_fields_exit_incomplete(self):
        path = self.write_spec(MATCHING.replace("  updates: force\n", ""))
        code, out, _ = run_cli("diff", "--spec", path, "--root", MISSING)
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertIn("instance.hostname: unknown (declared blog; not"
                      " inferred: ", out)
        self.assertIn("network.managed_by: unknown (declared host;", out)
        self.assertNotIn(": drift (", out)
        self.assertTrue(out.endswith(
            "; no drift, but declared fields could not be observed\n"))

    def test_drift_takes_precedence_over_unknown_fields(self):
        path = self.write_spec(MATCHING)
        code, out, _ = run_cli("diff", "--spec", path, "--root", MISSING)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("security.updates: drift (declared force, observed"
                      " skip)", out)
        self.assertIn(": unknown (", out)

    def test_json_format_carries_everything_a_caller_needs(self):
        path = self.write_spec(MATCHING)
        code, out, err = run_cli("diff", "--spec", path, "--root", TURNKEY,
                                 "--format", "json", "--non-interactive")
        self.assertEqual((code, err), (exits.OK, ""))
        document = json.loads(out)
        self.assertEqual(document["spec"], path)
        self.assertEqual(document["root"], TURNKEY)
        self.assertEqual(document["exit_code"], exits.OK)
        self.assertEqual(document["counts"]["same"], 8)
        first = document["fields"][0]
        self.assertEqual(first, {
            "field": "instance.hostname", "section": "instance",
            "status": "same", "declared": "blog", "observed": "blog",
            "reason": "",
        })

    def test_secrets_are_never_compared(self):
        path = self.write_spec(
            MATCHING + "secrets:\n  root_password:\n    generate: true\n"
            "first_login_wizard: true\n"
        )
        code, out, _ = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual(code, exits.OK)
        self.assertIn("secrets: not compared (values are never read, on"
                      " either side)\n", out)
        self.assertIn("first_login_wizard: not compared (", out)

    def test_absent_spec_is_a_no_op(self):
        path = join(self.tmpdir, "absent.yaml")
        code, out, err = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual((code, out), (exits.OK, ""))
        self.assertEqual(err, f"{path}: not found, nothing to do\n")

    def test_invalid_spec_exits_spec_invalid_before_inspecting(self):
        path = self.write_spec("version: 2\n")
        code, out, err = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual((code, out), (exits.SPEC_INVALID, ""))
        self.assertIn("version: must be 1", err)

    def test_unreadable_spec_exits_spec_unreadable(self):
        path = self.write_spec("- not a mapping\n")
        code, _, err = run_cli("diff", "--spec", path, "--root", TURNKEY)
        self.assertEqual(code, exits.SPEC_UNREADABLE)
        self.assertIn("top level must be a mapping", err)

    def test_unknown_format_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            run_cli("diff", "--format", "yaml")
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_diff_writes_nothing_under_the_root(self):
        path = self.write_spec(MATCHING)
        before = sorted(
            (join(base, name), os.stat(join(base, name)).st_mtime_ns)
            for base, _, names in os.walk(TURNKEY) for name in names
        )
        run_cli("diff", "--spec", path, "--root", TURNKEY)
        after = sorted(
            (join(base, name), os.stat(join(base, name)).st_mtime_ns)
            for base, _, names in os.walk(TURNKEY) for name in names
        )
        self.assertEqual(before, after)


class TestRoundTrip(DiffTestCase):
    """inspect a tree into a spec, then diff that spec against the tree"""

    def setUp(self):
        super().setUp()
        self.secrets = join(self.tmpdir, "secrets")
        os.mkdir(self.secrets)
        for name in spec.SECRET_VARS:
            path = join(self.secrets, name)
            with open(path, "w") as fob:
                fob.write("provided-by-the-operator\n")
            os.chmod(path, 0o600)

    def test_every_fixture_diffs_clean_against_itself(self):
        for root in (TURNKEY, DHCP, MISSING):
            with self.subTest(root=os.path.basename(root)):
                output = join(self.tmpdir, f"{os.path.basename(root)}.yaml")
                run_cli("inspect", "--root", root, "--output", output,
                        "--secrets-dir", self.secrets)
                code, out, err = run_cli("diff", "--spec", output, "--root",
                                         root, "--format", "json")
                self.assertEqual(err, "")
                document = json.loads(out)
                self.assertEqual(document["counts"]["drift"], 0)
                self.assertEqual(document["counts"]["unknown"], 0)
                self.assertEqual(document["counts"]["not_declared"], 0)
                self.assertEqual(code, exits.OK)

    def test_one_edited_field_is_the_only_drift(self):
        output = join(self.tmpdir, "instance.yaml")
        run_cli("inspect", "--root", TURNKEY, "--output", output,
                "--secrets-dir", self.secrets)
        with open(output) as fob:
            text = fob.read()
        with open(output, "w") as fob:
            fob.write(text.replace("hostname: blog", "hostname: shop"))
        code, out, _ = run_cli("diff", "--spec", output, "--root", TURNKEY)
        self.assertEqual(code, exits.DRIFT_FOUND)
        drifted = [line for line in out.splitlines() if ": drift (" in line]
        self.assertEqual(drifted, [
            "instance.hostname: drift (declared shop, observed blog)"
        ])


if __name__ == "__main__":
    unittest.main()
