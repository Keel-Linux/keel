# Copyright (c) 2026 KeelLinux maintainers
"""A first boot that refuses its spec leaves a signal (keel#268)

The boot continues by design (firstboot.d/10keel-system). Before keel#268
nothing remained of the refusal but a log line: a system that said running,
no failed unit, no drift, and a site at 503. Now the refusal stays in a
state file, keel diff, keel spec validate and keel database status show it,
it fires once on the alert path, and a later apply that succeeds clears it.
"""

import argparse
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import exits
from keel.cli import main
from keel.system import bootrefusal

REASON = ("Error: /etc/keel/instance.yaml: database.server.replication"
          ".primary: required when the role is replica\n")
VALID = "version: 1\n"
INVALID = "version: 1\ndatabase:\n  server:\n    engine: mariadb\n" \
          "    role: replica\n"


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = join(tmp.name, "root")
        os.makedirs(self.root)
        self.spec = join(tmp.name, "instance.yaml")
        self.conf = join(tmp.name, "inithooks.conf")
        self.settings = join(tmp.name, "absent-monitor.json")
        self.write(VALID)
        patcher = mock.patch("keel.commands.notifier.last_resort",
                             return_value=["syslog"])
        self.last_resort = patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, text: str) -> None:
        with open(self.spec, "w") as fob:
            fob.write(text)

    def cli(self, *argv: str, stdin: str = "") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(stdin)):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def refuse(self) -> tuple[int, str, str]:
        return self.cli("spec", "record-refusal", "--spec", self.spec,
                        "--root", self.root, "--settings", self.settings,
                        stdin=REASON)


class TestRecord(Case):
    def test_the_refusal_stays_in_a_file_that_only_root_reads(self):
        code, _, err = self.refuse()
        self.assertEqual(code, exits.OK, err)
        found = bootrefusal.read(self.root)
        self.assertIn("required when the role is replica", found.reason)
        self.assertEqual(found.spec, self.spec)
        mode = os.stat(join(self.root, bootrefusal.RECORD)).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_a_long_reason_is_cut(self):
        self.cli("spec", "record-refusal", "--spec", self.spec, "--root",
                 self.root, "--settings", self.settings,
                 stdin="x" * (bootrefusal.REASON_LIMIT * 2))
        self.assertLessEqual(len(bootrefusal.read(self.root).reason),
                             bootrefusal.REASON_LIMIT)

    def test_a_damaged_record_still_counts_as_a_refusal(self):
        path = join(self.root, bootrefusal.RECORD)
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fob:
            fob.write("not json")
        self.assertIn("cannot be read", bootrefusal.read(self.root).reason)

    def test_no_record_is_none(self):
        self.assertIsNone(bootrefusal.read(self.root))


class TestAlert(Case):
    def test_it_fires_on_the_alert_path(self):
        self.refuse()
        self.assertEqual(self.last_resort.call_count, 1)
        message = self.last_resort.call_args.args[0]
        self.assertIn("[critical]", message.title)
        self.assertIn("required when the role is replica", message.text)
        self.assertIn("keel spec apply --system-only", message.text)

    def test_it_fires_once(self):
        self.refuse()
        self.refuse()
        self.assertEqual(self.last_resort.call_count, 1)

    def test_it_uses_the_declared_channels(self):
        with mock.patch("keel.commands.channelfile.load",
                        return_value={"host": "blog"}), \
                mock.patch("keel.commands.notifier.send") as send:
            send.return_value = [mock.Mock(problem=None, line=lambda: "ok")]
            self.refuse()
        self.assertEqual(send.call_count, 1)
        self.assertEqual(self.last_resort.call_count, 0)

    def test_an_alert_that_fails_does_not_fail_the_record(self):
        self.last_resort.return_value = []
        code, _, err = self.refuse()
        self.assertEqual(code, exits.OK, err)
        self.assertIsNotNone(bootrefusal.read(self.root))

    def test_it_fires_again_after_a_clear(self):
        self.refuse()
        bootrefusal.clear(self.root)
        self.refuse()
        self.assertEqual(self.last_resort.call_count, 2)


class TestShown(Case):
    def test_keel_diff_reports_drift(self):
        self.refuse()
        code, out, _ = self.cli("diff", "--spec", self.spec,
                                "--root", self.root)
        self.assertEqual(code, exits.DRIFT_FOUND, out)
        self.assertIn(f"{bootrefusal.FIELD}: drift", out)
        self.assertIn("required when the role is replica", out)

    def test_keel_diff_has_no_such_line_with_no_refusal(self):
        _, out, _ = self.cli("diff", "--spec", self.spec, "--root", self.root)
        self.assertNotIn(bootrefusal.FIELD, out)

    def test_keel_diff_says_it_when_the_spec_is_still_invalid(self):
        self.refuse()
        self.write(INVALID)
        code, _, err = self.cli("diff", "--spec", self.spec,
                                "--root", self.root)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("first boot refused", err)

    def test_keel_spec_validate_warns_and_keeps_its_exit(self):
        self.refuse()
        code, _, err = self.cli("spec", "validate", "--spec", self.spec,
                                "--no-secret-files", "--root", self.root)
        self.assertEqual(code, exits.OK)
        self.assertIn("first boot refused", err)

    def test_keel_database_status_shows_it(self):
        from keel.system import dbstatus
        self.refuse()
        said = []
        args = argparse.Namespace(root=self.root, spec=self.spec)
        dbstatus.main(args, said.append)
        self.assertIn("first boot refused", "\n".join(said))


class TestClear(Case):
    def apply(self, *flags: str) -> tuple[int, str, str]:
        return self.cli("spec", "apply", "--spec", self.spec, "--conf",
                        self.conf, "--root", self.root, *flags)

    def test_a_system_apply_that_succeeds_clears_it(self):
        self.refuse()
        code, out, err = self.apply("--system-only")
        self.assertEqual(code, exits.OK, out + err)
        self.assertIsNone(bootrefusal.read(self.root))
        code, _, _ = self.cli("diff", "--spec", self.spec,
                              "--root", self.root)
        self.assertEqual(code, exits.OK)

    def test_an_apply_that_refuses_keeps_it(self):
        self.refuse()
        self.write(INVALID)
        code, _, _ = self.apply("--system-only")
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIsNotNone(bootrefusal.read(self.root))

    def test_an_apply_that_fails_keeps_it(self):
        self.refuse()
        with mock.patch("keel.commands.apply_system",
                        return_value=exits.APPLY_FAILED):
            self.apply("--system-only")
        self.assertIsNotNone(bootrefusal.read(self.root))

    def test_a_dry_run_keeps_it(self):
        self.refuse()
        self.apply("--system-only", "--dry-run")
        self.assertIsNotNone(bootrefusal.read(self.root))

    def test_the_conf_phase_alone_keeps_it(self):
        self.refuse()
        self.apply()
        self.assertIsNotNone(bootrefusal.read(self.root))


class TestRecordFormat(Case):
    def test_the_file_is_json(self):
        self.refuse()
        with open(join(self.root, bootrefusal.RECORD)) as fob:
            self.assertEqual(json.load(fob)["spec"], self.spec)


if __name__ == "__main__":
    unittest.main()
