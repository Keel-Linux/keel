# Copyright (c) 2026 KeelLinux maintainers
"""keel database follow, watch and status wired to their flows, and one
alert through the monitor's channels (decisions 0031, 0049)"""

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from keel import cli, exits
from keel.monitor import alerting, channelfile
from keel.monitor import notify as notifier


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestTheCommands(unittest.TestCase):
    def setUp(self):
        self.root = self.enterContext(tempfile.TemporaryDirectory())
        self.spec = os.path.join(self.root, "instance.yaml")
        with open(self.spec, "w") as fob:
            fob.write("version: 1\n")

    def test_follow_and_watch_need_root_on_the_live_system(self):
        for action in ("follow", "watch"):
            with self.subTest(action=action), \
                    mock.patch("os.geteuid", return_value=1000):
                code, _, err = run_cli("database", action, "--spec",
                                       self.spec)
                self.assertEqual(code, exits.APPLY_NEEDS_ROOT, err)
                self.assertIn(f"database {action}", err)

    def test_follow_reaches_its_flow_and_reports_a_refusal(self):
        from keel.system import dbfollow

        def refusing(root, spec, confirmed, found):
            found.fail(f"no pair ({confirmed})")
        with mock.patch.object(dbfollow, "follow", side_effect=refusing):
            code, out, _ = run_cli("database", "follow", "--spec", self.spec,
                                   "--root", self.root,
                                   "--destroy-local-database")
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("database.server.role: refused: no pair (True)", out)

        def fine(root, spec, confirmed, found):
            found.say("unchanged (the primary, writable)")
        with mock.patch.object(dbfollow, "follow", side_effect=fine):
            code, out, _ = run_cli("database", "follow", "--spec", self.spec,
                                   "--root", self.root)
        self.assertEqual(code, exits.OK, out)

    def test_watch_and_status_reach_their_flows(self):
        from keel.system import dbstatus, dbwatch
        with mock.patch.object(dbwatch, "watch", return_value=exits.OK) as w:
            code, _, _ = run_cli("database", "watch", "--spec", self.spec,
                                 "--root", self.root)
        self.assertEqual(code, exits.OK)
        self.assertEqual(w.call_args.args[:2], (self.root, self.spec))
        with mock.patch.object(dbstatus, "lines",
                               return_value=["pair: none"]):
            code, out, _ = run_cli("database", "status", "--spec", self.spec,
                                   "--root", self.root)
        self.assertEqual((code, out.strip()), (exits.OK, "pair: none"))


class TestAlerting(unittest.TestCase):
    def test_an_alert_goes_to_every_channel_and_says_so(self):
        root = self.enterContext(tempfile.TemporaryDirectory())
        path = os.path.join(root, channelfile.PATH.lstrip("/"))
        os.makedirs(os.path.dirname(path))
        with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(channelfile.render({
                "instance": {"hostname": "db1"},
                "monitor": {"enabled": True, "notify": {
                    "webhook": {"url": "https://hooks.example.org/k"}}}}))
        said: list[str] = []
        with mock.patch.object(notifier, "send", return_value=[
                notifier.Delivery("webhook")]) as sent:
            self.assertTrue(alerting.alert(root, said.append, "the title",
                                           "the text", "database-semi-sync"))
        message = sent.call_args.args[1]
        self.assertEqual(message.title, "[db1] the title")
        self.assertEqual(message.fields, {"check": "database-semi-sync"})
        self.assertEqual(sent.call_args.args[2], "critical")
        self.assertEqual(said, ["database-semi-sync: alert webhook: sent"])
        with mock.patch.object(notifier, "send", return_value=[
                notifier.Delivery("webhook", "timed out")]):
            self.assertFalse(alerting.alert(root, said.append, "t", "x",
                                            "c", "recovery"))

    def test_no_settings_means_no_alert_and_the_reason_said(self):
        root = self.enterContext(tempfile.TemporaryDirectory())
        said: list[str] = []
        self.assertFalse(alerting.alert(root, said.append, "t", "x",
                                        "database-rejoin"))
        self.assertIn("no alert sent", said[0])


if __name__ == "__main__":
    unittest.main()
