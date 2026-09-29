# Copyright (c) 2026 KeelLinux maintainers
"""keel spec apply --system with a monitor section, then keel diff

Under --root: the file is written, a second run changes nothing, diff
reads it back as the thresholds that were declared, and turning the
monitor off removes it. The tree carries its own mount table, so the
checks follow the filesystems it lists.
"""

import contextlib
import io
import os
import stat
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel import exits
from keel.cli import main

MONIT_CONF = join("etc", "monit", "conf.d", "keel.conf")
SPEC = """\
version: 1
security:
  alerts: admin@example.org
monitor:
  enabled: {enabled}
  checks:
    disk: {{warn: 75.0}}
    load_per_core: {{warn: 1.5, for_minutes: 3}}
    network:
      eth0: {{link: true, max_mbit: 800}}
  notify:
    email: true
    telegram:
      chat_id: "-1001234567890"
      token: {{file: /etc/keel/secrets/telegram_token}}
"""
MOUNTINFO = (
    "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
    "23 22 8:2 / /srv rw,relatime - xfs /dev/sda2 rw\n"
    "24 22 0:5 / /dev rw - devtmpfs udev rw\n"
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestApplyThenDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = join(self.tmp.name, "root")
        os.makedirs(join(self.root, "etc"))
        os.makedirs(join(self.root, "proc", "self"))
        for name in ("passwd", "group", "aliases"):
            open(join(self.root, "etc", name), "w").close()
        with open(join(self.root, "proc", "self", "mountinfo"), "w") as fob:
            fob.write(MOUNTINFO)
        self.spec = join(self.tmp.name, "instance.yaml")
        self.write_spec("true")

    def tearDown(self):
        self.tmp.cleanup()

    def write_spec(self, enabled: str) -> None:
        with open(self.spec, "w") as fob:
            fob.write(SPEC.format(enabled=enabled))

    def apply(self, *extra: str) -> tuple[int, str, str]:
        return run_cli("spec", "apply", "--system-only", "--spec", self.spec,
                       "--root", self.root, *extra)

    def diff(self) -> tuple[int, str, str]:
        return run_cli("diff", "--spec", self.spec, "--root", self.root)

    def test_apply_diff_off_and_diff_again(self):
        code, out, err = self.apply()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn(
            "monitor: write /etc/monit/conf.d/keel.conf: 2 filesystem(s)"
            " (/, /srv), memory, swap, cpu, load, eth0 (mode 0600): done",
            out)
        self.assertIn("monitor: monit not reloaded: not the live system", out)
        path = join(self.root, MONIT_CONF)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as fob:
            text = fob.read()
        self.assertIn("check filesystem keel_disk_warn_srv with path /srv",
                      text)
        self.assertIn("--spec /etc/keel/instance.yaml", text)
        self.assertNotIn("SECRET", text)

        code, out, _ = self.apply()
        self.assertEqual(code, exits.OK)
        self.assertIn("monitor: unchanged (/etc/monit/conf.d/keel.conf", out)
        self.assertIn("apply --system-only: 0 change(s), 0 failed", out)

        code, out, err = self.diff()
        self.assertEqual((code, err), (exits.OK, ""))
        for line in (
            "monitor.enabled: same (true)",
            "monitor.checks.disk.warn: same (75.0)",
            "monitor.checks.load_per_core.warn: same (1.5)",
            "monitor.checks.load_per_core.for_minutes: same (3)",
            "monitor.checks.network.eth0.link: same (true)",
            "monitor.checks.network.eth0.max_mbit: same (800)",
            "monitor.checks.disk.critical: not declared (observed 90)",
            "monitor.notify.telegram.token.file: not compared (the channels"
            " stay in the spec: keel notify reads them there when an alert"
            " fires, and monit's file only runs it)",
        ):
            self.assertIn(line, out.splitlines())

        self.write_spec("false")
        code, out, _ = self.apply()
        self.assertEqual(code, exits.OK)
        self.assertIn("monitor: remove /etc/monit/conf.d/keel.conf, which"
                      " keel wrote: the monitor is off in the spec: done", out)
        self.assertFalse(os.path.exists(path))
        code, out, _ = self.diff()
        self.assertEqual(code, exits.OK)
        self.assertIn("monitor.enabled: same (false)", out.splitlines())
        self.assertIn("monitor.checks.disk.warn: not compared (monitor is off"
                      " in the spec (enabled is false), so what it governs is"
                      " not compared; it takes effect when enabled becomes"
                      " true)", out.splitlines())

    def test_a_threshold_changed_behind_the_spec_is_drift(self):
        self.apply()
        path = join(self.root, MONIT_CONF)
        with open(path) as fob:
            text = fob.read()
        with open(path, "w") as fob:
            fob.write(text.replace("space usage > 75%", "space usage > 95%"))
        code, out, _ = self.diff()
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("monitor.checks.disk.warn: drift (declared 75.0,"
                      " observed 95)", out.splitlines())
        code, out, _ = self.apply()
        self.assertIn("monitor: write /etc/monit/conf.d/keel.conf", out)
        self.assertEqual(self.diff()[0], exits.OK)

    def test_dry_run_writes_nothing(self):
        code, out, _ = self.apply("--dry-run")
        self.assertEqual(code, exits.OK)
        self.assertIn("monitor: would write /etc/monit/conf.d/keel.conf", out)
        self.assertFalse(os.path.exists(join(self.root, MONIT_CONF)))

    def test_without_the_system_phase_apply_says_it_waits(self):
        conf = join(self.tmp.name, "inithooks.conf")
        with open(self.spec, "w") as fob:
            fob.write("version: 1\nsecurity:\n  alerts: admin@example.org\n"
                      "monitor:\n  enabled: true\n  notify: {email: true}\n")
        code, _, err = run_cli("spec", "apply", "--spec", self.spec,
                               "--conf", conf)
        self.assertEqual(code, exits.OK)
        self.assertIn("Warning: monitor: monit's configuration is written by"
                      " the system phase", err)


if __name__ == "__main__":
    unittest.main()
