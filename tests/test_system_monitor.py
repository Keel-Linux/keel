# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: the monitor section (decision 0021)

The planner is a pure function of the spec and a MonitorState, so every
branch is checked with hand built states; the state reader and the one
new effect, removing keel's files, against a temporary root.
"""

import json
import os
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.monitor import Cycle
from keel.inspect.tree import File
from keel.monitor import channelfile
from keel.system import observe, plan
from keel.system.actions import Note, Refuse, RemoveFile, Run, WriteFile
from keel.system.effects import Effects
from keel.system.monitor import MONIT_CONF, SETTINGS, plan_monitor
from keel.system.monstate import MonitorState, observe_monitor

ON = {"enabled": True, "notify": {"webhook": {
    "url": "https://hooks.example.org/keel"}}}
DOC = {"version": 1, "instance": {"hostname": "blog"}, "monitor": ON}
LIVE = frozenset(("monit", "systemctl"))
CYCLE = Cycle(120, "set daemon 120 in /r/etc/monit/monitrc")
MOUNTINFO = (
    "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
    "23 22 8:2 / /srv rw,relatime - xfs /dev/sda2 rw\n"
    "24 22 0:5 / /run rw - tmpfs tmpfs rw\n"
    "25 22 8:3 / /my\\040files rw - ext4 /dev/sda3 rw\n"
)
KEEL_FILE = "# written by keel spec apply --system\ncheck system x\n"
ABSENT = File("/r/etc/monit/conf.d/keel.conf", problem="not present")
NO_SETTINGS = File("/r/etc/keel/monitor.json", problem="not present")


def state(current: File = ABSENT, mountinfo: str | None = MOUNTINFO,
          settings: File = NO_SETTINGS, problems=()) -> MonitorState:
    table = (File("/r/proc/self/mountinfo", mountinfo) if mountinfo
             is not None else File("/r/proc/self/mountinfo",
                                   problem="not present"))
    return MonitorState(current, table, CYCLE, settings, tuple(problems))


def actions(monitor=ON, doc=None, live=False, available=frozenset(),
            **kwargs):
    doc = doc if doc is not None else dict(DOC, monitor=monitor)
    steps = plan_monitor(monitor, doc, state(**kwargs), live, available)
    return [action for step in steps for action in step.actions]


def writes(found) -> dict[str, WriteFile]:
    return {a.path: a for a in found if isinstance(a, WriteFile)}


class TestEnabled(unittest.TestCase):
    def test_no_state_is_no_step(self):
        self.assertEqual(plan_monitor(ON, DOC, None, True, LIVE), [])

    def test_under_a_root_both_files_are_written_and_nothing_reloaded(self):
        found = actions()
        conf = writes(found)[MONIT_CONF]
        self.assertEqual(conf.mode, 0o600)
        self.assertIsNone(conf.owner)
        self.assertIn("with path /srv\n", conf.content)
        self.assertNotIn("/run", conf.content)
        self.assertNotIn("hooks.example.org", conf.content)
        self.assertEqual(
            conf.describe(),
            "write /etc/monit/conf.d/keel.conf: 2 filesystem(s) (/, /srv),"
            " memory, swap, cpu, load; monit's cycle is 120 s (set daemon"
            " 120 in /r/etc/monit/monitrc) (mode 0600)")
        settings = writes(found)[SETTINGS]
        self.assertEqual(settings.mode, 0o600)
        self.assertEqual(json.loads(settings.content)["webhook"],
                         {"url": "https://hooks.example.org/keel"})
        self.assertNotIn("hooks.example.org", settings.describe())
        notes = [a.describe() for a in found if isinstance(a, Note)]
        self.assertEqual(notes, [
            "/my files not watched: monit cannot take its name as a path",
            "monit not reloaded: not the live system",
        ])

    def test_on_the_live_system_monit_checks_then_reloads(self):
        found = actions(live=True, available=LIVE)
        runs = [a.argv for a in found if isinstance(a, Run)]
        self.assertEqual(runs, [
            ("monit", "-t"),
            ("systemctl", "try-reload-or-restart", "monit.service"),
        ])

    def test_live_without_monit_is_refused_and_nothing_installed(self):
        found = actions(live=True, available=frozenset(("systemctl",)))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("apt install monit", found[0].describe())

    def test_live_without_systemctl_writes_and_says_why(self):
        found = actions(live=True, available=frozenset(("monit",)))
        self.assertIsInstance(found[-2], WriteFile)
        self.assertEqual(found[-1].describe(),
                         "monit not reloaded: systemctl not found")

    def test_the_same_files_are_unchanged_and_not_reloaded(self):
        first = writes(actions())
        found = actions(
            current=File("/r/x", first[MONIT_CONF].content),
            settings=File("/r/y", first[SETTINGS].content),
            live=True, available=LIVE)
        self.assertFalse([a for a in found if not isinstance(a, Note)])
        self.assertTrue(found[-1].describe().startswith(
            "unchanged (/etc/monit/conf.d/keel.conf, 2 filesystem(s)"))

    def test_new_channels_rewrite_the_settings_and_do_not_reload(self):
        first = writes(actions())
        other = {"enabled": True, "notify": {"ntfy": {
            "url": "https://ntfy.example.org/keel"}}}
        found = actions(other, current=File("/r/x", first[MONIT_CONF].content),
                        settings=File("/r/y", first[SETTINGS].content),
                        live=True, available=LIVE)
        self.assertEqual(list(writes(found)), [SETTINGS])
        self.assertFalse([a for a in found if isinstance(a, Run)])

    def test_the_network_is_in_the_summary(self):
        monitor = dict(ON, checks={"network": {"eth0": {"link": True}}})
        conf = writes(actions(monitor))[MONIT_CONF]
        self.assertIn("load, eth0; monit's cycle", conf.describe())

    def test_a_keel_conf_keel_did_not_write_is_never_overwritten(self):
        found = actions(current=File("/r/x", "check system mine\n"))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("keel did not write it", found[0].describe())

    def test_a_duration_monit_cannot_hold_at_the_cycle_is_refused(self):
        monitor = dict(ON, checks={"cpu": {"for_minutes": 180}})
        found = actions(monitor)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].describe(), (
            "monitor.checks.cpu.for_minutes: 180 minutes is 90 cycles of"
            " 120 s, and monit holds a condition for at most 64 (set daemon"
            " 120 in /r/etc/monit/monitrc); shorten the duration, or the"
            " cycle"))

    def test_an_unusable_secret_file_is_a_note_not_a_failure(self):
        found = actions(problems=["/etc/keel/secrets/t: secret file not"
                                  " found"])
        self.assertIn("/etc/keel/secrets/t: secret file not found: that"
                      " channel fails until it is fixed",
                      [a.describe() for a in found])
        self.assertIn(MONIT_CONF, writes(found))

    def test_no_mount_table_watches_the_root_and_says_so(self):
        found = actions(mountinfo=None)
        self.assertIn("no mount table at /r/proc/self/mountinfo (not"
                      " present): watching / only", found[0].describe())
        self.assertIn("1 filesystem(s) (/)",
                      writes(found)[MONIT_CONF].describe())

    def test_a_table_without_a_real_filesystem_watches_the_root(self):
        found = actions(mountinfo="1 0 0:1 / / rw - overlay o rw\n")
        self.assertIn("lists no filesystem that holds data",
                      found[0].describe())


class TestOff(unittest.TestCase):
    SETTINGS = File("/r/y", channelfile.render(DOC))

    def test_disabled_removes_both_files_keel_wrote(self):
        found = actions({"enabled": False}, current=File("/r/x", KEEL_FILE),
                        settings=self.SETTINGS, live=True, available=LIVE)
        self.assertEqual([a.path for a in found
                          if isinstance(a, RemoveFile)],
                         [SETTINGS, MONIT_CONF])
        self.assertIn("the monitor is off", found[1].describe())
        self.assertEqual([a.argv[0] for a in found[2:]],
                         ["monit", "systemctl"])

    def test_absent_removes_the_files_keel_wrote_too(self):
        found = actions(None, current=File("/r/x", KEEL_FILE))
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[1].describe(),
                         "monit not reloaded: not the live system")
        found = actions(None, settings=self.SETTINGS)
        self.assertEqual([a.path for a in found], [SETTINGS])

    def test_files_keel_did_not_write_are_left_alone(self):
        other = File("/r/x", "check system mine\n")
        foreign = File("/r/y", '{"host": "x"}')
        self.assertEqual(actions(None, current=other, settings=foreign), [])
        found = actions({"enabled": False}, current=other)
        self.assertEqual([a.describe() for a in found], ["unchanged (off)"])

    def test_off_without_monit_on_the_live_system_still_removes(self):
        found = actions({"enabled": False}, current=File("/r/x", KEEL_FILE),
                        live=True, available=frozenset(("systemctl",)))
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[1].describe(),
                         "monit not reloaded: monit not found")


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative: str, text: str, mode: int = 0o644) -> None:
        path = join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)
        os.chmod(path, mode)

    def test_nothing_declared_and_no_file_is_no_state(self):
        self.assertIsNone(observe_monitor(self.root, {}))

    def test_files_left_behind_are_observed_without_a_section(self):
        self.write(MONIT_CONF, KEEL_FILE)
        self.write("proc/self/mountinfo", MOUNTINFO)
        found = observe_monitor(self.root, {})
        self.assertEqual(found.current.text, KEEL_FILE)
        self.assertEqual(found.mountinfo.text, MOUNTINFO)
        self.write(SETTINGS, "{}")
        os.remove(join(self.root, MONIT_CONF))
        self.assertIsNotNone(observe_monitor(self.root, {}))

    def test_the_secret_files_are_checked_under_the_root(self):
        doc = {"version": 1, "monitor": {"enabled": True, "notify": {
            "telegram": {"chat_id": 1, "token": {"file": "/etc/keel/t"}},
            "webhook": {"url": {"file": "/etc/keel/w"}}}}}
        self.write("etc/keel/w", "https://hooks.example.org/x\n", 0o600)
        found = observe_monitor(self.root, doc)
        self.assertEqual(len(found.secret_problems), 1)
        self.assertIn("etc/keel/t: secret file not found",
                      found.secret_problems[0])
        self.write("etc/monit/monitrc", "set daemon 30\n")
        self.assertEqual(observe_monitor(self.root, doc).cycle.seconds, 30)

    def test_the_whole_plan_writes_no_spec_path(self):
        steps = plan(DOC, observe(self.root, DOC)).steps
        monitor = [s for s in steps if s.field == "monitor"][0]
        conf = writes(monitor.actions)[MONIT_CONF]
        self.assertNotIn("--spec", conf.content)
        self.assertIn("keel notify --level", conf.content)

    def test_remove_file_is_an_effect(self):
        self.write(MONIT_CONF, KEEL_FILE)
        effects = Effects(self.root)
        action = RemoveFile(MONIT_CONF, "remove it")
        self.assertIsNone(effects.apply(action))
        self.assertFalse(os.path.exists(join(self.root, MONIT_CONF)))
        self.assertIn("No such file", effects.apply(action))


if __name__ == "__main__":
    unittest.main()
