# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: the monitor section (decision 0021)

The planner is a pure function of the spec and a MonitorState, so every
branch is checked with hand built states; the state reader and the one
new effect, removing keel's file, against a temporary root.
"""

import os
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.tree import File
from keel.system import observe, plan
from keel.system.actions import Note, Refuse, RemoveFile, Run, WriteFile
from keel.system.effects import Effects
from keel.system.monitor import (
    MONIT_CONF,
    notify_argv,
    plan_monitor,
)
from keel.system.monstate import MonitorState, observe_monitor

ON = {"enabled": True, "notify": {"webhook": {
    "url": "https://hooks.example.org/keel"}}}
LIVE = frozenset(("monit", "systemctl"))
SPEC = "/etc/keel/instance.yaml"
MOUNTINFO = (
    "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
    "23 22 8:2 / /srv rw,relatime - xfs /dev/sda2 rw\n"
    "24 22 0:5 / /run rw - tmpfs tmpfs rw\n"
    "25 22 8:3 / /my\\040files rw - ext4 /dev/sda3 rw\n"
)
KEEL_FILE = "# written by keel spec apply --system\nset daemon 60\n"
ABSENT = File("/r/etc/monit/conf.d/keel.conf", problem="not present")


def state(current: File = ABSENT, mountinfo: str | None = MOUNTINFO) -> (
    MonitorState
):
    table = (File("/r/proc/self/mountinfo", mountinfo) if mountinfo
             is not None else File("/r/proc/self/mountinfo",
                                   problem="not present"))
    return MonitorState(current, table)


def actions(monitor, current=ABSENT, live=False, available=frozenset(),
            spec_path=SPEC, mountinfo=MOUNTINFO):
    steps = plan_monitor(monitor, state(current, mountinfo), live,
                         available, spec_path)
    return [action for step in steps for action in step.actions]


class TestEnabled(unittest.TestCase):
    def test_no_state_is_no_step(self):
        self.assertEqual(plan_monitor(ON, None, True, LIVE, SPEC), [])

    def test_under_a_root_the_file_is_written_and_nothing_reloaded(self):
        found = actions(ON)
        notes = [a.describe() for a in found if isinstance(a, Note)]
        write = [a for a in found if isinstance(a, WriteFile)][0]
        self.assertEqual(write.path, MONIT_CONF)
        self.assertEqual(write.mode, 0o600)
        self.assertIsNone(write.owner)
        self.assertIn("with path /srv\n", write.content)
        self.assertNotIn("/run", write.content)
        self.assertEqual(
            write.describe(),
            "write /etc/monit/conf.d/keel.conf: 2 filesystem(s) (/, /srv),"
            " memory, swap, cpu, load (mode 0600)")
        self.assertEqual(notes, [
            "/my files not watched: monit's exec line cannot carry its name",
            "monit not reloaded: not the live system",
        ])

    def test_on_the_live_system_monit_checks_then_reloads(self):
        found = actions(ON, live=True, available=LIVE)
        runs = [a.argv for a in found if isinstance(a, Run)]
        self.assertEqual(runs, [
            ("monit", "-t"),
            ("systemctl", "try-reload-or-restart", "monit.service"),
        ])

    def test_live_without_monit_is_refused_and_nothing_installed(self):
        found = actions(ON, live=True, available=frozenset(("systemctl",)))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("apt install monit", found[0].describe())

    def test_live_without_systemctl_writes_and_says_why(self):
        found = actions(ON, live=True, available=frozenset(("monit",)))
        self.assertIsInstance(found[-2], WriteFile)
        self.assertEqual(found[-1].describe(),
                         "monit not reloaded: systemctl not found")

    def test_the_same_file_is_unchanged_and_not_reloaded(self):
        content = [a for a in actions(ON)
                   if isinstance(a, WriteFile)][0].content
        found = actions(ON, current=File("/r/x", content), live=True,
                        available=LIVE)
        self.assertFalse([a for a in found if not isinstance(a, Note)])
        self.assertTrue(found[-1].describe().startswith(
            "unchanged (/etc/monit/conf.d/keel.conf, 2 filesystem(s)"))

    def test_the_network_is_in_the_summary(self):
        monitor = dict(ON, checks={"network": {"eth0": {"link": True}}})
        write = [a for a in actions(monitor) if isinstance(a, WriteFile)][0]
        self.assertIn("load, eth0 (mode", write.describe())

    def test_a_spec_path_monit_cannot_carry_is_refused(self):
        found = actions(ON, spec_path="/root/my spec.yaml")
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("/root/my spec.yaml", found[0].describe())

    def test_the_exec_line_names_the_spec_that_was_applied(self):
        write = [a for a in actions(ON, spec_path="/srv/spec/blog.yaml")
                 if isinstance(a, WriteFile)][0]
        self.assertIn('exec "/usr/bin/python3 -B -m keel notify --spec'
                      ' /srv/spec/blog.yaml --level', write.content)
        self.assertEqual(notify_argv("/s")[:5],
                         ("/usr/bin/python3", "-B", "-m", "keel", "notify"))

    def test_no_mount_table_watches_the_root_and_says_so(self):
        found = actions(ON, mountinfo=None)
        self.assertIn("no mount table at /r/proc/self/mountinfo (not"
                      " present): watching / only", found[0].describe())
        write = [a for a in found if isinstance(a, WriteFile)][0]
        self.assertIn("1 filesystem(s) (/)", write.describe())

    def test_a_table_without_a_real_filesystem_watches_the_root(self):
        found = actions(ON, mountinfo="1 0 0:1 / / rw - overlay o rw\n")
        self.assertIn("lists no filesystem that holds data",
                      found[0].describe())


class TestOff(unittest.TestCase):
    def test_disabled_removes_the_file_keel_wrote(self):
        found = actions({"enabled": False}, current=File("/r/x", KEEL_FILE),
                        live=True, available=LIVE)
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[0].path, MONIT_CONF)
        self.assertIn("the monitor is off", found[0].describe())
        self.assertEqual([a.argv[0] for a in found[1:]],
                         ["monit", "systemctl"])

    def test_absent_removes_the_file_keel_wrote_too(self):
        found = actions(None, current=File("/r/x", KEEL_FILE))
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[1].describe(),
                         "monit not reloaded: not the live system")

    def test_a_file_keel_did_not_write_is_left_alone(self):
        other = File("/r/x", "check system mine\n")
        self.assertEqual(actions(None, current=other), [])
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

    def write(self, relative: str, text: str) -> None:
        path = join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)

    def test_nothing_declared_and_no_file_is_no_state(self):
        self.assertIsNone(observe_monitor(self.root, {}))

    def test_a_file_left_behind_is_observed_without_a_section(self):
        self.write(MONIT_CONF, KEEL_FILE)
        self.write("proc/self/mountinfo", MOUNTINFO)
        found = observe_monitor(self.root, {})
        self.assertEqual(found.current.text, KEEL_FILE)
        self.assertEqual(found.mountinfo.text, MOUNTINFO)

    def test_the_whole_plan_renders_the_default_spec_under_a_root(self):
        doc = {"version": 1, "monitor": ON}
        steps = plan(doc, observe(self.root, doc),
                     spec_path="/home/admin/blog.yaml").steps
        write = [a for a in steps[0].actions if isinstance(a, WriteFile)][0]
        self.assertIn("--spec /etc/keel/instance.yaml ", write.content)

    def test_remove_file_is_an_effect(self):
        self.write(MONIT_CONF, KEEL_FILE)
        effects = Effects(self.root)
        action = RemoveFile(MONIT_CONF, "remove it")
        self.assertIsNone(effects.apply(action))
        self.assertFalse(os.path.exists(join(self.root, MONIT_CONF)))
        self.assertIn("No such file", effects.apply(action))


if __name__ == "__main__":
    unittest.main()
