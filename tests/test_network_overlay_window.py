# Copyright (c) 2026 KeelLinux maintainers
"""The overlay under the window of decision 0018 (decision 0020)

The same marker, lock and timers as the uplink, with wg-quick in place of
ifupdown: down on the outgoing file under /etc/wireguard, the new file in
place with mode 0600, up on it; a change that created the file reverts
by removing it. Every command goes through a recording runner.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401
from test_network_window import Recorder

from keel.network import confirm as netconfirm
from keel.network import live, marker, session, switch
from keel.network.confirm import Probes

CONF = "etc/wireguard/wg0.conf"
OLD = "[Interface]\nAddress = fd00:1::1/64\n"
NEW = "[Interface]\nAddress = fd00:1::9/64\n"
STOP = ("systemctl", "stop", "keel-network-window.timer",
        "keel-network-window-safety.timer")
ENABLE = ("systemctl", "enable", "wg-quick@wg0")


def pending(**overrides):
    values = dict(iface="wg0", path=CONF, window=120,
                  addresses=("fd00:1::9",), kind=marker.OVERLAY)
    values.update(overrides)
    return marker.Pending(**values)


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(join(self.root, "etc", "wireguard"))
        for name, value in (("boot_id", "b1"), ("process_clock", 50.0)):
            patcher = mock.patch.object(marker, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, text):
        with open(join(self.root, CONF), "w") as fob:
            fob.write(text)

    def current(self):
        try:
            with open(join(self.root, CONF)) as fob:
                return fob.read()
        except FileNotFoundError:
            return None

    def mode(self):
        return stat.S_IMODE(os.stat(join(self.root, CONF)).st_mode)

    def wg_calls(self, run):
        return [argv for argv in run.calls if argv[0] == "wg-quick"]


class TestChange(RootCase):
    def test_a_first_overlay_is_created_under_the_window(self):
        run = Recorder()
        self.assertIsNone(switch.change(self.root, pending(), NEW, run))
        self.assertEqual(self.current(), NEW)
        self.assertEqual(self.mode(), 0o600)
        names = run.names()
        self.assertLess(names.index("systemd-run"), names.index("wg-quick"))
        self.assertEqual(self.wg_calls(run), [
            ("wg-quick", "down", "wg0"), ("wg-quick", "up", "wg0")])
        found = marker.read(self.root)
        self.assertEqual((found.kind, found.absent, found.changed_at,
                          found.boot_id, found.autoconf),
                         ("overlay", True, 50.0, "b1", None))
        self.assertEqual(marker.saved(self.root), "")

    def test_a_changed_overlay_keeps_the_old_file_for_the_revert(self):
        self.write(OLD)
        switch.change(self.root, pending(), NEW, Recorder())
        found = marker.read(self.root)
        self.assertFalse(found.absent)
        self.assertEqual(marker.saved(self.root), OLD)

    def test_the_process_clock_dates_an_overlay_change(self):
        with mock.patch.object(marker, "uptime", return_value=None):
            self.assertIsNone(switch.change(self.root, pending(), NEW,
                                            Recorder()))
        self.assertEqual(marker.read(self.root).changed_at, 50.0)

    def test_no_clock_changes_nothing(self):
        marker.process_clock.return_value = None
        problem = switch.change(self.root, pending(), NEW, Recorder())
        self.assertIn("nothing changed", problem)
        self.assertIsNone(self.current())

    def test_a_first_overlay_that_does_not_come_up_is_removed(self):
        run = Recorder(fail={"wg-quick": 2})  # down, then the up
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("reverted to the previous file", problem)
        self.assertIsNone(self.current())
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(self.wg_calls(run)[-1], ("wg-quick", "down", "wg0"))

    def test_a_changed_overlay_that_does_not_come_up_goes_back(self):
        self.write(OLD)
        run = Recorder(fail={"wg-quick": 2})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("reverted", problem)
        self.assertEqual(self.current(), OLD)
        self.assertEqual(self.wg_calls(run)[-1], ("wg-quick", "up", "wg0"))

    def test_a_file_that_cannot_be_staged_touches_nothing(self):
        with mock.patch.object(switch, "stage", return_value=(
                None, "cannot write /etc/wireguard/wg0.conf: full")):
            problem = switch.change(self.root, pending(), NEW, Recorder())
        self.assertIn("nothing changed", problem)
        self.assertFalse(marker.exists(self.root))

    def test_a_rename_that_fails_brings_the_old_file_up_again(self):
        self.write(OLD)
        run = Recorder()
        with mock.patch.object(switch.os, "replace",
                               side_effect=OSError(28, "No space")):
            written, problem = switch.bounce_overlay(self.root, "wg0", CONF,
                                                     NEW, run)
        self.assertFalse(written)
        self.assertIn("No space", problem)
        self.assertEqual(self.wg_calls(run)[-1], ("wg-quick", "up", "wg0"))

    def test_a_rename_that_fails_with_no_old_file_leaves_it_down(self):
        run = Recorder()
        with mock.patch.object(switch.os, "replace",
                               side_effect=OSError(28, "No space")):
            written, _ = switch.bounce_overlay(self.root, "wg0", CONF, NEW,
                                               run)
        self.assertFalse(written)
        self.assertEqual(self.wg_calls(run), [("wg-quick", "down", "wg0")])

    def test_a_file_that_cannot_be_staged_in_the_bounce(self):
        with mock.patch.object(switch, "stage", return_value=(
                None, "full")):
            self.assertEqual(switch.bounce_overlay(
                self.root, "wg0", CONF, NEW, Recorder()), (False, "full"))

    def test_remove(self):
        self.assertIsNone(switch.remove(self.root, CONF))
        with mock.patch.object(switch.os, "remove",
                               side_effect=OSError(30, "Read-only")):
            self.assertIn("cannot remove", switch.remove(self.root, CONF))


class TestRevert(RootCase):
    def prepared(self, absent, saved=""):
        marker.save(self.root, saved)
        marker.write(self.root, pending(absent=absent).up("b1", 50.0))
        self.write(NEW)

    def test_a_first_overlay_reverts_to_none(self):
        self.prepared(absent=True)
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertTrue(worked)
        self.assertIn("removed /etc/wireguard/wg0.conf, which the change had"
                      " created; wg0 is down", line)
        self.assertIsNone(self.current())
        self.assertEqual(self.wg_calls(run), [("wg-quick", "down", "wg0")])
        self.assertIn(STOP, run.calls)

    def test_a_changed_overlay_reverts_to_the_saved_file(self):
        self.prepared(absent=False, saved=OLD)
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertTrue(worked)
        self.assertEqual(line, "restored /etc/wireguard/wg0.conf and wg0 is"
                         " up on it")
        self.assertEqual(self.current(), OLD)
        self.assertEqual(self.mode(), 0o600)

    def test_wg_quick_up_failing_on_the_restored_file_is_said(self):
        self.prepared(absent=False, saved=OLD)
        worked, line = switch.revert(self.root,
                                     Recorder(fail={"wg-quick": 2}))
        self.assertFalse(worked)
        self.assertIn("restored /etc/wireguard/wg0.conf, but wg-quick", line)

    def test_a_revert_that_cannot_remove_keeps_the_marker(self):
        self.prepared(absent=True)
        with mock.patch.object(switch.os, "remove",
                               side_effect=OSError(30, "Read-only")):
            worked, line = switch.revert(self.root, Recorder())
        self.assertFalse(worked)
        self.assertIn("cannot remove", line)
        self.assertTrue(marker.exists(self.root))

    def test_the_boot_revert_removes_or_restores_the_file(self):
        self.prepared(absent=True)
        worked, line = switch.revert(self.root, Recorder(), boot=True)
        self.assertTrue(worked)
        self.assertIn("removed", line)
        self.assertIn("before networking starts", line)
        self.assertIsNone(self.current())
        self.prepared(absent=False, saved=OLD)
        run = Recorder()
        switch.revert(self.root, run, boot=True)
        self.assertEqual(self.current(), OLD)
        self.assertEqual(self.mode(), 0o600)
        self.assertEqual(run.calls, [])

    def test_a_boot_restore_that_cannot_stage_is_a_failure(self):
        self.prepared(absent=False, saved=OLD)
        with mock.patch.object(switch, "stage",
                               return_value=(None, "read-only")):
            worked, line = switch.revert(self.root, Recorder(), boot=True)
        self.assertFalse(worked)
        self.assertIn("read-only", line)


class TestMarkerKind(RootCase):
    def test_a_marker_from_before_the_overlay_is_an_uplink_change(self):
        marker.write(self.root, pending())
        with open(join(self.root, marker.PENDING)) as fob:
            data = json.load(fob)
        del data["kind"], data["absent"]
        with open(join(self.root, marker.PENDING), "w") as fob:
            json.dump(data, fob)
        found = marker.read(self.root)
        self.assertEqual((found.kind, found.absent), ("uplink", False))

    def test_an_unknown_kind_is_unreadable(self):
        marker.write(self.root, pending(kind="vxlan"))
        self.assertIsNone(marker.read(self.root))


class TestClock(unittest.TestCase):
    def test_the_process_clock_is_a_session_clock(self):
        now = marker.process_clock()
        started = session.process("/proc", os.getpid()).started
        self.assertGreaterEqual(now, started)
        self.assertLess(now - started, 3600)

    def test_an_unreadable_thread(self):
        self.assertIsNone(marker.thread_started("/nonexistent", 1))
        with mock.patch.object(marker, "thread_started", return_value=None):
            self.assertIsNone(marker.process_clock())

    def test_the_clock_of_each_kind(self):
        with mock.patch.object(marker, "uptime", return_value=1.0), \
                mock.patch.object(marker, "process_clock", return_value=2.0):
            self.assertEqual(marker.clock(marker.UPLINK), 1.0)
            self.assertEqual(marker.clock(marker.OVERLAY), 2.0)


HOLDERS = {"2001:db8:1::20": "eth0", "fd00:1::9": "wg0", "fd00:1::7": "wg0",
           "2001:db8:1::21": "eth0"}


def probes(boot="b1"):
    return Probes(boot_id=lambda: boot, addresses=lambda iface: [],
                  route_via=lambda peer: None, holder=HOLDERS.get)


def ssh(local, peer="2001:db8:9::5", started=60.0):
    return session.Origin(session.SSH, "an SSH session", started, local,
                          peer)


class TestConfirm(RootCase):
    def setUp(self):
        super().setUp()
        marker.save(self.root, "")
        marker.write(self.root, pending(absent=True).up("b1", 50.0))

    def confirm(self, origin, run=None):
        run = run or Recorder()
        return netconfirm.confirm(self.root, origin, probes(), run), run

    def test_a_session_over_the_overlay_confirms_and_enables_the_unit(self):
        (confirmed, lines), run = self.confirm(ssh("fd00:1::9",
                                                   "fd00:1::2"))
        self.assertTrue(confirmed)
        self.assertIn("the overlay was tested", lines[1])
        self.assertIn("wg-quick@wg0 enabled", lines[2])
        self.assertEqual(run.calls, [STOP, ENABLE])
        self.assertFalse(marker.exists(self.root))

    def test_a_session_over_the_uplink_confirms_and_says_so(self):
        (confirmed, lines), _ = self.confirm(ssh("2001:db8:1::20"))
        self.assertTrue(confirmed)
        self.assertIn("the overlay itself was not tested", lines[1])
        self.assertIn("on eth0", lines[1])
        self.assertIn("fd00:1::9", lines[1])

    def test_a_console_confirms(self):
        origin = session.Origin(session.CONSOLE_KIND, "the console /dev/tty1")
        (confirmed, lines), _ = self.confirm(origin)
        self.assertTrue(confirmed)
        self.assertIn("wg-quick@wg0 enabled", lines[1])

    def test_a_unit_that_cannot_be_enabled_is_said(self):
        (confirmed, lines), _ = self.confirm(
            ssh("fd00:1::9"), Recorder(fail={"systemctl": 2}))
        self.assertTrue(confirmed)
        self.assertIn("does not come back after a reboot", lines[2])

    def test_refusals(self):
        for origin, words in (
            (ssh("fd00:1::9", started=40.0), "open before the change"),
            (ssh("fd00:1::7"), "neither an address the overlay declares"),
            (ssh("2001:db8:5::1"), "neither an address"),
            (ssh("fd00:1::9", peer="2001:db8:1::21"), "the machine itself"),
            (ssh("fd00:1::9", peer="::1"), "the machine itself"),
            (session.Origin(session.SSH, "an SSH session whose socket was"
                            " not found", 60.0), "socket was not found"),
            (session.Origin(session.UNKNOWN, "neither an SSH session"),
             "refused: neither"),
        ):
            with self.subTest(origin=origin):
                (confirmed, lines), run = self.confirm(origin)
                self.assertFalse(confirmed)
                self.assertIn(words, lines[0])
                self.assertTrue(marker.exists(self.root))
                self.assertEqual(run.calls, [])

    def test_the_overlay_lines_of_a_console(self):
        origin = session.Origin(session.CONSOLE_KIND, "the console")
        self.assertEqual(netconfirm.overlay_lines(pending(), origin,
                                                  probes()), [])


class TestHolder(unittest.TestCase):
    TEXT = (
        "1: lo    inet6 ::1/128 scope host \\       valid_lft forever\n"
        "2: eth0    inet6 2001:db8:1::20/64 scope global \\  valid_lft\n"
        "5: wg0    inet6 fd00:1::9/64 scope global \\       valid_lft\n"
        "6: veth1@if2    inet 10.66.0.1/24 scope global veth1\n"
        "7: odd    inet6 not-an-address scope global\n"
        "8: short\n"
    )

    def test_which_interface_holds_an_address(self):
        self.assertEqual(live.holder_in(self.TEXT, "fd00:1::9"), "wg0")
        self.assertEqual(live.holder_in(self.TEXT, "2001:DB8:1::20"), "eth0")
        self.assertEqual(live.holder_in(self.TEXT, "10.66.0.1"), "veth1")
        self.assertIsNone(live.holder_in(self.TEXT, "2001:db8:5::1"))

    def test_the_live_probe_asks_ip(self):
        with mock.patch.object(live, "output", return_value=self.TEXT) as out:
            self.assertEqual(live.holder("fd00:1::9"), "wg0")
        out.assert_called_once_with(("ip", "-o", "address", "show"))
        with mock.patch.object(live, "output", return_value=None):
            self.assertIsNone(live.holder("fd00:1::9"))
        self.assertIs(live.probes().holder, live.holder)
