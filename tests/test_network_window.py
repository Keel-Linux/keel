# Copyright (c) 2026 KeelLinux maintainers
"""The change, its revert and its confirmation (decision 0018)

Every command goes through a recording runner, so the order is checked
without touching a network: down on the old file, flush, link down, the
new file written, up on it, with the revert armed before any of it.
"""

import json
import os
import shutil
import signal
import tempfile
import threading
import time
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.network import confirm as netconfirm
from keel.network import marker, session, switch
from keel.network.confirm import Probes

OLD = "iface eth0 inet6 static\n    address 2001:db8:1::10/64\n"
NEW = "iface eth0 inet6 static\n    address 2001:db8:1::20/64\n"
INTERFACES = "etc/network/interfaces"
READ_AUTOCONF = marker.autoconf
STOP = ("systemctl", "stop", "keel-network-window.timer",
        "keel-network-window-safety.timer")


class Recorder:
    """A runner that records argv and fails the commands it is told to"""

    def __init__(self, fail=(), root=None):
        self.calls = []
        self.fail = dict(fail)
        self.root = root

    def __call__(self, argv):
        self.calls.append(argv)
        key = argv[0] if argv[0] != "ip" else " ".join(argv[:3])
        if key in self.fail:
            self.fail[key] -= 1
            if self.fail[key] >= 0:
                return f"{argv[0]} failed"
        return None

    def names(self):
        return [a[0] if a[0] != "ip" else " ".join(a[:3]) for a in self.calls]


def pending(**overrides):
    values = dict(iface="eth0", path=INTERFACES, window=120,
                  addresses=("2001:db8:1::20",), gateways=("fe80::2",),
                  old_gateways=("fe80::1",))
    values.update(overrides)
    return marker.Pending(**values)


class RootCase(unittest.TestCase):
    # the interface's IPv6 autoconf setting as /proc would give it; None
    # is an interface without IPv6 settings, so no sysctl is issued
    AUTOCONF = None

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(join(self.root, "etc", "network"))
        self.write(OLD)
        patcher = mock.patch.object(marker, "autoconf",
                                    side_effect=lambda iface: self.AUTOCONF)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, text):
        with open(join(self.root, INTERFACES), "w") as fob:
            fob.write(text)

    def current(self):
        with open(join(self.root, INTERFACES)) as fob:
            return fob.read()


class TestMarker(RootCase):
    def test_round_trip_and_private_modes(self):
        marker.save(self.root, OLD)
        marker.write(self.root, pending().up("boot", 12.5))
        found = marker.read(self.root)
        self.assertEqual(found, pending(boot_id="boot", changed_at=12.5))
        self.assertEqual(marker.saved(self.root), OLD)
        for name in (marker.PENDING, marker.SAVED):
            mode = os.stat(join(self.root, name)).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        mode = os.stat(join(self.root, marker.DIR)).st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_an_unparseable_marker_reads_as_none_but_exists(self):
        marker.write_private(self.root, marker.PENDING, "{not json")
        self.assertIsNone(marker.read(self.root))
        self.assertTrue(marker.exists(self.root))
        marker.write_private(self.root, marker.PENDING, json.dumps({"x": 1}))
        self.assertIsNone(marker.read(self.root))

    def test_clear_is_idempotent(self):
        marker.clear(self.root)
        self.assertIsNone(marker.read(self.root))
        self.assertIsNone(marker.saved(self.root))

    def test_boot_id_and_uptime_from_proc(self):
        proc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, proc)
        self.assertIsNone(marker.boot_id(proc))
        self.assertIsNone(marker.uptime(proc))
        os.makedirs(join(proc, "proc/sys/kernel/random"))
        with open(join(proc, marker.BOOT_ID), "w") as fob:
            fob.write("abc\n")
        with open(join(proc, marker.UPTIME), "w") as fob:
            fob.write("123.45 67.8\n")
        self.assertEqual(marker.boot_id(proc), "abc")
        self.assertEqual(marker.uptime(proc), 123.45)

    def test_the_lock_excludes_a_second_holder(self):
        order = []

        def second():
            with marker.locked(self.root):
                order.append("second")

        with marker.locked(self.root):
            thread = threading.Thread(target=second)
            thread.start()
            time.sleep(0.2)
            order.append("first")
        thread.join()
        self.assertEqual(order, ["first", "second"])


class TestChange(RootCase):
    def test_the_revert_is_armed_before_the_interface_moves(self):
        run = Recorder()
        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0):
            self.assertIsNone(switch.change(self.root, pending(), NEW, run))
        self.assertEqual(run.names(), [
            "systemctl", "systemctl", "systemd-run", "ifdown",
            "ip address flush", "ip link set", "ifup",
            "systemctl", "systemctl", "systemd-run",
        ])
        safety, window = run.calls[2], run.calls[9]
        self.assertIn("--unit=keel-network-window-safety", safety)
        self.assertIn("--on-active=180s", safety)
        self.assertIn("--unit=keel-network-window", window)
        self.assertIn("--on-active=120s", window)
        self.assertEqual(window[-3:], ("keel", "network", "revert"))
        self.assertEqual(self.current(), NEW)
        self.assertEqual(marker.saved(self.root), OLD)
        found = marker.read(self.root)
        self.assertEqual((found.boot_id, found.changed_at), ("b1", 50.0))

    def test_ifdown_failing_is_not_fatal(self):
        run = Recorder(fail={"ifdown": 1})
        self.assertIsNone(switch.change(self.root, pending(), NEW, run))
        self.assertEqual(self.current(), NEW)

    def test_no_timer_means_nothing_changes(self):
        run = Recorder(fail={"systemd-run": 1})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("revert timer not armed, nothing changed", problem)
        self.assertEqual(self.current(), OLD)
        self.assertFalse(marker.exists(self.root))
        self.assertNotIn("ifdown", run.names())

    def test_ifup_failing_on_the_new_file_reverts_at_once(self):
        run = Recorder(fail={"ifup": 1})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("ifup failed; reverted to the previous file", problem)
        self.assertEqual(self.current(), OLD)
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(run.calls[-1], STOP)
        self.assertEqual(marker.last(self.root).outcome, marker.REVERTED)

    def test_the_old_file_back_but_down_is_said(self):
        run = Recorder(fail={"ifup": 2})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("the previous file is back, but bringing", problem)
        self.assertEqual(self.current(), OLD)

    def test_a_rollback_that_cannot_write_keeps_the_marker_and_timer(self):
        real = switch.stage
        calls = []

        def second_stage_fails(root, relative, text):
            # the first call is the check before the marker, the second
            # the change itself, the third the rollback
            calls.append(text)
            if len(calls) == 3:
                return None, "cannot write /etc/network/interfaces: full"
            return real(root, relative, text)

        with mock.patch.object(switch, "stage",
                               side_effect=second_stage_fails):
            problem = switch.change(self.root, pending(), NEW,
                                    Recorder(fail={"ifup": 1}))
        self.assertIn("the revert timer will try again", problem)
        self.assertTrue(marker.exists(self.root))
        self.assertEqual(marker.saved(self.root), OLD)

    def test_an_unreadable_uptime_changes_nothing(self):
        run = Recorder()
        with mock.patch.object(marker, "uptime", return_value=None):
            problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("nothing changed", problem)
        self.assertEqual((run.calls, self.current()), ([], OLD))

    def test_uptime_lost_after_ifup_leaves_the_change_undated(self):
        with mock.patch.object(marker, "uptime", side_effect=[1.0, None]):
            self.assertIsNone(switch.change(self.root, pending(), NEW,
                                            Recorder()))
        self.assertIsNone(marker.read(self.root).changed_at)

    def test_a_hangup_is_ignored_while_the_interface_moves(self):
        seen = []

        def run(argv):
            seen.append(signal.getsignal(signal.SIGHUP))
            return None

        before = signal.getsignal(signal.SIGHUP)
        switch.change(self.root, pending(), NEW, run)
        self.assertEqual(set(seen), {signal.SIG_IGN})
        self.assertEqual(signal.getsignal(signal.SIGHUP), before)

    def test_the_transient_units_never_take_the_shipped_unit_name(self):
        shipped = "keel-network-revert"
        self.assertNotIn(shipped, switch.UNITS)

    def test_a_flush_that_fails_on_the_way_in_rolls_back(self):
        run = Recorder(fail={"ip address flush": 1})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("ip failed", problem)
        self.assertEqual(self.current(), OLD)

    def test_a_pending_change_refuses_another(self):
        marker.write(self.root, pending())
        problem = switch.change(self.root, pending(), NEW, Recorder())
        self.assertIn("already waiting", problem)

    def test_a_missing_file_is_saved_as_empty(self):
        os.remove(join(self.root, INTERFACES))
        self.assertIsNone(switch.change(self.root, pending(), NEW,
                                        Recorder()))
        self.assertEqual(marker.saved(self.root), "")

    def test_an_unreadable_file_is_refused(self):
        with mock.patch.object(switch, "read_current",
                               side_effect=PermissionError(13, "denied")):
            problem = switch.change(self.root, pending(), NEW, Recorder())
        self.assertIn("cannot read", problem)

    def read_only(self):
        directory = join(self.root, "etc", "network")
        os.chmod(directory, 0o555)
        self.addCleanup(os.chmod, directory, 0o755)

    def test_an_unwritable_file_leaves_the_interface_untouched(self):
        self.read_only()
        run = Recorder()
        written, problem = switch.bounce(self.root, "eth0", INTERFACES, NEW,
                                         run)
        self.assertFalse(written)
        self.assertIn("cannot write /etc/network/interfaces", problem)
        self.assertEqual(run.calls, [])
        self.assertEqual(self.current(), OLD)

    def test_a_change_that_cannot_stage_leaves_nothing_waiting(self):
        self.read_only()
        run = Recorder()
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("nothing changed", problem)
        self.assertEqual(run.calls, [])
        self.assertFalse(marker.exists(self.root))

    def test_a_failed_rename_still_brings_the_interface_up(self):
        run = Recorder()
        with mock.patch.object(switch.os, "replace",
                               side_effect=OSError(5, "I/O error")):
            written, problem = switch.bounce(self.root, "eth0", INTERFACES,
                                             NEW, run)
        self.assertFalse(written)
        self.assertEqual(run.names()[-1], "ifup")
        self.assertEqual(self.current(), OLD)

    def test_the_file_keeps_mode_0644_whatever_the_umask(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        self.assertIsNone(switch.put_file(self.root, INTERFACES, NEW))
        mode = os.stat(join(self.root, INTERFACES)).st_mode & 0o777
        self.assertEqual(mode, 0o644)


class TestRevert(RootCase):
    def prepared(self, **overrides):
        marker.save(self.root, OLD)
        marker.write(self.root, pending(**overrides).up("b1", 50.0))
        self.write(NEW)

    def test_nothing_pending_is_fine(self):
        self.assertEqual(switch.revert(self.root, Recorder()),
                         (True, "no network change is waiting; nothing"
                          " to revert"))
        self.assertIsNone(marker.last(self.root))

    def test_a_record_that_cannot_be_written_never_fails_a_revert(self):
        for boot in (True, False):
            self.prepared()
            os.makedirs(join(self.root, marker.LAST), exist_ok=True)
            worked, line = switch.revert(self.root, Recorder(), boot=boot)
            self.assertTrue(worked)
            self.assertFalse(marker.exists(self.root))
            self.assertEqual(self.current(), OLD)
            self.assertIn("could not be recorded", line)
        marker.save(self.root, OLD, marker.Target(INTERFACES))
        marker.write_private(self.root, marker.PENDING, "garbage")
        worked, line = switch.revert(self.root, Recorder())
        self.assertTrue(worked)
        self.assertIn("could not be recorded", line)

    def test_a_failed_change_rolled_back_says_a_record_it_could_not_write(
            self):
        write = marker.write_private

        def full_disk(root, relative, text):
            if relative == marker.LAST:
                raise OSError(28, "No space left on device")
            write(root, relative, text)

        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0), \
                mock.patch.object(marker, "write_private", full_disk):
            problem = switch.change(self.root, pending(), NEW,
                                    Recorder(fail={"ifup": 1}))
        self.assertIn("reverted to the previous file", problem)
        self.assertIn("could not be recorded", problem)
        self.assertIn("No space left on device", problem)
        self.assertFalse(marker.exists(self.root))

    def test_a_record_that_cannot_be_removed_changes_nothing(self):
        os.makedirs(join(self.root, marker.LAST, "x"))
        run = Recorder()
        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0):
            problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn(f"cannot remove /{marker.LAST}", problem)
        self.assertTrue(problem.endswith("nothing changed"))
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(self.current(), OLD)
        self.assertEqual(run.calls, [])

    def test_every_revert_that_restored_the_file_is_recorded(self):
        self.prepared()
        self.assertTrue(switch.revert(self.root, Recorder(), boot=True)[0])
        self.assertEqual(marker.last(self.root).outcome, marker.REVERTED)
        self.assertEqual(marker.last(self.root).path, INTERFACES)
        mode = os.stat(join(self.root, marker.LAST)).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_live_revert_bounces_onto_the_saved_file(self):
        self.prepared()
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertTrue(worked)
        self.assertIn("eth0 is up on it", line)
        self.assertEqual(self.current(), OLD)
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(run.names()[:4], ["ifdown", "ip address flush",
                                           "ip link set", "ifup"])

    def test_boot_revert_restores_without_touching_the_interface(self):
        self.prepared()
        run = Recorder()
        worked, line = switch.revert(self.root, run, boot=True)
        self.assertTrue(worked)
        self.assertIn("before networking starts", line)
        self.assertEqual(run.calls, [])
        self.assertEqual(self.current(), OLD)

    def test_an_unparseable_marker_restores_the_recorded_file(self):
        marker.save(self.root, OLD, marker.Target(INTERFACES))
        marker.write_private(self.root, marker.PENDING, "garbage")
        self.write(NEW)
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertEqual(run.calls, [STOP])
        self.assertTrue(worked)
        self.assertIn("restored /etc/network/interfaces; the pending change"
                      " could not be read, so no interface was restarted",
                      line)
        self.assertEqual(self.current(), OLD)
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(marker.last(self.root),
                         marker.Last(marker.REVERTED, INTERFACES,
                                     marker.last(self.root).at))

    def test_an_unparseable_marker_with_no_known_file_restores_nothing(self):
        for target in (None, "garbage", json.dumps({"path": "etc/passwd"}),
                       json.dumps({"path": INTERFACES, "kind": "overlay"}),
                       json.dumps({"path": "etc/wireguard/wg0.conf"}),
                       json.dumps({"kind": "uplink"})):
            with self.subTest(target=target):
                marker.save(self.root, OLD)
                if target is not None:
                    marker.write_private(self.root, marker.TARGET, target)
                marker.write_private(self.root, marker.PENDING, "garbage")
                self.write(NEW)
                run = Recorder()
                worked, line = switch.revert(self.root, run)
                self.assertFalse(worked)
                self.assertIn("does not say which file", line)
                self.assertIn("/var/lib/keel/network/saved", line)
                self.assertEqual(run.calls, [])
                self.assertEqual(self.current(), NEW)
                self.assertTrue(marker.exists(self.root))
                marker.clear(self.root)

    def test_the_change_records_its_file_beside_the_saved_copy(self):
        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0):
            switch.change(self.root, pending(), NEW, Recorder())
        self.assertEqual(marker.saved_target(self.root),
                         marker.Target(INTERFACES))
        marker.clear(self.root)
        self.assertIsNone(marker.saved_target(self.root))
        self.assertFalse(os.path.exists(join(self.root, marker.TARGET)))

    def test_a_missing_saved_copy_is_a_failure(self):
        marker.write(self.root, pending())
        worked, line = switch.revert(self.root, Recorder())
        self.assertFalse(worked)
        self.assertIn("saved copy", line)
        self.assertFalse(marker.exists(self.root))

    def test_a_flush_that_fails_still_restores_the_file(self):
        self.prepared()
        worked, line = switch.revert(self.root,
                                     Recorder(fail={"ip address flush": 1}))
        self.assertFalse(worked)
        self.assertIn("restored /etc/network/interfaces, but ip failed", line)
        self.assertEqual(self.current(), OLD)
        self.assertFalse(marker.exists(self.root))

    def test_a_revert_that_cannot_write_keeps_the_marker(self):
        self.prepared()
        with mock.patch.object(switch, "stage", return_value=(
                None, "cannot write /etc/network/interfaces: read-only")):
            worked, line = switch.revert(self.root, Recorder())
        self.assertFalse(worked)
        self.assertIn("cannot restore", line)
        self.assertTrue(marker.exists(self.root))

    def test_ifup_failing_on_the_restored_file_is_said(self):
        self.prepared()
        worked, line = switch.revert(self.root, Recorder(fail={"ifup": 1}))
        self.assertFalse(worked)
        self.assertIn("but ifup failed", line)

    def test_a_boot_restore_that_cannot_write_is_a_failure(self):
        self.prepared()
        with mock.patch.object(switch, "stage", return_value=(
                None, "cannot write /etc/network/interfaces: read-only")):
            worked, line = switch.revert(self.root, Recorder(), boot=True)
        self.assertFalse(worked)
        self.assertIn("cannot restore", line)
        self.assertTrue(marker.exists(self.root))


NO_SLAAC = NEW + (
    "    pre-up sysctl -q -w net/ipv6/conf/eth0/autoconf=0\n"
    "    post-down sysctl -q -w net/ipv6/conf/eth0/autoconf=1\n"
)
AUTOCONF_ON = ("sysctl", "-q", "-w", "net/ipv6/conf/eth0/autoconf=1")


class TestAutoconf(RootCase):
    """keel#45: SLAAC comes back whatever ifupdown-ng did with post-down"""

    AUTOCONF = "1"

    def change(self, text, run):
        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0):
            return switch.change(self.root, pending(), text, run)

    def test_the_setting_is_recorded_before_the_change(self):
        run = Recorder()
        self.assertIsNone(self.change(NO_SLAAC, run))
        self.assertEqual(marker.read(self.root).autoconf, "1")
        # the incoming file turns it off itself, in pre-up
        self.assertNotIn("sysctl", run.names())

    def test_a_failed_up_on_a_slaac_off_file_gives_slaac_back(self):
        """pre-up ran (autoconf=0), up failed, and ifdown then skips an
        interface ifupdown-ng never recorded as up: no post-down"""
        run = Recorder(fail={"ifup": 1})
        problem = self.change(NO_SLAAC, run)
        self.assertIn("reverted to the previous file", problem)
        self.assertEqual(self.current(), OLD)
        back = run.names().index("sysctl")
        self.assertEqual(run.calls[back], AUTOCONF_ON)
        self.assertEqual(run.names()[back:back + 2], ["sysctl", "ifup"])

    def test_a_timed_revert_gives_slaac_back(self):
        self.assertIsNone(self.change(NO_SLAAC, Recorder()))
        run = Recorder()
        worked, _ = switch.revert(self.root, run)
        self.assertTrue(worked)
        self.assertEqual(self.current(), OLD)
        self.assertIn(AUTOCONF_ON, run.calls)
        self.assertLess(run.calls.index(AUTOCONF_ON),
                        run.names().index("ifup"))

    def test_an_operator_setting_of_zero_is_what_comes_back(self):
        self.AUTOCONF = "0"
        self.assertIsNone(self.change(NO_SLAAC, Recorder()))
        run = Recorder()
        switch.revert(self.root, run)
        self.assertIn(("sysctl", "-q", "-w",
                       "net/ipv6/conf/eth0/autoconf=0"), run.calls)

    def test_leaving_a_slaac_off_file_restores_one_not_its_zero(self):
        self.write(NO_SLAAC)
        self.AUTOCONF = "0"
        run = Recorder()
        self.assertIsNone(self.change(NEW, run))
        self.assertEqual(marker.read(self.root).autoconf, "1")
        self.assertIn(AUTOCONF_ON, run.calls)
        # and going back to it leaves autoconf to its own pre-up
        run = Recorder()
        switch.revert(self.root, run)
        self.assertEqual(self.current(), NO_SLAAC)
        self.assertNotIn("sysctl", run.names())

    def test_a_marker_without_a_setting_restores_the_default(self):
        marker.save(self.root, OLD)
        marker.write(self.root, pending().up("b1", 50.0))
        self.write(NO_SLAAC)
        run = Recorder()
        switch.revert(self.root, run)
        self.assertIn(AUTOCONF_ON, run.calls)

    def test_no_ipv6_settings_means_no_sysctl(self):
        self.AUTOCONF = None
        marker.save(self.root, OLD)
        marker.write(self.root, pending().up("b1", 50.0))
        run = Recorder()
        switch.revert(self.root, run)
        self.assertNotIn("sysctl", run.names())

    def test_a_sysctl_that_fails_is_reported(self):
        run = Recorder(fail={"sysctl": 1})
        problem = self.change(NEW, run)
        self.assertIn("sysctl failed", problem)

    def test_the_boot_revert_writes_no_sysctl(self):
        """Before networking at boot autoconf is the kernel's default: a
        pre-up's sysctl -w is not persisted, and keel writes no sysctl.d"""
        self.assertIsNone(self.change(NO_SLAAC, Recorder()))
        run = Recorder()
        worked, _ = switch.revert(self.root, run, boot=True)
        self.assertTrue(worked)
        self.assertEqual(run.calls, [])

    def test_autoconf_is_read_from_proc(self):
        proc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, proc)
        self.assertIsNone(READ_AUTOCONF("eth0.45", proc))
        conf = join(proc, "proc/sys/net/ipv6/conf/eth0.45")
        os.makedirs(conf)
        for text, expected in (("0\n", "0"), ("1\n", "1"), ("7\n", None)):
            with open(join(conf, "autoconf"), "w") as fob:
                fob.write(text)
            self.assertEqual(READ_AUTOCONF("eth0.45", proc), expected)


def probes(boot="b1", addresses=(), via=None):
    return Probes(boot_id=lambda: boot, addresses=lambda iface: list(
        addresses), route_via=lambda peer: via)


def ssh(started=60.0, local="2001:db8:1::20", peer="2001:db8:9::5"):
    return session.Origin(session.SSH, "an SSH session", started, local,
                          peer)


class TestConfirm(RootCase):
    def prepared(self, **overrides):
        marker.save(self.root, OLD)
        marker.write(self.root, pending(**overrides).up("b1", 50.0))

    def confirm(self, origin, found=None):
        run = Recorder()
        result = netconfirm.confirm(self.root, origin, found or probes(), run)
        return result, run

    def test_a_new_ssh_session_at_the_new_address_confirms(self):
        self.prepared()
        (confirmed, lines), run = self.confirm(ssh(), probes(via="fe80::2"))
        self.assertTrue(confirmed)
        self.assertIn("goes through the new gateway fe80::2", lines[1])
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(run.calls, [STOP])

    def test_an_on_link_confirmation_says_the_gateway_was_not_tested(self):
        self.prepared()
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertTrue(confirmed)
        self.assertIn("was not tested", lines[1])

    def test_an_unchanged_gateway_is_not_mentioned(self):
        self.prepared(gateways=("fe80::1",))
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertEqual(len(lines), 2)

    def test_a_session_older_than_the_change_is_refused(self):
        self.prepared()
        for started in (40.0, 50.0, None):
            (confirmed, lines), _ = self.confirm(ssh(started=started))
            self.assertFalse(confirmed)
            self.assertIn("open before the change", lines[0])
        self.assertTrue(marker.exists(self.root))

    def test_a_session_at_another_address_is_refused(self):
        self.prepared()
        (confirmed, lines), _ = self.confirm(ssh(local="2001:db8:1::10"))
        self.assertFalse(confirmed)
        self.assertIn("not at the static address the change declares"
                      " (2001:db8:1::20)", lines[0])
        self.prepared(addresses=())
        (confirmed, lines), _ = self.confirm(
            ssh(local="2001:db8:1::10"), probes(addresses=["2001:db8:1::99"]))
        self.assertFalse(confirmed)
        self.assertIn("not an address of the new configuration"
                      " (2001:db8:1::99)", lines[0])

    def test_a_slaac_address_does_not_prove_the_static_one(self):
        """keel#45: SLAAC stays beside a static address, and a session
        over the SLAAC address says nothing of the declared one"""
        self.prepared()
        slaac = "2001:db8:1:0:be24:11ff:fef9:707d"
        (confirmed, lines), _ = self.confirm(
            ssh(local=slaac), probes(addresses=["2001:db8:1::20", slaac]))
        self.assertFalse(confirmed)
        self.assertIn(f"arrived at {slaac}, not at the static address",
                      lines[0])
        self.assertTrue(marker.exists(self.root))

    def test_a_static_address_of_the_other_family_is_said_untested(self):
        self.prepared(addresses=("2001:db8:1::20", "192.0.2.20"),
                      gateways=("fe80::1",))
        (confirmed, lines), _ = self.confirm(
            ssh(), probes(addresses=["2001:db8:1::20", "192.0.2.20"]))
        self.assertTrue(confirmed)
        self.assertEqual(lines[1], "the static address 192.0.2.20 was not"
                         " tested: this session arrived at 2001:db8:1::20,"
                         " over the other family")
        self.assertEqual(len(lines), 3)

    def test_an_ipv4_session_at_the_static_ipv4_address_confirms(self):
        self.prepared(addresses=("2001:db8:1::20", "192.0.2.20"),
                      gateways=("fe80::1",))
        (confirmed, lines), _ = self.confirm(
            ssh(local="192.0.2.20", peer="192.0.2.99"))
        self.assertTrue(confirmed)
        self.assertIn("the static address 2001:db8:1::20 was not tested",
                      lines[1])

    def test_a_dynamic_address_is_checked_against_the_interface(self):
        self.prepared(addresses=())
        (confirmed, _), _ = self.confirm(
            ssh(local="192.0.2.99"), probes(addresses=["192.0.2.99"]))
        self.assertTrue(confirmed)

    def test_a_dynamic_family_beside_a_static_one_confirms(self):
        self.prepared()
        (confirmed, _), _ = self.confirm(
            ssh(local="192.0.2.99"), probes(addresses=["2001:db8:1::20",
                                                       "192.0.2.99"]))
        self.assertTrue(confirmed)

    def test_a_session_from_the_machine_itself_is_refused(self):
        for peer in ("::1", "2001:db8:1::20"):
            self.prepared()
            (confirmed, lines), _ = self.confirm(
                ssh(peer=peer), probes(addresses=["2001:db8:1::20"]))
            self.assertFalse(confirmed)
            self.assertIn("comes from the machine itself", lines[0])

    def test_a_session_whose_socket_was_not_found_is_refused(self):
        self.prepared()
        origin = session.Origin(session.SSH, "an SSH session whose socket"
                                " was not found", 60.0)
        (confirmed, lines), _ = self.confirm(origin)
        self.assertFalse(confirmed)
        self.assertIn("socket was not found", lines[0])

    def test_a_console_and_the_host_confirm(self):
        for origin in (session.Origin(session.CONSOLE_KIND, "the console"),
                       session.Origin(session.HOST, "the host")):
            self.prepared(addresses=("2001:db8:1::20", "192.0.2.20"))
            (confirmed, lines), _ = self.confirm(origin)
            self.assertTrue(confirmed)
            self.assertEqual(len(lines), 2)

    def test_an_unknown_origin_is_refused(self):
        self.prepared()
        origin = session.Origin(session.UNKNOWN, "a tmux shell")
        (confirmed, lines), _ = self.confirm(origin)
        self.assertEqual((confirmed, lines), (False, ["refused: a tmux"
                                                      " shell"]))

    def test_nothing_waiting(self):
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertFalse(confirmed)
        self.assertIn("no network change is waiting", lines[0])
        self.assertNotIn("reverted", lines[0])

    def test_a_change_another_session_confirmed_stays_confirmed(self):
        """The maintainer's screenshot 040: a session attached from the
        host confirmed the overlay, then the console's confirm said the
        change had been reverted, and confconsole that it would revert"""
        self.prepared(kind=marker.OVERLAY, iface="wg0",
                      path="etc/wireguard/wg0.conf")
        console = session.Origin(session.CONSOLE_KIND, "the console")
        (confirmed, _), _ = self.confirm(
            session.Origin(session.HOST, "the host"))
        self.assertTrue(confirmed)
        (confirmed, lines), run = self.confirm(console)
        self.assertTrue(confirmed)
        self.assertEqual(len(lines), 1)
        self.assertIn("already confirmed", lines[0])
        self.assertIn("/etc/wireguard/wg0.conf", lines[0])
        self.assertIn("UTC", lines[0])
        self.assertIn("it stays", lines[0])
        self.assertNotIn("revert", lines[0])
        self.assertEqual(run.calls, [])

    def test_a_reverted_change_is_called_reverted(self):
        self.prepared()
        self.write(NEW)
        self.assertTrue(switch.revert(self.root, Recorder())[0])
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertFalse(confirmed)
        self.assertIn("no network change is waiting", lines[0])
        self.assertIn(f"the last one, of /{INTERFACES}, was reverted",
                      lines[0])

    def test_a_record_that_cannot_be_written_never_undoes_a_confirmation(
            self):
        """A full disk at the record must not crash confirm: the marker
        would stay and the timer revert a change the operator confirmed"""
        self.prepared()
        os.makedirs(join(self.root, marker.LAST))
        (confirmed, lines), run = self.confirm(ssh(), probes(via="fe80::2"))
        self.assertTrue(confirmed)
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(run.calls, [STOP])
        self.assertIn("could not be recorded", lines[-1])
        self.assertIsNone(marker.last(self.root))

    def test_a_new_change_forgets_how_the_last_one_ended(self):
        """Its revert may record nothing (a missing saved copy), so an
        older confirmation must not answer for it"""
        marker.record(self.root, marker.CONFIRMED, INTERFACES)
        with mock.patch.object(marker, "boot_id", return_value="b1"), \
                mock.patch.object(marker, "uptime", return_value=50.0):
            self.assertIsNone(switch.change(self.root, pending(), NEW,
                                            Recorder()))
        self.assertIsNone(marker.last(self.root))
        os.remove(join(self.root, marker.SAVED))
        self.assertFalse(switch.revert(self.root, Recorder())[0])
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertFalse(confirmed)
        self.assertEqual(lines, [netconfirm.NOTHING_WAITING])

    def test_a_record_that_cannot_be_read_says_nothing_of_the_last(self):
        for text in ("{not json", json.dumps({"outcome": "kept"}),
                     json.dumps(["confirmed"])):
            marker.write_private(self.root, marker.LAST, text)
            (confirmed, lines), _ = self.confirm(ssh())
            self.assertFalse(confirmed)
            self.assertEqual(lines, [netconfirm.NOTHING_WAITING])

    def test_not_ready_reasons(self):
        marker.write_private(self.root, marker.PENDING, "garbage")
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertIn("cannot be read", lines[0])
        marker.write(self.root, pending())
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertIn("could not be dated", lines[0])
        self.prepared()
        (confirmed, lines), _ = self.confirm(ssh(), probes(boot="b2"))
        self.assertIn("before the last boot", lines[0])
        self.assertFalse(confirmed)

    def test_a_revert_in_progress_wins_and_confirm_finds_nothing(self):
        """The race the lock exists for: revert first, then confirm"""
        self.prepared()
        self.write(NEW)
        started = threading.Event()
        results = {}

        def slow_revert():
            def run(argv):
                started.set()
                time.sleep(0.2)
                return None
            results["revert"] = switch.revert(self.root, run)

        thread = threading.Thread(target=slow_revert)
        thread.start()
        started.wait()
        (confirmed, lines), _ = self.confirm(ssh())
        thread.join()
        self.assertTrue(results["revert"][0])
        self.assertFalse(confirmed)
        self.assertIn("no network change is waiting", lines[0])
        self.assertEqual(self.current(), OLD)


if __name__ == "__main__":
    unittest.main()
