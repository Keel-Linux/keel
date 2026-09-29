# Copyright (c) 2026 KeelLinux maintainers
"""The change, its revert and its confirmation (decision 0018)

Every command goes through a recording runner, so the order is checked
without touching a network: down on the old file, flush, link down, the
new file written, up on it, with the revert armed before any of it.
"""

import json
import os
import shutil
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
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(join(self.root, "etc", "network"))
        self.write(OLD)

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
            "systemctl", "systemd-run", "ifdown", "ip address flush",
            "ip link set", "ifup",
        ])
        armed = run.calls[1]
        self.assertIn("--on-active=120s", armed)
        self.assertEqual(armed[-3:], ("keel", "network", "revert"))
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
        self.assertEqual(run.calls[-1], ("systemctl", "stop",
                                         "keel-network-revert.timer"))

    def test_both_directions_failing_is_said(self):
        run = Recorder(fail={"ifup": 2})
        problem = switch.change(self.root, pending(), NEW, run)
        self.assertIn("the revert failed too", problem)

    def test_a_flush_that_fails_stops_before_the_write(self):
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

    def test_an_unwritable_file_is_the_problem(self):
        with mock.patch.object(marker, "write_private",
                               side_effect=OSError(30, "Read-only")):
            problem = switch.bounce(self.root, "eth0", INTERFACES, NEW,
                                    Recorder())
        self.assertIn("cannot write /etc/network/interfaces", problem)


class TestRevert(RootCase):
    def prepared(self, **overrides):
        marker.save(self.root, OLD)
        marker.write(self.root, pending(**overrides).up("b1", 50.0))
        self.write(NEW)

    def test_nothing_pending_is_fine(self):
        self.assertEqual(switch.revert(self.root, Recorder()),
                         (True, "no network change is waiting; nothing"
                          " to revert"))

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

    def test_an_unparseable_marker_restores_the_default_file(self):
        marker.save(self.root, OLD)
        marker.write_private(self.root, marker.PENDING, "garbage")
        self.write(NEW)
        worked, line = switch.revert(self.root, Recorder())
        self.assertTrue(worked)
        self.assertIn("no interface was restarted", line)
        self.assertEqual(self.current(), OLD)

    def test_a_missing_saved_copy_is_a_failure(self):
        marker.write(self.root, pending())
        worked, line = switch.revert(self.root, Recorder())
        self.assertFalse(worked)
        self.assertIn("saved copy", line)
        self.assertFalse(marker.exists(self.root))

    def test_ifup_failing_on_the_restored_file_is_said(self):
        self.prepared()
        worked, line = switch.revert(self.root, Recorder(fail={"ifup": 1}))
        self.assertFalse(worked)
        self.assertIn("but ifup failed", line)

    def test_a_boot_restore_that_cannot_write_is_a_failure(self):
        self.prepared()
        with mock.patch.object(marker, "write_private",
                               side_effect=OSError(30, "Read-only")):
            worked, line = switch.revert(self.root, Recorder(), boot=True)
        self.assertFalse(worked)
        self.assertIn("cannot restore", line)
        self.assertTrue(marker.exists(self.root))


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
        self.assertEqual(run.calls, [("systemctl", "stop",
                                      "keel-network-revert.timer")])

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
        self.assertIn("not an address of the new configuration", lines[0])

    def test_a_dynamic_address_is_checked_against_the_interface(self):
        self.prepared(addresses=())
        (confirmed, _), _ = self.confirm(
            ssh(local="192.0.2.99"), probes(addresses=["192.0.2.99"]))
        self.assertTrue(confirmed)

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
            self.prepared()
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

    def test_not_ready_reasons(self):
        marker.write_private(self.root, marker.PENDING, "garbage")
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertIn("cannot be read", lines[0])
        marker.write(self.root, pending())
        (confirmed, lines), _ = self.confirm(ssh())
        self.assertIn("still being applied", lines[0])
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
