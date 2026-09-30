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

    def test_an_unreadable_marker_restores_the_overlay_file_it_recorded(self):
        with open(join(self.root, "interfaces"), "w") as fob:
            fob.write("uplink\n")
        for absent, saved, left in ((False, OLD, OLD), (True, "", None)):
            with self.subTest(absent=absent):
                marker.save(self.root, saved, pending(absent=absent).target())
                marker.write_private(self.root, marker.PENDING, "garbage")
                self.write(NEW)
                run = Recorder()
                worked, line = switch.revert(self.root, run)
                self.assertTrue(worked, line)
                self.assertEqual(self.current(), left)
                if left is not None:
                    self.assertEqual(self.mode(), 0o600)
                self.assertIn("no interface was restarted", line)
                self.assertEqual(self.wg_calls(run), [])
                self.assertFalse(os.path.exists(join(
                    self.root, switch.INTERFACES)))

    def test_the_change_records_the_overlay_file(self):
        switch.change(self.root, pending(), NEW, Recorder())
        self.assertEqual(marker.saved_target(self.root),
                         marker.Target(CONF, "overlay", True))

    def test_an_overlay_that_was_down_is_left_down_by_its_revert(self):
        self.prepared(absent=False, saved=OLD)
        marker.write(self.root, pending(down_before=True).up("b1", 50.0))
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertTrue(worked)
        self.assertEqual(line, "restored /etc/wireguard/wg0.conf; wg0 is"
                         " down, as it was before the change")
        self.assertEqual(self.current(), OLD)
        self.assertEqual(self.wg_calls(run), [("wg-quick", "down", "wg0")])

    def test_an_overlay_that_was_down_is_brought_up_by_its_change(self):
        self.write(OLD)
        run = Recorder(fail={"wg-quick": 2})
        problem = switch.change(self.root, pending(down_before=True), NEW,
                                run)
        self.assertIn("reverted", problem)
        self.assertEqual(self.wg_calls(run), [
            ("wg-quick", "down", "wg0"), ("wg-quick", "up", "wg0"),
            ("wg-quick", "down", "wg0")])
        self.assertEqual(self.current(), OLD)

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


def probes(boot="b1", routes=None, gateways=()):
    """`routes` None: every route leaves through eth0; a mapping: only
    the addresses it names have a route, the others get no answer"""
    return Probes(boot_id=lambda: boot, addresses=lambda iface: [],
                  route_via=lambda peer: None, holder=HOLDERS.get,
                  route_dev=(lambda address: "eth0") if routes is None
                  else routes.get,
                  gateways=lambda: None if gateways is None
                  else list(gateways))


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


GATEWAYS = ("192.0.2.1", "2001:db8:1::1")


class TestCapturedUplink(RootCase):
    """A confirmation is refused while the uplink's gateway is routed
    into the overlay: whoever confirms, the uplink is cut off"""

    def setUp(self):
        super().setUp()
        marker.save(self.root, "")
        marker.write(self.root, pending(
            absent=True, uplink_gateways=GATEWAYS).up("b1", 50.0))

    def confirm(self, origin, routes, gateways=()):
        run = Recorder()
        return netconfirm.confirm(self.root, origin,
                                  probes(routes=routes, gateways=gateways),
                                  run), run

    def refused(self, origin, routes, words, gateways=()):
        (confirmed, lines), run = self.confirm(origin, routes, gateways)
        self.assertFalse(confirmed)
        self.assertEqual(len(lines), 1)
        self.assertIn(words, lines[0])
        self.assertIn("left to revert", lines[0])
        self.assertEqual(run.calls, [])
        self.assertTrue(marker.exists(self.root))

    def test_a_captured_gateway_refuses_every_origin(self):
        routes = {"2001:db8:1::1": "wg0", "192.0.2.1": "eth0"}
        for origin in (
            session.Origin(session.CONSOLE_KIND, "the console /dev/tty1"),
            session.Origin(session.HOST, "a process attached from the host"),
            ssh("fd00:1::9", "fd00:1::2"),
            ssh("2001:db8:1::20"),
        ):
            with self.subTest(origin=origin.detail):
                (confirmed, lines), run = self.confirm(origin, routes)
                self.assertFalse(confirmed)
                self.assertEqual(len(lines), 1)
                self.assertIn("the route to the uplink gateway 2001:db8:1::1"
                              " leaves through wg0", lines[0])
                self.assertIn("left to revert", lines[0])
                self.assertEqual(run.calls, [])
                self.assertTrue(marker.exists(self.root))

    def test_the_ipv6_gateway_is_asked_first(self):
        console = session.Origin(session.CONSOLE_KIND, "the console")
        self.refused(console, {"2001:db8:1::1": "wg0", "192.0.2.1": "wg0"},
                     "gateway 2001:db8:1::1 leaves")
        self.refused(console, {"2001:db8:1::1": "eth0", "192.0.2.1": "wg0"},
                     "gateway 192.0.2.1 leaves")

    def test_gateways_through_the_uplink_confirm(self):
        (confirmed, lines), _ = self.confirm(
            session.Origin(session.CONSOLE_KIND, "the console"),
            {"2001:db8:1::1": "eth0", "192.0.2.1": "eth0"})
        self.assertTrue(confirmed, lines)

    def test_a_gateway_ip_does_not_answer_for_is_refused(self):
        """The probe fails closed: no answer is not a clean route"""
        self.refused(session.Origin(session.CONSOLE_KIND, "the console"),
                     {"2001:db8:1::1": "eth0"},
                     "`ip route get 192.0.2.1` (the uplink gateway) gave no"
                     " answer")

    def test_the_live_default_gateways_are_asked_too(self):
        """What DHCP, SLAAC or the host configured, which the spec does
        not declare, and what --skip-uplink left in place"""
        console = session.Origin(session.CONSOLE_KIND, "the console")
        routes = {"2001:db8:1::1": "eth0", "192.0.2.1": "eth0",
                  "fe80::1": "wg0", "10.0.3.1": "eth0"}
        self.refused(console, routes, "gateway fe80::1 leaves through wg0",
                     gateways=("10.0.3.1", "fe80::1", "192.0.2.1"))
        self.refused(console, routes, "`ip route show default` gave no"
                     " answer", gateways=None)
        routes["fe80::1"] = "eth0"
        (confirmed, lines), _ = self.confirm(
            console, routes, ("10.0.3.1", "fe80::1"))
        self.assertTrue(confirmed, lines)

    def test_the_route_back_to_an_uplink_session_is_asked(self):
        routes = {"2001:db8:1::1": "eth0", "192.0.2.1": "eth0",
                  "2001:db8:9::5": "wg0"}
        self.refused(ssh("2001:db8:1::20"), routes, "the route to this"
                     " session's client 2001:db8:9::5 leaves through wg0")
        del routes["2001:db8:9::5"]
        self.refused(ssh("2001:db8:1::20"), routes, "`ip route get"
                     " 2001:db8:9::5` (this session's client) gave no"
                     " answer")

    def test_a_session_over_the_overlay_is_answered_through_it(self):
        routes = {"2001:db8:1::1": "eth0", "192.0.2.1": "eth0",
                  "fd00:1::2": "wg0"}
        (confirmed, lines), _ = self.confirm(ssh("fd00:1::9", "fd00:1::2"),
                                             routes)
        self.assertTrue(confirmed, lines)

    def test_a_zoned_gateway_is_asked_without_its_zone(self):
        """`ip route get fe80::1%eth0` fails; the spec accepts the form"""
        marker.write(self.root, pending(
            absent=True, uplink_gateways=("fe80::1%eth0",)).up("b1", 50.0))
        console = session.Origin(session.CONSOLE_KIND, "the console")
        (confirmed, lines), _ = self.confirm(console, {"fe80::1": "eth0"},
                                             gateways=("fe80::1%eth0",))
        self.assertTrue(confirmed, lines)
        self.assertEqual(netconfirm.route_targets(
            marker.Pending(iface="wg0", path=CONF, window=120,
                           uplink_gateways=("fe80::1%eth0", "fe80::1")),
            console, ["192.0.2.1"]),
            [("fe80::1", "the uplink gateway"),
             ("192.0.2.1", "the uplink gateway")])

    def test_an_uplink_change_is_not_asked(self):
        uplink = marker.Pending(iface="eth0",
                                path="etc/network/interfaces", window=120,
                                uplink_gateways=GATEWAYS)
        self.assertIsNone(netconfirm.captured(
            uplink, ssh("2001:db8:1::20"), probes(routes={})))


class TestMarkerFields(RootCase):
    def test_the_overlay_fields_round_trip(self):
        written = pending(uplink_gateways=GATEWAYS, down_before=True)
        marker.write(self.root, written)
        self.assertEqual(marker.read(self.root), written)

    def test_a_marker_without_them_has_none(self):
        marker.write(self.root, pending())
        with open(join(self.root, marker.PENDING)) as fob:
            data = json.load(fob)
        del data["uplink_gateways"], data["down_before"]
        with open(join(self.root, marker.PENDING), "w") as fob:
            json.dump(data, fob)
        found = marker.read(self.root)
        self.assertEqual((found.uplink_gateways, found.down_before),
                         ((), False))


class TestRouteDev(unittest.TestCase):
    def test_the_interface_a_route_leaves_through(self):
        for text, iface in (
            ("2001:db8:1::1 from :: dev wg0 proto kernel src fd00:1::9"
             " metric 256 pref medium\n", "wg0"),
            ("192.0.2.1 dev eth0 src 192.0.2.10 uid 0 \n    cache \n",
             "eth0"),
            ("192.0.2.1 via 10.0.0.1 dev\n", None),
            ("", None),
        ):
            with self.subTest(text=text):
                self.assertEqual(live.route_dev_in(text), iface)

    def test_the_live_probe_asks_ip(self):
        text = "192.0.2.1 dev wg0 src x\n"
        with mock.patch.object(live, "output", return_value=text) as out:
            self.assertEqual(live.route_dev("192.0.2.1"), "wg0")
        out.assert_called_once_with(("ip", "route", "get", "192.0.2.1"))
        with mock.patch.object(live, "output", return_value=None):
            self.assertIsNone(live.route_dev("192.0.2.1"))
        self.assertIs(live.probes().route_dev, live.route_dev)

    def test_a_family_word_after_via_and_what_is_not_an_address(self):
        """RFC 5549: an IPv4 route via an IPv6 next hop"""
        self.assertEqual(live.gateways_in(
            "default via inet6 fe80::1 dev eth0 proto bgp\n"
            "default via inet 192.0.2.1 dev eth1\n"
            "default via inet6\n"
            "default via something dev eth2\n"), ["fe80::1", "192.0.2.1"])

    def test_the_default_routes_gateways(self):
        self.assertEqual(live.gateways_in(
            "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n"
            "default dev ppp0 scope link\n"
            "default via 192.0.2.1 dev eth1 onlink\n"
            "default via\n"), ["fe80::1", "192.0.2.1"])
        self.assertEqual(live.gateways_in(""), [])

    def test_the_live_default_gateways_ask_both_families(self):
        answers = {"-6": "default via fe80::1 dev eth0\n", "-4": ""}
        with mock.patch.object(live, "output", side_effect=lambda argv:
                               answers[argv[1]]) as out:
            self.assertEqual(live.default_gateways(), ["fe80::1"])
        self.assertEqual([call.args[0] for call in out.call_args_list], [
            ("ip", "-6", "route", "show", "default"),
            ("ip", "-4", "route", "show", "default")])
        answers["-4"] = None
        with mock.patch.object(live, "output", side_effect=lambda argv:
                               answers[argv[1]]):
            self.assertIsNone(live.default_gateways())
        self.assertIs(live.probes().gateways, live.default_gateways)


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
