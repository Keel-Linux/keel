# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: network.overlay, the WireGuard interface (decision 0020)

The planner is pure; its state is read from a scratch root; the plan as
a whole puts the overlay after the uplink and refuses both in one run.
"""

import importlib
import os
import shutil
import stat
import tempfile
import unittest
from dataclasses import replace
from os.path import join
from unittest import mock

import wgtools
from helpers import spec  # noqa: F401

from keel.network import live, marker, wireguard
from keel.system.actions import (
    AdoptKey,
    GenerateKey,
    Note,
    Refuse,
    Run,
    SwitchNetwork,
    WriteFile,
)
from keel.system.effects import Effects
from keel.system.overlay import LIVE_COMMANDS, plan_overlay
from keel.system.ovstate import OverlayState, observe_overlay
from keel.system.state import observe

whole = importlib.import_module("keel.system.plan")
ALL = frozenset(LIVE_COMMANDS)
PEER_KEY = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OVERLAY = {"address": "fd00:1::1/64", "peers": [
    {"public_key": PEER_KEY, "endpoint": "[2001:db8::20]:51820",
     "allowed_ips": ["fd00:1::2/128"]}]}
DOC = {"version": 1, "network": {"overlay": {"wireguard": OVERLAY}}}
RENDERED = wireguard.render(OVERLAY)


def state(**overrides) -> OverlayState:
    values = dict(iface="wg0", key_path="/etc/wireguard/wg0.key",
                  current=None, rendered=RENDERED, key_present=True,
                  key_problem=None, in_container=False, module_loaded=True,
                  pending=False, enabled=False, addresses=("fd00:1::1",),
                  inline_key=False, up=None, uplink_gateways=())
    values.update(overrides)
    return OverlayState(**values)


def actions(steps):
    return [a for step in steps for a in step.actions]


class TestPlan(unittest.TestCase):
    def test_no_overlay_is_no_step(self):
        self.assertEqual(plan_overlay(None, True, ALL, 120), [])

    def test_a_first_overlay_makes_the_key_and_switches(self):
        steps = plan_overlay(state(key_present=False), True, ALL, 90)
        self.assertEqual(steps[0].field, "network.overlay")
        found = actions(steps)
        self.assertEqual(found[0], GenerateKey("/etc/wireguard/wg0.key"))
        self.assertIn("never printed", found[0].describe())
        switch = found[1]
        self.assertIsInstance(switch, SwitchNetwork)
        self.assertEqual((switch.kind, switch.iface, switch.path,
                          switch.window, switch.addresses),
                         ("overlay", "wg0", "etc/wireguard/wg0.conf", 90,
                          ("fd00:1::1",)))
        self.assertEqual(switch.content, RENDERED)
        self.assertIn("wg-quick down, then up", switch.describe())
        self.assertIn("a change of its peers alone with wg set, live",
                      switch.describe())
        self.assertIn("over the overlay or the uplink", switch.describe())

    def test_missing_tools_are_refused_first(self):
        found = actions(plan_overlay(state(key_present=False), True,
                                     frozenset({"ip", "systemctl"}), 120))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("wg, wg-quick, systemd-run", found[0].describe())
        self.assertIn("wireguard-tools", found[0].describe())

    def test_a_key_file_others_can_read_is_refused(self):
        found = actions(plan_overlay(state(key_problem="mode must be 0600"),
                                     True, ALL, 120))
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("mode must be 0600", found[0].describe())

    def test_no_key_is_made_under_a_root(self):
        found = actions(plan_overlay(state(key_present=False), False,
                                     frozenset(), 120))
        self.assertIsInstance(found[0], Note)
        self.assertIn("never in an image (keel-core#8)",
                      found[0].describe())
        self.assertEqual(found[1], WriteFile(
            "etc/wireguard/wg0.conf", RENDERED, 0o600, None,
            "write /etc/wireguard/wg0.conf"))
        self.assertIsInstance(found[2], Note)

    def test_skip_network_still_makes_the_key(self):
        found = actions(plan_overlay(state(key_present=False), True, ALL,
                                     120, skip=True))
        self.assertIsInstance(found[0], GenerateKey)
        self.assertIn("--skip-network", found[1].describe())

    def test_the_same_file_is_left_and_the_unit_enabled(self):
        found = actions(plan_overlay(state(current=RENDERED), True, ALL,
                                     120))
        self.assertIn("unchanged", found[0].describe())
        self.assertEqual(found[1].argv,
                         ("systemctl", "enable", "wg-quick@wg0"))
        self.assertIsInstance(found[1], Run)

    def test_the_same_file_enabled_or_pending_or_offline_is_a_note(self):
        for overrides, live in (({"enabled": True}, True),
                                ({"pending": True}, True), ({}, False)):
            with self.subTest(overrides=overrides, live=live):
                found = actions(plan_overlay(
                    state(current=RENDERED, **overrides), live, ALL, 120))
                self.assertEqual([type(one) for one in found], [Note])

    def test_a_pending_change_refuses_another(self):
        found = actions(plan_overlay(state(pending=True), True, ALL, 120))
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("waiting for its confirmation", found[0].describe())

    def test_an_uplink_moving_in_the_same_run_refuses_the_overlay(self):
        found = actions(plan_overlay(state(), True, ALL, 120,
                                     uplink_moves=True))
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("one change in the window at a time",
                      found[0].describe())

    def test_a_container_without_the_module_names_modprobe_on_the_host(self):
        found = actions(plan_overlay(state(in_container=True,
                                           module_loaded=False),
                                     True, ALL, 120))
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("modprobe wireguard", found[0].describe())
        self.assertIn("on the host", found[0].describe())

    def test_a_container_with_the_module_converges(self):
        found = actions(plan_overlay(state(in_container=True), True, ALL,
                                     120))
        self.assertIsInstance(found[0], SwitchNetwork)

    def test_a_vm_without_the_module_lets_wg_quick_load_it(self):
        found = actions(plan_overlay(state(module_loaded=False), True, ALL,
                                     120))
        self.assertIsInstance(found[0], SwitchNetwork)

    def test_the_switch_carries_the_uplink_gateways(self):
        found = actions(plan_overlay(state(
            uplink_gateways=("2001:db8:1::1", "192.0.2.1")), True, ALL, 120))
        self.assertEqual(found[0].uplink_gateways,
                         ("2001:db8:1::1", "192.0.2.1"))


ADOPT = AdoptKey("etc/wireguard/wg0.conf", "/etc/wireguard/wg0.key")


class TestInlineKey(unittest.TestCase):
    """A file with a PrivateKey line keeps its identity (keel#49)"""

    def test_the_inline_key_is_moved_instead_of_a_new_one(self):
        for live, present in ((True, False), (True, True), (False, False)):
            with self.subTest(live=live, present=present):
                found = actions(plan_overlay(state(
                    current="[Interface]\nPrivateKey = x\n", inline_key=True,
                    key_present=present), live, ALL, 120))
                self.assertEqual(found[0], ADOPT)
                self.assertFalse(any(isinstance(one, GenerateKey)
                                     for one in found))
                self.assertIn("never printed", found[0].describe())
                self.assertIn("keeps its public key", found[0].describe())

    def test_the_move_comes_before_the_file_is_rewritten(self):
        found = actions(plan_overlay(state(current="old", inline_key=True),
                                     True, ALL, 120))
        self.assertEqual([type(one) for one in found],
                         [AdoptKey, SwitchNetwork])

    def test_skip_network_still_moves_it(self):
        found = actions(plan_overlay(state(current="old", inline_key=True,
                                           key_present=False),
                                     True, ALL, 120, skip=True))
        self.assertEqual(found[0], ADOPT)

    def test_a_key_file_that_cannot_be_used_is_refused_first(self):
        found = actions(plan_overlay(state(inline_key=True,
                                           key_problem="mode 0644"),
                                     True, ALL, 120))
        self.assertIsInstance(found[0], Refuse)


class TestLiveInterface(unittest.TestCase):
    """The file alone is not the overlay: the interface is read too"""

    def test_a_confirmed_overlay_that_is_down_is_started(self):
        found = actions(plan_overlay(state(current=RENDERED, enabled=True,
                                           up=False), True, ALL, 120))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].argv,
                         ("systemctl", "restart", "wg-quick@wg0"))
        self.assertIn("drift: wg0 is down", found[0].describe())

    def test_an_overlay_that_is_up_is_left_or_enabled(self):
        found = actions(plan_overlay(state(current=RENDERED, enabled=True,
                                           up=True), True, ALL, 120))
        self.assertEqual([type(one) for one in found], [Note])
        found = actions(plan_overlay(state(current=RENDERED, up=True),
                                     True, ALL, 120))
        self.assertEqual(found[1].argv,
                         ("systemctl", "enable", "wg-quick@wg0"))

    def test_an_overlay_never_confirmed_here_comes_up_under_the_window(self):
        found = actions(plan_overlay(state(current=RENDERED, up=False),
                                     True, ALL, 120))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], SwitchNetwork)
        self.assertTrue(found[0].down_before)
        self.assertIn("a revert leaves it down", found[0].describe())

    def test_a_changed_file_records_whether_it_was_down(self):
        for up, down in ((False, True), (True, False), (None, False)):
            with self.subTest(up=up):
                found = actions(plan_overlay(state(current="old", up=up),
                                             True, ALL, 120))
                self.assertEqual(found[0].down_before, down)

    def test_a_pending_change_is_not_started(self):
        found = actions(plan_overlay(state(current=RENDERED, enabled=True,
                                           pending=True, up=False),
                                     True, ALL, 120))
        self.assertEqual([type(one) for one in found], [Note])

    def test_under_a_root_the_interface_means_nothing(self):
        found = actions(plan_overlay(state(current=RENDERED, up=False),
                                     False, ALL, 120))
        self.assertEqual([type(one) for one in found], [Note])


class TestLinkProbe(unittest.TestCase):
    def test_up_among_the_flags(self):
        for text, up in (
            ("5: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc"
             " noqueue state UNKNOWN\n", True),
            ("5: wg0: <POINTOPOINT,NOARP> mtu 1420 state DOWN\n", False),
            ("5: wg0: <POINTOPOINT,NOARP,LOWER_UP> UP\n", False),
            ("", False),
            ("odd > text <\n", False),
        ):
            with self.subTest(text=text):
                self.assertEqual(live.link_up_in(text), up)

    def test_the_live_probe_asks_ip(self):
        with mock.patch.object(live, "output",
                               return_value="5: wg0: <UP> mtu\n") as out:
            self.assertTrue(live.link_up("wg0"))
        out.assert_called_once_with(("ip", "link", "show", "dev", "wg0"))
        with mock.patch.object(live, "output", return_value=None):
            self.assertFalse(live.link_up("wg0"))


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def put(self, relative, text="", mode=0o600):
        path = join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)
        os.chmod(path, mode)
        return path


class TestObserve(RootCase):
    def test_no_overlay_declared(self):
        self.assertIsNone(observe_overlay(self.root, {"version": 1}))
        self.assertIsNone(observe_overlay(self.root, {"network": {
            "overlay": {"wireguard": None}}}))

    def test_an_empty_root(self):
        found = observe_overlay(self.root, DOC)
        self.assertEqual(found, state(current=None, key_present=False,
                                      module_loaded=None))

    def test_a_populated_root(self):
        self.put("etc/wireguard/wg0.conf", RENDERED)
        self.put("etc/wireguard/wg0.key", "k\n", 0o644)
        self.put(marker.PENDING, "{}")
        self.put("var/lib/turnkey-info/inithooks.service/lxc")
        os.makedirs(join(self.root, "etc/systemd/system/"
                         "multi-user.target.wants"))
        os.symlink("/lib/systemd/system/wg-quick@.service",
                   join(self.root, "etc/systemd/system/multi-user.target"
                        ".wants/wg-quick@wg0.service"))
        found = observe_overlay(self.root, DOC)
        # a key's mode is judged on the live system only
        self.assertEqual(found, state(current=RENDERED, in_container=True,
                                      module_loaded=None, pending=True,
                                      enabled=True))

    def test_the_live_system_is_asked_about_the_module_and_the_key(self):
        self.put("etc/wireguard/wg0.key", "k\n", 0o644)
        with mock.patch("keel.system.ovstate.paths.ROOT_DEFAULT",
                        self.root), \
                mock.patch("keel.system.ovstate.live.link_up",
                           return_value=False) as link:
            found = observe_overlay(self.root, DOC)
        self.assertFalse(found.module_loaded)
        self.assertIn("0600", found.key_problem)
        self.assertIs(found.up, False)
        link.assert_called_once_with("wg0")

    def test_an_inline_key_and_the_uplink_gateways(self):
        self.put("etc/wireguard/wg0.conf",
                 "[Interface]\nPrivateKey = x\n")
        doc = {"version": 1, "network": {
            "interfaces": {
                "eth0": {"ipv4": {"method": "static",
                                  "address": "192.0.2.10/24",
                                  "gateway": "192.0.2.1"},
                         "ipv6": {"method": "static",
                                  "address": "2001:db8:1::10/64",
                                  "gateway": "2001:db8:1::1"}},
                "eth1": {"ipv6": {"method": "auto"}}, "eth2": None},
            "overlay": {"wireguard": OVERLAY}}}
        found = observe_overlay(self.root, doc)
        self.assertTrue(found.inline_key)
        self.assertEqual(found.uplink_gateways,
                         ("2001:db8:1::1", "192.0.2.1"))
        self.assertIsNone(found.up)


class TestWholePlan(RootCase):
    def test_the_overlay_comes_last_under_a_root(self):
        doc = {**DOC, "locale": {"timezone": "UTC"}}
        steps = whole.plan(doc, observe(self.root, doc)).steps
        self.assertEqual(steps[-1].field, "network.overlay")
        self.assertIsInstance(steps[-1].actions[1], WriteFile)

    def test_an_uplink_switch_refuses_the_overlay(self):
        uplink = whole.Step("network", (SwitchNetwork(
            "eth0", "etc/network/interfaces", "x", 120, (), (), ()),))
        with mock.patch.object(whole, "plan_network",
                               return_value=[uplink]):
            live = replace(observe(self.root, DOC), live=True,
                           available=frozenset(LIVE_COMMANDS),
                           overlay=state())
            steps = whole.plan(DOC, live).steps
        self.assertIsInstance(steps[-1].actions[0], Refuse)

    def test_skip_uplink_converges_the_overlay_alone(self):
        """What the console's overlay screen passes (confconsole#13)"""
        doc = {"version": 1, "network": {
            "managed_by": "file",
            "interfaces": {"eth0": {"ipv6": {"method": "static",
                                             "address": "2001:db8:1::5/64"}}},
            "overlay": {"wireguard": OVERLAY}}}
        # live, with an uplink that would move: skipped, it does not
        # hold the overlay back
        def uplink(network, net_state, live, available, window, skip,
                   skipped_by):
            if skip:
                return [whole.Step("network", (Note(skipped_by),))]
            return [whole.Step("network", (SwitchNetwork(
                "eth0", "etc/network/interfaces", "x", 120, (), (), ()),))]

        live = replace(observe(self.root, doc), live=True,
                       available=frozenset(LIVE_COMMANDS), overlay=state())
        with mock.patch.object(whole, "plan_network", side_effect=uplink):
            steps = whole.plan(doc, live, skip_uplink=True).steps
            self.assertEqual(steps[-2].actions, (Note("--skip-uplink"),))
            self.assertIsInstance(steps[-1].actions[0], SwitchNetwork)
            steps = whole.plan(doc, live).steps
            self.assertIsInstance(steps[-1].actions[0], Refuse)
        steps = whole.plan(doc, observe(self.root, doc),
                           skip_uplink=True).steps
        self.assertIn("(--skip-uplink)", steps[-2].actions[0].describe())
        self.assertIsInstance(steps[-1].actions[1], WriteFile)

    def test_the_uplink_step_ignores_the_overlay(self):
        doc = {"version": 1, "network": {
            "managed_by": "file",
            "interfaces": {"eth0": {"ipv6": {"method": "auto"}}},
            "overlay": {"wireguard": OVERLAY}}}
        observed = {"managed_by": "file", "interfaces": {
            "eth0": {"ipv6": {"method": "auto"}}}}
        from keel.system.netstate import NetworkState
        from keel.system.network import plan_network
        net = NetworkState(observed, {}, False, "file", False, None)
        found = actions(plan_network(doc["network"], net, True, ALL))
        self.assertIn("unchanged", found[0].describe())


class TestEffects(RootCase):
    def test_generate_key_goes_to_wgkeys_under_the_root(self):
        with mock.patch("keel.system.effects.wgkeys.generate",
                        return_value=None) as generate:
            problem = Effects(self.root).apply(
                GenerateKey("/etc/wireguard/wg0.key"))
        self.assertIsNone(problem)
        generate.assert_called_once_with(
            join(self.root, "etc/wireguard/wg0.key"))

    def test_the_overlay_switch_reaches_the_switch_with_its_kind(self):
        with mock.patch("keel.system.effects.switch.change",
                        return_value=None) as change:
            Effects(self.root).apply(SwitchNetwork(
                "wg0", "etc/wireguard/wg0.conf", RENDERED, 120,
                ("fd00:1::1",), (), (), kind="overlay", down_before=True,
                uplink_gateways=("2001:db8:1::1",)))
        pending = change.call_args.args[1]
        self.assertEqual((pending.kind, pending.iface, pending.addresses,
                          pending.down_before, pending.uplink_gateways),
                         ("overlay", "wg0", ("fd00:1::1",), True,
                          ("2001:db8:1::1",)))

    def test_adopt_key_goes_to_wgkeys_under_the_root(self):
        with mock.patch("keel.system.effects.wgkeys.adopt",
                        return_value=None) as adopt:
            self.assertIsNone(Effects(self.root).apply(ADOPT))
        adopt.assert_called_once_with(
            join(self.root, "etc/wireguard/wg0.conf"),
            join(self.root, "etc/wireguard/wg0.key"))

    def test_a_real_key_made_by_apply(self):
        tools = wgtools.require(self)
        with mock.patch.dict(os.environ, wgtools.env(tools)):
            problem = Effects(self.root).apply(
                GenerateKey("/etc/wireguard/wg0.key"))
        self.assertIsNone(problem)
        key = join(self.root, "etc/wireguard/wg0.key")
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        with open(key) as fob:
            self.assertTrue(wireguard.is_key(fob.read().strip()))
