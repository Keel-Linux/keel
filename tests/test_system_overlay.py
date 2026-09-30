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

from keel.network import marker, wireguard
from keel.system.actions import (
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
                  pending=False, enabled=False, addresses=("fd00:1::1",))
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
                        self.root):
            found = observe_overlay(self.root, DOC)
        self.assertFalse(found.module_loaded)
        self.assertIn("0600", found.key_problem)


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
                ("fd00:1::1",), (), (), kind="overlay"))
        pending = change.call_args.args[1]
        self.assertEqual((pending.kind, pending.iface, pending.addresses),
                         ("overlay", "wg0", ("fd00:1::1",)))

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
