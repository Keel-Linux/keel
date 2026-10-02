# Copyright (c) 2026 KeelLinux maintainers
"""overlays.wireguard, read from the interface apply converges (0041)

The WireGuard overlay owns no unit in its manifest: the interface is the
spec's (network.overlay.wireguard), and apply enables wg-quick@<iface>
once a change of it is confirmed (keel.system.overlay). So inspect reads
the state the way apply leaves it: the unit's link and, on the live
system, whether the interface is up. Screenshots 047 and 057 of step 8
showed "not inferred" with wg0 up and its unit enabled.
"""

import os
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.overlays import wireguard_state
from keel.inspect.tree import Tree
from keel.network.wireguard import WANTS


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.asked = []

    def tearDown(self):
        self.tmp.cleanup()

    def conf(self, iface: str) -> None:
        os.makedirs(join(self.root, "etc/wireguard"), exist_ok=True)
        with open(join(self.root, f"etc/wireguard/{iface}.conf"), "w"):
            pass

    def enable(self, iface: str) -> None:
        link = join(self.root, WANTS.format(iface=iface))
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink("/usr/lib/systemd/system/wg-quick@.service", link)

    def link_up(self, up: set):
        def probe(iface: str) -> bool:
            self.asked.append(iface)
            return iface in up
        return probe

    def state(self, live: bool, up: set = frozenset()):
        return wireguard_state(Tree(self.root), live, self.link_up(up))


class TestLive(Case):
    def test_unit_enabled_and_interface_up_is_enabled(self):
        self.conf("wg0")
        self.enable("wg0")
        self.assertEqual(self.state(True, {"wg0"}), (
            "enabled", "wg-quick@wg0.service enabled, wg0 up"))
        self.assertEqual(self.asked, ["wg0"])

    def test_no_unit_and_interface_down_is_disabled(self):
        self.conf("wg0")
        self.assertEqual(self.state(True), (
            "disabled", "wg-quick@wg0.service disabled, wg0 down"))

    def test_up_but_not_enabled_is_not_a_state(self):
        # a change brought up and waiting for its confirmation
        self.conf("wg0")
        self.assertEqual(self.state(True, {"wg0"}), (
            None, "wg-quick@wg0.service disabled, wg0 up"))

    def test_enabled_but_down_is_not_a_state(self):
        # the drift apply restarts the unit for
        self.conf("wg0")
        self.enable("wg0")
        self.assertEqual(self.state(True), (
            None, "wg-quick@wg0.service enabled, wg0 down"))

    def test_the_default_interface_is_the_one_read(self):
        self.conf("wg1")
        self.conf("wg0")
        self.enable("wg1")
        self.assertEqual(self.state(True)[0], "disabled")
        self.assertEqual(self.asked, ["wg0"])

    def test_another_name_is_read_when_it_is_the_only_one(self):
        self.conf("mesh")
        self.enable("mesh")
        self.assertEqual(self.state(True, {"mesh"}), (
            "enabled", "wg-quick@mesh.service enabled, mesh up"))

    def test_no_file_says_nothing(self):
        self.enable("wg0")
        self.assertIsNone(self.state(True, {"wg0"}))
        self.assertEqual(self.asked, [])


class TestUnderARoot(Case):
    def test_the_link_alone_decides_and_no_interface_is_asked(self):
        self.conf("wg0")
        self.assertEqual(self.state(False), (
            "disabled", "wg-quick@wg0.service disabled"))
        self.enable("wg0")
        self.assertEqual(self.state(False), (
            "enabled", "wg-quick@wg0.service enabled"))
        self.assertEqual(self.asked, [])


if __name__ == "__main__":
    unittest.main()
