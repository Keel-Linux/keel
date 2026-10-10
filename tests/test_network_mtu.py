# Copyright (c) 2026 KeelLinux maintainers
"""The overlay's MTU set live (keel#139)

After the upgrade to 0.23.13, wg0.conf had `MTU = 1280` and the live wg0
kept 1420: only `wg-quick up` reads the line, apply planned nothing and
diff said nothing. `ip link set dev wg0 mtu 1280` sets it with no
restart: in the live change of the peers (keel.network.switch), in
apply when the file is kept (keel.system.overlay), and in `keel network
mtu`, which the package's postinst runs. `ip` is replaced at the
boundary; tests/test_network_overlay_live_netns.py gives it the real one.
"""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from helpers import spec  # noqa: F401

import keel.commands  # noqa: F401, I001
from test_network_overlay_live import BEFORE, INTERFACE, dump, peer

from keel import commands, exits
from keel.network import mtu, switch

LINK = ("9: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu {} qdisc noqueue"
        " state UNKNOWN mode DEFAULT group default qlen 1000\n")
WITH = INTERFACE + "MTU = 1280\n"


def ip(values):
    """`ip link show dev IFACE` for interfaces of these MTUs"""
    def answer(argv):
        found = values.get(argv[-1])
        return None if found is None else LINK.format(found)
    return answer


class TestRead(unittest.TestCase):
    def test_the_mtu_of_ip_link_show(self):
        self.assertEqual(mtu.mtu_in(LINK.format(1420)), 1420)
        self.assertIsNone(mtu.mtu_in("9: wg0: <UP> qdisc noqueue"))
        self.assertIsNone(mtu.mtu_in("mtu"))
        self.assertEqual(mtu.live_mtu("wg0", ip({"wg0": 1280})), 1280)
        self.assertIsNone(mtu.live_mtu("wg0", ip({})))

    def test_the_live_reader_is_ip(self):
        with mock.patch("keel.network.live.output",
                        return_value=LINK.format(1420)) as output:
            self.assertEqual(mtu.live_mtu("wg0"), 1420)
        output.assert_called_once_with(("ip", "link", "show", "dev", "wg0"))
        with mock.patch.object(mtu, "live_mtu", return_value=7):
            self.assertEqual(switch.wg_mtu("wg0"), 7)


class TestLivePlan(unittest.TestCase):
    def test_a_live_mtu_that_is_not_the_file_s_is_set_live(self):
        after = WITH + peer(
            "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=", "fd00:1::2/128",
            "[2001:db8::2]:51820")
        # the old file had the line too, and wg0 never took it
        self.assertEqual(switch.live_plan(after, after, "wg0", dump(after),
                                          1420),
                         ([mtu.set_mtu("wg0", 1280)], False))
        # the line comes now, with wg0 up at 1420: no bounce
        self.assertEqual(switch.live_plan(BEFORE, after, "wg0",
                                          dump(BEFORE), 1420),
                         ([("ip", "link", "set", "dev", "wg0", "mtu",
                            "1280")], False))
        self.assertEqual(switch.live_plan(after, after, "wg0", dump(after),
                                          1280), ([], False))

    def test_what_is_still_a_bounce(self):
        # the line comes and wg0's MTU cannot be read; the line goes
        self.assertIsNone(switch.live_plan(BEFORE, WITH, "wg0",
                                           dump(BEFORE), None))
        self.assertIsNone(switch.live_plan(WITH, BEFORE, "wg0",
                                           dump(WITH), 1280))


class TestConverge(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(os.path.join(self.root, "etc/wireguard"))
        self.calls = []

    def write(self, name, text):
        with open(os.path.join(self.root, "etc/wireguard", name), "w") as fob:
            fob.write(text)

    def run_(self, problem=None):
        def run(argv):
            self.calls.append(argv)
            return problem
        return run

    def test_each_interface_up_gets_its_file_s_mtu(self):
        self.write("wg0.conf", WITH)
        self.write("wg1.conf", WITH)
        self.write("wg2.conf", INTERFACE)
        self.write("wg3.conf", WITH)
        found = mtu.converge(self.root, ip({"wg0": 1420, "wg1": 1280,
                                            "wg2": 1420}), self.run_())
        self.assertEqual(self.calls, [mtu.set_mtu("wg0", 1280)])
        self.assertEqual(found, ["wg0: MTU 1420 set to 1280, as its file"
                                 " says (ip link set, no restart)"])

    def test_a_failure_and_a_file_that_cannot_be_read_are_said(self):
        self.write("wg0.conf", WITH)
        found = mtu.converge(self.root, ip({"wg0": 1420}),
                             self.run_("ip exited 2: busy"))
        self.assertEqual(found, ["wg0: MTU 1420 is not its file's 1280, and"
                                 " ip link set failed: ip exited 2: busy"])
        with mock.patch("builtins.open", side_effect=OSError(13, "denied")):
            found = mtu.converge(self.root, ip({"wg0": 1420}), self.run_())
        self.assertIn("wg0: /etc/wireguard/wg0.conf cannot be read", found[0])

    def test_the_live_runner_is_live_run(self):
        self.write("wg0.conf", WITH)
        with mock.patch("keel.network.live.run", return_value=None) as run:
            mtu.converge(self.root, ip({"wg0": 1420}))
        run.assert_called_once_with(mtu.set_mtu("wg0", 1280))


class TestCommand(unittest.TestCase):
    def args(self):
        return SimpleNamespace(root="/tmp/keel-not-live")

    def test_prints_what_it_set_and_fails_on_a_failure(self):
        with mock.patch.object(mtu, "converge", return_value=[
                "wg0: MTU 1420 set to 1280"]):
            self.assertEqual(commands.network_mtu(self.args()), exits.OK)
        with mock.patch.object(mtu, "converge", return_value=[
                "wg0: ... ip link set failed: x", "wg1: MTU 1 set to 2"]), \
                mock.patch.object(commands, "error") as error:
            self.assertEqual(commands.network_mtu(self.args()),
                             exits.APPLY_FAILED)
        error.assert_called_once()

    def test_the_live_system_needs_root(self):
        with mock.patch("os.geteuid", return_value=1000):
            self.assertEqual(commands.network_mtu(SimpleNamespace(root="/")),
                             exits.APPLY_NEEDS_ROOT)

    def test_the_cli_names_it(self):
        from keel import cli
        with mock.patch.object(commands, "network_mtu",
                               return_value=0) as handler:
            self.assertEqual(cli.main(["network", "mtu", "--root",
                                       self.args().root]), 0)
        handler.assert_called_once()


if __name__ == "__main__":
    unittest.main()
