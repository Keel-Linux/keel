# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: network.* on a running machine (keel#35, decision 0018)

The planner is pure and decides from the comparison keel diff makes; the
file comes from inithooks' lib/ipconfig.sh, a copy of which is the
fixture tests/fixtures/network/ipconfig.sh.
"""

import os
import shutil
import tempfile
import unittest
from os.path import abspath, dirname, join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.network import marker
from keel.network.render import LIBRARY, Rendered, render
from keel.system import netstate
from keel.system.actions import Note, Refuse, SwitchNetwork, WriteFile
from keel.system.netstate import NetworkState, observe_network
from keel.system.network import (
    LIVE_COMMANDS,
    observed_gateways,
    plan_network,
    static_addresses,
)

HERE = dirname(abspath(__file__))
IPCONFIG = join(HERE, "fixtures", "network", "ipconfig.sh")
ALL = frozenset(LIVE_COMMANDS)
STATIC = {
    "managed_by": "file",
    "interfaces": {"eth0": {
        "ipv6": {"method": "static", "address": "2001:db8:1::20/64",
                 "gateway": "fe80::1"},
        "ipv4": {"method": "static", "address": "192.0.2.20/24",
                 "gateway": "192.0.2.1"},
    }},
    "nameservers": ["2001:db8:1::53"],
}
OBSERVED = {
    "managed_by": "file",
    "interfaces": {"eth0": {
        "ipv6": {"method": "static", "address": "2001:db8:1::10/64",
                 "gateway": "fe80::1"},
    }},
    "nameservers": ["2001:db8:1::53"],
}


def state(**overrides) -> NetworkState:
    values = dict(observed=OBSERVED, unknowns={}, in_container=False,
                  owner="file", pending=False,
                  rendered=Rendered(text="# the new file\n"))
    values.update(overrides)
    return NetworkState(**values)


def actions(steps):
    return [a for step in steps for a in step.actions]


class TestPlan(unittest.TestCase):
    def test_no_interfaces_declared_is_no_step(self):
        self.assertEqual(plan_network({}, None, True, ALL), [])

    def test_skip_network_is_a_note(self):
        found = actions(plan_network(STATIC, state(), True, ALL, skip=True))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Note)
        self.assertIn("--skip-network", found[0].describe())

    def test_a_host_owned_network_is_compared_not_converged(self):
        found = actions(plan_network(STATIC, state(owner="host"), True, ALL))
        self.assertIsInstance(found[0], Note)
        self.assertIn("host owns", found[0].describe())

    def test_no_drift_is_unchanged(self):
        found = actions(plan_network(OBSERVED, state(), True, ALL))
        self.assertEqual(len(found), 1)
        self.assertIn("unchanged", found[0].describe())

    def test_an_unknown_field_does_not_bounce_the_interface(self):
        declared = {"managed_by": "file", "interfaces": {
            "eth0": {"ipv6": {"method": "auto"}}}}
        observed = {"managed_by": "file", "interfaces": {"eth0": {}}}
        unknowns = {"network.interfaces.eth0.ipv6.method": "dhcp or auto"}
        found = actions(plan_network(declared, state(
            observed=observed, unknowns=unknowns), True, ALL))
        self.assertIn("unchanged", found[0].describe())

    def test_drift_on_the_live_system_is_a_switch_with_the_window(self):
        found = actions(plan_network(STATIC, state(), True, ALL, window=90))
        self.assertIn("differs: network.interfaces.eth0.ipv6.address",
                      found[0].describe())
        switch = found[1]
        self.assertIsInstance(switch, SwitchNetwork)
        self.assertEqual(switch.iface, "eth0")
        self.assertEqual(switch.window, 90)
        self.assertEqual(switch.content, "# the new file\n")
        self.assertEqual(switch.addresses, ("2001:db8:1::20", "192.0.2.20"))
        self.assertEqual(switch.gateways, ("fe80::1", "192.0.2.1"))
        self.assertEqual(switch.old_gateways, ("fe80::1",))
        self.assertIn("reverts in 90 s", switch.describe())

    def test_drift_under_a_root_is_a_write_and_no_window(self):
        found = actions(plan_network(STATIC, state(), False, frozenset()))
        self.assertIsInstance(found[1], WriteFile)
        self.assertEqual(found[1].path, "etc/network/interfaces")
        self.assertEqual(found[1].mode, 0o644)
        self.assertIn("no revert armed", found[2].describe())

    def test_a_pending_change_refuses_another(self):
        found = actions(plan_network(STATIC, state(pending=True), True, ALL))
        self.assertIsInstance(found[1], Refuse)
        self.assertIn("waiting for its confirmation", found[1].describe())

    def test_nothing_rendered_refuses_with_the_reason(self):
        for rendered, reason in ((Rendered(problem="no library"),
                                  "no library"), (None, "nothing rendered")):
            found = actions(plan_network(
                STATIC, state(rendered=rendered), True, ALL))
            self.assertIsInstance(found[1], Refuse)
            self.assertIn(reason, found[1].describe())

    def test_a_missing_command_refuses_on_the_live_system(self):
        found = actions(plan_network(STATIC, state(), True,
                                     ALL - {"systemd-run"}))
        self.assertIsInstance(found[1], Refuse)
        self.assertIn("systemd-run", found[1].describe())

    def test_drift_in_a_container_declared_file_is_refused(self):
        found = actions(plan_network(STATIC, state(in_container=True),
                                     True, ALL))
        self.assertIsInstance(found[1], Refuse)
        self.assertIn("container", found[1].describe())

    def test_drift_with_two_interfaces_is_refused(self):
        two = dict(STATIC, interfaces=dict(
            STATIC["interfaces"], eth1={"ipv6": {"method": "auto"}}))
        found = actions(plan_network(two, state(), True, ALL))
        self.assertIsInstance(found[-1], Refuse)
        self.assertIn("2 interfaces declared", found[-1].describe())

    def test_a_file_that_already_says_it_is_not_bounced(self):
        found = actions(plan_network(STATIC, state(
            current="# the new file\n"), True, ALL))
        self.assertEqual(len(found), 1)
        self.assertIn("already says", found[0].describe())

    def test_nameservers_the_file_cannot_hold_do_not_loop(self):
        declared = dict(OBSERVED, nameservers=["2001:db8:1::99"])
        found = actions(plan_network(declared, state(
            rendered=Rendered(text="iface eth0 inet6 dhcp\n")), True, ALL))
        self.assertEqual(len(found), 1)
        self.assertIn("cannot hold them", found[0].describe())

    def test_nameservers_the_file_can_hold_are_converged(self):
        declared = dict(OBSERVED, nameservers=["2001:db8:1::99"])
        found = actions(plan_network(declared, state(rendered=Rendered(
            text="    dns-nameservers 2001:db8:1::99\n")), True, ALL))
        self.assertIsInstance(found[-1], SwitchNetwork)

    def test_moving_to_another_interface_is_refused(self):
        moved = dict(STATIC, interfaces={"ens18": STATIC["interfaces"]
                                         ["eth0"]})
        found = actions(plan_network(moved, state(), True, ALL))
        self.assertIsInstance(found[-1], Refuse)
        self.assertIn("ens18 is declared and the file configures eth0",
                      found[-1].describe())

    def test_addresses_and_gateways_helpers(self):
        self.assertEqual(static_addresses({"ipv6": {"method": "dhcp"}}), ())
        self.assertEqual(observed_gateways(None), ())
        self.assertEqual(observed_gateways({"interfaces": {"eth0": None}}),
                         ())


class TestRender(unittest.TestCase):
    """The same functions as 01ipconfig, with the variables of the conf"""

    def test_static_ipv6_and_ipv4(self):
        env = {"IP_CONFIG": "static", "IP_ADDRESS": "192.0.2.20",
               "IP_NETMASK": "255.255.255.0", "IP_GW": "192.0.2.1",
               "IP6_CONFIG": "static", "IP6_ADDRESS": "2001:db8:1::20/64",
               "IP6_GW": "fe80::1", "IP6_DNS1": "2001:db8:1::53"}
        found = render(IPCONFIG, "eth0", "blog", env)
        self.assertIsNone(found.problem)
        self.assertEqual(found.text, (
            "# UNCONFIGURED INTERFACES\n"
            "# remove the above line if you edit this file\n\n"
            "auto lo\niface lo inet loopback\n\n"
            "auto eth0\niface eth0 inet static\n    hostname blog\n"
            "    address 192.0.2.20\n    netmask 255.255.255.0\n"
            "    gateway 192.0.2.1\n"
            "iface eth0 inet6 static\n    hostname blog\n"
            "    address 2001:db8:1::20/64\n    gateway fe80::1\n"
            "    dns-nameservers 2001:db8:1::53\n"
        ))

    def test_ipv6_only_keeps_ipv4_on_dhcp_as_the_hook_does(self):
        found = render(IPCONFIG, "eth0", "blog", {"IP6_CONFIG": "dhcp"})
        self.assertIn("iface eth0 inet dhcp\n", found.text)
        self.assertIn("iface eth0 inet6 dhcp\n", found.text)

    def test_a_value_is_never_parsed_as_shell(self):
        found = render(IPCONFIG, "eth0", "$(touch /tmp/keel-x); blog",
                       {"IP6_CONFIG": "dhcp"})
        self.assertIn("hostname $(touch /tmp/keel-x); blog", found.text)
        self.assertFalse(os.path.exists("/tmp/keel-x"))

    def test_the_library_refusing_is_the_problem(self):
        for env, reason in (
            ({"IP_CONFIG": "bogus"}, "invalid IP_CONFIG"),
            ({"IP6_CONFIG": "bogus"}, "invalid IP6_CONFIG"),
            ({"IP6_CONFIG": "static"}, "requires IP6_ADDRESS"),
            ({"IP_CONFIG": "static"}, "requires IP_ADDRESS"),
        ):
            found = render(IPCONFIG, "eth0", "blog", env)
            self.assertIsNone(found.text)
            self.assertIn(reason, found.problem)

    def test_no_library_is_the_problem(self):
        found = render("/nonexistent/ipconfig.sh", "eth0", "blog", {})
        self.assertIn("inithooks", found.problem)

    def test_no_bash_is_the_problem(self):
        with mock.patch("keel.network.render.subprocess.run",
                        side_effect=OSError(2, "No such file")):
            found = render(IPCONFIG, "eth0", "blog", {})
        self.assertIn("cannot run bash", found.problem)


class TestObserve(unittest.TestCase):
    """The state read once from a root, with the library under it"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(join(self.root, "etc", "network"))
        with open(join(self.root, "etc", "network", "interfaces"), "w") as f:
            f.write("auto eth0\niface eth0 inet6 static\n"
                    "    address 2001:db8:1::10/64\n")
        with open(join(self.root, "etc", "hostname"), "w") as f:
            f.write("blog\n")
        library = join(self.root, LIBRARY)
        os.makedirs(dirname(library))
        shutil.copy(IPCONFIG, library)

    def test_no_interfaces_is_none(self):
        self.assertIsNone(observe_network(self.root, {}))
        self.assertIsNone(observe_network(
            self.root, {"network": {"interfaces": []}}))

    def test_file_owned_renders_with_the_file_hostname(self):
        found = observe_network(self.root, {"network": STATIC})
        self.assertEqual(found.owner, "file")
        self.assertFalse(found.pending)
        self.assertIn("hostname blog", found.rendered.text)
        self.assertIn("address 2001:db8:1::20/64", found.rendered.text)
        self.assertEqual(
            found.observed["interfaces"]["eth0"]["ipv6"]["address"],
            "2001:db8:1::10/64")

    def test_an_undeclared_family_stays_as_the_machine_has_it(self):
        with open(join(self.root, "etc", "network", "interfaces"), "w") as f:
            f.write("auto eth0\niface eth0 inet static\n"
                    "    address 192.0.2.5\n    netmask 255.255.255.0\n"
                    "iface eth0 inet6 static\n"
                    "    address 2001:db8:1::10/64\n")
        ipv6_only = {"managed_by": "file", "interfaces": {"eth0": {
            "ipv6": STATIC["interfaces"]["eth0"]["ipv6"]}}}
        found = observe_network(self.root, {"network": ipv6_only})
        self.assertIn("iface eth0 inet static\n", found.rendered.text)
        self.assertIn("address 192.0.2.5\n", found.rendered.text)
        self.assertIn("address 2001:db8:1::20/64", found.rendered.text)
        self.assertEqual(found.current.count("192.0.2.5"), 1)

    def test_the_declared_hostname_wins(self):
        found = observe_network(self.root, {
            "network": STATIC, "instance": {"hostname": "news."}})
        self.assertIn("hostname news\n", found.rendered.text)

    def test_the_container_marker_makes_the_host_the_owner(self):
        marker_path = join(self.root, "var/lib/turnkey-info/"
                           "inithooks.service/lxc")
        os.makedirs(dirname(marker_path))
        open(marker_path, "w").close()
        undeclared = {k: v for k, v in STATIC.items() if k != "managed_by"}
        found = observe_network(self.root, {"network": undeclared})
        self.assertEqual(found.owner, "host")
        self.assertTrue(found.in_container)
        self.assertIsNone(found.rendered)

    def test_a_pending_marker_is_seen(self):
        marker.write(self.root, marker.Pending("eth0", "etc/network/"
                                               "interfaces", 120))
        self.assertTrue(observe_network(self.root, {"network": STATIC})
                        .pending)

    def test_hostname_falls_back_to_localhost(self):
        os.remove(join(self.root, "etc", "hostname"))
        tree = netstate.Tree(self.root)
        self.assertEqual(netstate.hostname(tree, {}), "localhost")


class TestRoundTrip(unittest.TestCase):
    """apply under a root writes the file, and diff then finds no drift"""

    SPEC = (
        "version: 1\n"
        "network:\n"
        "  managed_by: file\n"
        "  interfaces:\n"
        "    eth0:\n"
        "      ipv6:\n"
        "        method: static\n"
        "        address: 2001:db8:1::20/64\n"
        "        gateway: fe80::1\n"
        "      ipv4:\n"
        "        method: dhcp\n"
        "  nameservers:\n"
        "    - 2001:db8:1::53\n"
        "    - 2001:db8:1::54\n"
        "    - 192.0.2.53\n"
    )

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = join(self.tmp, "machine")
        shutil.copytree(join(HERE, "fixtures", "inspect", "turnkey"),
                        self.root)
        library = join(self.root, LIBRARY)
        os.makedirs(dirname(library))
        shutil.copy(IPCONFIG, library)
        self.spec = join(self.tmp, "instance.yaml")
        with open(self.spec, "w") as fob:
            fob.write(self.SPEC)

    def cli(self, *argv):
        from test_network_session import run_cli
        return run_cli(*argv)

    def test_drift_then_apply_then_same_then_unchanged(self):
        code, _, _ = self.cli("diff", "--spec", self.spec, "--root",
                              self.root)
        self.assertEqual(code, 14)
        code, out, _ = self.cli("spec", "apply", "--spec", self.spec,
                                "--system-only", "--root", self.root)
        self.assertEqual(code, 0, out)
        self.assertIn("network: write /etc/network/interfaces (mode 0644): done", out)
        code, out, _ = self.cli("diff", "--spec", self.spec, "--root",
                                self.root)
        self.assertEqual(code, 0, out)
        code, out, _ = self.cli("spec", "apply", "--spec", self.spec,
                                "--system-only", "--root", self.root)
        self.assertIn("network: unchanged", out)

    def test_skip_network_leaves_the_file(self):
        before = open(join(self.root, "etc/network/interfaces")).read()
        code, out, _ = self.cli("spec", "apply", "--spec", self.spec,
                                "--system-only", "--skip-network",
                                "--root", self.root)
        self.assertEqual(code, 0)
        self.assertIn("--skip-network", out)
        self.assertEqual(
            open(join(self.root, "etc/network/interfaces")).read(), before)


if __name__ == "__main__":
    unittest.main()
