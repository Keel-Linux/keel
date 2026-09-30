# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: the firewall derived from the manifests (0041)

Optional and for cloud advanced only (the maintainer, 2026-09-30). The
planner is pure over a FirewallState; the lockout guards are each a
test: the SSH port must be in what the ruleset opens, nothing moves
while a network change waits for its confirmation (0018), nft checks the
file before it is loaded, and a file keel did not write is never
replaced.
"""

import dataclasses
import os
import subprocess
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase

from keel.inspect.tree import File, Tree
from keel.manifest.facts import gather
from keel.manifest.firewall import HEADER, PATH, render
from keel.system.actions import Note, Refuse, RemoveFile, Run, WriteFile
from keel.system.firewall import plan_firewall
from keel.system.fwstate import FirewallState, observe_firewall, ssh_ports

LIVE = frozenset(("nft", "systemctl"))
STATES = {"installer": "enabled", "wireguard": "enabled",
          "etcd": "enabled", "crowdsec": "enabled"}
WG = {"address": "fd00:1::1/64", "private_key": {"file": "/etc/k"}}
ABSENT = File("/r/" + PATH, problem="not present")


def doc(enabled=True, wireguard=WG, mode="cloud_advanced") -> dict:
    found = {"version": 1, "appliance": {"name": "core"},
             "installation": {"mode": mode}, "overlays": STATES}
    if enabled is not None:
        found["firewall"] = {"enabled": enabled}
    if wireguard is not None:
        found["network"] = {"overlay": {"wireguard": wireguard}}
    return found


class FirewallCase(ManifestCase):
    def setUp(self):
        super().setUp()
        self.resolved = gather(self.root, "core").resolved

    def state(self, **fields) -> FirewallState:
        base = FirewallState(file=ABSENT, loaded=None, ssh_ports=(22,),
                             ssh_source="/r/etc/ssh/sshd_config",
                             pending=False)
        return dataclasses.replace(base, **fields)

    def rendered(self):
        return render(self.resolved, STATES, WG)

    def actions(self, spec=None, state=None, live=True, available=LIVE):
        steps = plan_firewall(spec if spec is not None else doc(),
                              self.resolved, state or self.state(), live,
                              available)
        return [action for step in steps for action in step.actions]


class TestEnabled(FirewallCase):
    def test_written_checked_then_loaded(self):
        found = self.actions()
        self.assertIsInstance(found[0], WriteFile)
        self.assertEqual((found[0].path, found[0].mode), (PATH, 0o600))
        self.assertEqual(found[0].content, self.rendered().text)
        self.assertEqual(found[0].describe(), (
            f"write /{PATH}: public tcp 22, 12320, 12321 and udp 51820,"
            " mesh tcp 2379, 2380 on wg0 (mode 0600)"))
        self.assertEqual([a.argv for a in found[1:]], [
            ("nft", "-c", "-f", f"/{PATH}"),
            ("nft", "-f", f"/{PATH}")])

    def test_the_same_file_loaded_is_unchanged(self):
        ruleset = self.rendered()
        found = self.actions(state=self.state(
            file=File("/r/x", ruleset.text), loaded=ruleset.digest))
        self.assertEqual([a.describe() for a in found], [
            f"unchanged (/{PATH}, loaded as table inet keel)"])

    def test_a_table_that_is_not_the_file_s_is_loaded_again(self):
        ruleset = self.rendered()
        found = self.actions(state=self.state(
            file=File("/r/x", ruleset.text), loaded=None))
        self.assertEqual([a.argv for a in found],
                         [("nft", "-c", "-f", f"/{PATH}"),
                          ("nft", "-f", f"/{PATH}")])

    def test_under_a_root_it_is_written_and_loaded_at_boot(self):
        found = self.actions(live=False, available=frozenset())
        self.assertIsInstance(found[0], WriteFile)
        self.assertEqual(found[1].describe(), (
            "not loaded: not the live system; keel-firewall.service loads"
            " it at boot"))

    def test_no_ssh_port_opened_is_refused_before_anything(self):
        found = self.actions(state=self.state(
            ssh_ports=(22, 2222), ssh_source="/r/etc/ssh/sshd_config"))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Refuse)
        self.assertEqual(found[0].describe(), (
            "the ruleset would close SSH: sshd listens on 2222/tcp"
            " (/r/etc/ssh/sshd_config), and no enabled process of the"
            " manifests opens it; nothing is written or loaded"))

    def test_nothing_moves_while_a_network_change_waits(self):
        found = self.actions(state=self.state(pending=True))
        self.assertEqual([type(a) for a in found], [Note])
        self.assertIn("keel network confirm", found[0].describe())

    def test_live_without_nft_is_refused(self):
        found = self.actions(available=frozenset(("systemctl",)))
        self.assertEqual([type(a) for a in found], [Refuse])
        self.assertIn("apt install nftables", found[0].describe())

    def test_a_file_keel_did_not_write_is_not_replaced(self):
        found = self.actions(state=self.state(
            file=File("/r/x", "table inet mine {}\n")))
        self.assertEqual([type(a) for a in found], [Refuse])
        self.assertIn("keel did not write it", found[0].describe())

    def test_the_renderer_s_notes_are_said(self):
        found = self.actions(doc(wireguard=None))
        self.assertIn("2379/tcp, 2380/tcp of etcd not opened: they are mesh"
                      " ports, and the spec declares no"
                      " network.overlay.wireguard",
                      [a.describe() for a in found])


class TestOff(FirewallCase):
    def test_not_declared_is_no_step(self):
        self.assertEqual(self.actions(doc(enabled=None)), [])

    def test_not_declared_says_that_keel_s_table_is_left(self):
        found = self.actions(doc(enabled=None), self.state(
            file=File("/r/x", HEADER + "\n")))
        self.assertEqual([a.describe() for a in found], [
            "not declared: the firewall keel set up earlier is left as it"
            " is; `firewall.enabled: false` removes it"])

    def test_off_removes_keel_s_file_and_table(self):
        found = self.actions(doc(enabled=False), self.state(
            file=File("/r/x", HEADER + "\n"), loaded="abc"))
        self.assertIsInstance(found[0], RemoveFile)
        self.assertEqual(found[0].path, PATH)
        self.assertEqual(found[1].argv, ("nft", "delete", "table", "inet",
                                         "keel"))

    def test_off_with_nothing_of_keel_s_is_unchanged(self):
        found = self.actions(doc(enabled=False, mode="simple"), self.state(
            file=File("/r/x", "table inet mine {}\n")))
        self.assertEqual([a.describe() for a in found], ["unchanged (off)"])

    def test_off_under_a_root_removes_the_file_only(self):
        found = self.actions(doc(enabled=False), self.state(
            file=File("/r/x", HEADER + "\n"), loaded=None), live=False,
            available=frozenset())
        self.assertEqual([type(a) for a in found], [RemoveFile])

    def test_no_appliance_state_is_no_step(self):
        self.assertEqual(plan_firewall(doc(), None, None, True, LIVE), [])


class TestBootUnit(FirewallCase):
    def test_the_shipped_unit_loads_the_file_apply_writes(self):
        unit = join(os.path.dirname(os.path.dirname(os.path.abspath(
            __file__))), "debian", "keel.keel-firewall.service")
        with open(unit) as fob:
            lines = fob.read().splitlines()
        self.assertIn(f"ConditionPathExists=/{PATH}", lines)
        self.assertIn(f"ExecStart=/usr/sbin/nft -f /{PATH}", lines)
        self.assertIn("After=local-fs.target nftables.service", lines)
        self.assertIn("Before=network-pre.target shutdown.target", lines)


class TestObserve(FirewallCase):
    def write(self, path: str, text: str) -> None:
        full = join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)

    def test_ssh_ports_default_to_22(self):
        self.assertEqual(ssh_ports(Tree(self.root))[0], (22,))

    def test_ssh_ports_from_the_config_and_its_drop_ins(self):
        self.write("etc/ssh/sshd_config",
                   "Include /etc/ssh/sshd_config.d/*.conf\n#Port 99\n"
                   "Port 22\nListenAddress [2001:db8::1]:2200\n"
                   "ListenAddress 192.0.2.1:2201\nListenAddress ::1\n")
        self.write("etc/ssh/sshd_config.d/10-keel.conf", "port 2222\n")
        ports, source = ssh_ports(Tree(self.root))
        self.assertEqual(ports, (22, 2200, 2201, 2222))
        self.assertIn("sshd_config", source)

    def test_the_live_table_s_digest(self):
        listing = 'table inet keel {\n\tcomment "keel-manifest 0123"\n'

        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, listing, "")
        with mock.patch("keel.system.fwstate.subprocess.run", run):
            found = observe_firewall(Tree(self.root), True)
        self.assertEqual(found.loaded, "0123")

    def test_no_table_or_no_nft_is_none(self):
        def absent(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "No such file")

        def missing(argv, **kwargs):
            raise OSError(2, "No such file or directory")
        for run in (absent, missing):
            with mock.patch("keel.system.fwstate.subprocess.run", run):
                self.assertIsNone(observe_firewall(Tree(self.root),
                                                   True).loaded)
        self.assertIsNone(observe_firewall(Tree(self.root), False).loaded)

    def test_a_pending_network_change(self):
        self.write("var/lib/keel/network/pending.json", "{}\n")
        self.assertTrue(observe_firewall(Tree(self.root), False).pending)
