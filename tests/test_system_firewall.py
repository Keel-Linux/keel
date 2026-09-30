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
import stat
import subprocess
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase

from keel.inspect.tree import File, Tree
from keel.manifest.facts import gather
from keel.manifest.firewall import HEADER, PATH, render
from keel.system.actions import (
    InstallRuleset,
    Note,
    Refuse,
    RemoveFile,
    Run,
    WriteFile,
)
from keel.system.effects import Effects
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


class Answers:
    """subprocess.run answering by command name; OSError for the rest"""

    def __init__(self, table: dict):
        self.table = table
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv[0] not in self.table:
            raise OSError(2, "No such file or directory")
        code, out = self.table[argv[0]]
        return subprocess.CompletedProcess(argv, code, out, "")


class FirewallCase(ManifestCase):
    def setUp(self):
        super().setUp()
        self.resolved = gather(self.root, "core").resolved

    def state(self, **fields) -> FirewallState:
        base = FirewallState(file=ABSENT, loaded=None, ssh_ports=(22,),
                             ssh_source="/r/etc/ssh/sshd_config",
                             pending=False, bridges=())
        return dataclasses.replace(base, **fields)

    def rendered(self):
        return render(self.resolved, STATES, WG)

    def actions(self, spec=None, state=None, live=True, available=LIVE):
        steps = plan_firewall(spec if spec is not None else doc(),
                              self.resolved, state or self.state(), live,
                              available)
        return [action for step in steps for action in step.actions]


class TestEnabled(FirewallCase):
    def test_checked_as_a_copy_put_in_place_then_loaded(self):
        """a file nft refuses never reaches the path the boot unit loads"""
        found = self.actions()
        self.assertIsInstance(found[0], InstallRuleset)
        self.assertEqual(found[0].path, PATH)
        self.assertEqual(found[0].content, self.rendered().text)
        self.assertEqual(found[0].describe(), (
            f"write /{PATH}: public tcp 22, 12320, 12321 and udp 51820,"
            " mesh tcp 2379, 2380 on wg0; checked by nft -c as a copy"
            " first, so a file nft refuses is never put in place (mode"
            " 0600)"))
        self.assertEqual([a.argv for a in found[1:]], [
            ("nft", "-f", f"/{PATH}")])

    def test_the_ssh_ports_unknown_is_refused_and_never_guessed(self):
        found = self.actions(state=self.state(
            ssh_ports=(), ssh_source="sshd -T failed and /r/etc/ssh/"
            "sshd_config cannot be read"))
        self.assertEqual([type(a) for a in found], [Refuse])
        self.assertEqual(found[0].describe(), (
            "the ports sshd listens on cannot be determined (sshd -T failed"
            " and /r/etc/ssh/sshd_config cannot be read): no firewall is"
            " applied, since one could close SSH; nothing is written or"
            " loaded"))

    def test_the_host_s_bridges_are_in_the_ruleset(self):
        found = self.actions(state=self.state(bridges=("lxcbr0",)))
        self.assertIn('iifname "lxcbr0" udp dport { 53, 67, 547 } accept',
                      found[0].content)

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
        self.assertEqual((found[0].path, found[0].mode), (PATH, 0o600))
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


class TestInstall(FirewallCase):
    """The copy nft checks, and what is left on disk either way"""

    def install(self, code: int, err: str = "") -> tuple:
        target = join(self.root, PATH)
        calls = []

        def nft(argv, **kwargs):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, code, "", err)
        with mock.patch("keel.system.fwinstall.subprocess.run", nft):
            problem = Effects(self.root).apply(
                InstallRuleset(PATH, "table inet keel {}\n", "x"))
        return problem, target, calls

    def test_a_checked_copy_is_put_in_place(self):
        problem, target, calls = self.install(0)
        self.assertIsNone(problem)
        with open(target) as fob:
            self.assertEqual(fob.read(), "table inet keel {}\n")
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        self.assertEqual(calls, [("nft", "-c", "-f",
                                  target + ".keel-check")])
        self.assertEqual(os.listdir(os.path.dirname(target)),
                         ["keel-manifest.nft"])

    def test_a_refused_copy_is_removed_and_the_old_file_kept(self):
        os.makedirs(os.path.dirname(join(self.root, PATH)))
        with open(join(self.root, PATH), "w") as fob:
            fob.write("old\n")
        problem, target, _ = self.install(1, "Error: syntax error\n")
        self.assertEqual(problem, "nft -c refused the ruleset, which is"
                                  " not put in place: Error: syntax error")
        with open(target) as fob:
            self.assertEqual(fob.read(), "old\n")
        self.assertEqual(os.listdir(os.path.dirname(target)),
                         ["keel-manifest.nft"])

    def test_no_nft(self):
        def missing(argv, **kwargs):
            raise OSError(2, "No such file or directory")
        with mock.patch("keel.system.fwinstall.subprocess.run", missing):
            problem = Effects(self.root).apply(
                InstallRuleset(PATH, "x\n", "x"))
        self.assertEqual(problem, "cannot run nft: No such file or"
                                  " directory")
        self.assertFalse(os.path.exists(join(self.root, PATH)))


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

    def test_no_config_is_unknown_never_22(self):
        ports, why = ssh_ports(Tree(self.root), False)
        self.assertEqual(ports, ())
        self.assertIn("sshd_config not present", why)

    def test_a_config_that_sets_no_port_is_sshd_s_default(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n")
        ports, source = ssh_ports(Tree(self.root), False)
        self.assertEqual(ports, (22,))
        self.assertIn("sets no Port: sshd's default", source)

    def test_every_spelling_sshd_reads(self):
        self.write("etc/ssh/sshd_config",
                   "Include /etc/ssh/sshd_config.d/*.conf\n#Port 99\n"
                   "Port=2222\nPort = 2223\n\tport\t2224\n"
                   "ListenAddress [2001:db8::1]:2200 rdomain vrf1\n"
                   "ListenAddress=192.0.2.1:2201\nListenAddress ::1\n")
        self.write("etc/ssh/sshd_config.d/10-keel.conf", "port 2225\n")
        ports, _ = ssh_ports(Tree(self.root), False)
        self.assertEqual(ports, (2200, 2201, 2222, 2223, 2224, 2225))

    def test_an_include_it_cannot_follow_is_unknown(self):
        self.write("etc/ssh/sshd_config", "Include /opt/ssh/*.conf\n")
        ports, why = ssh_ports(Tree(self.root), False)
        self.assertEqual(ports, ())
        self.assertIn("Include /opt/ssh/*.conf", why)

    def test_live_asks_sshd_and_the_socket(self):
        run = Answers({
            "sshd": (0, "port 22\nlistenaddress [::]:2222 rdomain x\n"
                        "listenaddress 0.0.0.0:22\naddressfamily any\n"),
            "systemctl": (0, "ActiveState=active\n"
                             "Listen=[::]:2230 (Stream) 0.0.0.0:22 (Stream)"
                             "\n"),
        })
        ports, source = ssh_ports(Tree(self.root), True, run)
        self.assertEqual(ports, (22, 2222, 2230))
        self.assertEqual(source, "sshd -T, ssh.socket")
        self.assertEqual(run.calls[:2], [
            ("sshd", "-T"),
            ("systemctl", "show", "ssh.socket", "-p", "ActiveState",
             "-p", "Listen")])

    def test_an_inactive_socket_adds_nothing(self):
        run = Answers({"sshd": (0, "port 22\n"),
                       "systemctl": (0, "ActiveState=inactive\n"
                                        "Listen=[::]:2230 (Stream)\n")})
        self.assertEqual(ssh_ports(Tree(self.root), True, run),
                         ((22,), "sshd -T"))

    def test_an_active_socket_without_a_stream_adds_nothing(self):
        run = Answers({"sshd": (0, "port 22\n"),
                       "systemctl": (0, "ActiveState=active\nListen=\n")})
        self.assertEqual(ssh_ports(Tree(self.root), True, run),
                         ((22,), "sshd -T"))

    def test_live_without_sshd_t_falls_back_to_the_files(self):
        self.write("etc/ssh/sshd_config", "Port 2222\n")
        run = Answers({"systemctl": (1, "")})
        ports, source = ssh_ports(Tree(self.root), True, run)
        self.assertEqual(ports, (2222,))
        self.assertIn("sshd_config", source)

    def test_the_host_s_bridges(self):
        for name in ("lxcbr0", "docker0"):
            os.makedirs(join(self.root, "sys/class/net", name, "bridge"))
        os.makedirs(join(self.root, "sys/class/net/eth0"))
        self.assertEqual(observe_firewall(Tree(self.root), False).bridges,
                         ("docker0", "lxcbr0"))

    def port(self, bridge: str, name: str, device: bool = False,
             devtype: str | None = None, tap: bool = False) -> None:
        """An interface enslaved to BRIDGE, as /sys/class/net shows it"""
        os.makedirs(join(self.root, "sys/class/net", bridge, "bridge"),
                    exist_ok=True)
        os.makedirs(join(self.root, "sys/class/net", bridge, "brif", name))
        self.write(f"sys/class/net/{name}/uevent",
                   f"INTERFACE={name}\n"
                   + (f"DEVTYPE={devtype}\n" if devtype else ""))
        if device:
            os.symlink("../../../0000:01:00.0",
                       join(self.root, "sys/class/net", name, "device"))
        if tap:
            self.write(f"sys/class/net/{name}/tun_flags", "0x1002\n")

    def test_an_uplink_bridge_is_never_exempt(self):
        """a Proxmox vmbr0 with a physical port reaches the internet:
        opening 53, 67 and 547 on it would open them to everybody"""
        self.port("vmbr0", "enp1s0", device=True)
        self.port("vmbr0", "tap100i0", tap=True)
        self.port("br1", "eno1.10", devtype="vlan")
        self.port("br2", "bond0", devtype="bond")
        self.assertEqual(observe_firewall(Tree(self.root), False).bridges,
                         ())

    def test_a_nat_bridge_of_veths_and_taps_is_exempt(self):
        self.port("lxcbr0", "vethAbC123")
        self.port("virbr0", "vnet0", tap=True)
        os.makedirs(join(self.root, "sys/class/net/docker0/bridge"))
        self.assertEqual(observe_firewall(Tree(self.root), False).bridges,
                         ("docker0", "lxcbr0", "virbr0"))

    def test_a_bridge_that_holds_a_default_route_is_not_exempt(self):
        self.port("lxcbr0", "vethAbC123")
        self.port("br6", "vethDeF456")
        self.port("br7", "vethGhI789")
        self.write("proc/net/route",
                   "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric"
                   "\tMask\tMTU\tWindow\tIRTT\n"
                   "br7\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0"
                   "\t0\n"
                   "lxcbr0\t0003000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0"
                   "\t0\t0\n")
        self.write("proc/net/ipv6_route",
                   "00000000000000000000000000000000 00 "
                   "00000000000000000000000000000000 00 "
                   "fe800000000000000000000000000001 00000400 00000001"
                   " 00000000 00000003 br6\n"
                   "00000000000000000000000000000000 00 "
                   "00000000000000000000000000000000 00 "
                   "00000000000000000000000000000000 ffffffff 00000001"
                   " 00000000 00200200 lo\n"
                   "fd420000000000b20000000000000001 40 "
                   "00000000000000000000000000000000 00 "
                   "00000000000000000000000000000000 00000100 00000001"
                   " 00000000 00000001 lxcbr0\n")
        self.assertEqual(observe_firewall(Tree(self.root), False).bridges,
                         ("lxcbr0",))

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
