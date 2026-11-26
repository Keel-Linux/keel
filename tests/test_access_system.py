# Copyright (c) 2026 KeelLinux maintainers
"""The access network on the node (decision 0098): its plan, what the
plan reads, its drift in keel diff, keel access list and remove, the
SSH rule of answer 6 and the sockets rule B sees on it"""

import argparse
import dataclasses
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)
from test_access_network import ACCESS, KEY_A, KEY_B, KEY_C
from test_system_firewall import FirewallCase
from test_system_firewall import doc as fwdoc

from keel import exits
from keel.access import commands
from keel.diff import access as diffaccess
from keel.diff.report import DRIFT, SAME
from keel.inspect.tree import File, Tree
from keel.manifest.firewall import SSH_LINE
from keel.network import access as acc
from keel.system import accstate, fwstate
from keel.system.access import plan_access
from keel.system.accstate import AccessState, observe_access
from keel.system.actions import GenerateKey, Note, Refuse, RemoveFile, Run
from keel.system.actions import WriteFile
from keel.system.firewall import ssh_narrowed
from keel.system.listeners import Listener, classify, unopened

LIVE = frozenset(("wg", "wg-quick", "ip", "systemctl"))
DB = {"server": {"engine": "mariadb"}}
CONF = acc.conf_path("keel-access")
SOCKET = "etc/systemd/system/keel-access-relay-3306.socket"
SERVICE = "etc/systemd/system/keel-access-relay-3306.service"
PEER = "fd12:3456:789a:1::2/128"


def doc(access=ACCESS, database=DB) -> dict:
    found = {"version": 1, "network": {"access": access}}
    if database:
        found["database"] = database
    return found


def state(**fields) -> AccessState:
    access = fields.pop("access", ACCESS)
    whole = doc(access)
    wanted = acc.relay_files(access, whole)
    base = AccessState(
        iface="keel-access", declared=True, current=acc.render(access),
        rendered=acc.render(access), key_path=acc.key_path(access),
        key_present=True, enabled=True, up=True,
        held={KEY_A: PEER}, wanted_peers=acc.wanted_peers(access),
        relays=dict(wanted), wanted=wanted,
        sockets_enabled=frozenset(acc.relay_socket_units(wanted)),
        sockets_active=frozenset(acc.relay_socket_units(wanted)))
    return dataclasses.replace(base, **fields)


def actions(found: AccessState | None, live=True, available=LIVE) -> list:
    return [action for step in plan_access(found, live, available)
            for action in step.actions]


def argvs(found: list) -> list:
    return [action.argv for action in found if isinstance(action, Run)]


class TestPlan(unittest.TestCase):
    def test_nothing_declared_and_nothing_written_is_no_step(self):
        self.assertEqual(plan_access(None, True, LIVE), [])

    def test_the_same_files_and_peers_are_unchanged(self):
        found = actions(state())
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], Note)
        self.assertIn("unchanged", found[0].summary)

    def test_a_first_converge_makes_the_key_and_brings_it_up(self):
        found = actions(state(key_present=False, current=None,
                              enabled=False, up=False, held=None,
                              relays={}, sockets_enabled=frozenset()))
        self.assertIsInstance(found[0], GenerateKey)
        writes = [one.path for one in found if isinstance(one, WriteFile)]
        self.assertEqual(writes, [CONF, SERVICE, SOCKET])
        self.assertEqual(next(one.mode for one in found
                              if isinstance(one, WriteFile)), 0o600)
        self.assertEqual(argvs(found), [
            ("systemctl", "enable", "keel-access@keel-access.service"),
            ("systemctl", "restart", "keel-access@keel-access.service"),
            ("systemctl", "daemon-reload"),
            ("systemctl", "enable", "--now",
             "keel-access-relay-3306.socket")])

    def test_under_a_root_the_key_is_not_made_and_nothing_runs(self):
        found = actions(state(key_present=False, current=None),
                        live=False, available=frozenset())
        self.assertIsInstance(found[0], Note)
        self.assertIn("never in an image", found[0].summary)
        self.assertEqual(argvs(found), [])
        self.assertTrue(any(isinstance(one, WriteFile) and one.path == CONF
                            for one in found))

    def test_a_new_computer_is_added_live_and_a_stranger_removed(self):
        two = {**ACCESS, "peers": ACCESS["peers"] + [{
            "name": "desk", "public_key": KEY_B,
            "address": "fd12:3456:789a:1::3/128",
            "enrolled": "2026-11-25"}]}
        found = actions(state(access=two, current=acc.render(ACCESS),
                              held={KEY_A: PEER, KEY_C: "fd99::1/128"}))
        self.assertEqual(argvs(found), [
            ("wg", "set", "keel-access", "peer", KEY_B, "allowed-ips",
             "fd12:3456:789a:1::3/128"),
            ("wg", "set", "keel-access", "peer", KEY_C, "remove")])

    def test_an_interface_change_restarts_and_unknown_peers_too(self):
        moved = {**ACCESS, "listen_port": 51823}
        found = actions(state(access=moved, current=acc.render(ACCESS)))
        self.assertIn(("systemctl", "restart",
                       "keel-access@keel-access.service"), argvs(found))
        found = actions(state(held=None))
        self.assertEqual(argvs(found), [
            ("systemctl", "restart", "keel-access@keel-access.service")])

    def test_refusals(self):
        found = actions(state(), available=frozenset(("ip",)))
        self.assertIsInstance(found[0], Refuse)
        found = actions(state(current="[Interface]\n"))
        self.assertIsInstance(found[0], Refuse)
        self.assertIn("keel did not write it", found[0].summary)
        found = actions(state(relays={SOCKET: "[Socket]\n"}))
        self.assertTrue(all(isinstance(one, Refuse) for one in found))
        found = actions(state(key_problem="mode 0644"))
        self.assertIsInstance(found[0], Refuse)

    def test_a_relay_that_should_run_and_does_not_is_started(self):
        found = actions(state(sockets_active=frozenset()))
        self.assertEqual(argvs(found), [
            ("systemctl", "start", "keel-access-relay-3306.socket")])
        found = actions(state(), live=False, available=frozenset())
        self.assertEqual(argvs(found), [])

    def test_a_changed_relay_restarts_and_a_stale_one_goes(self):
        wanted = acc.relay_files(ACCESS, doc())
        stale = "etc/systemd/system/keel-access-relay-5432.socket"
        found = actions(state(relays={**wanted, SOCKET: acc.HEADER[0],
                                      stale: acc.HEADER[0]}))
        self.assertEqual(argvs(found), [
            ("systemctl", "disable", "--now",
             "keel-access-relay-5432.socket"),
            ("systemctl", "daemon-reload"),
            ("systemctl", "restart", "keel-access-relay-3306.socket")])
        self.assertTrue(any(isinstance(one, RemoveFile)
                            and one.path == stale for one in found))

    def test_a_section_removed_takes_keel_s_interface_down(self):
        found = actions(AccessState(
            iface="keel-access", declared=False,
            current=acc.render(ACCESS), rendered=None, enabled=True,
            up=True, relays={SOCKET: acc.HEADER[0]}))
        self.assertEqual(argvs(found), [
            ("systemctl", "disable", "--now",
             "keel-access@keel-access.service"),
            ("systemctl", "disable", "--now",
             "keel-access-relay-3306.socket"),
            ("systemctl", "daemon-reload")])
        self.assertEqual([one.path for one in found
                          if isinstance(one, RemoveFile)], [CONF, SOCKET])
        found = actions(AccessState(iface="keel-access", declared=False,
                                    current=None, rendered=None))
        self.assertIn("unchanged", found[0].summary)


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def put(self, path: str, text: str) -> None:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)


class TestObserve(RootCase):
    def test_nothing_declared_nothing_written(self):
        self.assertIsNone(observe_access(self.root, {"version": 1}))

    def test_what_keel_wrote_is_seen_when_the_section_goes(self):
        self.put(CONF, acc.render(ACCESS))
        self.put(SOCKET, acc.HEADER[0] + "\n")
        self.put("etc/systemd/system/keel-access-relay-9.socket", "other\n")
        found = observe_access(self.root, {"version": 1})
        self.assertFalse(found.declared)
        self.assertEqual(found.iface, "keel-access")
        self.assertEqual(list(found.relays), [SOCKET])
        self.assertIsNone(found.up)

    def test_a_declared_section_is_rendered_under_the_root(self):
        self.put(SOCKET, "x")
        self.put("etc/systemd/system/sockets.target.wants/"
                 "keel-access-relay-3306.socket", "")
        found = observe_access(self.root, doc())
        self.assertTrue(found.declared)
        self.assertIsNone(found.current)
        self.assertFalse(found.key_present)
        self.assertEqual(found.rendered, acc.render(ACCESS))
        self.assertEqual(found.relays[SOCKET], "x")
        self.assertEqual(found.sockets_enabled,
                         frozenset({"keel-access-relay-3306.socket"}))
        self.assertIsNone(found.held)

    def test_the_active_relays_come_from_systemctl(self):
        done = mock.Mock(returncode=0, stdout="active\n")
        with mock.patch("keel.system.accstate.subprocess.run",
                        return_value=done):
            self.assertTrue(accstate.active("x.socket"))
        done.stdout = "inactive\n"
        with mock.patch("keel.system.accstate.subprocess.run",
                        return_value=done):
            self.assertFalse(accstate.active("x.socket"))
        with mock.patch("keel.system.accstate.subprocess.run",
                        side_effect=OSError):
            self.assertFalse(accstate.active("x.socket"))

    def test_the_held_peers_come_from_wg_show(self):
        done = mock.Mock(returncode=0, stdout=f"{KEY_A}\t{PEER}\n")
        with mock.patch("keel.system.accstate.subprocess.run",
                        return_value=done):
            self.assertEqual(accstate.held_peers("keel-access"),
                             {KEY_A: PEER})
        done.returncode = 1
        with mock.patch("keel.system.accstate.subprocess.run",
                        return_value=done):
            self.assertIsNone(accstate.held_peers("keel-access"))
        with mock.patch("keel.system.accstate.subprocess.run",
                        side_effect=OSError):
            self.assertIsNone(accstate.held_peers("keel-access"))


class TestFirstBootRelay(RootCase):
    """keel#340: at the first boot's apply (10keel-system) the spec has no
    database section yet: 75keel-role records database.server later, and
    no apply follows. The relay follows the engine installed then"""

    MARIADBD = "usr/sbin/mariadbd"
    POSTGRES = "usr/lib/postgresql/17/bin/postgres"

    def test_the_installed_engine_when_none_is_declared(self):
        self.assertEqual(acc.relay_ports({}, "mariadb"), (3306,))
        self.assertEqual(acc.relay_ports({}, "postgresql"), (5432,))
        self.assertEqual(acc.relay_ports({}, None), ())
        # what the spec declares comes first, also an engine with no relay
        self.assertEqual(acc.relay_ports({"database": {"server": {
            "engine": "postgresql"}}}, "mariadb"), (5432,))
        self.assertEqual(acc.relay_ports({"database": {"server": {
            "engine": "redis"}}}, "mariadb"), ())

    def test_the_engine_is_the_one_server_binary_on_the_tree(self):
        tree = Tree(self.root)
        self.assertIsNone(accstate.installed_engine(tree))
        self.put(self.MARIADBD, "")
        self.assertEqual(accstate.installed_engine(tree), "mariadb")
        # two engines: no guess
        self.put(self.POSTGRES, "")
        self.assertIsNone(accstate.installed_engine(tree))

    def test_a_spec_with_no_database_section_wants_the_relay(self):
        self.put(self.MARIADBD, "")
        found = observe_access(self.root, doc(database=None))
        self.assertEqual(sorted(found.wanted), [SERVICE, SOCKET])
        self.assertEqual(found.wanted, acc.relay_files(ACCESS, doc()))

    def test_no_database_server_no_relay(self):
        found = observe_access(self.root, doc(database=None))
        self.assertEqual(found.wanted, {})

    def test_the_firewall_opens_the_same_port(self):
        from keel.system.firewall import access_of
        self.put(self.MARIADBD, "")
        state = fwstate.observe_firewall(Tree(self.root), False)
        self.assertEqual(state.db_engine, "mariadb")
        self.assertEqual(access_of(doc(database=None),
                                   state.db_engine).relays, (3306,))
        self.assertEqual(access_of(doc(database=None)).relays, ())


class TestDiff(RootCase):
    def test_same_and_drift_under_a_root(self):
        self.put(CONF, acc.render(ACCESS))
        fields = {one.field: one for one in diffaccess.access_fields(
            doc(), self.root, False)}
        self.assertEqual(fields["network.access.file"].status, SAME)
        relay = fields["network.access.relays.keel-access-relay-3306.socket"]
        self.assertEqual((relay.status, relay.observed), (DRIFT, "missing"))
        self.put(CONF, "changed")
        self.put("etc/systemd/system/keel-access-relay-5432.socket",
                 acc.HEADER[0])
        fields = {one.field: one for one in diffaccess.access_fields(
            doc(), self.root, False)}
        self.assertEqual(fields["network.access.file"].status, DRIFT)
        self.assertEqual(fields["network.access.relays."
                                "keel-access-relay-5432.socket"].status,
                         DRIFT)

    def test_live_peers_the_unit_and_a_stranger(self):
        found = state(held={KEY_C: "fd99::1/128"})
        fields = {one.field: one for one in diffaccess.fields_of(
            found, doc(), True)}
        self.assertEqual(fields["network.access.unit"].status, SAME)
        self.assertEqual(fields["network.access.peers.laptop"].observed,
                         "not held")
        stranger = fields[f"network.access.peers.{KEY_C}"]
        self.assertEqual(stranger.status, DRIFT)
        self.assertIn("does not declare", stranger.note)
        fields = diffaccess.fields_of(state(up=False, enabled=False), doc(),
                                      True)
        self.assertEqual([one.status for one in fields
                          if one.field == "network.access.unit"], [DRIFT])

    def test_keel_s_interface_with_no_section_is_drift(self):
        self.assertEqual(diffaccess.fields_of(None, {}, True), [])
        found = diffaccess.fields_of(AccessState(
            iface="keel-access", declared=False, current="x",
            rendered=None), {}, True)
        self.assertEqual([(one.field, one.status) for one in found],
                         [("network.access", DRIFT)])


class TestCommands(RootCase):
    def args(self, **fields):
        path = os.path.join(self.root, "instance.yaml")
        return argparse.Namespace(spec=path, root=self.root, json=False,
                                  name="laptop", **fields)

    def write(self, text: str) -> None:
        self.put("instance.yaml", text)

    def run_quiet(self, call):
        said, told = io.StringIO(), io.StringIO()
        with redirect_stdout(said), redirect_stderr(told):
            code = call()
        return code, said.getvalue(), told.getvalue()

    def test_list_without_and_with_a_section(self):
        self.write("version: 1\n")
        code, said, _ = self.run_quiet(lambda: commands.access_list(
            self.args()))
        self.assertEqual(code, exits.OK)
        self.assertIn("no access network", said)
        self.write(json.dumps(doc(database=None)))
        code, said, _ = self.run_quiet(lambda: commands.access_list(
            self.args()))
        self.assertIn("laptop\tfd12:3456:789a:1::2\tenrolled 2026-11-25"
                      "\tlast handshake none", said)

    def test_list_json_with_a_handshake_on_the_live_system(self):
        self.write(json.dumps(doc(database=None)))
        args = self.args()
        args.json, args.root = True, "/"
        code, said, _ = self.run_quiet(lambda: commands.access_list(
            args, output=lambda argv: f"{KEY_A}\t1764028800\nbad\n"))
        found = json.loads(said)
        self.assertEqual(found["computers"][0]["last_handshake"],
                         "2025-11-25T00:00:00Z")
        self.assertEqual(found["port"], 51822)
        self.write("version: 1\n")
        _, said, _ = self.run_quiet(lambda: commands.access_list(args))
        self.assertEqual(json.loads(said)["computers"], [])

    def test_an_unreadable_spec(self):
        self.write(": :\n")
        code, _, told = self.run_quiet(lambda: commands.access_list(
            self.args()))
        self.assertEqual(code, exits.SPEC_UNREADABLE)

    def test_without_names_the_computer(self):
        self.assertIsNone(commands.without({"version": 1}, "laptop"))
        self.assertIsNone(commands.without(doc(), "other"))
        found = commands.without(doc(), "laptop")
        self.assertEqual(found["network"]["access"]["peers"], [])
        self.assertEqual(ACCESS["peers"][0]["name"], "laptop")

    def test_remove_writes_and_applies(self):
        node = mock.Mock()
        node.document.return_value = doc()
        node.change.return_value = mock.Mock(code=exits.OK)
        with mock.patch("keel.mesh.commands.as_root",
                        return_value=exits.OK):
            code, said, _ = self.run_quiet(lambda: commands.access_remove(
                self.args(), node))
        self.assertEqual(code, exits.OK)
        self.assertIn("removed laptop", said)
        written = node.change.call_args.args[0]
        self.assertEqual(written["network"]["access"]["peers"], [])

    def test_remove_refusals(self):
        from keel.mesh.node import NodeError
        node = mock.Mock()
        node.document.return_value = doc()
        with mock.patch("keel.mesh.commands.as_root",
                        return_value=exits.APPLY_NEEDS_ROOT):
            self.assertEqual(commands.access_remove(self.args(), node),
                             exits.APPLY_NEEDS_ROOT)
        with mock.patch("keel.mesh.commands.as_root",
                        return_value=exits.OK):
            args = self.args()
            args.name = "nobody"
            code, _, told = self.run_quiet(
                lambda: commands.access_remove(args, node))
            self.assertEqual(code, exits.USAGE)
            node.change.return_value = mock.Mock(code=exits.APPLY_FAILED)
            code, _, told = self.run_quiet(
                lambda: commands.access_remove(self.args(), node))
            self.assertEqual(code, exits.APPLY_FAILED)
            self.assertIn("the apply failed", told)
            node.change.side_effect = NodeError("bad")
            code, _, _ = self.run_quiet(
                lambda: commands.access_remove(self.args(), node))
            self.assertEqual(code, exits.SPEC_INVALID)
            node.document.side_effect = NodeError("bad")
            code, _, _ = self.run_quiet(
                lambda: commands.access_remove(self.args(), node))
            self.assertEqual(code, exits.SPEC_UNREADABLE)


IF_INET6 = (
    "20010db8000000000000000000000001 02 40 00 80 eth0\n"
    "fd123456789a00010000000000000001 05 40 00 80 keel-access\n"
    "fe800000000000000000000000000001 02 40 20 80 eth0\n"
    "20010db8000000000000000000000002 02 40 00 c0 eth0\n"
    "short line\n"
    "zz010db8000000000000000000000003 02 40 00 80 eth0\n")
ROUTE6 = ("00000000000000000000000000000000 00"
          " 00000000000000000000000000000000"
          " 00 fe800000000000000000000000000001 00000400 00000001 00000000"
          " 00450003 eth0\n")
UNREACHABLE = ROUTE6.replace("eth0", "lo")


class TestGlobalIpv6(RootCase):
    def test_a_global_address_and_a_default_route(self):
        self.put(fwstate.IF_INET6, IF_INET6)
        self.put(fwstate.ROUTE6, ROUTE6)
        tree = Tree(self.root)
        self.assertEqual(fwstate.global_addresses(tree), ["2001:db8::1"])
        self.assertTrue(fwstate.global_ipv6(tree))
        self.assertEqual(fwstate.global_ipv6_source(tree),
                         "global IPv6 2001:db8::1, an IPv6 default route")

    def test_an_endpoint_is_a_stable_address_only(self):
        self.put(fwstate.IF_INET6, IF_INET6 + (
            "20010db8000000000000000000000009 02 40 00 01 eth0\n"
            "2001db8000000000000000000000000a 02 40 00 20 eth0\n"))
        tree = Tree(self.root)
        self.assertEqual(fwstate.global_addresses(tree, stable=True),
                         ["2001:db8::1"])
        self.assertEqual(len(fwstate.global_addresses(tree)), 3)

    def test_no_default_route_or_no_address_is_no_global_ipv6(self):
        self.put(fwstate.IF_INET6, IF_INET6)
        self.put(fwstate.ROUTE6, UNREACHABLE)
        tree = Tree(self.root)
        self.assertFalse(fwstate.global_ipv6(tree))
        self.put(fwstate.IF_INET6, IF_INET6.splitlines()[1] + "\n")
        self.assertEqual(fwstate.global_ipv6_source(tree),
                         "no global IPv6 address, no IPv6 default route")


class TestSshRule(FirewallCase):
    def state(self, **fields):
        # sshd listens on IPv6 unless a test says otherwise
        return super().state(**{"ssh_ipv6": True, **fields})

    def test_not_narrowed_when_sshd_does_not_listen_on_ipv6(self):
        for value in (False, None):
            found, said = ssh_narrowed(self.state(global_ipv6=True,
                                                  ssh_ipv6=value), True)
            self.assertFalse(found)
            self.assertIn("sshd does not listen on IPv6", said)

    def test_sshd_t_says_whether_it_listens_on_ipv6(self):
        self.assertTrue(fwstate.sshd_on_ipv6(
            "port 22\naddressfamily any\nlistenaddress [::]:22\n"
            "listenaddress 0.0.0.0:22\n"))
        self.assertFalse(fwstate.sshd_on_ipv6(
            "port 22\naddressfamily inet\nlistenaddress 0.0.0.0:22\n"))
        self.assertFalse(fwstate.sshd_on_ipv6(
            "addressfamily any\nlistenaddress 192.0.2.1:22\n"))
        self.assertTrue(fwstate.sshd_on_ipv6("addressfamily inet6\n"))
        self.assertIsNone(fwstate.sshd_on_ipv6(None))

    def test_narrowed_only_with_global_ipv6_and_a_person(self):
        self.assertEqual(ssh_narrowed(self.state(), True), (False, ""))
        found, said = ssh_narrowed(self.state(
            global_ipv6=False, global_ipv6_source="no global IPv6"), True)
        self.assertFalse(found)
        self.assertIn("keel refuses to close tcp 22 on IPv4", said)
        self.assertEqual(ssh_narrowed(self.state(global_ipv6=True), True),
                         (True, ""))
        found, said = ssh_narrowed(self.state(global_ipv6=True), False)
        self.assertFalse(found)
        self.assertIn("until an apply a person runs", said)
        kept = File("/r/x", "\n".join(["x", SSH_LINE, ""]))
        self.assertFalse(ssh_narrowed(self.state(global_ipv6=True,
                                                 file=kept), False)[0])

    def test_an_unattended_run_keeps_what_a_person_narrowed(self):
        declared = fwdoc()
        declared["network"]["access"] = ACCESS
        first = self.actions(spec=declared,
                             state=self.state(global_ipv6=True))
        written = next(one for one in first if hasattr(one, "content"))
        kept = self.state(global_ipv6=True,
                          file=File("/r/x", written.content),
                          copy=written.content, recorded="enforce")
        found = self.actions(spec=declared, state=kept, attended=False)
        self.assertFalse(any(hasattr(one, "content") for one in found))
        said = " ".join(one.summary for one in found
                        if isinstance(one, Note))
        self.assertIn("SSH: tcp 22 on IPv6 and on keel-access only", said)

    def test_the_plan_narrows_ssh_and_says_so(self):
        declared = fwdoc()
        declared["network"]["access"] = ACCESS
        found = self.actions(spec=declared,
                             state=self.state(global_ipv6=True))
        said = " ".join(one.summary for one in found
                        if isinstance(one, Note))
        self.assertIn("SSH: tcp 22 on IPv6 and on keel-access only", said)
        written = next(one for one in found if hasattr(one, "content"))
        self.assertIn("meta nfproto ipv6 tcp dport 22 accept",
                      written.content)
        found = self.actions(spec=declared, state=self.state(
            global_ipv6=False, global_ipv6_source="none"))
        said = " ".join(one.summary for one in found
                        if isinstance(one, Note))
        self.assertIn("keel refuses to close tcp 22 on IPv4", said)
        found = self.actions(spec=fwdoc(), state=self.state(
            global_ipv6=True))
        said = " ".join(one.summary for one in found
                        if isinstance(one, Note))
        self.assertIn("SSH: tcp 22 on IPv6 only", said)


class TestSockets(unittest.TestCase):
    def test_the_access_address_and_its_kernel_socket_are_known(self):
        relay = Listener("tcp", "fd12:3456:789a:1::1", None, 3306, (1,),
                         ("systemd",), ("init.scope",))
        kernel = Listener("udp", "*", None, 51822, ())
        device = Listener("tcp", "::", "keel-access", 9, (5,), ("x",),
                          ("x.service",))
        other = Listener("tcp", "::", None, 9, (5,), ("x",), ("x.service",))
        found = classify((relay, kernel, device, other), frozenset(),
                         ssh=(22,), allow=frozenset(), opened=frozenset(),
                         overlay=None, access=("keel-access", 51822),
                         access_addresses=frozenset({"fd12:3456:789a:1::1"}))
        self.assertEqual(found.undeclared, (other,))
        found = classify((relay,), frozenset(), ssh=(22,),
                         allow=frozenset(), opened=frozenset(), overlay=None)
        self.assertEqual(found.undeclared, (relay,))
        self.assertEqual(unopened(
            (relay, device, other), frozenset(), None,
            access_device="keel-access",
            access_addresses=frozenset({"fd12:3456:789a:1::1"})), (other,))



class TestParser(unittest.TestCase):
    def test_keel_access_list_and_remove_parse(self):
        from keel.cli import build_parser
        found = build_parser().parse_args(["access", "list", "--json"])
        self.assertEqual(found.handler, "keel.access.commands.access_list")
        self.assertTrue(found.json)
        found = build_parser().parse_args(["access", "remove", "laptop"])
        self.assertEqual(found.handler, "keel.access.commands.access_remove")
        self.assertEqual(found.name, "laptop")


if __name__ == "__main__":
    unittest.main()
