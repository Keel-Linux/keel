# Copyright (c) 2026 KeelLinux maintainers
"""The access network of decision 0098: its files, its validation, and
its rules in keel's firewall

The renderer and the validation are pure. As in
tests/test_manifest_firewall.py, each ruleset is also checked with
`nft -c` in a network namespace of its own when nft is at hand.
"""

import unittest

from manifest_helpers import ManifestCase
from test_manifest_firewall import nft_binary, nft_check
from wgtools import namespace_prefix

from keel.manifest.firewall import (
    ENFORCE,
    REPORT,
    SSH_LINE,
    Access,
    digest_of,
    file_ssh_ipv6_only,
    render,
)
from keel.manifest.facts import gather
from keel.network import access as acc
from keel.spec.validate import validate

KEY_A = "0niNkgzhpbKmTSrWCzukb6jaYogKZkGhW+xWlh52Mh8="
KEY_B = "4S5ORakWeqlbmOH4I0Ux5wgAxGuoZuFTGuQEGm4HM34="
KEY_C = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
ACCESS = {"address": "fd12:3456:789a:1::1/64",
          "peers": [{"name": "laptop", "public_key": KEY_A,
                     "address": "fd12:3456:789a:1::2/128",
                     "enrolled": "2026-11-25"}]}
STATES = {"installer": "enabled", "wireguard": "enabled",
          "etcd": "enabled", "crowdsec": "enabled"}
OFF = {"installer": "enabled", "wireguard": "disabled",
       "etcd": "disabled", "crowdsec": "disabled"}
WG = {"address": "fd00:1::1/64", "interface": "wg0", "listen_port": 51820}


def spec(access=None, overlay=None, firewall=None, **extra) -> dict:
    network = {"access": ACCESS if access is None else access}
    if overlay is not None:
        network["overlay"] = {"wireguard": overlay}
    found = {"version": 1, "network": network, **extra}
    if firewall is not None:
        found["firewall"] = firewall
    return found


def problems(doc: dict) -> list[str]:
    return [one for one in validate(doc, check_secret_files=False)
            if "network.access" in one or "firewall" in one]


class TestFiles(unittest.TestCase):
    def test_the_file_has_no_private_key_and_routes_each_computer_only(self):
        text = acc.render(ACCESS)
        self.assertIn("Address = fd12:3456:789a:1::1/64\n", text)
        self.assertIn("ListenPort = 51822\n", text)
        self.assertIn("PostUp = wg set %i private-key"
                      " /etc/wireguard/keel-access.key\n", text)
        self.assertIn(f"PublicKey = {KEY_A}\n"
                      "AllowedIPs = fd12:3456:789a:1::2/128\n", text)
        self.assertNotIn("PrivateKey", text)
        self.assertNotIn("Endpoint", text)
        self.assertNotIn("PersistentKeepalive", text)

    def test_a_key_path_a_shell_reads_is_refused(self):
        with self.assertRaises(ValueError):
            acc.render({**ACCESS, "private_key": {"file": "/k;rm -rf /"}})

    def test_defaults_are_the_answers(self):
        self.assertEqual(acc.interface({}), "keel-access")
        self.assertEqual(acc.port({}), 51822)
        self.assertEqual(acc.token_minutes({}), 15)
        self.assertEqual(acc.conf_path("keel-access"),
                         "etc/keel/access/keel-access.conf")
        self.assertEqual(acc.key_path({"interface": "adm"}),
                         "/etc/wireguard/adm.key")

    def test_interface_lines_ignore_the_peers_and_comments(self):
        one = acc.render(ACCESS)
        other = acc.render({**ACCESS, "peers": []})
        self.assertEqual(acc.interface_lines(one), acc.interface_lines(other))
        moved = acc.render({**ACCESS, "listen_port": 51823})
        self.assertNotEqual(acc.interface_lines(one),
                            acc.interface_lines(moved))
        self.assertEqual(acc.interface_lines(None), ())

    def test_wg_show_allowed_ips_is_read_and_compared(self):
        held = acc.parse_allowed(
            f"{KEY_A}\tfd12:3456:789a:1::2/128\n{KEY_B}\t(none)\n\n")
        self.assertEqual(held, {KEY_A: "fd12:3456:789a:1::2/128",
                                KEY_B: ""})
        add, remove = acc.peer_changes(
            {KEY_A: "fd12:3456:789a:1::2/128",
             KEY_C: "fd12:3456:789a:1::3/128"}, held)
        self.assertEqual(add, [(KEY_C, "fd12:3456:789a:1::3/128")])
        self.assertEqual(remove, [KEY_B])

    def test_a_relay_for_the_engine_of_the_server_only(self):
        doc = {"database": {"server": {"engine": "postgresql"}}}
        self.assertEqual(acc.relay_ports(doc), (5432,))
        self.assertEqual(acc.relay_ports({"database": {"server": {
            "engine": "redis"}}}), ())
        self.assertEqual(acc.relay_ports({}), ())
        files = acc.relay_files(ACCESS, doc)
        socket = files["etc/systemd/system/keel-access-relay-5432.socket"]
        service = files["etc/systemd/system/keel-access-relay-5432.service"]
        self.assertIn("ListenStream=[fd12:3456:789a:1::1]:5432\n", socket)
        self.assertIn("FreeBind=yes\n", socket)
        self.assertIn("systemd-socket-proxyd 127.0.0.1:5432\n", service)
        self.assertIn("DynamicUser=yes\n", service)
        self.assertEqual(acc.relay_socket_units(files),
                         ("keel-access-relay-5432.socket",))

    def test_addresses_and_suggestions(self):
        self.assertEqual(acc.addresses_of(spec()),
                         frozenset({"fd12:3456:789a:1::1"}))
        self.assertEqual(acc.addresses_of({}), frozenset())
        self.assertEqual(acc.addresses_of(spec(access={"address": "x"})),
                         frozenset())
        self.assertEqual(acc.suggest_address(bytes(5)), "fd00::1/64")
        self.assertEqual(acc.free_address(ACCESS, 7),
                         "fd12:3456:789a:1::7/128")


class TestValidation(unittest.TestCase):
    def test_a_good_section_has_no_error(self):
        self.assertEqual(problems(spec(overlay=WG)), [])

    def test_unknown_keys_and_types(self):
        found = problems(spec(access={**ACCESS, "endpoint": "x",
                                      "token_minutes": 61}))
        self.assertIn("network.access.endpoint: unknown key", found)
        self.assertTrue(any("token_minutes" in one for one in found))
        self.assertEqual(problems(spec(access={**ACCESS,
                                               "token_minutes": 5})), [])
        self.assertTrue(problems({"version": 1,
                                  "network": {"access": "yes"}}))

    def test_the_address_is_one_unique_local_64(self):
        for value, said in (
                (None, "required"), ("fd12::1/48", "one /64"),
                ("2001:db8::1/64", "unique local"), ("nonsense", "not an"),
                ("fd12:3456:789a:1::/64", "prefix itself")):
            access = {**ACCESS, "peers": []}
            if value is None:
                del access["address"]
            else:
                access["address"] = value
            found = problems(spec(access=access))
            self.assertTrue(any(said in one for one in found), (value, found))

    def test_apart_from_the_mesh(self):
        found = problems(spec(
            access={**ACCESS, "interface": "wg0", "listen_port": 51820,
                    "address": "fd00:1::99/64", "peers": []},
            overlay=WG))
        self.assertTrue(any("mesh's interface" in one for one in found))
        self.assertTrue(any("mesh's UDP port" in one for one in found))
        self.assertTrue(any("overlaps the mesh prefix" in one
                            for one in found))

    def test_an_access_peer_is_never_a_mesh_peer(self):
        overlay = {**WG, "peers": [{"public_key": KEY_A,
                                    "allowed_ips": ["fd00:1::2/128"]}]}
        found = problems(spec(overlay=overlay))
        self.assertTrue(any("never a mesh member" in one for one in found))

    def test_peers_are_checked_one_by_one_and_together(self):
        peers = [
            {"name": "Laptop", "public_key": "short",
             "address": "fd99::2/128", "enrolled": "today", "x": 1},
            {"name": "a", "public_key": KEY_B,
             "address": "fd12:3456:789a:1::5/64"},
            {"name": "b", "public_key": KEY_C,
             "address": "fd12:3456:789a:1::1/128"},
            {"name": "b", "public_key": KEY_C,
             "address": "fd12:3456:789a:1::7/128"},
            {"name": "c", "public_key": KEY_A},
            {"name": "d", "public_key": KEY_A, "address": "bad"},
            "not a mapping",
        ]
        found = problems(spec(access={**ACCESS, "peers": peers}))
        for said in ("name: required", "public_key: required",
                     "not in the access prefix", "enrolled",
                     "unknown key", "one /128", "own address",
                     "is given to", "address: required",
                     "not an IPv6 address", "must be a mapping"):
            self.assertTrue(any(said in one for one in found), (said, found))
        self.assertTrue(problems(spec(access={**ACCESS, "peers": "x"})))

    def test_the_firewall_off_is_refused_with_the_access_network(self):
        found = problems(spec(firewall={"state": "off"},
                              appliance={"name": "core"}))
        self.assertTrue(any("needs keel's firewall" in one for one in found))
        self.assertEqual(problems(spec(firewall={"state": "report"},
                                       appliance={"name": "core"})), [])


class TestRules(ManifestCase):
    def setUp(self):
        super().setUp()
        # keel-core's follow-up: Webmin moves from public to access
        self.edit("appliances", "core",
                  "{port: 12321, protocol: tcp, expose: public}",
                  "{port: 12321, protocol: tcp, expose: access}")
        self.resolved = gather(self.root, "core").resolved

    def ruleset(self, state=ENFORCE, access=Access("keel-access", 51822,
                                                     (3306,)),
                ssh_ipv6_only=False, wireguard=WG):
        return render(self.resolved, STATES, wireguard, state=state,
                      ssh=(22,), access=access, ssh_ipv6_only=ssh_ipv6_only)

    def assertNftAccepts(self, text: str) -> None:
        prefix = namespace_prefix() if nft_binary() else None
        if prefix is None:
            return
        out = nft_check(prefix, text)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_the_access_ports_come_first_then_a_drop(self):
        found = self.ruleset()
        lines = [line.strip() for line in found.text.splitlines()]
        first = lines.index('iifname "keel-access" tcp dport'
                            ' { 22, 3306, 12321 } accept')
        self.assertEqual(lines[first + 1], 'iifname "keel-access" drop')
        public = next(index for index, line in enumerate(lines)
                      if line.startswith("tcp dport"))
        self.assertLess(first, public)
        self.assertEqual(lines[public], "tcp dport { 22, 12320 } accept")
        self.assertIn("udp dport { 51820, 51822 } accept", lines)
        self.assertEqual(found.access, ((22, "tcp"), (3306, "tcp"),
                                        (12321, "tcp")))
        self.assertEqual(found.access_iface, "keel-access")
        self.assertNftAccepts(found.text)

    def test_the_forward_chain_drops_what_the_access_interface_brings(self):
        found = self.ruleset()
        self.assertIn('\tchain forward {\n\t\ttype filter hook forward'
                      ' priority filter; policy accept;\n'
                      '\t\tiifname "keel-access" drop\n\t}\n', found.text)
        self.assertEqual(digest_of(found.text), found.digest)

    def test_report_keeps_both_access_drops(self):
        found = self.ruleset(state=REPORT)
        self.assertIn('iifname "keel-access" drop', found.text)
        self.assertIn("policy accept;", found.text)
        self.assertEqual(digest_of(found.text), found.digest)
        self.assertNftAccepts(found.text)

    def test_without_the_access_network_the_access_ports_stay_closed(self):
        found = self.ruleset(access=None, wireguard=None)
        self.assertNotIn("keel-access", found.text)
        self.assertNotIn("12321", found.text)
        self.assertTrue(any("12321/tcp not opened: they are access ports"
                            in note for note in found.notes))
        self.assertNotIn("chain forward", found.text)

    def test_ssh_on_ipv6_and_the_access_interface_only(self):
        found = self.ruleset(ssh_ipv6_only=True)
        self.assertIn("\t\tmeta nfproto ipv6 tcp dport 22 accept\n",
                      found.text)
        self.assertIn("\t\ttcp dport 12320 accept\n", found.text)
        self.assertNotIn((22, "tcp"), found.public)
        self.assertIn(f"\n{SSH_LINE}\n", found.text)
        self.assertTrue(file_ssh_ipv6_only(found.text))
        self.assertFalse(file_ssh_ipv6_only(self.ruleset().text))
        self.assertFalse(file_ssh_ipv6_only(None))
        self.assertEqual(digest_of(found.text), found.digest)
        self.assertNftAccepts(found.text)


if __name__ == "__main__":
    unittest.main()
