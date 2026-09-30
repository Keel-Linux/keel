# Copyright (c) 2026 KeelLinux maintainers
"""network.overlay.wireguard validation (decision 0020), IPv6 first"""

import os
import tempfile
import unittest

from helpers import spec
from helpers import errors as yaml_errors

from keel.spec.apply import unsupported

PEER_KEY = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OTHER_KEY = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="


def peer(**overrides):
    values = {"public_key": PEER_KEY, "endpoint": "[2001:db8::20]:51820",
              "allowed_ips": ["fd00:1::2/128"], "persistent_keepalive": 25}
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


def document(wg=None, **network):
    overlay = {"wireguard": {"address": "fd00:1::1/64", **(wg or {})}}
    return {"version": 1, "network": {"overlay": overlay, **network}}


def errors(doc, check=True):
    return spec.validate(doc, check_secret_files=check)


def one(case, doc, words):
    found = errors(doc)
    case.assertEqual(len(found), 1, found)
    case.assertIn(words, found[0])


class TestValid(unittest.TestCase):
    def test_the_documented_example(self):
        found = yaml_errors(
            "version: 1\n"
            "network:\n"
            "  managed_by: host\n"
            "  overlay:\n"
            "    wireguard:\n"
            "      interface: wg0\n"
            "      address: fd00:1::1/64\n"
            "      ipv4_address: 10.66.0.1/24\n"
            "      listen_port: 51820\n"
            "      private_key:\n"
            "        file: /etc/wireguard/wg0.key\n"
            "      peers:\n"
            f"        - public_key: {PEER_KEY}\n"
            "          endpoint: \"[2001:db8::20]:51820\"\n"
            "          allowed_ips: [fd00:1::2/128]\n"
            "          persistent_keepalive: 25\n"
            f"        - public_key: {OTHER_KEY}\n"
            "          endpoint: node3.example.org:51820\n"
            "          allowed_ips: [fd00:1::3/128, 10.66.0.3/32]\n"
        )
        self.assertEqual(found, [])

    def test_an_address_alone_is_enough(self):
        self.assertEqual(errors(document()), [])

    def test_no_overlay_and_an_empty_one(self):
        self.assertEqual(errors({"version": 1, "network": {"overlay": {}}}),
                         [])
        self.assertEqual(errors({"version": 1, "network": {
            "overlay": {"wireguard": None}}}), [])

    def test_a_peer_without_an_endpoint_waits_to_be_reached(self):
        found = errors(document({"peers": [{
            "public_key": PEER_KEY, "endpoint": None,
            "allowed_ips": ["fd00:1::2/128"]}]}))
        self.assertEqual(found, [])

    def test_an_ipv4_endpoint(self):
        self.assertEqual(errors(document({"peers": [peer(
            endpoint="192.0.2.20:51820")]})), [])

    def test_a_missing_key_file_is_made_later(self):
        self.assertEqual(errors(document({"private_key": {
            "file": "/nonexistent/wg0.key"}})), [])


class TestInvalid(unittest.TestCase):
    def test_overlay_shapes(self):
        one(self, {"version": 1, "network": {"overlay": []}},
            "network.overlay: must be a mapping")
        one(self, {"version": 1, "network": {"overlay": {"vxlan": {}}}},
            "network.overlay.vxlan: unknown key")
        one(self, {"version": 1, "network": {"overlay": {"wireguard": 1}}},
            "must be a mapping")
        one(self, document({"mtu": 1420}), "wireguard.mtu: unknown key")

    def test_address(self):
        one(self, {"version": 1, "network": {"overlay": {"wireguard": {}}}},
            "address: required")
        one(self, document({"address": "fd00:1::1"}), "prefix length")
        one(self, document({"address": "fd00::zz/64"}), "wireguard.address")
        one(self, document({"address": "10.66.0.1/24"}), "not an IPv6")
        one(self, document({"address": "fe80::1/64"}), "unicast")
        one(self, document({"ipv4_address": "fd00:1::1/64"}), "not an IPv4")

    def test_interface(self):
        one(self, document({"interface": "a-name-far-too-long"}),
            "not an interface name")
        one(self, document({"interface": "wg 0"}), "not an interface name")
        one(self, document({"interface": 7}), "not an interface name")
        one(self, document({"interface": "eth0"}, interfaces={
            "eth0": {"ipv6": {"method": "auto"}}}), "declared under")

    def test_port(self):
        one(self, document({"listen_port": 0}), "listen_port")
        one(self, document({"listen_port": "51820"}), "listen_port")

    def test_private_key(self):
        one(self, document({"private_key": "/etc/wireguard/wg0.key"}),
            "file: PATH")
        one(self, document({"private_key": {"generate": True,
                                            "file": "/etc/k"}}),
            "no other backend")
        one(self, document({"private_key": {"file": "relative.key"}}),
            "absolute path")
        one(self, document({"private_key": {"file": "/etc/$(reboot)"}}),
            "absolute path")

    def test_an_open_key_file_is_refused_when_files_are_checked(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.remove, path)
        os.chmod(path, 0o644)
        doc = document({"private_key": {"file": path}})
        self.assertIn("0600", " ".join(errors(doc)))
        self.assertEqual(errors(doc, check=False), [])
        os.chmod(path, 0o600)
        self.assertEqual(errors(doc), [])

    def test_peers(self):
        one(self, document({"peers": {"a": 1}}), "peers: must be a list")
        one(self, document({"peers": [None]}), "must be a mapping")
        one(self, document({"peers": ["x"]}), "must be a mapping")
        one(self, document({"peers": [peer(name="b")]}), "name: unknown key")
        one(self, document({"peers": [peer(public_key=None)]}),
            "public_key: required")
        one(self, document({"peers": [peer(public_key="abc")]}),
            "not a WireGuard key")

    def test_endpoint(self):
        for endpoint, words in (
            ("2001:db8::20:51820", "brackets"),
            ("[2001:db8::20]", "[address]:port"),
            ("node2", "port is required"),
            ("999.1.1.1:5", "999.1.1.1"),
            ("bad_name!:5", "invalid"),
        ):
            with self.subTest(endpoint=endpoint):
                one(self, document({"peers": [peer(endpoint=endpoint)]}),
                    words)

    def test_allowed_ips(self):
        one(self, document({"peers": [peer(allowed_ips=None)]}),
            "at least one prefix")
        one(self, document({"peers": [peer(allowed_ips=[])]}),
            "at least one prefix")
        one(self, document({"peers": [peer(allowed_ips="fd00:1::2/128")]}),
            "must be a list")
        one(self, document({"peers": [peer(allowed_ips=["fd00:1::2/64"])]}),
            "host bits set")

    def test_keepalive(self):
        for value in (0, 70000, True, "25"):
            with self.subTest(value=value):
                one(self, document({"peers": [peer(
                    persistent_keepalive=value)]}), "persistent_keepalive")

    def test_a_key_or_a_prefix_twice(self):
        found = errors(document({"peers": [
            peer(), peer(allowed_ips=["fd00:1::2/128", "bad"])]}))
        joined = " ".join(found)
        self.assertIn(f"public key {PEER_KEY} is declared twice", joined)
        self.assertIn("fd00:1::2/128 is already routed to peers[0]", joined)
        self.assertIn("bad", joined)

    def test_a_peer_without_a_list_is_left_to_its_own_error(self):
        found = errors(document({"peers": [peer(allowed_ips=None),
                                           peer(public_key=OTHER_KEY)]}))
        self.assertEqual(len(found), 1, found)


UPLINK = {"eth0": {
    "ipv6": {"method": "static", "address": "2001:db8:1::10/64",
             "gateway": "2001:db8:ff::1"},
    "ipv4": {"method": "static", "address": "192.0.2.10/24",
             "gateway": "192.0.2.1"},
}}


class TestRouteCapture(unittest.TestCase):
    """A route wg-quick adds must never take the uplink's traffic"""

    def test_a_route_to_every_address_is_refused(self):
        for prefix in ("::/0", "0.0.0.0/0"):
            with self.subTest(prefix=prefix):
                one(self, document({"peers": [peer(allowed_ips=[prefix])]}),
                    f"{prefix} routes every address to this peer")

    def test_a_prefix_over_the_uplink_is_refused(self):
        for prefix, words in (
            ("2001:db8:1::5/128", "network.interfaces.eth0.ipv6.address"
             " 2001:db8:1::10/64"),
            ("2001:db8::/32", "network.interfaces.eth0.ipv6.address"),
            ("2001:db8:ff::1/128", "network.interfaces.eth0.ipv6.gateway"
             " 2001:db8:ff::1"),
            ("192.0.2.128/25", "network.interfaces.eth0.ipv4.address"),
        ):
            with self.subTest(prefix=prefix):
                found = errors(document({"peers": [peer(
                    allowed_ips=["fd00:1::2/128", prefix])]},
                    interfaces=UPLINK))
                self.assertTrue(found, prefix)
                self.assertTrue(all(prefix in line and "into the overlay"
                                    in line for line in found), found)
                self.assertIn(words, " ".join(found))

    def test_a_prefix_over_an_endpoint_is_refused(self):
        other = peer(public_key=OTHER_KEY, endpoint="192.0.2.77:51820",
                     allowed_ips=["fd00:1::3/128", "2001:db8::/48"])
        one(self, document({"peers": [peer(), other]}),
            "network.overlay.wireguard.peers[0].endpoint 2001:db8::20")
        own = peer(allowed_ips=["fd00:1::2/128", "2001:db8::20/128"])
        one(self, document({"peers": [own]}), "peers[0].endpoint")

    def test_a_named_endpoint_and_a_dynamic_uplink_leave_nothing_to_check(
            self):
        found = errors(document({"peers": [peer(
            endpoint="node2.example.org:51820",
            allowed_ips=["fd00:1::2/128", "2001:db8::/32"])]},
            interfaces={"eth0": {"ipv6": {"method": "auto"}}}))
        self.assertEqual(found, [])

    def test_the_overlay_prefixes_beside_the_uplink(self):
        found = errors(document({"ipv4_address": "10.66.0.1/24"},
                                interfaces=UPLINK))
        self.assertEqual(found, [])

    def test_an_address_that_is_not_unique_local_is_refused(self):
        one(self, document({"address": "2001:db8:5::1/64"}),
            "a unique local address (fc00::/7, RFC 4193)")
        one(self, document({"address": "fd00::1/6"}),
            "a unique local address (fc00::/7, RFC 4193)")
        self.assertEqual(errors(document({"address": "fc00:1::1/64"})), [])

    def test_an_ipv4_address_must_be_private_or_shared(self):
        one(self, document({"ipv4_address": "198.51.100.1/24"}),
            "RFC 1918 or the shared 100.64.0.0/10")
        one(self, document({"ipv4_address": "10.0.0.1/7"}),
            "RFC 1918 or the shared 100.64.0.0/10")
        for address in ("10.66.0.1/24", "172.16.5.1/24", "192.168.9.1/24",
                        "100.64.0.1/24"):
            with self.subTest(address=address):
                self.assertEqual(errors(document({"ipv4_address": address})),
                                 [])

    def test_an_overlay_address_over_the_uplink_is_refused(self):
        uplink = {"eth0": {
            "ipv6": {"method": "static", "address": "fd00:1::10/64"},
            "ipv4": {"method": "static", "address": "10.66.0.5/16"},
        }}
        found = errors(document({"ipv4_address": "10.66.0.1/24"},
                                interfaces=uplink))
        self.assertEqual(len(found), 2, found)
        self.assertIn("wireguard.address: fd00:1::/64 overlaps"
                      " network.interfaces.eth0.ipv6.address", found[0])
        self.assertIn("wireguard.ipv4_address: 10.66.0.0/24 overlaps"
                      " network.interfaces.eth0.ipv4.address", found[1])

    def test_unparseable_uplink_values_are_left_to_their_own_errors(self):
        uplink = {"eth0": {"ipv6": {"method": "static", "address": "bad",
                                    "gateway": "worse"}},
                  "eth1": None, "eth2": {"ipv4": "x"}}
        found = errors(document(interfaces=uplink))
        self.assertTrue(found)
        self.assertFalse(any("overlay" in line for line in found), found)


class TestWarning(unittest.TestCase):
    def test_apply_without_the_system_phase_says_so(self):
        found = unsupported(document())
        self.assertTrue(any(line.startswith("network.overlay:")
                            for line in found))
        self.assertEqual(unsupported(document(), system=True), [])
