# Copyright (c) 2026 KeelLinux maintainers
"""Network validation and rendering, IPv6 first"""

import unittest

from helpers import env, errors


class TestNetwork(unittest.TestCase):
    def test_rejects_ipv6_address_without_prefix_length(self):
        found = errors(
            "version: 1\n"
            "network:\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10\n"
        )
        self.assertTrue(found)

    def test_rejects_link_local_address(self):
        found = errors(
            "version: 1\n"
            "network:\n"
            "  managed_by: host\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: fe80::10/64\n"
        )
        self.assertTrue(any("unicast" in error for error in found))

    def test_accepts_link_local_gateway(self):
        text = (
            "version: 1\n"
            "network:\n"
            "  managed_by: host\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "        gateway: fe80::1\n"
        )
        self.assertEqual(errors(text), [])

    def test_host_managed_network_exports_no_ip_variables(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: host\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
        )
        self.assertEqual(exported, {})

    def test_file_managed_ipv4_static_maps_to_ip_variables(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv4:\n"
            "        method: static\n"
            "        address: 192.0.2.10/24\n"
            "        gateway: 192.0.2.1\n"
            "  nameservers:\n"
            "    - 2001:db8:1::53\n"
            "    - 192.0.2.53\n"
            "    - 192.0.2.54\n"
        )
        self.assertEqual(exported["IP_CONFIG"], "static")
        self.assertEqual(exported["IP_ADDRESS"], "192.0.2.10")
        self.assertEqual(exported["IP_NETMASK"], "255.255.255.0")
        self.assertEqual(exported["IP_GW"], "192.0.2.1")
        # IPv6 is left dynamic, so the static inet stanza carries the
        # first two nameservers in the spec's order, whatever the family
        self.assertEqual(exported["IP_DNS1"], "2001:db8:1::53")
        self.assertEqual(exported["IP_DNS2"], "192.0.2.53")
        self.assertNotIn("IP6_DNS1", exported)

    def test_file_managed_ipv6_static_maps_to_ip6_variables(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "        gateway: fe80::1\n"
            "  nameservers:\n"
            "    - 2001:db8:1::53\n"
            "    - 2001:db8:2::53\n"
            "    - 2001:db8:3::53\n"
        )
        self.assertEqual(exported, {
            "IP6_CONFIG": "static",
            "IP6_ADDRESS": "2001:db8:1::10/64",
            "IP6_GW": "fe80::1",
            "IP6_DNS1": "2001:db8:1::53",
            "IP6_DNS2": "2001:db8:2::53",
        })

    def test_both_families_static_render_both_sets_of_variables(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv4:\n"
            "        method: static\n"
            "        address: 192.0.2.10/24\n"
            "        gateway: 192.0.2.1\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:DB8:1::10/64\n"
            "  nameservers:\n"
            "    - 192.0.2.53\n"
            "    - 2001:db8:1::53\n"
        )
        self.assertEqual(list(exported), [
            "IP_CONFIG", "IP_ADDRESS", "IP_NETMASK", "IP_GW", "IP_DNS1",
            "IP6_CONFIG", "IP6_ADDRESS", "IP6_DNS1",
        ])
        self.assertEqual(exported["IP6_ADDRESS"], "2001:db8:1::10/64")
        self.assertEqual(exported["IP_DNS1"], "192.0.2.53")
        self.assertEqual(exported["IP6_DNS1"], "2001:db8:1::53")
        self.assertNotIn("IP6_GW", exported)

    def test_rejects_unknown_managed_by(self):
        self.assertTrue(errors("version: 1\nnetwork:\n  managed_by: magic\n"))

    def test_rejects_nameserver_that_is_not_an_address(self):
        found = errors(
            "version: 1\nnetwork:\n  nameservers:\n    - ns.example.org\n"
        )
        self.assertTrue(found)


class TestNetworkErrors(unittest.TestCase):
    """Every mistake in the network section names the field"""

    def interface(self, body: str, managed_by: str = "host") -> str:
        return (
            "version: 1\n"
            "network:\n"
            f"  managed_by: {managed_by}\n"
            "  interfaces:\n"
            "    eth0:\n"
            + body
        )

    def assert_one_error(self, text: str, fragment: str) -> None:
        found = errors(text)
        matching = [error for error in found if fragment in error]
        self.assertEqual(
            len(matching), 1, f"expected one error with {fragment!r}: {found}"
        )

    def test_rejects_unknown_network_key(self):
        self.assert_one_error(
            "version: 1\nnetwork:\n  dns: []\n", "network.dns: unknown key"
        )

    def test_rejects_nameservers_that_are_not_a_list(self):
        for value in ("2001:db8:1::53", "{a: 1}"):
            with self.subTest(value=value):
                found = errors(
                    f"version: 1\nnetwork:\n  nameservers: {value}\n"
                )
                self.assertEqual(found, ["network.nameservers: must be a list"])

    def test_rejects_interfaces_that_are_not_a_mapping(self):
        self.assert_one_error(
            "version: 1\nnetwork:\n  interfaces: [eth0]\n",
            "network.interfaces: must be a mapping",
        )

    def test_rejects_interface_that_is_not_a_mapping(self):
        self.assert_one_error(
            "version: 1\nnetwork:\n  interfaces:\n    eth0: dhcp\n",
            "network.interfaces.eth0: must be a mapping",
        )

    def test_accepts_interface_without_any_family(self):
        self.assertEqual(
            errors("version: 1\nnetwork:\n  interfaces:\n    eth0:\n"), []
        )

    def test_rejects_unknown_family(self):
        self.assert_one_error(
            self.interface("      ipx:\n        method: auto\n"),
            "network.interfaces.eth0.ipx: unknown key",
        )

    def test_rejects_family_that_is_not_a_mapping(self):
        self.assert_one_error(
            self.interface("      ipv6: auto\n"),
            "network.interfaces.eth0.ipv6: must be a mapping",
        )

    def test_rejects_unknown_family_key(self):
        self.assert_one_error(
            self.interface(
                "      ipv6:\n        method: auto\n        mtu: 1280\n"
            ),
            "network.interfaces.eth0.ipv6.mtu: unknown key",
        )

    def test_accepts_slaac_beside_a_static_ipv6_address(self):
        for value in ("true", "false"):
            with self.subTest(value=value):
                self.assertEqual(errors(self.interface(
                    "      ipv6:\n        method: static\n"
                    "        address: 2001:db8:1::10/64\n"
                    f"        slaac: {value}\n", managed_by="file")), [])

    def test_rejects_slaac_with_another_method(self):
        for method in ("auto", "dhcp", "manual", "none"):
            with self.subTest(method=method):
                self.assert_one_error(
                    self.interface(f"      ipv6:\n        method: {method}\n"
                                   "        slaac: false\n"),
                    "network.interfaces.eth0.ipv6.slaac: only valid when"
                    " method is static",
                )

    def test_rejects_slaac_that_is_not_a_boolean(self):
        for value in ("0", "'false'", "sometimes"):
            with self.subTest(value=value):
                self.assert_one_error(
                    self.interface(
                        "      ipv6:\n        method: static\n"
                        "        address: 2001:db8:1::10/64\n"
                        f"        slaac: {value}\n"),
                    "network.interfaces.eth0.ipv6.slaac: must be true or"
                    " false",
                )

    def test_rejects_slaac_on_ipv4(self):
        self.assert_one_error(
            self.interface("      ipv4:\n        method: static\n"
                           "        address: 192.0.2.10/24\n"
                           "        slaac: false\n"),
            "network.interfaces.eth0.ipv4.slaac: unknown key",
        )

    def test_rejects_family_without_a_method(self):
        self.assert_one_error(
            self.interface("      ipv6:\n        gateway: fe80::1\n"),
            "network.interfaces.eth0.ipv6.method: must be one of",
        )

    def test_rejects_method_of_the_other_family(self):
        self.assert_one_error(
            self.interface("      ipv4:\n        method: auto\n"),
            "network.interfaces.eth0.ipv4.method: must be one of",
        )

    def test_rejects_static_method_without_an_address(self):
        self.assert_one_error(
            self.interface("      ipv6:\n        method: static\n"),
            "network.interfaces.eth0.ipv6.address: required when method"
            " is static",
        )

    def test_rejects_address_that_is_not_an_address(self):
        self.assert_one_error(
            self.interface(
                "      ipv6:\n        method: static\n"
                "        address: 2001:db8::zz/64\n"
            ),
            "network.interfaces.eth0.ipv6.address: ",
        )

    def test_rejects_address_of_the_other_family(self):
        self.assert_one_error(
            self.interface(
                "      ipv6:\n        method: static\n"
                "        address: 192.0.2.10/24\n"
            ),
            "network.interfaces.eth0.ipv6.address: not an IPv6 address",
        )

    def test_rejects_gateway_that_is_not_an_address(self):
        self.assert_one_error(
            self.interface(
                "      ipv6:\n        method: auto\n        gateway: router\n"
            ),
            "network.interfaces.eth0.ipv6.gateway: ",
        )

    def test_rejects_gateway_of_the_other_family(self):
        self.assert_one_error(
            self.interface(
                "      ipv4:\n        method: dhcp\n        gateway: fe80::1\n"
            ),
            "network.interfaces.eth0.ipv4.gateway: not an IPv4 address",
        )

    def test_accepts_dhcp_with_a_gateway_and_no_address(self):
        text = self.interface(
            "      ipv4:\n        method: dhcp\n        gateway: 192.0.2.1\n"
            "      ipv6:\n        method: auto\n        gateway: fe80::1\n",
            managed_by="file",
        )
        self.assertEqual(errors(text), [])

    def test_accepts_ipv4_static_with_a_link_local_ipv6_gateway(self):
        text = self.interface(
            "      ipv4:\n        method: static\n"
            "        address: 192.0.2.10/24\n"
            "      ipv6:\n        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "        gateway: fe80::1\n"
        )
        self.assertEqual(errors(text), [])


if __name__ == "__main__":
    unittest.main()
