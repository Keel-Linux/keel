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
        self.assertEqual(exported["IP_DNS1"], "192.0.2.53")
        self.assertEqual(exported["IP_DNS2"], "192.0.2.54")

    def test_file_managed_static_ipv6_is_refused_in_this_version(self):
        found = errors(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
        )
        self.assertTrue(found)

    def test_rejects_unknown_managed_by(self):
        self.assertTrue(errors("version: 1\nnetwork:\n  managed_by: magic\n"))

    def test_rejects_nameserver_that_is_not_an_address(self):
        found = errors(
            "version: 1\nnetwork:\n  nameservers:\n    - ns.example.org\n"
        )
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
