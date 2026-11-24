# Copyright (c) 2026 KeelLinux maintainers
"""The spec's firewall section (decisions 0041 and 0097)

Decision 0097 ends the scope of 2026-09-30 (cloud advanced only): the
section is valid in every mode. `state` is enforce, report or off;
`enabled: true` is the old spelling of enforce, `enabled: false` and an
absent section read as report, which an apply a person runs may move to
enforce (the maintainer's answer B). `allow` holds the administrator's
own ports, each open everywhere or only from its prefixes.
"""

import unittest

from helpers import spec

from keel.spec.validate_firewall import declared_state, validate_firewall

ADVANCED = {"version": 1, "appliance": {"name": "core"},
            "installation": {"mode": "cloud_advanced"}}
MODES = ("simple", "cloud_simple", "cloud_advanced")


def check(firewall, **sections) -> list[str]:
    return validate_firewall({**ADVANCED, **sections, "firewall": firewall})


class TestFirewall(unittest.TestCase):
    def test_absent_or_off_is_valid_in_every_mode(self):
        self.assertEqual(validate_firewall({"version": 1}), [])
        for mode in MODES:
            self.assertEqual(check({"enabled": False},
                                   installation={"mode": mode}), [])

    def test_enabled_and_every_state_are_valid_in_every_mode(self):
        for mode in MODES:
            for firewall in ({"enabled": True}, {"state": "enforce"},
                             {"state": "report"}, {"state": "off"}):
                self.assertEqual(check(firewall,
                                       installation={"mode": mode}), [])
        self.assertEqual(spec.validate({**ADVANCED, "overlays": {},
                                        "firewall": {"state": "enforce"}}),
                         [])

    def test_a_state_without_an_appliance_is_refused(self):
        for firewall in ({"enabled": True}, {"state": "enforce"},
                         {"state": "report"}):
            key = "enabled" if "enabled" in firewall else "state"
            self.assertEqual(validate_firewall(
                {"version": 1, "firewall": firewall}), [
                f"firewall.{key}: needs appliance.name: the ports come"
                " from its manifests"])
        self.assertEqual(validate_firewall(
            {"version": 1, "firewall": {"state": "off"}}), [])

    def test_the_shape(self):
        self.assertEqual(check("on"), ["firewall: must be a mapping"])
        self.assertEqual(check({"enabled": "yes"}),
                         ["firewall.enabled: must be true or false"])
        self.assertEqual(check({"state": "drop"}), [
            "firewall.state: must be one of enforce, report, off"])
        self.assertEqual(check({"enabled": True, "ports": [80]}),
                         ["firewall.ports: unknown key"])

    def test_enabled_and_state_together_are_refused(self):
        self.assertEqual(check({"enabled": True, "state": "enforce"}), [
            "firewall: say `state` or `enabled`, not both; `enabled` is the"
            " old spelling (true is state: enforce)"])

    def test_a_top_level_key(self):
        self.assertNotIn("firewall: unknown top level key", spec.validate(
            {"version": 1, "firewall": {"enabled": False}}))


class TestAllow(unittest.TestCase):
    def test_a_port_everywhere_or_from_prefixes(self):
        self.assertEqual(check({"allow": [
            {"port": 8080, "protocol": "tcp"},
            {"port": 5432, "protocol": "tcp",
             "from": ["192.0.2.0/24", "2001:db8::/32", "198.51.100.7"]},
        ]}), [])

    def test_each_item_is_checked(self):
        self.assertEqual(check({"allow": "8080"}),
                         ["firewall.allow: must be a list"])
        self.assertEqual(check({"allow": [
            8080,
            {"port": 0, "protocol": "tcp"},
            {"port": True, "protocol": "tcp"},
            {"port": 80, "protocol": "icmp"},
            {"port": 80},
            {"port": 80, "protocol": "tcp", "from": "192.0.2.0/24"},
            {"port": 80, "protocol": "tcp", "from": []},
            {"port": 80, "protocol": "tcp", "from": ["192.0.2.1/24"]},
            {"port": 80, "protocol": "tcp", "from": ["example.org"]},
            {"port": 80, "protocol": "tcp", "to": "x"},
        ]}), [
            "firewall.allow[0]: must be a mapping",
            "firewall.allow[1].port: must be a port number, 1 to 65535",
            "firewall.allow[2].port: must be a port number, 1 to 65535",
            "firewall.allow[3].protocol: must be tcp or udp",
            "firewall.allow[4].protocol: must be tcp or udp",
            "firewall.allow[5].from: must be a list of prefixes",
            "firewall.allow[6].from: must be a list of prefixes",
            "firewall.allow[7].from: 192.0.2.1/24 is not a prefix: it has"
            " host bits set",
            "firewall.allow[8].from: example.org is not a prefix: it does"
            " not appear to be an IPv4 or IPv6 network",
            "firewall.allow[9].to: unknown key",
        ])


class TestDeclaredState(unittest.TestCase):
    def test_what_each_spelling_reads_as(self):
        """None is the implicit state: report, which rule B may move to
        enforce; only an explicit word is a choice"""
        self.assertIsNone(declared_state({}))
        self.assertIsNone(declared_state({"firewall": {}}))
        self.assertIsNone(declared_state({"firewall": {"enabled": False}}))
        self.assertIsNone(declared_state({"firewall": {"allow": []}}))
        self.assertEqual(declared_state({"firewall": {"enabled": True}}),
                         "enforce")
        for state in ("enforce", "report", "off"):
            self.assertEqual(declared_state({"firewall": {"state": state}}),
                             state)

    def test_an_unquoted_off_is_off(self):
        """YAML 1.1, which PyYAML reads, makes `state: off` false"""
        self.assertEqual(declared_state({"firewall": {"state": False}}),
                         "off")
        self.assertEqual(check({"state": False}), [])
        self.assertEqual(check({"state": True}), [
            "firewall.state: must be one of enforce, report, off"])


if __name__ == "__main__":
    unittest.main()
