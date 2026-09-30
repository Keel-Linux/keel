# Copyright (c) 2026 KeelLinux maintainers
"""The spec's firewall section (decision 0041, as scoped 2026-09-30)

The firewall derived from the manifests is optional and for cloud
advanced installations only: off unless the spec says `enabled: true`,
and refused in the simple and cloud simple modes.
"""

import unittest

from helpers import spec

from keel.spec.validate_firewall import validate_firewall

ADVANCED = {"version": 1, "appliance": {"name": "core"},
            "installation": {"mode": "cloud_advanced"}}


def check(firewall, **sections) -> list[str]:
    return validate_firewall({**ADVANCED, **sections, "firewall": firewall})


class TestFirewall(unittest.TestCase):
    def test_absent_or_off_is_valid_in_every_mode(self):
        self.assertEqual(validate_firewall({"version": 1}), [])
        for mode in ("simple", "cloud_simple", "cloud_advanced"):
            self.assertEqual(check({"enabled": False},
                                   installation={"mode": mode}), [])

    def test_enabled_in_cloud_advanced_is_valid(self):
        self.assertEqual(check({"enabled": True}), [])
        self.assertEqual(spec.validate({**ADVANCED, "overlays": {},
                                        "firewall": {"enabled": True}}), [])

    def test_enabled_outside_cloud_advanced_is_refused(self):
        for mode in ("simple", "cloud_simple"):
            self.assertEqual(check({"enabled": True},
                                   installation={"mode": mode}), [
                "firewall.enabled: the firewall derived from the manifests"
                " is for cloud advanced installations only, and"
                f" installation.mode is {mode}; in the other modes keel"
                " leaves the firewall alone"])

    def test_enabled_without_a_mode_or_an_appliance_is_refused(self):
        found = validate_firewall({"version": 1,
                                   "firewall": {"enabled": True}})
        self.assertEqual(found, [
            "firewall.enabled: the firewall derived from the manifests is"
            " for cloud advanced installations only, and installation.mode"
            " is not declared; in the other modes keel leaves the firewall"
            " alone",
            "firewall.enabled: needs appliance.name: the ports come from"
            " its manifests"])

    def test_the_shape(self):
        self.assertEqual(check("on"), ["firewall: must be a mapping"])
        self.assertEqual(check({"enabled": "yes"}),
                         ["firewall.enabled: must be true or false"])
        self.assertEqual(check({"enabled": True, "ports": [80]}),
                         ["firewall.ports: unknown key"])

    def test_a_top_level_key(self):
        self.assertNotIn("firewall: unknown top level key", spec.validate(
            {"version": 1, "firewall": {"enabled": False}}))


if __name__ == "__main__":
    unittest.main()
