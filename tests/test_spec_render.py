# Copyright (c) 2026 KeelLinux maintainers
"""Mapping of spec fields onto the conf variables the hooks read"""

import os
import tempfile
import unittest
from os.path import join

from helpers import doc, env, errors, spec

from keel.spec.fields import is_ipv4, is_ipv6  # noqa: E402
from keel.spec.render import (  # noqa: E402
    nameserver_env,
    one_of_each,
    unwritten_nameservers,
)


class TestMapping(unittest.TestCase):
    def test_maps_instance_and_app_keys_to_env_names(self):
        exported = env(
            "version: 1\n"
            "instance:\n"
            "  hostname: blog\n"
            "  fqdn: blog.example.org\n"
            "app:\n"
            "  email: admin@example.org\n"
            "  domain: blog.example.org\n"
        )
        self.assertEqual(exported["HOSTNAME"], "blog")
        self.assertEqual(exported["FQDN"], "blog.example.org")
        self.assertEqual(exported["APP_EMAIL"], "admin@example.org")
        self.assertEqual(exported["APP_DOMAIN"], "blog.example.org")

    def test_app_options_are_upper_cased_with_app_prefix(self):
        exported = env(
            "version: 1\n"
            "app:\n"
            "  options:\n"
            "    ip_bind: '[2001:db8:1::10]'\n"
            "    realm: example\n"
        )
        self.assertEqual(exported["APP_IP_BIND"], "'[2001:db8:1::10]'")
        self.assertEqual(exported["APP_REALM"], "example")

    def test_preseed_keys_pass_through_verbatim(self):
        exported = env("version: 1\npreseed:\n  AUTOGROW: ONCE\n")
        self.assertEqual(exported["AUTOGROW"], "ONCE")

    def test_hub_and_security_values_are_upper_cased(self):
        exported = env(
            "version: 1\n"
            "hub:\n"
            "  api_key: skip\n"
            "security:\n"
            "  alerts: skip\n"
            "  updates_at_first_boot: force\n"
        )
        self.assertEqual(exported["HUB_APIKEY"], "SKIP")
        self.assertEqual(exported["SEC_ALERTS"], "SKIP")
        self.assertEqual(exported["SEC_UPDATES"], "FORCE")

    def test_security_alerts_email_is_kept_as_is(self):
        exported = env("version: 1\nsecurity:\n  alerts: A@example.org\n")
        self.assertEqual(exported["SEC_ALERTS"], "A@example.org")

    def test_rejects_security_alerts_that_is_not_an_email(self):
        self.assertTrue(errors("version: 1\nsecurity:\n  alerts: nope\n"))

    def test_first_login_wizard_true_exports_auto_run(self):
        exported = env("version: 1\nfirst_login_wizard: true\n")
        self.assertEqual(exported["AUTO_RUN"], "TRUE")

    def test_first_login_wizard_false_does_not_export_auto_run(self):
        exported = env("version: 1\nfirst_login_wizard: false\n")
        self.assertNotIn("AUTO_RUN", exported)

    def test_boolean_values_are_exported_as_the_hooks_keywords(self):
        exported = env(
            "version: 1\n"
            "app:\n  options:\n    debug: true\n"
            "preseed:\n  AUTOGROW: false\n"
        )
        self.assertEqual(exported["APP_DEBUG"], "TRUE")
        self.assertEqual(exported["AUTOGROW"], "FALSE")

    def test_hub_api_key_from_a_file_is_exported_and_masked_for_display(self):
        tmpdir = tempfile.mkdtemp()
        path = join(tmpdir, "apikey")
        with open(path, "w") as fob:
            fob.write("ABCDEF123456\n")
        os.chmod(path, 0o600)
        text = f"version: 1\nhub:\n  api_key:\n    file: {path}\n"

        self.assertEqual(env(text)["HUB_APIKEY"], "ABCDEF123456")

        document = doc(text)
        placeholders = spec.masked_secrets(document)
        self.assertEqual(placeholders, {"HUB_APIKEY": spec.MASK})
        rendered = spec.mask(spec.render_env(document, placeholders))
        self.assertIn(f"export HUB_APIKEY={spec.MASK}\n", rendered)
        self.assertNotIn("ABCDEF123456", rendered)

    def test_mask_leaves_the_skip_keyword_readable(self):
        rendered = spec.mask("export HUB_APIKEY=SKIP\nexport ROOT_PASS=x\n")
        self.assertEqual(
            rendered, f"export HUB_APIKEY=SKIP\nexport ROOT_PASS={spec.MASK}\n"
        )


IPV4_ONLY = (
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
    "    - 192.0.2.53\n"
    "    - 2001:db8:1::53\n"
)
IPV4_ONLY_CONF = (
    "export IP_CONFIG=static\n"
    "export IP_ADDRESS=192.0.2.10\n"
    "export IP_NETMASK=255.255.255.0\n"
    "export IP_GW=192.0.2.1\n"
    "export IP_DNS1=192.0.2.53\n"
    "export IP_DNS2=2001:db8:1::53\n"
)


class TestNetworkMapping(unittest.TestCase):
    def file_managed(self, family: str, method: str) -> dict:
        return env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            f"      {family}:\n"
            f"        method: {method}\n"
        )

    def test_ipv4_none_exports_nothing(self):
        self.assertEqual(self.file_managed("ipv4", "none"), {})

    def test_ipv4_dhcp_exports_only_the_method(self):
        self.assertEqual(self.file_managed("ipv4", "dhcp"),
                         {"IP_CONFIG": "dhcp"})

    def test_ipv6_none_exports_nothing(self):
        self.assertEqual(self.file_managed("ipv6", "none"), {})

    def test_ipv6_dhcp_and_auto_both_export_the_dhcp_method(self):
        for method in ("dhcp", "auto"):
            with self.subTest(method=method):
                self.assertEqual(self.file_managed("ipv6", method),
                                 {"IP6_CONFIG": "dhcp"})

    def test_ipv6_manual_exports_only_the_method(self):
        self.assertEqual(self.file_managed("ipv6", "manual"),
                         {"IP6_CONFIG": "manual"})

    def test_spec_without_an_ipv6_block_exports_no_ip6_variable(self):
        """IPv6 stays dynamic, so the static inet stanza takes the IPv6
        nameserver too; no IP6_* variable appears (keel#45)"""
        document = doc(IPV4_ONLY)
        self.assertEqual(spec.validate(document), [])
        self.assertEqual(spec.render_env(document, {}), IPV4_ONLY_CONF)

    def test_an_ipv4_nameserver_never_lands_in_the_ip6_dns_variables(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: dhcp\n"
            "  nameservers:\n"
            "    - 192.0.2.53\n"
            "    - 192.0.2.54\n"
            "    - 2001:db8:1::53\n"
        )
        self.assertEqual(exported, {
            "IP_DNS1": "192.0.2.53", "IP_DNS2": "192.0.2.54",
            "IP6_CONFIG": "dhcp", "IP6_DNS1": "2001:db8:1::53",
        })

    def test_ipv6_nameservers_are_not_exported_without_an_ipv6_block(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  nameservers:\n"
            "    - 2001:db8:1::53\n"
            "    - 192.0.2.53\n"
        )
        self.assertEqual(exported, {"IP_DNS1": "192.0.2.53"})

    def test_the_last_ipv6_block_wins_as_a_whole(self):
        static = (
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "        gateway: fe80::1\n"
        )
        auto = "        method: auto\n"
        for first, second, expected in (
            (static, auto, {"IP6_CONFIG": "dhcp"}),
            (auto, static, {"IP6_CONFIG": "static",
                            "IP6_ADDRESS": "2001:db8:1::10/64",
                            "IP6_GW": "fe80::1"}),
        ):
            with self.subTest(expected=expected):
                exported = env(
                    "version: 1\n"
                    "network:\n"
                    "  managed_by: file\n"
                    "  interfaces:\n"
                    "    eth0:\n"
                    "      ipv6:\n" + first +
                    "    eth1:\n"
                    "      ipv6:\n" + second
                )
                self.assertEqual(exported, expected)

    def test_a_dynamic_ipv6_keeps_its_nameserver_in_the_static_ipv4(self):
        """keel#45: a real VM lost 2606:4700:4700::1111 this way"""
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: auto\n"
            "      ipv4:\n"
            "        method: static\n"
            "        address: 192.0.2.10/24\n"
            "  nameservers:\n"
            "    - 2606:4700:4700::1111\n"
            "    - 192.0.2.53\n"
            "    - 192.0.2.54\n"
        )
        self.assertEqual(exported, {
            "IP_CONFIG": "static", "IP_ADDRESS": "192.0.2.10",
            "IP_NETMASK": "255.255.255.0",
            "IP_DNS1": "2606:4700:4700::1111", "IP_DNS2": "192.0.2.53",
            "IP6_CONFIG": "dhcp",
        })

    def test_a_dynamic_ipv4_keeps_its_nameserver_in_the_static_ipv6(self):
        exported = env(
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv4:\n"
            "        method: dhcp\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "  nameservers:\n"
            "    - 2001:db8:1::53\n"
            "    - 192.0.2.53\n"
        )
        self.assertEqual(list(exported), [
            "IP_CONFIG", "IP6_CONFIG", "IP6_ADDRESS", "IP6_DNS1", "IP6_DNS2",
        ])
        self.assertEqual(exported["IP6_DNS1"], "2001:db8:1::53")
        self.assertEqual(exported["IP6_DNS2"], "192.0.2.53")

    def test_one_of_each_keeps_a_resolver_of_each_family(self):
        """keel#45 review: IPv6 listed first must not push every IPv4
        server out, since inet6 auto adds no resolver to resolv.conf"""
        for servers, kept in (
            (["2001:db8:1::53", "2001:db8:2::53", "192.0.2.53"],
             ["2001:db8:1::53", "192.0.2.53"]),
            (["192.0.2.53", "192.0.2.54", "2001:db8:1::53"],
             ["192.0.2.53", "2001:db8:1::53"]),
            (["2001:db8:1::53", "2001:db8:2::53", "2001:db8:3::53"],
             ["2001:db8:1::53", "2001:db8:2::53"]),
            (["192.0.2.53"], ["192.0.2.53"]),
            ([], []),
        ):
            with self.subTest(servers=servers):
                self.assertEqual(one_of_each(servers), kept)

    def test_unwritten_nameservers_names_what_the_file_cannot_hold(self):
        def network(ipv4, ipv6, servers, managed_by="file"):
            return {"managed_by": managed_by, "interfaces": {"eth0": {
                "ipv4": ipv4, "ipv6": ipv6}}, "nameservers": servers}
        static4 = {"method": "static", "address": "192.0.2.10/24"}
        static6 = {"method": "static", "address": "2001:db8:1::10/64"}
        servers = ["2001:db8:1::53", "2001:db8:2::53", "192.0.2.53"]
        for ipv4, ipv6, lost in (
            (static4, {"method": "auto"}, ["2001:db8:2::53"]),
            (static4, static6, []),
            ({"method": "dhcp"}, {"method": "auto"}, servers),
            (None, {"method": "auto"}, servers),
        ):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.assertEqual(unwritten_nameservers(
                    network(ipv4, ipv6, servers)), lost)
        self.assertEqual(unwritten_nameservers(network(
            static4, None, servers, managed_by="host")), [])
        self.assertEqual(unwritten_nameservers(None), [])

    def test_nameserver_env_places_servers_by_the_static_stanza(self):
        servers = ["2001:db8:1::53", "192.0.2.53", "2001:db8:2::53",
                   "192.0.2.54"]
        for methods, expected in (
            ({"IP_CONFIG": "static", "IP6_CONFIG": "static"},
             {"IP_DNS1": "192.0.2.53", "IP_DNS2": "192.0.2.54",
              "IP6_DNS1": "2001:db8:1::53", "IP6_DNS2": "2001:db8:2::53"}),
            ({"IP_CONFIG": "dhcp", "IP6_CONFIG": "dhcp"},
             {"IP_DNS1": "192.0.2.53", "IP_DNS2": "192.0.2.54",
              "IP6_DNS1": "2001:db8:1::53", "IP6_DNS2": "2001:db8:2::53"}),
            ({"IP_CONFIG": "dhcp"},
             {"IP_DNS1": "192.0.2.53", "IP_DNS2": "192.0.2.54"}),
            ({"IP6_CONFIG": "static"},
             {"IP6_DNS1": "2001:db8:1::53", "IP6_DNS2": "192.0.2.53"}),
            ({"IP_CONFIG": "static", "IP6_CONFIG": "manual"},
             {"IP_DNS1": "2001:db8:1::53", "IP_DNS2": "192.0.2.53"}),
        ):
            with self.subTest(methods=methods):
                self.assertEqual(nameserver_env(servers, methods), expected)

    def test_slaac_false_exports_ip6_slaac_no(self):
        body = (
            "version: 1\n"
            "network:\n"
            "  managed_by: file\n"
            "  interfaces:\n"
            "    eth0:\n"
            "      ipv6:\n"
            "        method: static\n"
            "        address: 2001:db8:1::10/64\n"
            "        gateway: fe80::1\n"
        )
        self.assertEqual(env(body + "        slaac: false\n"), {
            "IP6_CONFIG": "static", "IP6_ADDRESS": "2001:db8:1::10/64",
            "IP6_GW": "fe80::1", "IP6_SLAAC": "no",
        })
        for kept in ("", "        slaac: true\n"):
            with self.subTest(kept=kept):
                self.assertNotIn("IP6_SLAAC", env(body + kept))

    def test_is_ipv4_and_is_ipv6_tell_the_families_apart(self):
        self.assertTrue(is_ipv4("192.0.2.53"))
        self.assertFalse(is_ipv4("2001:db8:1::53"))
        self.assertFalse(is_ipv4("ns.example.org"))
        self.assertTrue(is_ipv6("2001:db8:1::53"))
        self.assertFalse(is_ipv6("192.0.2.53"))
        self.assertFalse(is_ipv6("ns.example.org"))


class TestDomains(unittest.TestCase):
    def test_rejects_domain_with_path(self):
        found = errors("version: 1\napp:\n  domain: example.org/blog\n")
        self.assertTrue(found)

    def test_rejects_fqdn_with_port(self):
        found = errors("version: 1\ninstance:\n  fqdn: example.org:8080\n")
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
