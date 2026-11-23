# Copyright (c) 2026 KeelLinux maintainers
"""The firewall, derived from the manifests' exposure classes (0041)

The renderer is pure. When an nft binary is at hand (on PATH, or named
by KEEL_NFT) every ruleset rendered here is also checked with `nft -c`
in a network namespace of its own (tests/wgtools.py says how), which
changes no rule of the machine running the tests.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from manifest_helpers import ManifestCase
from wgtools import namespace_prefix

from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.firewall import (
    ENFORCE,
    HEADER,
    REPORT,
    REPORT_COUNTER,
    Allow,
    file_state,
    loaded_digest,
    render,
)
from keel.manifest.resolve import resolve

CORE_OFF = {"installer": "enabled", "wireguard": "disabled",
            "etcd": "disabled", "crowdsec": "disabled"}
ADVANCED = {"installer": "enabled", "wireguard": "enabled",
            "etcd": "enabled", "crowdsec": "enabled"}
WG = {"address": "fd00:1::1/64", "interface": "wg0", "listen_port": 51820}


def nft_binary() -> str | None:
    return os.environ.get("KEEL_NFT") or shutil.which("nft")


def nft_check(prefix: list[str], text: str) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile("w", suffix=".nft") as fob:
        fob.write(text)
        fob.flush()
        return subprocess.run([*prefix, nft_binary(), "-c", "-f", fob.name],
                              capture_output=True, text=True)


class FirewallCase(ManifestCase):
    def render(self, states: dict, wireguard: dict | None = None,
               name: str = "core"):
        catalog = Catalog(self.root)
        resolved, errors = resolve(catalog, catalog.read(APPLIANCE, name))
        self.assertEqual(errors, [])
        return render(resolved, states, wireguard)

    def assertNftAccepts(self, text: str) -> None:
        """nft -c as root in a network namespace of its own: `unshare
        -n` as root, `unshare -rn`, or `sudo -n unshare -n` where user
        namespaces are not allowed (Ubuntu's CI runners)"""
        prefix = namespace_prefix() if nft_binary() else None
        if prefix is None:
            return
        out = nft_check(prefix, text)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


class TestRender(FirewallCase):
    def test_core_simple_opens_what_webmin_fw_did(self):
        found = self.render(CORE_OFF)
        self.assertTrue(found.text.startswith(HEADER))
        self.assertEqual(found.public, ((22, "tcp"), (12320, "tcp"),
                                        (12321, "tcp")))
        self.assertIn("\t\ttcp dport { 22, 12320, 12321 } accept\n",
                      found.text)
        self.assertNotIn("iifname", found.text)
        self.assertEqual(found.notes, ())
        self.assertNftAccepts(found.text)

    def test_what_is_always_let_in(self):
        text = self.render(CORE_OFF).text
        for line in ('iif "lo" accept',
                     "ct state established,related accept",
                     "ct state invalid drop",
                     "meta l4proto ipv6-icmp accept",
                     "icmp type echo-request accept",
                     "ip6 saddr fe80::/10 udp dport 546 accept",
                     "udp dport 68 accept"):
            self.assertIn(f"\t\t{line}\n", text)
        self.assertIn("type filter hook input priority filter; policy"
                      " drop;", text)
        self.assertIn("table inet keel\ndelete table inet keel\n", text)

    def test_cloud_advanced_opens_the_mesh_on_the_overlay_only(self):
        found = self.render(ADVANCED, WG)
        self.assertEqual(found.mesh, ((2379, "tcp"), (2380, "tcp")))
        self.assertIn('\t\tiifname "wg0" tcp dport { 2379, 2380 } accept\n',
                      found.text)
        self.assertIn("\t\tudp dport 51820 accept\n", found.text)
        # CrowdSec listens on the loopback only: nothing opened for it
        self.assertNotIn("8080", found.text)
        self.assertNftAccepts(found.text)

    def test_a_named_set_for_the_pending_invites_ports(self):
        """keel mesh invite adds its TCP port to the set with a timeout,
        so the port is open while the invite is pending and closes by
        itself (decision 0048); empty while none is"""
        found = self.render(ADVANCED, WG)
        self.assertIn("\tset mesh_invites {\n\t\ttype inet_service\n"
                      "\t\tflags timeout\n\t}\n\tchain input {\n",
                      found.text)
        self.assertIn("\t\ttcp dport @mesh_invites accept\n", found.text)
        self.assertNftAccepts(found.text)
        without = self.render(CORE_OFF)
        self.assertNotIn("mesh_invites", without.text)

    def test_the_members_port_on_the_overlay_alone(self):
        """keel mesh sync and the announcement of a new node, between
        members over the overlay (decision 0048, keel.mesh.members)"""
        found = self.render(ADVANCED, WG)
        self.assertIn('\t\tiifname "wg0" tcp dport 51821 accept\n',
                      found.text)
        self.assertNftAccepts(found.text)
        self.assertNotIn("51821", self.render(CORE_OFF).text)

    def test_the_overlay_s_defaults(self):
        found = self.render(ADVANCED, {"address": "fd00:1::1/64"})
        self.assertIn('iifname "wg0"', found.text)
        self.assertIn("udp dport 51820 accept", found.text)

    def test_mesh_ports_without_an_overlay_are_left_closed(self):
        found = self.render(ADVANCED)
        self.assertEqual(found.mesh, ())
        self.assertEqual(found.notes, (
            "2379/tcp, 2380/tcp of etcd not opened: they are mesh ports,"
            " and the spec declares no network.overlay.wireguard",))

    def test_a_disabled_overlay_opens_nothing(self):
        found = self.render({**ADVANCED, "etcd": "disabled"}, WG)
        self.assertNotIn("2379", found.text)

    def test_single_ports_and_udp(self):
        self.edit("overlays", "etcd", "- {port: 2380, protocol: tcp,"
                  " expose: mesh}", "- {port: 2380, protocol: udp,"
                  " expose: public}")
        found = self.render(ADVANCED, WG)
        self.assertIn('\t\tiifname "wg0" tcp dport 2379 accept\n', found.text)
        self.assertIn("\t\tudp dport { 2380, 51820 } accept\n", found.text)
        self.assertNftAccepts(found.text)

    def test_the_host_s_bridges_keep_their_dhcp_and_dns(self):
        """containers on lxcbr0 or docker0 get their leases and names
        from the host's dnsmasq: DHCPv4 67, DHCPv6 547, DNS 53"""
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        found = render(resolved, CORE_OFF, None, ("lxcbr0", "docker0"))
        self.assertIn('\t\tiifname { "docker0", "lxcbr0" } udp dport'
                      " { 53, 67, 547 } accept\n", found.text)
        self.assertIn('\t\tiifname { "docker0", "lxcbr0" } tcp dport 53'
                      " accept\n", found.text)
        one = render(resolved, CORE_OFF, None, ("lxcbr0",))
        self.assertIn('\t\tiifname "lxcbr0" udp dport { 53, 67, 547 }'
                      " accept\n", one.text)
        self.assertNotEqual(one.digest, found.digest)
        self.assertNotIn("dport 67", self.render(CORE_OFF).text)
        self.assertNftAccepts(found.text)

    def test_the_digest_is_in_the_table_and_read_back(self):
        found = self.render(CORE_OFF)
        self.assertEqual(len(found.digest), 16)
        self.assertIn(f'\tcomment "keel-manifest {found.digest}"\n',
                      found.text)
        self.assertNotEqual(found.digest, self.render(ADVANCED, WG).digest)
        listing = ('table inet keel {\n\tcomment "keel-manifest'
                   f' {found.digest}"\n\tchain input {{\n')
        self.assertEqual(loaded_digest(listing), found.digest)
        self.assertIsNone(loaded_digest("table inet keel {\n}\n"))


class TestEveryMode(FirewallCase):
    """Decision 0097: one ruleset in every mode, in two states"""

    def resolved(self):
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        return resolved

    def test_each_mode_renders_a_drop_policy_nft_accepts(self):
        simple = render(self.resolved(), CORE_OFF, None)
        cloud_simple = render(self.resolved(), {**ADVANCED, "etcd":
                                                "disabled"}, WG)
        advanced = render(self.resolved(), ADVANCED, WG)
        for found in (simple, cloud_simple, advanced):
            self.assertEqual(found.state, ENFORCE)
            self.assertIn("policy drop;", found.text)
            self.assertIn("\t\tct state invalid drop\n", found.text)
            self.assertNftAccepts(found.text)
        self.assertNotIn("2379", cloud_simple.text)
        self.assertIn('iifname "wg0" tcp dport 51821 accept',
                      cloud_simple.text)

    def test_report_drops_nothing_and_counts_what_enforce_would(self):
        found = render(self.resolved(), ADVANCED, WG, state=REPORT)
        self.assertEqual(found.state, REPORT)
        self.assertIn("type filter hook input priority filter; policy"
                      " accept;", found.text)
        chain = found.text.split("chain input {\n")[1].split("\t}\n")[0]
        self.assertFalse([line for line in chain.splitlines()
                          if line.endswith(" drop")])
        self.assertEqual(chain.splitlines()[-1],
                         f'\t\tcounter comment "{REPORT_COUNTER}"')
        self.assertTrue(found.text.startswith(HEADER + "\n# state: report"
                                              "\n"))
        self.assertNftAccepts(found.text)

    def test_the_two_states_have_two_digests(self):
        enforce = render(self.resolved(), CORE_OFF, None)
        report = render(self.resolved(), CORE_OFF, None, state=REPORT)
        self.assertNotEqual(enforce.digest, report.digest)

    def test_the_state_of_a_file_is_read_from_its_policy(self):
        enforce = render(self.resolved(), CORE_OFF, None)
        report = render(self.resolved(), CORE_OFF, None, state=REPORT)
        self.assertEqual(file_state(enforce.text), ENFORCE)
        self.assertEqual(file_state(report.text), REPORT)
        self.assertIsNone(file_state(None))
        self.assertIsNone(file_state("table inet mine {}\n"))

    def test_off_is_no_ruleset_and_a_header_alone_no_state(self):
        with self.assertRaisesRegex(ValueError, "enforce or report"):
            render(self.resolved(), CORE_OFF, None, state="off")
        self.assertIsNone(file_state(HEADER + "\n"))

    def test_a_file_of_keel_0_23_97_reads_as_enforce(self):
        """cloud advanced nodes with `firewall.enabled: true` have the
        old file: it has the same header and a drop policy"""
        old = (HEADER + "\ntable inet keel\ndelete table inet keel\n"
               "table inet keel {\n\tchain input {\n\t\ttype filter hook"
               " input priority filter; policy drop;\n\t}\n}\n")
        self.assertEqual(file_state(old), ENFORCE)

    def test_every_port_sshd_listens_on_is_opened(self):
        found = render(self.resolved(), CORE_OFF, None, ssh=(22, 2222))
        self.assertIn((2222, "tcp"), found.public)
        self.assertEqual(found.ssh, (22, 2222))
        self.assertIn("\t\ttcp dport { 22, 2222, 12320, 12321 } accept\n",
                      found.text)
        self.assertNftAccepts(found.text)

    def test_allow_opens_a_port_everywhere_or_from_its_prefixes(self):
        allow = (Allow(8080, "tcp"),
                 Allow(5432, "tcp", ("192.0.2.0/24", "2001:db8::/32",
                                     "198.51.100.7/32")),
                 Allow(9000, "udp", ("2001:db8:1::/48",)))
        found = render(self.resolved(), CORE_OFF, None, allow=allow)
        self.assertIn("\t\ttcp dport 8080 accept\n", found.text)
        self.assertIn("\t\tip saddr { 192.0.2.0/24, 198.51.100.7/32 } tcp"
                      " dport 5432 accept\n", found.text)
        self.assertIn("\t\tip6 saddr 2001:db8::/32 tcp dport 5432 accept\n",
                      found.text)
        self.assertIn("\t\tip6 saddr 2001:db8:1::/48 udp dport 9000"
                      " accept\n", found.text)
        self.assertNotIn("ip saddr 2001", found.text)
        self.assertNftAccepts(found.text)

    def test_the_fence_ports_only_for_redirected_packets(self):
        """turnkey-init-fence redirects 80 and 443 to its own ports: the
        input hook sees the fence port, so only a DNAT packet passes"""
        found = render(self.resolved(), CORE_OFF, None, fence=(60080, 60443))
        self.assertIn("\t\tct status dnat tcp dport { 60080, 60443 }"
                      " accept\n", found.text)
        self.assertNotIn("60080", render(self.resolved(), CORE_OFF,
                                         None).text)
        self.assertNftAccepts(found.text)


if __name__ == "__main__":
    unittest.main()
