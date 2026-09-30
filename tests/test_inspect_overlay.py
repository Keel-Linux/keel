# Copyright (c) 2026 KeelLinux maintainers
"""keel inspect and keel diff on the WireGuard overlay (decision 0020)

inspect reads /etc/wireguard back into network.overlay.wireguard and
reports the public key beside the spec, never the private key; diff
compares peers by their public key, whatever the order of the list.
"""

import os
import shutil
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.diff import DRIFT, NOT_COMPARED, NOT_DECLARED, SAME, compare
from keel.inspect import inspect_root
from keel.inspect.collect import overlay_section
from keel.inspect.report import NOT_EXTRACTED, NOT_INFERRED
from keel.inspect.tree import File, Tree
from keel.inspect.wireguard import Module, probe_overlay
from keel.network import wireguard

PEER_KEY = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OTHER_KEY = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
PUBLIC = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
OVERLAY = {
    "address": "fd00:1::1/64",
    "peers": [
        {"public_key": PEER_KEY, "endpoint": "[2001:db8::20]:51820",
         "allowed_ips": ["fd00:1::2/128", "10.66.0.2/32"]},
        {"public_key": OTHER_KEY, "allowed_ips": ["fd00:1::3/128"]},
    ],
}
NO_MODULE_INFO = Module(None, False)


def conf(text, name="wg0"):
    return File(f"/etc/wireguard/{name}.conf", text)


def public(key):
    return PUBLIC, None


def by_field(findings):
    return {finding.field: finding for finding in findings}


class TestProbe(unittest.TestCase):
    def test_nothing_configured(self):
        self.assertEqual(probe_overlay([], public, NO_MODULE_INFO),
                         (None, []))
        unreadable = File("/etc/wireguard/wg0.conf", problem="denied")
        self.assertEqual(probe_overlay([unreadable], public,
                                       NO_MODULE_INFO), (None, []))

    def test_the_rendered_file_reads_back(self):
        section, findings = probe_overlay(
            [conf(wireguard.render(OVERLAY))], public, NO_MODULE_INFO)
        self.assertEqual(section, {"wireguard": {
            "interface": "wg0", **OVERLAY, "listen_port": 51820,
            "private_key": {"file": "/etc/wireguard/wg0.key"}}})
        found = by_field(findings)
        self.assertEqual(found["network.overlay.wireguard.public_key"].value,
                         PUBLIC)
        self.assertIn("never read",
                      found["network.overlay.wireguard.private_key"].source)
        self.assertIn(OTHER_KEY,
                      found["network.overlay.wireguard.peers"].value)

    def test_the_default_interface_is_chosen_and_the_others_named(self):
        section, findings = probe_overlay(
            [conf("[Interface]\nAddress = fd00:2::1/64\n", "a0"),
             conf(wireguard.render(OVERLAY))], public, NO_MODULE_INFO)
        self.assertEqual(section["wireguard"]["interface"], "wg0")
        self.assertTrue(any("a0.conf not read" in one.source
                            for one in findings))

    def test_an_inline_key_is_never_read(self):
        section, findings = probe_overlay(
            [conf("[Interface]\nPrivateKey = secret\nListenPort = 5\n")],
            mock.Mock(side_effect=AssertionError("must not be asked")),
            NO_MODULE_INFO)
        self.assertNotIn("secret", repr(section) + repr(findings))
        found = by_field(findings)
        self.assertEqual(found["network.overlay.wireguard.private_key"]
                         .status, NOT_EXTRACTED)
        self.assertEqual(found["network.overlay.wireguard.public_key"]
                         .status, NOT_INFERRED)
        self.assertEqual(found["network.overlay.wireguard.address"].status,
                         NOT_INFERRED)

    def test_a_file_without_a_key_and_a_key_that_gives_nothing(self):
        _, findings = probe_overlay([conf("[Interface]\n")], public,
                                    NO_MODULE_INFO)
        self.assertIn("names no private key", by_field(findings)[
            "network.overlay.wireguard.private_key"].source)
        _, findings = probe_overlay(
            [conf(wireguard.render(OVERLAY))],
            lambda key: (None, f"{key}: secret file not found"),
            NO_MODULE_INFO)
        self.assertIn("not found", by_field(findings)[
            "network.overlay.wireguard.public_key"].source)

    def test_lines_the_spec_cannot_hold_are_named(self):
        _, findings = probe_overlay(
            [conf(wireguard.render(OVERLAY) + "\n[Peer]\nPresharedKey = x"
                  "\nAllowedIPs = fd00:1::4/128\n")], public,
            NO_MODULE_INFO)
        self.assertTrue(any("presharedkey" in one.source
                            for one in findings))

    def test_the_module(self):
        cases = (
            (Module(False, True), [], "modprobe wireguard` on the host"),
            (Module(False, False), [conf("[Interface]\n")],
             "wg-quick loads it"),
        )
        for module, files, words in cases:
            with self.subTest(module=module):
                _, findings = probe_overlay(files, public, module)
                found = by_field(findings)[
                    "network.overlay.wireguard.kernel_module"]
                self.assertEqual(found.value, "not loaded")
                self.assertIn(words, found.source)
        for module in (Module(True, True), Module(False, False)):
            self.assertEqual(probe_overlay([], public, module), (None, []))


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def put(self, relative, text, mode=0o600):
        path = join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)
        os.chmod(path, mode)


class TestCollect(RootCase):
    def test_the_key_file_is_looked_for_under_the_root(self):
        self.put("etc/wireguard/wg0.conf", wireguard.render(OVERLAY))
        self.put("etc/wireguard/wg0.key", "k\n")
        with mock.patch("keel.inspect.collect.wgkeys.public",
                        return_value=(PUBLIC, None)) as asked:
            section, findings = overlay_section(Tree(self.root))
        asked.assert_called_once_with(
            join(self.root, "etc/wireguard/wg0.key"))
        self.assertEqual(section["wireguard"]["address"], "fd00:1::1/64")

    def test_the_live_system_is_asked_about_the_module(self):
        self.put("var/lib/turnkey-info/inithooks.service/lxc", "")
        with mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                        self.root):
            _, findings = overlay_section(Tree(self.root))
        self.assertIn("modprobe", findings[0].source)

    def test_inspect_puts_the_overlay_in_the_network_section(self):
        self.put("etc/wireguard/wg0.conf", wireguard.render(OVERLAY))
        with mock.patch("keel.inspect.collect.wgkeys.public",
                        return_value=(PUBLIC, None)):
            inspection = inspect_root(self.root)
        self.assertEqual(inspection.spec["network"]["overlay"]["wireguard"]
                         ["peers"], OVERLAY["peers"])


def declared(**wg):
    return {"version": 1, "network": {"overlay": {"wireguard": {
        **OVERLAY, **wg}}}}


class TestDiff(RootCase):
    def diff(self, doc):
        with mock.patch("keel.inspect.collect.wgkeys.public",
                        return_value=(PUBLIC, None)):
            comparison = compare(doc, inspect_root(self.root))
        return {field.field: field for field in comparison.fields
                if field.field.startswith("network.overlay")}

    def setUp(self):
        super().setUp()
        self.put("etc/wireguard/wg0.conf", wireguard.render(OVERLAY))

    def test_the_rendered_file_is_the_same_as_its_spec(self):
        found = self.diff(declared())
        self.assertEqual({one.status for one in found.values()}
                         - {NOT_DECLARED}, {SAME})
        self.assertEqual(found["network.overlay.wireguard.interface"].status,
                         SAME)
        self.assertEqual(found["network.overlay.wireguard.listen_port"]
                         .status, SAME)
        self.assertEqual(
            found["network.overlay.wireguard.private_key.file"].status,
            NOT_DECLARED)

    def test_peers_compare_by_key_whatever_their_order(self):
        doc = declared(peers=[
            {"public_key": OTHER_KEY, "allowed_ips": ["fd00:1::3/128"]},
            {"public_key": PEER_KEY, "endpoint": "[2001:DB8:0::20]:51820",
             "allowed_ips": ["10.66.0.2/32", "fd00:1:0::2/128"]},
        ])
        found = self.diff(doc)
        self.assertEqual(found[f"network.overlay.wireguard.peers.{PEER_KEY}"
                               ".endpoint"].status, SAME)
        self.assertEqual(found[f"network.overlay.wireguard.peers.{PEER_KEY}"
                               ".allowed_ips"].status, SAME)

    def test_a_missing_peer_and_a_moved_endpoint_are_drift(self):
        new_key = "Q" * 42 + "Y="
        doc = declared(peers=[
            {"public_key": PEER_KEY, "endpoint": "[2001:db8::21]:51820",
             "allowed_ips": ["fd00:1::2/128", "10.66.0.2/32"]},
            {"public_key": new_key, "allowed_ips": ["fd00:1::4/128"]},
        ])
        found = self.diff(doc)
        self.assertEqual(found[f"network.overlay.wireguard.peers.{PEER_KEY}"
                               ".endpoint"].status, DRIFT)
        self.assertEqual(found[f"network.overlay.wireguard.peers.{new_key}"
                               ".allowed_ips"].status, DRIFT)
        self.assertEqual(found[f"network.overlay.wireguard.peers.{OTHER_KEY}"
                               ".allowed_ips"].status, NOT_DECLARED)

    def test_the_key_file_is_a_secret_reference(self):
        found = self.diff(declared(private_key={"file": "/etc/k/wg0.key"}))
        self.assertEqual(
            found["network.overlay.wireguard.private_key.file"].status,
            NOT_COMPARED)

    def test_no_overlay_on_the_machine_is_drift(self):
        os.remove(join(self.root, "etc/wireguard/wg0.conf"))
        found = self.diff(declared())
        self.assertEqual(found["network.overlay.wireguard.address"].status,
                         DRIFT)

    def test_a_peer_list_that_is_not_a_list_is_left_alone(self):
        from keel.diff.compare import peers_by_key, with_overlay_defaults
        odd = {"overlay": {"wireguard": {"peers": "x"}}}
        self.assertIs(peers_by_key(odd), odd)
        self.assertIs(peers_by_key(None), None)
        self.assertEqual(with_overlay_defaults({"overlay": []}),
                         {"overlay": []})
