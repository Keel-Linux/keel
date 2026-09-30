# Copyright (c) 2026 KeelLinux maintainers
"""The overlay's file and key pair (decision 0020), checked by wg itself

The pure half (render, parse, the endpoint and key rules) is tested on
its own; then the rendered file and the key pair are handed to the real
wg and wg-quick (tests/wgtools.py): `wg genkey` and `wg pubkey` make and
read the key, `wg-quick strip` parses the file, and `wg-quick up` brings
it up in a network namespace of its own, where `wg show` says what the
kernel took from it.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from os.path import join
from unittest import mock

import wgtools
from helpers import spec  # noqa: F401

from keel.network import wgkeys, wireguard

PEER_KEY = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OTHER_KEY = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
OVERLAY = {
    "address": "fd00:1::1/64",
    "ipv4_address": "10.66.0.1/24",
    "listen_port": 51821,
    "private_key": {"file": "/etc/keel/wg/overlay.key"},
    "peers": [
        {"public_key": PEER_KEY, "endpoint": "[2001:db8::20]:51820",
         "allowed_ips": ["fd00:1::2/128", "10.66.0.2/32"],
         "persistent_keepalive": 25},
        {"public_key": OTHER_KEY, "allowed_ips": ["fd00:1::3/128"]},
    ],
}


class TestNames(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(wireguard.interface({}), "wg0")
        self.assertEqual(wireguard.conf_path("wg0"), "etc/wireguard/wg0.conf")
        self.assertEqual(wireguard.key_path({}), "/etc/wireguard/wg0.key")
        self.assertEqual(wireguard.key_path({"interface": "ov1"}),
                         "/etc/wireguard/ov1.key")
        self.assertEqual(wireguard.port({}), 51820)

    def test_declared(self):
        self.assertEqual(wireguard.key_path(OVERLAY),
                         "/etc/keel/wg/overlay.key")
        self.assertEqual(wireguard.port(OVERLAY), 51821)
        self.assertEqual(wireguard.addresses(OVERLAY),
                         ("fd00:1::1/64", "10.66.0.1/24"))


class TestKeyText(unittest.TestCase):
    def test_a_real_key_shape(self):
        self.assertTrue(wireguard.is_key(PEER_KEY))

    def test_not_keys(self):
        # the last is 44 characters of valid base64 holding 31 bytes
        for text in ("", "short", PEER_KEY[:-1] + "!", "A" * 44,
                     "A" * 42 + "=="):
            with self.subTest(text=text):
                self.assertFalse(wireguard.is_key(text))


class TestEndpoint(unittest.TestCase):
    def test_accepted(self):
        for text, expected in (
            ("[2001:db8::20]:51820", ("2001:db8::20", 51820)),
            ("node2.example.org:51820", ("node2.example.org", 51820)),
            ("192.0.2.20:1", ("192.0.2.20", 1)),
        ):
            with self.subTest(text=text):
                self.assertEqual(wireguard.split_endpoint(text), expected)

    def test_refused(self):
        for text, reason in (
            ("2001:db8::20:51820", "brackets"),
            ("[2001:db8::20]51820", "[address]:port"),
            ("[2001:db8::20", "[address]:port"),
            ("node2", "port is required"),
            (":51820", "port is required"),
            ("node2:0", "not a port"),
            ("node2:70000", "not a port"),
            ("node2:x", "not a port"),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError) as e:
                wireguard.split_endpoint(text)
            self.assertIn(reason, str(e.exception))

    def test_a_bracketed_non_address_is_refused(self):
        with self.assertRaises(ValueError):
            wireguard.split_endpoint("[node2]:51820")

    def test_canonical(self):
        self.assertEqual(
            wireguard.canonical_endpoint("[2001:DB8:0::20]:51820"),
            "[2001:db8::20]:51820")
        self.assertEqual(wireguard.canonical_endpoint("Node2.Example.org.:5"),
                         "node2.example.org:5")
        self.assertEqual(wireguard.canonical_endpoint("192.0.2.1:5"),
                         "192.0.2.1:5")
        self.assertEqual(wireguard.canonical_endpoint("garbage"), "garbage")


class TestRender(unittest.TestCase):
    def test_the_file(self):
        text = wireguard.render(OVERLAY)
        self.assertTrue(text.startswith("# Written by keel"))
        body = text.split("[Interface]", 1)[1]
        self.assertEqual(body, (
            "\nAddress = fd00:1::1/64, 10.66.0.1/24\n"
            "ListenPort = 51821\n"
            "PostUp = wg set %i private-key /etc/keel/wg/overlay.key\n"
            "\n[Peer]\n"
            f"PublicKey = {PEER_KEY}\n"
            "Endpoint = [2001:db8::20]:51820\n"
            "AllowedIPs = fd00:1::2/128, 10.66.0.2/32\n"
            "PersistentKeepalive = 25\n"
            "\n[Peer]\n"
            f"PublicKey = {OTHER_KEY}\n"
            "AllowedIPs = fd00:1::3/128\n"
        ))

    def test_no_private_key_in_the_file(self):
        self.assertNotIn("PrivateKey", wireguard.render(OVERLAY))

    def test_a_minimal_overlay(self):
        text = wireguard.render({"address": "fd00:1::1/64"})
        self.assertIn("ListenPort = 51820\n", text)
        self.assertIn("private-key /etc/wireguard/wg0.key\n", text)
        self.assertNotIn("[Peer]", text)


class TestParse(unittest.TestCase):
    def test_the_rendered_file_reads_back_as_the_spec(self):
        parsed = wireguard.parse(wireguard.render(OVERLAY))
        self.assertEqual(parsed.section, OVERLAY)
        self.assertFalse(parsed.inline_key)
        self.assertEqual(parsed.problems, ())

    def test_a_hand_written_file(self):
        parsed = wireguard.parse(
            "[Interface]\n"
            "PrivateKey = never-read\n"
            "Address = fd00:1::1/64\n"
            "Address = fd00:1::9/64  # a second IPv6\n"
            "Address = not-an-address\n"
            "DNS = 2001:db8::53\n"
            "garbage\n"
            "[Peer]\n"
            f"publickey={PEER_KEY}\n"
            "PresharedKey = x\n"
            "[Other]\n"
        )
        self.assertTrue(parsed.inline_key)
        self.assertEqual(parsed.section, {
            "address": "fd00:1::1/64",
            "peers": [{"public_key": PEER_KEY}],
        })
        self.assertEqual(len(parsed.problems), 6)
        joined = " ".join(parsed.problems)
        for word in ("one address per family", "not-an-address is not",
                     "dns", "not key = value", "presharedkey",
                     "[Other]"):
            self.assertIn(word, joined)


class TestSuggest(unittest.TestCase):
    def test_a_unique_local_address(self):
        self.assertEqual(wireguard.suggest_address(bytes([1, 2, 3, 4, 5])),
                         "fd01:203:405::1/64")

    def test_five_bytes_only(self):
        with self.assertRaises(ValueError):
            wireguard.suggest_address(b"1234")


class KeyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(subprocess.run, ["rm", "-rf", self.tmp])
        self.key = join(self.tmp, "keys", "wg0.key")


class TestKeysWithoutTools(KeyCase):
    def test_generate_without_wg_names_the_package(self):
        with mock.patch.object(wgkeys.subprocess, "run",
                               side_effect=FileNotFoundError):
            problem = wgkeys.generate(self.key)
        self.assertIn("wireguard-tools", problem)
        self.assertFalse(os.path.exists(self.key))

    def test_generate_failing_leaves_no_half_key(self):
        failed = subprocess.CompletedProcess([], 1, stderr="no entropy\n")
        with mock.patch.object(wgkeys.subprocess, "run",
                               return_value=failed):
            problem = wgkeys.generate(self.key)
        self.assertEqual(problem, "wg exited 1: no entropy")
        self.assertFalse(os.path.exists(self.key))

    def test_an_existing_key_is_never_replaced(self):
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as fob:
            fob.write("kept\n")
        with mock.patch.object(wgkeys.subprocess, "run") as run:
            self.assertIsNone(wgkeys.generate(self.key))
        run.assert_not_called()

    def test_a_key_that_cannot_be_created(self):
        os.makedirs(os.path.dirname(self.key))
        with mock.patch.object(wgkeys.os, "open",
                               side_effect=PermissionError(13, "denied")):
            problem = wgkeys.generate(self.key)
        self.assertIn("cannot create", problem)

    def test_public_refuses_a_missing_or_open_key(self):
        public, problem = wgkeys.public(self.key)
        self.assertIsNone(public)
        self.assertIn("not found", problem)
        os.makedirs(os.path.dirname(self.key))
        with open(self.key, "w") as fob:
            fob.write("x\n")
        os.chmod(self.key, 0o644)
        self.assertIn("0600", wgkeys.public(self.key)[1])

    def test_public_that_cannot_open_or_run(self):
        os.makedirs(os.path.dirname(self.key))
        fd = os.open(self.key, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        with mock.patch("builtins.open", side_effect=OSError(5, "EIO")):
            self.assertIn("cannot read", wgkeys.public(self.key)[1])
        with mock.patch.object(wgkeys.subprocess, "run",
                               side_effect=FileNotFoundError):
            self.assertIn("wireguard-tools", wgkeys.public(self.key)[1])


class TestRealKeys(KeyCase):
    """wg genkey and wg pubkey themselves"""

    def setUp(self):
        super().setUp()
        tools = wgtools.require(self)
        patcher = mock.patch.dict(os.environ, wgtools.env(tools))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_key_pair(self):
        self.assertIsNone(wgkeys.generate(self.key))
        mode = stat.S_IMODE(os.stat(self.key).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(
            os.stat(os.path.dirname(self.key)).st_mode) & 0o077, 0)
        public, problem = wgkeys.public(self.key)
        self.assertIsNone(problem)
        self.assertTrue(wireguard.is_key(public))
        with open(self.key) as fob:
            private = fob.read().strip()
        self.assertTrue(wireguard.is_key(private))
        self.assertNotEqual(private, public)
        again = subprocess.run(["wg", "pubkey"], input=private + "\n",
                               capture_output=True, text=True, check=True)
        self.assertEqual(again.stdout.strip(), public)

    def test_a_second_generate_keeps_the_identity(self):
        wgkeys.generate(self.key)
        first = wgkeys.public(self.key)
        wgkeys.generate(self.key)
        self.assertEqual(wgkeys.public(self.key), first)

    def test_pubkey_refuses_what_is_not_a_key(self):
        os.makedirs(os.path.dirname(self.key))
        fd = os.open(self.key, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as fob:
            fob.write("not a key\n")
        public, problem = wgkeys.public(self.key)
        self.assertIsNone(public)
        self.assertIn("does not hold a WireGuard private key", problem)


class TestRealWgQuick(KeyCase):
    """The rendered file, parsed by wg-quick and brought up by it"""

    def setUp(self):
        super().setUp()
        self.tools = wgtools.require(self)
        patcher = mock.patch.dict(os.environ, wgtools.env(self.tools))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertIsNone(wgkeys.generate(self.key))
        overlay = {**OVERLAY, "private_key": {"file": self.key}}
        self.overlay = overlay
        self.conf = join(self.tmp, "wg0.conf")
        with open(self.conf, "w") as fob:
            fob.write(wireguard.render(overlay))
        os.chmod(self.conf, 0o600)

    def test_wg_quick_strip_keeps_every_wg_line(self):
        done = wgtools.in_namespace(self, self.tools,
                                    'wg-quick strip "$1"', self.conf)
        self.assertEqual(done.returncode, 0, done.stderr)
        interface = done.stdout.split("[Interface]\n", 1)[1]
        self.assertEqual(interface.split("\n\n", 1)[0], "ListenPort = 51821")
        self.assertIn(f"PublicKey = {PEER_KEY}", done.stdout)
        self.assertIn("AllowedIPs = fd00:1::2/128, 10.66.0.2/32",
                      done.stdout)
        self.assertNotIn("PostUp =", done.stdout)

    def test_wg_quick_up_gives_the_kernel_what_the_spec_says(self):
        script = (
            'ip link set lo up; wg-quick up "$1" >/dev/null 2>&1'
            ' || { wg-quick up "$1"; exit 3; }; '
            'for what in public-key listen-port endpoints allowed-ips'
            ' persistent-keepalive; do echo "== $what"; wg show wg0 $what;'
            ' done; echo "== addresses"; ip -o address show dev wg0;'
            ' wg-quick down "$1" >/dev/null 2>&1'
        )
        done = wgtools.in_namespace(self, self.tools, script, self.conf)
        if done.returncode == 3 and "Operation not supported" in (
                done.stderr) and not os.environ.get("CI"):
            self.skipTest("no wireguard kernel module here")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        shown = dict(
            (part.split("\n", 1) + [""])[:2]
            for part in done.stdout.split("== ")[1:]
        )
        self.assertEqual(shown["public-key"].strip(),
                         wgkeys.public(self.key)[0])
        self.assertEqual(shown["listen-port"].strip(), "51821")
        self.assertIn(f"{PEER_KEY}\t[2001:db8::20]:51820",
                      shown["endpoints"])
        self.assertIn(f"{OTHER_KEY}\t(none)", shown["endpoints"])
        self.assertIn(f"{PEER_KEY}\tfd00:1::2/128 10.66.0.2/32",
                      shown["allowed-ips"])
        self.assertIn(f"{PEER_KEY}\t25", shown["persistent-keepalive"])
        self.assertIn("fd00:1::1/64", shown["addresses"])
        self.assertIn("10.66.0.1/24", shown["addresses"])
