# Copyright (c) 2026 KeelLinux maintainers
"""keel network wireguard key and suggest-address (decision 0020)

`key` prints the public key alone on standard output, making the key
pair first on the live system; the live system is stood in by pointing
ROOT_DEFAULT at a scratch root, and root by patching os.geteuid.
"""

import contextlib
import io
import ipaddress
import os
import shutil
import stat
import tempfile
import unittest
from os.path import join
from unittest import mock

import wgtools
from helpers import spec  # noqa: F401

from keel import cli, exits
from keel.network import wireguard

PUBLIC = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.spec = join(self.root, "instance.yaml")

    def write_spec(self, text):
        with open(self.spec, "w") as fob:
            fob.write(text)

    def live(self, euid=0):
        """The scratch root as the live system, as uid `euid`"""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch(
            "keel.commands.inspection.ROOT_DEFAULT", self.root))
        stack.enter_context(mock.patch("keel.system.ROOT_DEFAULT",
                                       self.root))
        if euid is None:
            # the real key file is this user's: secret_file_error accepts
            # the caller's own, so only the root check is stood in
            stack.enter_context(mock.patch("keel.commands.system.needs_root",
                                           return_value=None))
        else:
            stack.enter_context(mock.patch("os.geteuid", return_value=euid))
        return stack

    def key_cli(self):
        return run_cli("network", "wireguard", "key", "--spec", self.spec,
                       "--root", self.root)

    def key(self, name="etc/wireguard/wg0.key"):
        return join(self.root, name)


class TestSuggest(Case):
    def test_a_fresh_ula_each_time(self):
        code, out, _ = run_cli("network", "wireguard", "suggest-address")
        self.assertEqual(code, exits.OK)
        address = ipaddress.IPv6Interface(out.strip())
        self.assertEqual(address.network.prefixlen, 64)
        self.assertIn(address, ipaddress.IPv6Network("fd00::/8"))
        self.assertEqual(int(address.ip) & 0xFFFF, 1)
        self.assertNotEqual(out, run_cli("network", "wireguard",
                                         "suggest-address")[1])

    def test_no_action_is_a_usage_error(self):
        code, _, _ = run_cli("network", "wireguard")
        self.assertEqual(code, exits.USAGE)


class TestKeyMocked(Case):
    def test_an_existing_key_prints_its_public_key_only(self):
        with mock.patch("keel.commands.wgkeys.public",
                        return_value=(PUBLIC, None)) as public:
            os.makedirs(os.path.dirname(self.key()))
            open(self.key(), "w").close()
            code, out, err = run_cli("network", "wireguard", "key",
                                     "--spec", self.spec, "--root",
                                     self.root)
        self.assertEqual((code, out, err), (exits.OK, PUBLIC + "\n", ""))
        public.assert_called_once_with(self.key())

    def test_the_declared_key_file_is_the_one_read(self):
        self.write_spec("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                        "      interface: ov1\n      address: fd00:1::1/64\n")
        os.makedirs(os.path.dirname(self.key()))
        open(self.key("etc/wireguard/ov1.key"), "w").close()
        with mock.patch("keel.commands.wgkeys.public",
                        return_value=(PUBLIC, None)) as public:
            code, _, _ = run_cli("network", "wireguard", "key", "--spec",
                                 self.spec, "--root", self.root)
        self.assertEqual(code, exits.OK)
        public.assert_called_once_with(self.key("etc/wireguard/ov1.key"))

    def test_an_invalid_spec_stops_it(self):
        self.write_spec("version: 1\nnetwork:\n  overlay: 5\n")
        code, _, err = run_cli("network", "wireguard", "key", "--spec",
                               self.spec, "--root", self.root)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("must be a mapping", err)

    def test_no_key_is_made_under_a_root(self):
        code, out, err = run_cli("network", "wireguard", "key", "--spec",
                                 self.spec, "--root", self.root)
        self.assertEqual((code, out), (exits.APPLY_FAILED, ""))
        self.assertIn("never in an image", err)
        self.assertFalse(os.path.exists(self.key()))

    def test_making_a_key_needs_root(self):
        with self.live(euid=1000):
            code, _, err = self.key_cli()
        self.assertEqual(code, exits.APPLY_NEEDS_ROOT)
        self.assertIn("must run as root", err)

    def test_a_key_that_cannot_be_made_or_read(self):
        with self.live(), mock.patch("keel.commands.wgkeys.generate",
                                     return_value="wg is not installed"):
            code, _, err = self.key_cli()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("wg is not installed", err)
        os.makedirs(os.path.dirname(self.key()))
        open(self.key(), "w").close()
        with mock.patch("keel.commands.wgkeys.public",
                        return_value=(None, "mode must be 0600")):
            code, _, err = run_cli("network", "wireguard", "key", "--spec",
                                   self.spec, "--root", self.root)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("0600", err)


class TestKeyReal(Case):
    """wg genkey and wg pubkey behind the command"""

    def setUp(self):
        super().setUp()
        tools = wgtools.require(self)
        patcher = mock.patch.dict(os.environ, wgtools.env(tools))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_first_call_makes_the_pair_and_the_next_keeps_it(self):
        with self.live(euid=None):
            code, out, err = self.key_cli()
            again = self.key_cli()
        self.assertEqual(code, exits.OK)
        self.assertIn("generated /etc/wireguard/wg0.key, mode 0600", err)
        self.assertTrue(wireguard.is_key(out.strip()))
        self.assertEqual(again, (exits.OK, out, ""))
        self.assertEqual(stat.S_IMODE(os.stat(self.key()).st_mode), 0o600)
        with open(self.key()) as fob:
            self.assertNotIn(fob.read().strip(), out + err)
