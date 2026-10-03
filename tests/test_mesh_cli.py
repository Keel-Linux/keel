# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh invite and keel mesh join --dry-run (decision 0048)

Through keel.cli.main, against a scratch root, at the seam an operator
and confconsole see: what is printed where, the exit code, and what is
left under /var/lib/keel/mesh. The key pair is the real wg's and the
certificate the real openssl's (tests/wgtools.py; openssl is a
dependency of keel), so the token's key and fingerprint are checked
against what those tools say, not against keel's own arithmetic.
"""

import base64
import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from os.path import join
from unittest import mock

import wgtools
from helpers import spec  # noqa: F401

from keel import cli, exits
from keel.mesh import invites
from keel.mesh import token as mesh_token
from keel.mesh.identity import IDENTITY

OVERLAY = """\
version: 1
network:
  interfaces:
    eth0:
      ipv6:
        method: static
        address: 2001:db8:1::10/64
        gateway: fe80::1
      ipv4:
        method: static
        address: 192.0.2.10/24
  overlay:
    wireguard:
      address: fd00:6b65:1::1/64
      listen_port: 51821
      peers:
        - public_key: FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg=
          endpoint: "[2001:db8:2::20]:51820"
          allowed_ips: [fd00:6b65:1::2/128]
"""
INVITER = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OTHER = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
SECRET = bytes(range(32))


def run_cli(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch("sys.stdin", io.StringIO(stdin)):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def token_of(out: str) -> str:
    line = out.strip()
    assert line.startswith("keel mesh join keel1:"), line
    return line[len("keel mesh join "):]


def secret_forms(secret: bytes) -> tuple[str, ...]:
    return (secret.hex(), base64.b64encode(secret).decode().rstrip("="),
            base64.urlsafe_b64encode(secret).decode().rstrip("="))


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.spec = join(self.root, "instance.yaml")

    def write_spec(self, text):
        with open(self.spec, "w") as fob:
            fob.write(text)

    def key_file(self):
        path = join(self.root, "etc/wireguard/wg0.key")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        return path

    def invite(self, *extra):
        return run_cli("mesh", "invite", "--spec", self.spec, "--root",
                       self.root, *extra)

    def invite_files(self):
        try:
            return sorted(os.listdir(join(self.root, invites.INVITES)))
        except FileNotFoundError:
            return []


class TestInviteReal(Case):
    """wg genkey and wg pubkey, openssl req and x509, behind the command"""

    def setUp(self):
        super().setUp()
        tools = wgtools.require(self)
        patcher = mock.patch.dict(os.environ, wgtools.env(tools))
        patcher.start()
        self.addCleanup(patcher.stop)
        path = self.key_file()
        with open(path, "w") as fob:
            subprocess.run(["wg", "genkey"], stdout=fob, check=True)
        with open(path) as fob:
            self.public = subprocess.run(
                ["wg", "pubkey"], stdin=fob, capture_output=True,
                text=True, check=True).stdout.strip()
        self.write_spec(OVERLAY)
        # every draw is ::3, so a second invite searches on to ::4
        drawn = mock.patch("keel.mesh.allocate.secrets.randbelow",
                           return_value=2)
        drawn.start()
        self.addCleanup(drawn.stop)

    def test_the_line_and_the_invite_it_reserves(self):
        before = datetime.now(timezone.utc)
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(out.count("\n"), 1)
        found = mesh_token.parse(token_of(out), before)
        self.assertEqual(found.public_key, self.public)
        self.assertEqual(found.endpoints, ("2001:db8:1::10", "192.0.2.10"))
        self.assertEqual((found.port, found.https_port), (51821, 51820))
        self.assertEqual(found.address, "fd00:6b65:1::1/64")
        self.assertEqual(found.assigned, "fd00:6b65:1::3/64")
        self.assertEqual(found.etcd, "none")
        self.assertLessEqual(
            abs(found.expires - before - timedelta(hours=1)),
            timedelta(seconds=5))
        self.assertIn(f"invite {found.invite_id}: fd00:6b65:1::3/64"
                      " reserved", err)

        pending = invites.find(self.root, found.invite_id, before)
        self.assertEqual(pending.address, found.assigned)
        self.assertEqual(pending.expires, found.expires)
        self.assertEqual(pending.hmac_key, mesh_token.hmac_key(found.secret))
        pinned = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
            input=pending.certificate, capture_output=True, text=True,
            check=True).stdout
        self.assertEqual(pinned.strip().split("=")[1].replace(":", ""),
                         found.fingerprint.hex().upper())
        with open(join(self.root, invites.INVITES,
                       f"{found.invite_id}.json")) as fob:
            stored = fob.read()
        for form in secret_forms(found.secret):
            self.assertNotIn(form, stored + err)
        self.assertNotIn(token_of(out), stored + err)

    def test_the_next_invite_takes_the_next_address(self):
        first = mesh_token.parse(token_of(self.invite()[1]),
                                 datetime.now(timezone.utc))
        second = mesh_token.parse(token_of(self.invite()[1]),
                                  datetime.now(timezone.utc))
        self.assertEqual((first.assigned, second.assigned),
                         ("fd00:6b65:1::3/64", "fd00:6b65:1::4/64"))
        self.assertNotEqual(first.secret, second.secret)
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.mesh_id, second.mesh_id)

    def test_endpoint_and_port_given(self):
        code, out, err = self.invite("--endpoint", "198.51.100.7",
                                     "--endpoint", "2001:db8:9::7",
                                     "--port", "8443")
        self.assertEqual(code, exits.OK, err)
        found = mesh_token.parse(token_of(out), datetime.now(timezone.utc))
        self.assertEqual(found.endpoints, ("2001:db8:9::7", "198.51.100.7"))
        self.assertEqual(found.https_port, 8443)

    def test_what_invite_prints_join_reads(self):
        _, out, _ = self.invite()
        joiner = join(self.root, "joiner.yaml")
        code, change, err = run_cli("mesh", "join", token_of(out),
                                    "--dry-run", "--spec", joiner)
        self.assertEqual(code, exits.OK, err)
        self.assertIn(f"public_key: {self.public}", change)
        self.assertIn("address: fd00:6b65:1::3/64", change)


class TestInviteRefused(Case):
    def public(self, found=INVITER, problem=None):
        return mock.patch("keel.mesh.commands.wgkeys.public",
                          return_value=(found, problem))

    def test_no_spec(self):
        code, out, err = self.invite()
        self.assertEqual((code, out), (exits.MESH_REFUSED, ""))
        self.assertIn("no overlay to invite into", err)

    def test_no_overlay(self):
        self.write_spec("version: 1\n")
        code, _, err = self.invite()
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("keel mesh create", err)

    def test_an_invalid_spec(self):
        self.write_spec("version: 1\nnetwork:\n  overlay: 5\n")
        code, _, _ = self.invite()
        self.assertEqual(code, exits.SPEC_INVALID)

    def test_no_key_yet(self):
        self.write_spec(OVERLAY)
        code, _, err = self.invite()
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("converge the overlay first", err)

    def test_a_key_wg_cannot_read(self):
        self.write_spec(OVERLAY)
        self.key_file()
        with self.public(None, "mode must be 0600"):
            code, _, err = self.invite()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("0600", err)

    def test_no_endpoint(self):
        self.write_spec("version: 1\nnetwork:\n  interfaces:\n    eth0:\n"
                        "      ipv6:\n        method: auto\n  overlay:\n"
                        "    wireguard:\n      address: fd00:1::1/64\n")
        self.key_file()
        with self.public():
            code, _, err = self.invite()
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("--endpoint", err)
        self.assertEqual(self.invite_files(), [])

    def test_endpoints_given_wrong(self):
        self.write_spec(OVERLAY)
        self.key_file()
        for given, words in ((["not-an-address"], "does not appear"),
                             (["2001:db8::1", "2001:db8::2"], "per family"),
                             (["fe80::1"], "cannot be reached")):
            with self.subTest(given=given), self.public():
                argv = [one for host in given for one in ("--endpoint",
                                                          host)]
                code, out, err = self.invite(*argv)
                self.assertEqual((code, out), (exits.MESH_REFUSED, ""))
                self.assertIn(words, err)
        self.assertEqual(self.invite_files(), [])

    def test_a_full_prefix(self):
        # ::1 this node, ::2 and ::3 its peers: nothing left in a /126
        self.write_spec(OVERLAY.replace("fd00:6b65:1::1/64",
                                        "fd00:6b65:1::1/126")
                        + f"        - public_key: {OTHER}\n"
                        "          allowed_ips: [fd00:6b65:1::3/128]\n")
        self.key_file()
        with self.public():
            code, out, err = self.invite()
        self.assertEqual((code, out), (exits.MESH_REFUSED, ""), err)
        self.assertIn("no free address in fd00:6b65:1::/126", err)
        self.assertEqual(self.invite_files(), [])

    def test_a_bad_port(self):
        self.write_spec(OVERLAY)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as raised:
            cli.main(["mesh", "invite", "--spec", self.spec, "--port",
                      "0"])
        self.assertEqual(raised.exception.code, exits.USAGE)
        self.assertIn("not a port number", err.getvalue())

    def test_openssl_missing_or_failing(self):
        self.write_spec(OVERLAY)
        self.key_file()
        for command, words in (("/nonexistent/openssl", "could not be run"),
                               ("false", "openssl req exited 1")):
            with self.subTest(command=command), self.public(), mock.patch(
                    "keel.mesh.certificate.OPENSSL", command):
                code, out, err = self.invite()
                self.assertEqual((code, out), (exits.APPLY_FAILED, ""))
                self.assertIn(words, err)
        self.assertEqual(self.invite_files(), [])

    def test_a_damaged_identity_is_not_replaced(self):
        self.write_spec(OVERLAY)
        self.key_file()
        os.makedirs(join(self.root, os.path.dirname(IDENTITY)))
        with open(join(self.root, IDENTITY), "w") as fob:
            fob.write("zz\n")
        with self.public():
            code, _, err = self.invite()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("does not hold a mesh identity", err)
        with open(join(self.root, IDENTITY)) as fob:
            self.assertEqual(fob.read(), "zz\n")

    def test_the_live_system_needs_root(self):
        self.write_spec(OVERLAY)
        with mock.patch("keel.mesh.commands.ROOT_DEFAULT", self.root), \
                mock.patch("os.geteuid", return_value=1000):
            code, _, err = self.invite()
        self.assertEqual(code, exits.APPLY_NEEDS_ROOT)
        self.assertIn("must run as root", err)


class TestJoinDryRun(Case):
    def token(self, **overrides) -> str:
        values = dict(
            public_key=INVITER, endpoints=("2001:db8:1::10",), port=51820,
            https_port=51820, fingerprint=hashlib.sha256(b"c").digest(),
            address="fd00:6b65:1::1/64", assigned="fd00:6b65:1::3/64",
            mesh_id=bytes(16), invite_id=mesh_token.invite_id(SECRET),
            expires=datetime.now(timezone.utc).replace(microsecond=0)
            + timedelta(hours=1), secret=SECRET)
        values.update(overrides)
        return mesh_token.encode(mesh_token.Token(**values))

    def join(self, text, *extra, stdin=""):
        return run_cli("mesh", "join", text, "--spec", self.spec, "--root",
                       self.root, *extra, stdin=stdin)

    def test_the_change_on_a_node_with_no_spec(self):
        code, out, err = self.join(self.token(), "--dry-run")
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(out, (
            "network:\n"
            "  overlay:\n"
            "    wireguard:\n"
            "      address: fd00:6b65:1::3/64\n"
            "      peers:\n"
            f"      - public_key: {INVITER}\n"
            "        endpoint: '[2001:db8:1::10]:51820'\n"
            "        allowed_ips:\n"
            "        - fd00:6b65:1::1/128\n"))
        self.assertIn("dry run, nothing written or applied", err)
        self.assertIn("etcd: none", err)
        self.assertFalse(os.path.exists(self.spec))

    def test_the_token_on_standard_input(self):
        code, out, _ = self.join("-", "--dry-run",
                                 stdin=self.token() + "\n")
        self.assertEqual(code, exits.OK)
        self.assertIn("address: fd00:6b65:1::3/64", out)

    def test_an_inviter_with_ipv4_only(self):
        code, out, _ = self.join(self.token(endpoints=("192.0.2.10",)),
                                 "--dry-run")
        self.assertEqual(code, exits.OK)
        self.assertIn("endpoint: 192.0.2.10:51820", out)

    def test_the_spec_is_left_as_it_is(self):
        text = "version: 1\nnetwork:\n  managed_by: host\n"
        self.write_spec(text)
        code, _, _ = self.join(self.token(), "--dry-run")
        self.assertEqual(code, exits.OK)
        with open(self.spec) as fob:
            self.assertEqual(fob.read(), text)

    def test_a_node_already_at_its_address_in_this_mesh(self):
        self.write_spec("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                        "      address: fd00:6b65:1::3/64\n")
        code, _, err = self.join(self.token(), "--dry-run")
        self.assertEqual(code, exits.OK, err)

    def test_a_node_in_another_mesh(self):
        self.write_spec("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                        "      address: fd00:aaaa:1::1/64\n")
        code, out, err = self.join(self.token(), "--dry-run")
        self.assertEqual((code, out), (exits.MESH_REFUSED, ""))
        self.assertIn("another mesh", err)

    def test_a_node_at_another_address_of_this_mesh(self):
        self.write_spec("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                        "      address: fd00:6b65:1::9/64\n")
        code, _, err = self.join(self.token(), "--dry-run")
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("joins a mesh once", err)

    def test_a_change_the_spec_would_refuse(self):
        # this node's uplink on the overlay's prefix: wg-quick would route
        # it into the tunnel (keel#49)
        self.write_spec("version: 1\nnetwork:\n  interfaces:\n    eth0:\n"
                        "      ipv6:\n        method: static\n"
                        "        address: fd00:6b65:1::50/64\n")
        code, out, err = self.join(self.token(), "--dry-run")
        self.assertEqual((code, out), (exits.MESH_REFUSED, ""))
        self.assertIn("once joined", err)
        self.assertIn("overlaps", err)

    def test_an_invalid_spec(self):
        self.write_spec("version: 1\nnetwork:\n  overlay: 5\n")
        code, _, _ = self.join(self.token(), "--dry-run")
        self.assertEqual(code, exits.SPEC_INVALID)

    def test_refused_tokens_never_show_the_secret(self):
        expired = self.token(expires=datetime(2026, 1, 1,
                                              tzinfo=timezone.utc))
        good = self.token()
        for text, words in ((expired, "expired"),
                            (good[:-3], "mistyped or truncated"),
                            ("keel2:AAAA", "later format")):
            with self.subTest(words=words):
                code, out, err = self.join(text, "--dry-run")
                self.assertEqual((code, out),
                                 (exits.MESH_TOKEN_INVALID, ""))
                self.assertIn(words, err)
                for form in secret_forms(SECRET) + (text,):
                    self.assertNotIn(form, err)

    def test_standard_input_is_read_no_further_than_a_token_can_be(self):
        code, out, err = self.join("-", "--dry-run", stdin="A" * 100_000)
        self.assertEqual((code, out), (exits.MESH_TOKEN_INVALID, ""))
        self.assertIn("more than 1024 characters", err)

    def test_without_dry_run_nothing_is_done_yet(self):
        code, out, err = self.join(self.token())
        self.assertEqual((code, out), (exits.NOT_IMPLEMENTED, ""))
        self.assertIn("--dry-run", err)

    def test_no_action(self):
        code, _, _ = run_cli("mesh")
        self.assertEqual(code, exits.USAGE)


if __name__ == "__main__":
    unittest.main()
