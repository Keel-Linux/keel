# Copyright (c) 2026 KeelLinux maintainers
"""The keel1: token of keel mesh invite and join (handbook decision 0048)

Tested at its seam only: encode() and parse(). A token is built, encoded
and read back, or damaged the ways a paste damages it, and parse() must
say which. The secret is the one value of the token that is not public:
it may appear in no repr and no error message.
"""

import base64
import hashlib
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone

from keel.mesh import token as mesh_token
from keel.mesh.token import Token, TokenError, encode, parse

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
SECRET = bytes(range(32))
PUBLIC = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
FINGERPRINT = hashlib.sha256(b"a certificate").digest()
MESH = bytes(range(100, 116))


def token(**overrides) -> Token:
    values = dict(
        public_key=PUBLIC,
        endpoints=("2001:db8:1::10",),
        port=51820,
        https_port=51820,
        fingerprint=FINGERPRINT,
        address="fd00:6b65:1::1/64",
        assigned="fd00:6b65:1::2/64",
        mesh_id=MESH,
        invite_id=mesh_token.invite_id(SECRET),
        expires=NOW + timedelta(hours=1),
        secret=SECRET,
    )
    values.update(overrides)
    return Token(**values)


def body(text: str) -> bytes:
    data = text[len(mesh_token.PREFIX):]
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def rebuilt(payload: bytes) -> str:
    """A token around `payload` with a checksum that matches it"""
    whole = payload + mesh_token.checksum(payload)
    return mesh_token.PREFIX + base64.urlsafe_b64encode(whole).decode(
        ).rstrip("=")


def secret_forms() -> tuple[str, ...]:
    return (SECRET.hex(), base64.b64encode(SECRET).decode().rstrip("="),
            base64.urlsafe_b64encode(SECRET).decode().rstrip("="),
            repr(SECRET))


class TestRoundTrip(unittest.TestCase):
    def test_what_invite_writes_join_reads(self):
        made = token()
        self.assertEqual(parse(encode(made), NOW), made)

    def test_both_endpoint_families_ipv6_first(self):
        made = token(endpoints=("2001:db8:1::10", "192.0.2.10"))
        found = parse(encode(made), NOW)
        self.assertEqual(found.endpoints, ("2001:db8:1::10", "192.0.2.10"))
        self.assertEqual(found.endpoint(), "[2001:db8:1::10]:51820")

    def test_an_inviter_with_ipv4_only(self):
        found = parse(encode(token(endpoints=("192.0.2.10",))), NOW)
        self.assertEqual(found.endpoint(), "192.0.2.10:51820")

    def test_etcd_states(self):
        for state, port in (("none", None), ("forms", None),
                            ("running", 2380)):
            with self.subTest(state=state):
                made = token(etcd=state, etcd_port=port)
                self.assertEqual(parse(encode(made), NOW), made)

    def test_ports_and_prefix_survive(self):
        made = token(port=40000, https_port=8443,
                     address="fd12:3456:789a::1/48",
                     assigned="fd12:3456:789a::7/48")
        found = parse(encode(made), NOW)
        self.assertEqual((found.port, found.https_port), (40000, 8443))
        self.assertEqual(str(found.prefix()), "fd12:3456:789a::/48")

    def test_a_typical_invite_is_one_line_of_about_250(self):
        text = encode(token())
        self.assertTrue(text.startswith("keel1:"))
        self.assertRegex(text, r"^keel1:[A-Za-z0-9_-]+$")
        self.assertLessEqual(len(text), 260)

    def test_surrounding_whitespace_of_a_paste_is_ignored(self):
        self.assertEqual(parse(f"  {encode(token())}\n", NOW), token())

    def test_the_expiry_is_utc_to_the_second(self):
        made = token(expires=NOW + timedelta(minutes=59, seconds=30))
        found = parse(encode(made), NOW)
        self.assertEqual(found.expires.utcoffset(), timedelta(0))
        self.assertEqual(found.expires, made.expires)


class TestRefused(unittest.TestCase):
    def refused(self, text: str, words: str, now=NOW):
        with self.assertRaises(TokenError) as raised:
            parse(text, now)
        self.assertIn(words, str(raised.exception))
        for form in secret_forms():
            self.assertNotIn(form, str(raised.exception))
        return raised.exception

    def test_not_a_token(self):
        self.refused("hello", "not a keel mesh token")

    def test_the_whole_join_line_is_not_the_token(self):
        self.refused(f"keel mesh join {encode(token())}",
                     "not a keel mesh token")

    def test_a_later_version_names_itself(self):
        self.refused("keel2:AAAA", "keel2")

    def test_a_join_answer_is_not_a_token(self):
        self.refused("keel1a:AAAA", "not a keel mesh token")

    def test_a_character_outside_base64url(self):
        text = encode(token())
        self.refused(text[:20] + "+" + text[21:], "base64url")

    def test_one_character_changed(self):
        text = encode(token())
        index = len(text) // 2
        swapped = "A" if text[index] != "A" else "B"
        self.refused(text[:index] + swapped + text[index + 1:],
                     "mistyped or truncated")

    def test_truncated(self):
        text = encode(token())
        for cut in (1, 2, 3, 40, len(text) - 7):
            with self.subTest(cut=cut):
                self.refused(text[:-cut], "mistyped or truncated")

    def test_too_long_to_be_one_is_not_decoded(self):
        with mock.patch("keel.mesh.token.base64.urlsafe_b64decode") as b64:
            self.refused("keel1:" + "A" * 1100, "more than 1024 characters")
        b64.assert_not_called()

    def test_empty(self):
        self.refused("keel1:", "mistyped or truncated")

    def test_expired(self):
        made = token(expires=NOW - timedelta(seconds=1))
        self.refused(encode(made), "expired at 2026-10-03 11:59:59 UTC")

    def test_expired_at_the_exact_second(self):
        self.refused(encode(token()), "expired",
                     now=NOW + timedelta(hours=1))

    def test_an_invite_id_that_is_not_its_secret_s(self):
        payload = body(encode(token()))[:-4]
        wrong = payload.replace(bytes.fromhex(token().invite_id), b"\0" * 8)
        self.refused(rebuilt(wrong), "invite id")

    def test_unknown_flags(self):
        payload = bytearray(body(encode(token()))[:-4])
        payload[0] |= 0x80
        self.refused(rebuilt(bytes(payload)), "malformed")

    def test_a_length_that_does_not_match_the_flags(self):
        payload = body(encode(token()))[:-4]
        self.refused(rebuilt(payload + b"\0"), "malformed")
        self.refused(rebuilt(payload[:-1]), "malformed")

    def test_an_unknown_etcd_state(self):
        # the one byte two tokens differing in their etcd state differ in
        payload = bytearray(body(encode(token()))[:-4])
        other = body(encode(token(etcd="forms")))[:-4]
        offset = next(index for index, (one, two) in
                      enumerate(zip(payload, other)) if one != two)
        payload[offset] = 9
        self.refused(rebuilt(bytes(payload)), "etcd")


class TestInconsistent(unittest.TestCase):
    """What encode() refuses to write is what parse() refuses to read"""

    def refused(self, words: str, **overrides):
        with self.assertRaises(TokenError) as raised:
            encode(token(**overrides))
        self.assertIn(words, str(raised.exception))

    def test_no_endpoint(self):
        self.refused("endpoint", endpoints=())

    def test_two_endpoints_of_a_family(self):
        self.refused("endpoint", endpoints=("2001:db8::1", "2001:db8::2"))

    def test_ipv4_before_ipv6(self):
        self.refused("IPv6 first", endpoints=("192.0.2.1", "2001:db8::1"))

    def test_an_endpoint_no_one_can_reach(self):
        for one in ("::1", "fe80::1", "::", "ff02::1", "127.0.0.1",
                    "0.0.0.0", "224.0.0.1", "not an address"):
            with self.subTest(endpoint=one):
                self.refused("endpoint", endpoints=(one,))

    def test_ports(self):
        self.refused("port", port=0)
        self.refused("port", https_port=70000)

    def test_an_overlay_address_that_is_not_one(self):
        self.refused("overlay address", address="nonsense")
        self.refused("overlay address", assigned="fd00:6b65:1::2/64/1")

    def test_every_problem_is_named(self):
        self.refused("no endpoint to reach the inviter at; WireGuard port"
                     " 0 is not a port number", endpoints=(), port=0)

    def test_an_overlay_outside_unique_local(self):
        self.refused("fc00::/7", address="2001:db8::1/64",
                     assigned="2001:db8::2/64")

    def test_an_assigned_address_outside_the_prefix(self):
        self.refused("prefix", assigned="fd00:6b65:2::2/64")

    def test_the_inviter_at_the_prefix_s_own_address(self):
        self.refused("prefix's own", address="fd00:6b65:1::/64")

    def test_the_inviter_s_own_address(self):
        self.refused("inviter", assigned="fd00:6b65:1::1/64")

    def test_the_prefix_itself(self):
        self.refused("prefix", assigned="fd00:6b65:1::/64")

    def test_a_key_that_is_not_one(self):
        self.refused("public key", public_key="short")

    def test_sizes(self):
        self.refused("fingerprint", fingerprint=b"\0" * 31)
        self.refused("secret", secret=b"\0" * 16)
        self.refused("mesh", mesh_id=b"\0" * 8)

    def test_etcd_running_needs_its_port(self):
        self.refused("etcd", etcd="running")
        self.refused("etcd port", etcd="running", etcd_port=70000)
        self.refused("etcd", etcd="none", etcd_port=2380)
        self.refused("etcd", etcd="sometimes")

    def test_an_invite_id_that_is_not_its_secret_s(self):
        self.refused("invite id", invite_id="0" * 16)

    def test_a_naive_expiry(self):
        self.refused("UTC", expires=datetime(2026, 10, 3, 13, 0))


class TestSecret(unittest.TestCase):
    def test_repr_and_str_do_not_hold_it(self):
        made = token()
        for text in (repr(made), str(made)):
            for form in secret_forms():
                self.assertNotIn(form, text)
        self.assertIn(made.invite_id, repr(made))

    def test_the_hmac_key_and_the_id_are_derived_not_the_secret(self):
        key = mesh_token.hmac_key(SECRET)
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, SECRET)
        self.assertNotEqual(key.hex()[:16], mesh_token.invite_id(SECRET))
        self.assertNotEqual(key, mesh_token.hmac_key(SECRET[::-1]))


if __name__ == "__main__":
    unittest.main()
