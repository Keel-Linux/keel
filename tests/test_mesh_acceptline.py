# Copyright (c) 2026 KeelLinux maintainers
"""The keel1a: line the fallback prints for the inviter (decision 0048)

The new node's key, its endpoint, the reserved address, the invite id
and the time, with an HMAC keyed with the invite's HMAC key and a
checksum, so a mistyped paste and a line for another invite are told
apart and neither is accepted.
"""

import unittest

from keel.mesh import acceptline
from keel.mesh.acceptline import Accept, AcceptError

KEY = bytes(range(32))
JOINER = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
LINE = Accept(public_key=JOINER, endpoint="[2001:db8:2::20]:51820",
              address="fd00:6b65:1::3/64", invite_id="0123456789abcdef",
              time=1_790_000_000)


class TestRoundTrip(unittest.TestCase):
    def test_each_endpoint(self):
        for endpoint in ("[2001:db8:2::20]:51820", "198.51.100.7:51821",
                         None):
            with self.subTest(endpoint=endpoint):
                made = Accept(**{**LINE.__dict__, "endpoint": endpoint})
                text = acceptline.encode(made, KEY)
                self.assertTrue(text.startswith("keel1a:"))
                self.assertLess(len(text), 200)
                sealed = acceptline.parse(text)
                self.assertEqual(sealed.accept, made)
                self.assertTrue(sealed.authentic(KEY))
                self.assertFalse(sealed.authentic(bytes(32)))

    def test_the_whole_command_line_pasted_is_read(self):
        text = acceptline.encode(LINE, KEY)
        self.assertEqual(acceptline.parse(f"  {text}\n").accept, LINE)


class TestRefused(unittest.TestCase):
    def refused(self, text, words):
        with self.assertRaises(AcceptError) as caught:
            acceptline.parse(text)
        self.assertIn(words, str(caught.exception))

    def test_damaged(self):
        text = acceptline.encode(LINE, KEY)
        changed = text[:20] + ("A" if text[20] != "A" else "B") + text[21:]
        for found, words in (
                ("x" * 2000, "more than"),
                ("keel1:abc", "starts with keel1a:"),
                ("keel1a:ab*c", "base64url"),
                ("keel1a:", "mistyped or truncated"),
                ("keel1a:AAAAA", "mistyped or truncated"),
                (changed, "mistyped or truncated"),
                (text[:-3], "mistyped or truncated")):
            with self.subTest(found=found[:12]):
                self.refused(found, words)

    def test_a_layout_its_flags_do_not_match(self):
        for payload, words in (
                (bytes([4]) + bytes(100), "flags"),
                (bytes([3]) + bytes(100), "flags"),
                (bytes([1]) + bytes(10), "malformed"),
                (bytes([0]) + bytes(32) + bytes(61) + b"x", "bytes where")):
            with self.subTest(payload=payload[:2]):
                self.refused(acceptline.wrap(payload), words)

    def test_values_no_inviter_could_use(self):
        for changed, words in (
                ({"public_key": "A" * 43 + "B"}, "not a WireGuard key"),
                ({"endpoint": "[::1]:51820"}, "cannot be reached"),
                ({"address": "2001:db8::3/64"}, "not an overlay address")):
            with self.subTest(changed=changed):
                with self.assertRaises(AcceptError) as caught:
                    acceptline.encode(Accept(**{**LINE.__dict__, **changed}),
                                      KEY)
                self.assertIn(words, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
