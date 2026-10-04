# Copyright (c) 2026 KeelLinux maintainers
"""The join protocol's messages and their HMAC (decision 0048)

Pure: each message to JSON and back, every malformed field refused with
its reason, the HMAC over the method, the path and the body checked in
constant time, and the request's time against the clock.
"""

import json
import unittest
from datetime import datetime, timedelta, timezone

from keel.mesh import protocol
from keel.mesh.protocol import (
    Admission,
    ConfirmAnswer,
    ConfirmRequest,
    JoinAnswer,
    JoinRequest,
    Peer,
    ProtocolError,
)

KEY = bytes(range(32))
JOINER = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
INVITER = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
NONCE = "00112233445566778899aabbccddeeff"
SIGNER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
REQUEST = JoinRequest(
    invite_id="0123456789abcdef", public_key=JOINER,
    endpoint="[2001:db8:2::20]:51820", address="fd00:6b65:1::3/64",
    nonce=NONCE, time=int(NOW.timestamp()), sign_key=SIGNER)
EVIDENCE = Admission(
    mesh_id="00" * 16, invite_id="0123456789abcdef", public_key=JOINER,
    sign_key=SIGNER, address="fd00:6b65:1::3", endpoint=None, time=5,
    by=SIGNER, signature="A" * 86 + "==")
ANSWER = JoinAnswer(
    invite_id="0123456789abcdef", nonce=NONCE, public_key=INVITER,
    address="fd00:6b65:1::1/64",
    peers=(Peer(public_key=JOINER, endpoint=None,
                address="fd00:6b65:1::7"),
           Peer(JOINER, "[2001:db8::7]:51820", "fd00:6b65:1::3",
                EVIDENCE),),
    etcd="none", window=120, sign_key=SIGNER, admission=EVIDENCE)


def body(message, **changed):
    data = json.loads(protocol.dumps(message))
    data.update(changed)
    return json.dumps(data).encode()


class TestSignature(unittest.TestCase):
    def test_the_hmac_covers_the_method_the_path_and_the_body(self):
        found = protocol.sign(KEY, "POST", protocol.JOIN, b"{}")
        self.assertEqual(len(found), 64)
        self.assertTrue(protocol.signed(KEY, "POST", protocol.JOIN, b"{}",
                                        found))
        for method, path, data, key in (
                ("PUT", protocol.JOIN, b"{}", KEY),
                ("POST", protocol.CONFIRM, b"{}", KEY),
                ("POST", protocol.JOIN, b"{ }", KEY),
                ("POST", protocol.JOIN, b"{}", bytes(32))):
            with self.subTest(method=method, path=path, data=data):
                self.assertFalse(protocol.signed(key, method, path, data,
                                                 found))

    def test_a_missing_or_malformed_signature_is_false(self):
        for found in (None, "", "zz" * 32, "00" * 31, "é" * 64):
            with self.subTest(found=found):
                self.assertFalse(protocol.signed(KEY, "POST", protocol.JOIN,
                                                 b"{}", found))

    def test_the_answer_is_signed_apart_from_the_request(self):
        request = protocol.sign(KEY, "POST", protocol.JOIN, b"{}")
        answer = protocol.sign(KEY, protocol.ANSWER, protocol.JOIN, b"{}")
        self.assertNotEqual(request, answer)


class TestEvidence(unittest.TestCase):
    def test_what_is_signed(self):
        self.assertEqual(EVIDENCE.message(), (
            b"keel mesh admission 1\n" + b"00" * 16 + b"\n0123456789abcdef"
            + f"\n{JOINER}\n{SIGNER}\nfd00:6b65:1::3\n\n5\n{SIGNER}"
            .encode()))
        gone = protocol.Removal("00" * 16, JOINER, 5, SIGNER, "x")
        self.assertEqual(gone.message(), (
            b"keel mesh removal 1\n" + b"00" * 16
            + f"\n{JOINER}\n5\n{SIGNER}".encode()))

    def test_round_trips(self):
        data = json.loads(protocol.dumps(EVIDENCE))
        self.assertEqual(protocol.admission(data), EVIDENCE)
        self.assertEqual(protocol.admission({**data, "invite_id": ""}),
                         Admission(**{**data, "invite_id": ""}))
        gone = protocol.Removal("00" * 16, JOINER, 5, SIGNER,
                                "A" * 86 + "==")
        self.assertEqual(protocol.removal(json.loads(protocol.dumps(gone))),
                         gone)

    def test_malformed(self):
        data = json.loads(protocol.dumps(EVIDENCE))
        for changed in ({"invite_id": "x"}, {"mesh_id": "00"},
                        {"signature": "A" * 88}, {"by": "x"},
                        {"sign_key": 1}, {"address": "fd00::3/64"}):
            with self.subTest(changed=changed), \
                    self.assertRaises(ProtocolError):
                protocol.admission({**data, **changed})
        for bad in ([], None, "x"):
            with self.assertRaises(ProtocolError):
                protocol.admission(bad)
            with self.assertRaises(ProtocolError):
                protocol.removal(bad)


class TestMessages(unittest.TestCase):
    def test_round_trips(self):
        confirm = ConfirmRequest(invite_id="0123456789abcdef",
                                 public_key=JOINER, nonce=NONCE,
                                 time=int(NOW.timestamp()))
        confirmed = ConfirmAnswer(invite_id="0123456789abcdef", nonce=NONCE,
                                  confirmed=True, detail="confirmed",
                                  sign_key=SIGNER)
        for message, load in (
                (REQUEST, protocol.join_request),
                (REQUEST.__class__(**{**REQUEST.__dict__, "endpoint": None}),
                 protocol.join_request),
                (ANSWER, protocol.join_answer),
                (confirm, protocol.confirm_request),
                (confirmed, protocol.confirm_answer)):
            with self.subTest(message=type(message).__name__):
                self.assertEqual(load(protocol.dumps(message)), message)

    def test_an_ipv4_endpoint(self):
        found = protocol.join_request(body(REQUEST,
                                           endpoint="198.51.100.7:51820"))
        self.assertEqual(found.endpoint, "198.51.100.7:51820")

    def test_a_malformed_join_request_is_refused_with_its_reason(self):
        for changed, words in (
                ({"invite_id": "0123"}, "invite_id"),
                ({"public_key": "not a key"}, "public_key"),
                ({"public_key": 7}, "public_key"),
                ({"endpoint": "[::1]:51820"}, "cannot be reached"),
                ({"endpoint": "[fe80::1]:51820"}, "cannot be reached"),
                ({"endpoint": "host.example:51820"}, "endpoint"),
                ({"endpoint": "[2001:db8::1]"}, "endpoint"),
                ({"address": "192.0.2.1/24"}, "address"),
                ({"address": "fd00::3"}, "address"),
                ({"nonce": "00"}, "nonce"),
                ({"time": "now"}, "time"),
                ({"time": True}, "time")):
            with self.subTest(changed=changed):
                with self.assertRaises(ProtocolError) as caught:
                    protocol.join_request(body(REQUEST, **changed))
                self.assertIn(words, str(caught.exception))

    def test_not_a_message(self):
        for data in (b"", b"[]", b"\xff", b'{"invite_id": "x"}',
                     b"{" * 2000):
            with self.subTest(data=data[:10]):
                with self.assertRaises(ProtocolError):
                    protocol.join_request(data)

    def test_a_malformed_answer_is_refused(self):
        for changed in ({"peers": "none"}, {"peers": [1]},
                        {"peers": [{"public_key": 1}]},
                        {"peers": [{"public_key": JOINER, "address": "x",
                                    "endpoint": None}]},
                        {"etcd": "maybe"}, {"window": -1},
                        {"window": "120"}, {"address": "fd00::1"}):
            with self.subTest(changed=changed):
                with self.assertRaises(ProtocolError):
                    protocol.join_answer(body(ANSWER, **changed))
        with self.assertRaises(ProtocolError):
            protocol.confirm_answer(b'{"invite_id": "0123456789abcdef",'
                                    b' "nonce": "' + NONCE.encode()
                                    + b'", "confirmed": 1, "detail": ""}')


class TestFreshness(unittest.TestCase):
    def test_within_five_minutes_either_way(self):
        for offset, fresh in ((0, True), (299, True), (-299, True),
                              (301, False), (-301, False)):
            with self.subTest(offset=offset):
                self.assertEqual(protocol.fresh(
                    int(NOW.timestamp()) + offset, NOW), fresh)

    def test_a_nonce_is_new_each_time(self):
        self.assertNotEqual(protocol.new_nonce(), protocol.new_nonce())
        self.assertEqual(len(protocol.new_nonce()), 32)

    def test_now_in_seconds(self):
        self.assertEqual(protocol.seconds(NOW + timedelta(seconds=0.7)),
                         int(NOW.timestamp()))


if __name__ == "__main__":
    unittest.main()


class TestEtcdFieldsNeverFailAJoin(unittest.TestCase):
    def test_unreadable_etcd_fields_are_left_out(self):
        self.assertEqual(protocol.etcd_fields({"etcd_cluster": {"x": 1}}),
                         {})
        self.assertEqual(protocol.etcd_fields({})["etcd_ready"], {})
