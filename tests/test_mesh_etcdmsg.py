# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdmsg: what members say to each other about etcd; pure
but for the signature, made and checked with the real openssl"""

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from keel.mesh import etcdmsg, etcdstate, signing
from keel.mesh.etcdstate import Cluster, Grant, Member
from keel.mesh.protocol import ProtocolError

MESH = "ab" * 16
KEY = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
CSR = ("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n"
       "-----END CERTIFICATE REQUEST-----\n")
CERT = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"


class TestJoinFields(unittest.TestCase):
    def test_a_request_or_none(self):
        self.assertIsNone(etcdmsg.csr(None))
        self.assertEqual(etcdmsg.csr(CSR), CSR)
        for bad in (1, "x", CERT, CSR * 2, CSR + "x" * 5000):
            with self.assertRaises(ProtocolError):
                etcdmsg.csr(bad)

    def test_a_grant_round_trip(self):
        grant = Grant(CERT, (CERT, CERT), CERT)
        self.assertEqual(etcdmsg.grant(etcdmsg.grant_data(grant)), grant)
        self.assertIsNone(etcdmsg.grant(None))
        self.assertIsNone(etcdmsg.grant_data(None))
        for bad in ([], {"certificate": CERT, "chain": "x", "root": CERT},
                    {"certificate": CSR, "chain": [], "root": CERT},
                    {"certificate": CERT, "chain": [CERT] * 9,
                     "root": CERT}, {"chain": []}):
            with self.assertRaises(ProtocolError):
                etcdmsg.grant(bad)

    def test_a_cluster_round_trip(self):
        found = Cluster("existing", (Member(KEY, "fd00::1"),
                                     Member(None, "fd00::4")), MESH)
        self.assertEqual(etcdmsg.cluster(etcdmsg.cluster_data(found)), found)
        self.assertIsNone(etcdmsg.cluster(None))
        self.assertIsNone(etcdmsg.cluster_data(None))
        for bad in ({"state": "x"}, {"state": "new", "token": MESH,
                    "members": [{"public_key": "x", "address": "fd00::1"}]},
                    {"state": "new", "token": "zz", "members": []},
                    {"state": "new", "token": MESH, "members": [1]},
                    {"state": "new", "token": MESH, "members": [
                        {"public_key": None, "address": "x"}]},
                    {"state": "new", "token": MESH,
                     "members": [{"public_key": KEY, "address": "fd00::1"}]
                     * 10}):
            with self.assertRaises(ProtocolError):
                etcdmsg.cluster(bad)

    def test_ready_members(self):
        self.assertEqual(etcdmsg.ready({KEY: "fd00::1"}), {KEY: "fd00::1"})
        self.assertEqual(etcdmsg.ready(None), {})
        for bad in ([], {"x": "fd00::1"}, {KEY: "nope"}, {KEY: 1}):
            with self.assertRaises(ProtocolError):
                etcdmsg.ready(bad)


class TestSigned(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.signer = signing.ensure(self.root)

    def test_made_read_and_verified(self):
        body = etcdmsg.signed(self.root, etcdmsg.CLUSTER, MESH, KEY, NOW,
                              {"a": 1})
        found = etcdmsg.loads(body)
        self.assertEqual((found.kind, found.mesh_id, found.sender,
                          found.body), (etcdmsg.CLUSTER, MESH, KEY, {"a": 1}))
        self.assertTrue(found.verified(self.signer))
        self.assertTrue(found.fresh(NOW + timedelta(minutes=4)))
        self.assertFalse(found.fresh(NOW + timedelta(minutes=6)))
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        self.assertFalse(found.verified(signing.ensure(other)))

    def test_a_changed_body_fails_its_signature(self):
        data = json.loads(etcdmsg.signed(self.root, etcdmsg.PROBE, MESH, KEY,
                                         NOW, {}))
        data["message"]["body"] = {"x": 1}
        found = etcdmsg.loads(json.dumps(data).encode())
        self.assertFalse(found.verified(self.signer))

    def test_malformed(self):
        good = json.loads(etcdmsg.signed(self.root, etcdmsg.PROBE, MESH, KEY,
                                         NOW, {}))
        for bad in (b"[]", b"{", json.dumps({"message": 1}).encode(),
                    json.dumps({**good, "signature": 1}).encode(),
                    json.dumps({**good, "signature": "!!"}).encode(),
                    json.dumps({**good, "message": {
                        **good["message"], "kind": "x"}}).encode(),
                    json.dumps({**good, "message": {
                        **good["message"], "body": []}}).encode(),
                    json.dumps({**good, "message": {
                        **good["message"], "mesh_id": "x"}}).encode()):
            with self.assertRaises(ProtocolError):
                etcdmsg.loads(bad)

    def test_answers(self):
        self.assertEqual(etcdmsg.probe_answer(etcdmsg.probe_dumps(
            True, "f" * 64, False, "fd00::1")), etcdmsg.Probe(
                True, "f" * 64, False, "fd00::1"))
        self.assertEqual(etcdmsg.probe_answer(etcdmsg.probe_dumps(
            False, None, False, "fd00::1")).root, None)
        self.assertEqual(etcdmsg.enroll_answer(json.dumps(
            {"csr": CSR}).encode()), CSR)
        for bad in (b"[]", json.dumps({"ready": 1}).encode(),
                    json.dumps({"ready": True, "root": "x", "formed": False,
                                "address": "fd00::1"}).encode(),
                    json.dumps({"ready": True, "root": None, "formed": False,
                                "address": "nope"}).encode()):
            with self.assertRaises(ProtocolError):
                etcdmsg.probe_answer(bad)
        with self.assertRaises(ProtocolError):
            etcdmsg.enroll_answer(b"{}")


class TestNames(unittest.TestCase):
    def test_a_member_s_address_named(self):
        self.assertEqual(etcdstate.name("fd00::1"), "keel-fd00--1")


if __name__ == "__main__":
    unittest.main()
