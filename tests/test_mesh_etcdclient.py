# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdclient: etcd's v3 JSON gateway, over real TLS on the
loopback, against a fake gateway that asks for keel's client
certificate as etcd does"""

import json
import shutil
import socket
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pki_clock import NOW

from keel.mesh import etcdclient, etcdstate
from keel.mesh.etcdclient import EtcdError

MESH = "ab" * 16
LIST = {"header": {"member_id": "11"}, "members": [
    {"ID": "11", "name": "keel-fd00--1", "peerURLs": [
        "https://[fd00::1]:2380"], "clientURLs": ["https://[fd00::1]:2379"]},
    {"ID": "12", "peerURLs": ["https://[fd00::4]:2380"], "isLearner": True}]}


class Gateway(BaseHTTPRequestHandler):
    answers: dict = {}
    seen: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.seen.append((self.path, json.loads(body)))
        self.reply(*self.answers.get(self.path, (404, {"message": "no"})))

    def do_GET(self):  # noqa: N802
        self.seen.append((self.path, None))
        self.reply(*self.answers.get(self.path, (404, {"message": "no"})))

    def reply(self, status, data):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class Server6(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        etcdstate.make_root(cls.root, MESH, "fd00::1")
        etcdstate.leaves(cls.root, "fd00::1", NOW)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(f"{cls.root}/{etcdstate.MEMBER_CERT}",
                               f"{cls.root}/{etcdstate.MEMBER_KEY}")
        server.load_verify_locations(f"{cls.root}/{etcdstate.ROOT_CERT}")
        server.verify_mode = ssl.CERT_REQUIRED
        cls.httpd = Server6(("::1", 0), Gateway)
        cls.httpd.socket = server.wrap_socket(cls.httpd.socket,
                                              server_side=True)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.root)

    def setUp(self):
        Gateway.answers = {}
        Gateway.seen = []
        self.client = etcdclient.Client(
            (f"https://[::1]:{self.port}",), etcdclient.context(self.root),
            timeout=5)


class TestMembers(Case):
    def test_the_list_learners_and_unstarted(self):
        Gateway.answers["/v3/cluster/member/list"] = (200, LIST)
        found = self.client.members()
        self.assertEqual([one.id for one in found], ["11", "12"])
        self.assertEqual(found[0].address, "fd00::1")
        self.assertFalse(found[0].learner)
        self.assertTrue(found[1].learner)
        self.assertFalse(found[1].started)
        self.assertTrue(found[0].started)
        self.assertEqual(Gateway.seen, [("/v3/cluster/member/list", {})])
        named = etcdclient.Member("1", "", ("https://host:2380",), (), True)
        self.assertIsNone(named.address)

    def test_add_a_learner_promote_remove(self):
        Gateway.answers["/v3/cluster/member/add"] = (200, {
            "member": {"ID": "12", "peerURLs": ["https://[fd00::4]:2380"],
                       "isLearner": True}})
        Gateway.answers["/v3/cluster/member/promote"] = (200, {})
        Gateway.answers["/v3/cluster/member/remove"] = (200, {})
        added = self.client.add_learner("https://[fd00::4]:2380")
        self.assertEqual(added.id, "12")
        self.client.promote("12")
        self.client.remove("12")
        self.assertEqual(Gateway.seen, [
            ("/v3/cluster/member/add",
             {"peerURLs": ["https://[fd00::4]:2380"], "isLearner": True}),
            ("/v3/cluster/member/promote", {"ID": "12"}),
            ("/v3/cluster/member/remove", {"ID": "12"})])

    def test_etcd_s_refusal_is_said(self):
        Gateway.answers["/v3/cluster/member/promote"] = (400, {
            "code": 9, "message": "etcdserver: can only promote a learner"
            " member which is in sync with leader"})
        with self.assertRaisesRegex(EtcdError, "in sync with leader"):
            self.client.promote("12")
        Gateway.answers["/v3/cluster/member/list"] = (500, b"not json")
        with self.assertRaisesRegex(EtcdError, "500"):
            self.client.members()
        Gateway.answers["/v3/cluster/member/list"] = (200, b"[1]")
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.members()
        Gateway.answers["/v3/cluster/member/list"] = (200, {"members": [1]})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.members()


class TestStatusAndHealth(Case):
    def test_status_of_one_member(self):
        Gateway.answers["/v3/maintenance/status"] = (200, {
            "header": {"member_id": "11"}, "leader": "11",
            "raftTerm": "3", "version": "3.5.16"})
        found = self.client.status(f"https://[::1]:{self.port}")
        self.assertEqual((found.member_id, found.leader, found.raft_term,
                          found.learner), ("11", "11", 3, False))

    def test_health(self):
        Gateway.answers["/health"] = (200, {"health": "true", "reason": ""})
        self.assertEqual(self.client.health(f"https://[::1]:{self.port}"),
                         (True, ""))
        Gateway.answers["/health"] = (503, {"health": "false",
                                            "reason": "NO_LEADER"})
        self.assertEqual(self.client.health(f"https://[::1]:{self.port}"),
                         (False, "NO_LEADER"))

    def test_a_put(self):
        Gateway.answers["/v3/kv/put"] = (200, {"header": {"revision": "5"}})
        self.assertEqual(self.client.put("k", "v"), 5)
        self.assertEqual(Gateway.seen[-1],
                         ("/v3/kv/put", {"key": "aw==", "value": "dg=="}))


class TestLeasesAndTransactions(Case):
    """What the VIP's controller asks (keel.mesh.vipetcd)"""

    def test_a_lease_granted_renewed_and_revoked(self):
        Gateway.answers["/v3/lease/grant"] = (200, {"ID": "77", "TTL": "20"})
        Gateway.answers["/v3/lease/keepalive"] = (200, {"result": {
            "ID": "77", "TTL": "20"}})
        Gateway.answers["/v3/lease/revoke"] = (200, {})
        self.assertEqual(self.client.grant(20), "77")
        self.assertEqual(self.client.keepalive("77"), 20)
        self.client.revoke("77")
        Gateway.answers["/v3/lease/keepalive"] = (200, {"result": {
            "ID": "77"}})
        self.assertEqual(self.client.keepalive("77"), 0)
        self.assertEqual([one[0] for one in Gateway.seen], [
            "/v3/lease/grant", "/v3/lease/keepalive", "/v3/lease/revoke",
            "/v3/lease/keepalive"])

    def test_answers_that_are_not_etcd_s(self):
        Gateway.answers["/v3/lease/grant"] = (200, {"TTL": "20"})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.grant(20)
        Gateway.answers["/v3/lease/keepalive"] = (200, {"error": {
            "message": "no leader"}})
        with self.assertRaisesRegex(EtcdError, "no leader"):
            self.client.keepalive("77")
        Gateway.answers["/v3/kv/range"] = (200, {"kvs": [{"value": "x"}]})
        with self.assertRaisesRegex(EtcdError, "not etcd's"):
            self.client.prefix("/k/")

    def test_a_prefix_and_a_swap(self):
        Gateway.answers["/v3/kv/range"] = (200, {"kvs": [
            {"key": "L2svYQ==", "value": "b25l", "mod_revision": "4",
             "lease": "77"}, {"key": "L2svYg==", "mod_revision": "5"}]})
        found = self.client.prefix("/k/")
        self.assertEqual(found, [
            etcdclient.Value("/k/a", b"one", 4, "77"),
            etcdclient.Value("/k/b", b"", 5, None)])
        self.assertEqual(Gateway.seen[-1], ("/v3/kv/range", {
            "key": "L2sv", "range_end": "L2sw"}))
        Gateway.answers["/v3/kv/txn"] = (200, {"succeeded": True})
        self.assertTrue(self.client.swap(
            [etcdclient.modified("/k/a", 4), etcdclient.absent("/k/b")],
            [("/k/a", b"two", None), ("/k/b", b"two", "77")]))
        sent = Gateway.seen[-1][1]
        self.assertEqual(sent["compare"][0]["mod_revision"], "4")
        self.assertEqual(sent["compare"][1]["version"], "0")
        self.assertEqual(sent["success"][1]["request_put"]["lease"], "77")
        self.assertNotIn("lease", sent["success"][0]["request_put"])
        Gateway.answers["/v3/kv/txn"] = (200, {})
        self.assertFalse(self.client.swap([], []))


class TestUnreachable(Case):
    def test_every_endpoint_tried_then_refused(self):
        Gateway.answers["/v3/cluster/member/list"] = (200, LIST)
        client = etcdclient.Client(
            ("https://[::1]:1", f"https://[::1]:{self.port}"),
            etcdclient.context(self.root), timeout=5)
        self.assertEqual(len(client.members()), 2)
        nobody = etcdclient.Client(("https://[::1]:1",),
                                   etcdclient.context(self.root), timeout=2)
        with self.assertRaisesRegex(EtcdError, "no member answered"):
            nobody.members()
        self.assertEqual(nobody.health("https://[::1]:1")[0], False)

    def test_a_server_without_the_mesh_s_certificate(self):
        """A server whose certificate the root did not sign is not etcd"""
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        etcdstate.make_root(other, MESH, "fd00::1")
        etcdstate.leaves(other, "fd00::9", NOW)
        client = etcdclient.Client((f"https://[::1]:{self.port}",),
                                   etcdclient.context(other), timeout=2)
        with self.assertRaises(EtcdError):
            client.members()

    def test_no_client_certificate_yet(self):
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty)
        with self.assertRaisesRegex(EtcdError, "no client certificate"):
            etcdclient.context(empty)

    def test_local_names_the_loopback(self):
        self.assertEqual(etcdclient.local(self.root).endpoints,
                         ("https://[::1]:2379",))


if __name__ == "__main__":
    unittest.main()
