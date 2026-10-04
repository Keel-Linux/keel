# Copyright (c) 2026 KeelLinux maintainers
"""What only the root CA's holder does (keel.mesh.etcdca), and the
holder's answers on the members' channel: issue and revoke"""

import json
import os
import unittest
from datetime import timedelta
from unittest import mock

from etcd_helpers import KEYS, MESH, NOW, FakeEtcd, Mesh, address, voter

from keel.mesh import (
    etcd,
    etcdca,
    etcdform,
    etcdmsg,
    etcdpki,
    etcdserve,
    etcdstate,
    trust,
)
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, Member, StateError


class TestTheHolder(Mesh):
    def setUp(self):
        super().setUp()
        self.a, self.b, self.c = self.members(3)
        etcdstate.make_root(self.a.root, MESH.hex(), address(0))
        self.three = tuple(Member(KEYS[n], address(n)) for n in range(3))

    def test_only_the_holder_signs_a_record(self):
        with self.assertRaisesRegex(StateError, "only the node"):
            etcdca.record(self.b.root, self.three, MESH.hex(), NOW)
        with mock.patch("keel.mesh.etcdpki.sign",
                        side_effect=PkiError("no")), \
                self.assertRaisesRegex(StateError, "no"):
            etcdca.record(self.a.root, self.three, MESH.hex(), NOW)
        found = etcdca.record(self.a.root, self.three, MESH.hex(), NOW)
        self.assertIsNone(etcdca.problem(self.a.root, found, NOW))
        self.assertIn("holds no root", etcdca.problem(self.b.root, found,
                                                       NOW))

    def test_one_formation_reserved_given_back_once(self):
        found = etcdca.record(self.a.root, self.three, MESH.hex(), NOW)
        self.assertTrue(etcdca.reserve(self.a.root, found))
        self.assertFalse(etcdca.reserve(self.a.root, found))
        etcdca.release(self.a.root)
        etcdca.release(self.a.root)
        self.assertTrue(etcdca.reserve(self.a.root, found))
        etcdstate.save_cluster(self.a.root, found)
        etcdca.release(self.a.root)
        self.assertFalse(etcdca.reserve(self.a.root, found))

    def test_revoke_and_refresh_on_the_holder_alone(self):
        with self.assertRaisesRegex(StateError, "only the root"):
            etcdca.revoke(self.b.root, address(2), KEYS[2], NOW)
        self.assertFalse(etcdca.refresh(self.b.root, NOW))
        grant = etcdstate.grant_for(self.a.root, etcdstate.ca_request(
            self.c.root), address(2), KEYS[2])
        with self.assertRaisesRegex(StateError, "no intermediate"):
            etcdca.revoke(self.a.root, address(2), KEYS[1], NOW)
        etcdstate.write(self.a.root, etcdca.REVOKED, "{")
        found = etcdca.revoke(self.a.root, address(2), KEYS[2], NOW)
        self.assertEqual(etcdpki.crl_serials(found),
                         {etcdpki.serial(grant.certificate)})
        etcdstate.write(self.a.root, etcdca.REVOKED, "[1]")
        self.assertEqual(etcdca.revoked(self.a.root), {})
        with mock.patch("keel.mesh.etcdpki.crl", side_effect=PkiError("x")), \
                self.assertRaises(StateError):
            etcdca.revoke(self.a.root, address(2), KEYS[2], NOW)
        etcdstate.write(self.a.root, etcdstate.ISSUED, "{")
        with self.assertRaisesRegex(StateError, "no intermediate"):
            etcdca.revoke(self.a.root, address(2), KEYS[2], NOW)
        just = os.path.getmtime(os.path.join(self.a.root, etcdstate.CRL))
        from datetime import datetime, timezone
        self.assertFalse(etcdca.refresh(
            self.a.root, datetime.fromtimestamp(just, timezone.utc)))
        self.assertTrue(etcdca.refresh(self.a.root,
                                       NOW + timedelta(days=4000)))
        os.remove(os.path.join(self.a.root, etcdstate.CRL))
        self.assertTrue(etcdca.refresh(self.a.root, NOW))

    def test_no_intermediate_is_not_due(self):
        self.assertFalse(etcdca.ca_due(self.b.root, NOW))


class TestTheHolderAnswers(Mesh):
    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, self.b, self.c = self.members(3, etcd=self.fake)
        etcdform.form(self.a, False, lambda line: None)

    def ask(self, target, kind, body, sender=1):
        message = etcdmsg.signed(self.all[sender].root, kind, MESH.hex(),
                                 KEYS[sender], NOW, body)
        return etcdserve.answer(target, message, KEYS[sender])

    def error(self, *args, **kwargs):
        found = self.ask(*args, **kwargs)
        self.assertGreaterEqual(found.status, 400)
        return json.loads(found.body)["error"]

    def test_issue_refusals(self):
        csr = etcdstate.ca_request(self.c.root)
        body = {"csr": csr, "address": address(2), "public_key": KEYS[2]}
        self.assertIn("does not hold", self.error(self.b, etcdmsg.ISSUE,
                                                  body, sender=0))
        self.assertIn("not an overlay address", self.error(
            self.a, etcdmsg.ISSUE, {**body, "address": "x"}))
        self.assertIn("not in this mesh's prefix", self.error(
            self.a, etcdmsg.ISSUE, {**body, "address": "fd99::1"}))
        self.assertIn("no WireGuard key", self.error(
            self.a, etcdmsg.ISSUE, {**body, "public_key": "x"}))
        self.assertIn("PEM", self.error(
            self.a, etcdmsg.ISSUE, {**body, "csr": "x"}))
        self.assertIn("no request", self.error(
            self.a, etcdmsg.ISSUE, {**body, "csr": None}))
        # b asks for c's address with its own key: c's, refused
        self.assertIn("another member's", self.error(
            self.a, etcdmsg.ISSUE, {**body, "public_key": KEYS[1]}))
        self.assertIn("another member's", self.error(
            self.a, etcdmsg.ISSUE, {**body, "address": address(0),
                                    "public_key": KEYS[1]}))
        found = self.ask(self.a, etcdmsg.ISSUE, body)
        self.assertEqual(found.status, 200)
        # an address nobody holds yet: a node being admitted
        fresh = {**body, "address": "fd00:6b65:1::9", "public_key": KEYS[3]}
        self.assertEqual(self.ask(self.a, etcdmsg.ISSUE, fresh).status, 200)
        self.assertEqual(etcdserve.claimed(self.a, "fd00:6b65:1::9"),
                         KEYS[3])
        etcdstate.write(self.a.root, etcdstate.ISSUED,
                        '{"fd00:6b65:1::8": [[1]]}')
        self.assertIsNone(etcdserve.claimed(self.a, "fd00:6b65:1::8"))
        etcdstate.write(self.a.root, etcdstate.ISSUED, "{")
        self.assertIsNone(etcdserve.claimed(self.a, "fd00:6b65:1::8"))

    def test_a_member_cannot_revoke_another_s_certificates(self):
        """b names itself as the removed node, at c's address: refused,
        and c's intermediate is not revoked"""
        found = self.error(self.a, etcdmsg.REVOKE, {
            "address": address(2), "public_key": KEYS[1]})
        self.assertIn("no intermediate of", found)
        self.assertEqual(etcdpki.crl_serials(etcdstate.read(
            self.a.root, etcdstate.CRL)), set())
        # b leaving names its own address: its own intermediate goes
        own = self.ask(self.a, etcdmsg.REVOKE, {
            "address": address(1), "public_key": KEYS[1]})
        self.assertEqual(own.status, 200)
        self.assertEqual(etcdpki.crl_serials(json.loads(own.body)["crl"]),
                         {etcdpki.serial(etcdstate.read(
                             self.b.root, etcdstate.CA_CERT))})

    def test_revoke_refusals(self):
        self.assertIn("no WireGuard key", self.error(
            self.a, etcdmsg.REVOKE, {"address": address(2),
                                     "public_key": 1}))
        store = trust.load(self.a.root)
        store.members[store.find(KEYS[1])].root = False
        del store.members[store.find(KEYS[2])]
        trust.save(self.a.root, store)
        self.assertIn("may not remove", self.error(
            self.a, etcdmsg.REVOKE, {"address": address(2),
                                     "public_key": KEYS[2]}))
        self.assertTrue(etcdserve.may_revoke(self.a.root, KEYS[1], KEYS[1]))
        self.assertFalse(etcdserve.may_revoke(self.a.root, KEYS[2],
                                              KEYS[3]))
        # an admitter may: the evidence a keeps for d names b's key
        store = trust.load(self.a.root)
        evidence = trust.admit(self.b.root, MESH, "0123456789abcdef",
                               KEYS[3], KEYS[4], address(3), None, NOW)
        trust.recorded(store, evidence)
        trust.save(self.a.root, store)
        self.assertTrue(etcdserve.may_revoke(self.a.root, KEYS[1], KEYS[3]))

    def test_a_revocation_on_a_holder_in_no_cluster(self):
        os.remove(os.path.join(self.a.root, etcdstate.CLUSTER))
        found = self.ask(self.a, etcdmsg.REVOKE, {
            "address": address(2), "public_key": KEYS[2]})
        self.assertEqual(found.status, 200, found.body)

    def test_an_older_crl_is_not_written(self):
        held = etcdstate.read(self.b.root, etcdstate.CRL)
        from keel.mesh import etcdcare
        before = len(self.applied(self.b))
        etcdcare.crl_taken(self.b, held)
        self.assertEqual(len(self.applied(self.b)), before)

    def test_a_grant_with_no_crl_nor_holder(self):
        import shutil
        import tempfile
        from dataclasses import replace
        fresh = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, fresh)
        bare = replace(etcdstate.grant_for(
            self.a.root, etcdstate.ca_request(fresh), address(2)),
            crl=None, holder=None)
        etcdstate.take_grant(fresh, bare)
        self.assertIsNone(etcdstate.holder(fresh))
        self.assertIsNone(etcdstate.read(fresh, etcdstate.CRL))


class TestFormLimits(Mesh):
    def test_more_than_a_cluster_starts_with(self):
        a, *_ = self.members(3)
        with mock.patch("keel.mesh.etcd.MAX_FORMED", 2):
            self.assertEqual(etcdform.form(a, False, print), 24)
        self.assertIn("a cluster starts with at most 2", self.text(0))

    def test_a_formation_reserved_by_a_join(self):
        a, *_ = self.members(3)
        with mock.patch("keel.mesh.etcdca.reserve", return_value=False):
            self.assertEqual(etcdform.form(a, False, print), 24)
        self.assertIn("a formation is under way", self.text(0))


class TestSmallPaths(Mesh):
    def test_damaged_bookkeeping_and_late_records(self):
        from keel.mesh import etcdcare
        a, b, c = self.members(3)
        etcdstate.write(a.root, etcdstate.PENDING, "{")
        self.assertEqual(etcdstate.pending(a.root), [])
        etcdstate.write(a.root, etcdstate.RENEWAL, "{")
        self.assertIsNone(etcdcare.renewal_problem(a.root))
        sent = []
        with mock.patch("keel.monitor.channelfile.load", return_value={}), \
                mock.patch("keel.monitor.notify.send",
                           return_value=[mock.Mock(line=lambda: "x: sent")]):
            etcdcare.alert(a, "t", "x")
        self.assertIn("alert x: sent", self.text(0))
        del sent
        # a member of the first cluster that never started, after the
        # first record expired: signed again, at a newer epoch
        fake = FakeEtcd([voter(0), voter(1), voter(2, name=False)])
        a, b, c = self.members(3, etcd=fake)
        etcdform.form(a, False, lambda line: None)
        first = etcdca.epoch(etcdstate.cluster(a.root))
        for one in self.all:
            one.clock = lambda: NOW + timedelta(hours=2)
        out = []
        etcdform.form(a, False, out.append)
        self.assertGreater(etcdca.highest(c.root), 0)
        self.assertGreaterEqual(first, 1)

    def test_a_client_cluster_id(self):
        from keel.mesh import etcdclient
        client = etcdclient.Client(("https://[::1]:1",), None)
        with mock.patch.object(client, "ask", return_value={
                "header": {"cluster_id": "77"}}):
            self.assertEqual(client.cluster_id(), "77")


class TestJoinEdges(Mesh):
    def test_a_record_that_cannot_be_made_forms_nothing(self):
        a, b, c = self.members(3)
        etcd.created(a)
        etcdstate.add_ready(a.root, {KEYS[1]: address(1)})
        with mock.patch("keel.mesh.etcdca.record",
                        side_effect=StateError("no openssl")):
            found = etcd.admit(a, etcd.join_csr(c), KEYS[2], address(2))
        self.assertIsNone(found.cluster)
        self.assertIn("no cluster formed (no openssl)", self.text(0))

    def test_a_holder_whose_answer_holds_no_grant(self):
        a, b, c = self.members(3)
        etcdform.form(a, False, lambda line: None)
        with mock.patch("keel.mesh.etcdmsg.grant", return_value=None), \
                self.assertRaisesRegex(StateError, "holds no grant"):
            etcd.issued(b, etcdstate.ca_request(c.root), address(2),
                        KEYS[2])
        etcdstate.write(b.root, etcdstate.HOLDER, "")
        with self.assertRaisesRegex(StateError, "does not know"):
            etcd.issued(b, etcdstate.ca_request(c.root), address(2),
                        KEYS[2])

    def test_a_stray_member_directory_only_with_the_package_s_mark(self):
        a, = self.members(1)
        etcd.created(a)
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        stray = os.path.join(a.root, etcd.MEMBER_DIR)
        os.makedirs(stray)
        ran = []
        a.node.run = ran.append
        # not marked by keel-overlay-etcd: refused, kept
        self.assertFalse(etcd.start(a))
        self.assertTrue(os.path.exists(stray))
        self.assertIn("did not mark", self.text(0))
        mark = os.path.join(a.root, etcd.PACKAGE_MEMBER)
        os.makedirs(os.path.dirname(mark))
        open(mark, "w").close()
        self.assertTrue(etcd.start(a))
        self.assertFalse(os.path.exists(stray))
        self.assertFalse(os.path.exists(mark))
        self.assertEqual(ran, [("systemctl", "stop", "etcd.service")])
        self.assertIn("which the package marked", self.text(0))
        os.makedirs(stray)
        self.assertTrue(etcd.start(a))
        self.assertTrue(os.path.exists(stray))


if __name__ == "__main__":
    unittest.main()
