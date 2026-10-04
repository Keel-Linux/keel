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
            etcdca.record(self.b.root, self.three, MESH.hex())
        with mock.patch("keel.mesh.etcdpki.sign",
                        side_effect=PkiError("no")), \
                self.assertRaisesRegex(StateError, "no"):
            etcdca.record(self.a.root, self.three, MESH.hex())
        found = etcdca.record(self.a.root, self.three, MESH.hex())
        self.assertIsNone(etcdca.problem(self.a.root, found))
        self.assertIn("holds no root", etcdca.problem(self.b.root, found))

    def test_one_formation_reserved_given_back_once(self):
        found = etcdca.record(self.a.root, self.three, MESH.hex())
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
            etcdca.revoke(self.b.root, None, {}, NOW)
        self.assertFalse(etcdca.refresh(self.b.root, NOW))
        etcdstate.write(self.a.root, etcdca.REVOKED, "{")
        etcdstate.write(self.a.root, etcdstate.ISSUED, "{")
        found = etcdca.revoke(self.a.root, None, {"AB": "271004000000Z"},
                              NOW)
        self.assertEqual(etcdpki.crl_serials(found), {"AB"})
        etcdstate.write(self.a.root, etcdca.REVOKED, "[1]")
        self.assertEqual(etcdca.revoked(self.a.root), {})
        with mock.patch("keel.mesh.etcdpki.crl", side_effect=PkiError("x")), \
                self.assertRaises(StateError):
            etcdca.revoke(self.a.root, None, {}, NOW)
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
        self.assertIn("does not hold", self.error(
            self.b, etcdmsg.ISSUE, {"csr": csr, "address": address(2)},
            sender=0))
        self.assertIn("not an overlay address", self.error(
            self.a, etcdmsg.ISSUE, {"csr": csr, "address": "x"}))
        self.assertIn("not in this mesh's prefix", self.error(
            self.a, etcdmsg.ISSUE, {"csr": csr, "address": "fd99::1"}))
        self.assertIn("PEM", self.error(
            self.a, etcdmsg.ISSUE, {"csr": "x", "address": address(2)}))
        self.assertIn("no request", self.error(
            self.a, etcdmsg.ISSUE, {"address": address(2)}))
        found = self.ask(self.a, etcdmsg.ISSUE,
                         {"csr": csr, "address": address(2)})
        self.assertEqual(found.status, 200)

    def test_revoke_refusals(self):
        self.assertIn("malformed revocation", self.error(
            self.a, etcdmsg.REVOKE, {"address": address(2),
                                     "public_key": 1}))
        self.assertIn("malformed revocation", self.error(
            self.a, etcdmsg.REVOKE, {"address": address(2),
                                     "public_key": KEYS[2],
                                     "serials": {"a": 1}}))
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
        self.assertEqual(found.status, 200)

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
        with mock.patch("keel.mesh.etcdmsg.grant", return_value=None):
            found = etcd.issued(b, etcdstate.ca_request(c.root), address(2))
        self.assertEqual(len(found.chain), 1)
        self.assertIn("holds no grant", self.text(1))

    def test_a_stray_member_directory_is_removed_once(self):
        a, = self.members(1)
        etcd.created(a)
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        stray = os.path.join(a.root, etcd.MEMBER_DIR)
        os.makedirs(stray)
        ran = []
        a.node.run = ran.append
        self.assertTrue(etcd.start(a))
        self.assertFalse(os.path.exists(stray))
        self.assertEqual(ran, [("systemctl", "stop", "etcd.service")])
        self.assertIn("a lone member etcd-server's own start left",
                      self.text(0))
        os.makedirs(stray)
        self.assertTrue(etcd.start(a))
        self.assertTrue(os.path.exists(stray))


if __name__ == "__main__":
    unittest.main()
