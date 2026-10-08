# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdauth: etcd's users and roles, managed by the root's
holder (keel#83), with members in one process and a recording etcd
(tests/etcd_helpers.py)"""

import json
import os
from unittest import mock

from etcd_helpers import KEYS, MESH, FakeEtcd, Mesh, address, voter

from keel import exits
from keel.mesh import (
    etcdauth,
    etcdcare,
    etcdform,
    etcdmsg,
    etcdserve,
    etcdstate,
    vipnode,
    vippair,
)
from keel.mesh.etcdclient import EtcdError, Value
from keel.mesh.etcdstate import StateError

VIP = "fd00:6b65:1::ffff:100"
OTHER_VIP = "fd00:6b65:1::ffff:101"
PREFIX = f"/keel/{MESH.hex()}/"


def member_role():
    return {("read", PREFIX, PREFIX[:-1] + "0"),
            ("readwrite", f"{PREFIX}etcd/", f"{PREFIX}etcd0"),
            ("readwrite", f"{PREFIX}vips/", f"{PREFIX}vips0")}


class Formed(Mesh):
    """a holds the root and formed the cluster of a, b and c"""

    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, self.b, self.c = self.members(3, etcd=self.fake)
        etcdform.form(self.a, False, lambda line: None)

    def pair(self, first=0, second=1, vip=VIP, keep=True):
        """The record keel vip pair leaves on the pair's members"""
        record = vippair.made(MESH.hex(), vip, (KEYS[first], KEYS[second]))
        for index in (first, second):
            record = vippair.sign(self.all[index].root, record, KEYS[index])
        if keep:
            for index in (first, second):
                vippair.write(self.all[index].root, record)
        return record


class TestWanted(Formed):
    def test_members_read_the_mesh_and_the_pair_writes_its_keys(self):
        found = etcdauth.wanted(MESH.hex(), (address(0), address(1),
                                             address(2)),
                                {VIP: (address(0), address(1))})
        self.assertEqual(found.roles[etcdauth.MEMBER_ROLE], {
            ("read", PREFIX), ("readwrite", f"{PREFIX}etcd/"),
            ("readwrite", f"{PREFIX}vips/")})
        self.assertEqual(found.roles[f"keel-vip-{VIP}"], {
            ("readwrite", f"{PREFIX}vip/{VIP}/")})
        self.assertEqual(found.users["root"], {"root"})
        self.assertEqual(found.users[etcdstate.name(address(0))],
                         {etcdauth.MEMBER_ROLE, f"keel-vip-{VIP}"})
        self.assertEqual(found.users[etcdstate.name(address(2))],
                         {etcdauth.MEMBER_ROLE})

    def test_converged_then_nothing_to_do(self):
        want = etcdauth.wanted(MESH.hex(), (address(0), address(2)),
                               {VIP: (address(0), address(1))})
        done = etcdauth.converge(self.fake, want)
        self.assertIn("role root added", done)
        self.assertIn(f"user {etcdstate.name(address(1))}: role"
                      f" keel-vip-{VIP}", done)
        self.assertEqual(self.fake.roles_[etcdauth.MEMBER_ROLE],
                         member_role())
        self.assertEqual(self.fake.users_["root"], {"root"})
        self.assertEqual(etcdauth.converge(self.fake, want), [])

    def test_only_what_keel_made_is_taken_away(self):
        self.fake.roles_ = {"keel-vip-old": {("readwrite", "/x/", "/x0")},
                            "operator": {("read", "/o/", "/o0")},
                            etcdauth.MEMBER_ROLE: {("write", "/y/", "/y0")}}
        self.fake.users_ = {"keel-fd00-6b65-1--1": {"keel-vip-old",
                                                    "operator"},
                            "alice": {"operator"}}
        done = etcdauth.converge(self.fake, etcdauth.wanted(
            MESH.hex(), (address(0),), {}))
        self.assertNotIn("keel-vip-old", self.fake.roles_)
        self.assertIn("operator", self.fake.roles_)
        self.assertEqual(self.fake.users_["alice"], {"operator"})
        self.assertEqual(self.fake.users_["keel-fd00-6b65-1--1"],
                         {"operator", etcdauth.MEMBER_ROLE})
        self.assertEqual(self.fake.roles_[etcdauth.MEMBER_ROLE],
                         member_role())
        self.assertIn(f"role {etcdauth.MEMBER_ROLE}: no longer write on /y/",
                      done)


class TestState(Formed):
    def test_enabled_is_etcd_s_word_kept_a_few_seconds(self):
        """No file says whether auth is on: etcd does (auth status), and
        its answer is kept STATUS_FOR seconds, then asked again"""
        ticks = [100.0]
        now = lambda: ticks[0]  # noqa: E731
        self.assertFalse(etcdauth.enabled(self.a, now=now))
        self.fake.auth = True
        # kept: etcd is not asked again within STATUS_FOR
        self.assertFalse(etcdauth.enabled(self.a, now=now))
        ticks[0] += etcdauth.STATUS_FOR + 1
        self.assertTrue(etcdauth.enabled(self.a, now=now))
        self.assertEqual([one for one in self.fake.calls
                          if one[0] == "auth_enabled"],
                         [("auth_enabled",)] * 2)
        # a change this node made: asked again at once
        self.fake.auth = False
        etcdauth.forget(self.a.root)
        self.assertFalse(etcdauth.enabled(self.a, now=now))
        # etcd not answering is an error, never an answer
        etcdauth.forget(self.a.root)
        self.fake.refuse["auth_enabled"] = "no leader"
        with self.assertRaises(EtcdError):
            etcdauth.enabled(self.a, now=now)
        del self.fake.refuse["auth_enabled"]

    def test_pairs_kept_on_the_holder(self):
        self.assertEqual(etcdauth.pairs(self.a.root), {})
        etcdauth.keep_pair(self.a.root, VIP, (KEYS[0], KEYS[1]))
        self.assertEqual(etcdauth.pairs(self.a.root),
                         {VIP: [KEYS[0], KEYS[1]]})
        for damaged in ("{", "[]", json.dumps({VIP: "x"})):
            etcdstate.write(self.a.root, etcdauth.PAIRS, damaged)
            self.assertEqual(etcdauth.pairs(self.a.root), {})


class TestPairs(Formed):
    def test_a_pair_s_member_gets_its_role_from_the_holder(self):
        record = self.pair()
        self.assertEqual(etcdauth.announce(self.b), [
            f"etcd: {VIP}: its pair's role is granted"])
        self.assertEqual(etcdauth.pairs(self.a.root),
                         {VIP: list(record.members)})
        role = f"keel-vip-{VIP}"
        self.assertEqual(self.fake.roles_[role],
                         {("readwrite", f"{PREFIX}vip/{VIP}/",
                           f"{PREFIX}vip/{VIP}0")})
        self.assertIn(role, self.fake.users_[etcdstate.name(address(0))])
        self.assertIn(role, self.fake.users_[etcdstate.name(address(1))])
        self.assertNotIn(role, self.fake.users_[etcdstate.name(address(2))])
        # the holder keeps the record, which binds the VIP to that pair
        self.assertIsNotNone(vippair.read(self.a.root, VIP))
        # the holder, a member of the pair, grants it itself
        self.assertEqual(etcdauth.announce(self.a), [
            f"etcd: {VIP}: its pair's role is granted"])
        # c is in no pair: it announces nothing
        self.assertEqual(etcdauth.announce(self.c), [])

    def test_only_a_member_of_the_pair_sends_its_record(self):
        record = self.pair()
        message = etcdmsg.signed(self.c.root, etcdmsg.PAIR, MESH.hex(),
                                 KEYS[2], self.clock(),
                                 {"pair": record.dumps()})
        found = etcdserve.answer(self.a, message, KEYS[2])
        self.assertEqual(found.status, 403)
        self.assertIn("only a member of the pair", found.body.decode())
        found = etcdserve.answer(self.b, message, KEYS[2])
        self.assertEqual(found.status, 409)

    def test_a_record_not_signed_by_both_or_for_a_bound_vip(self):
        record = vippair.made(MESH.hex(), VIP, (KEYS[1], KEYS[2]))
        with self.assertRaisesRegex(StateError, "not signed"):
            etcdauth.checked_pair(self.a, record.dumps(), KEYS[1])
        with self.assertRaisesRegex(StateError, "not taken"):
            etcdauth.checked_pair(self.a, {"record": 1}, KEYS[1])
        self.pair()
        etcdauth.checked_pair(self.a, self.pair().dumps(), KEYS[0])
        other = self.pair(1, 2, keep=False)
        with self.assertRaisesRegex(StateError, "another pair"):
            etcdauth.checked_pair(self.a, other.dumps(), KEYS[1])

    def test_etcd_failing_is_a_503_and_the_role_waits(self):
        self.pair()
        self.fake.refuse["roles"] = "etcdserver: no leader"
        said = etcdauth.announce(self.b)
        self.assertIn("its pair's role waits for the root's holder", said[0])
        self.assertIn("etcd did not take the pair", said[0])

    def test_no_holder_known_or_reachable(self):
        self.pair()
        self.down.add(address(0))
        self.assertIn("timed out", etcdauth.announce(self.b)[0])
        etcdstate.write(self.b.root, etcdstate.HOLDER, "")
        self.assertIn("does not know the root's holder",
                      etcdauth.announce(self.b)[0])

    def test_a_damaged_record_is_skipped(self):
        self.pair()
        path = vippair.file_of(VIP)
        etcdstate.write(self.b.root, path, "{")
        etcdstate.write(self.b.root, "var/lib/keel/vip/other.txt", "x")
        self.assertEqual(etcdauth.announce(self.b), [])
        self.assertEqual(etcdauth.kept_pairs(self.scratch_root()), [])

    def scratch_root(self):
        import tempfile
        found = tempfile.mkdtemp(dir=self.parent)
        return found

    def test_a_pair_naming_a_node_the_holder_does_not_know_waits(self):
        etcdauth.keep_pair(self.a.root, VIP, (KEYS[0], KEYS[4]))
        etcdauth.reconcile(self.a)
        self.assertIn("names a node this holder does not know",
                      self.text(0))
        self.assertNotIn(f"keel-vip-{VIP}", self.fake.roles_)

    def test_only_the_holder_reconciles(self):
        with self.assertRaisesRegex(StateError, "only the root's holder"):
            etcdauth.reconcile(self.b)


class TestClaims(Formed):
    def test_the_pairs_the_claims_rest_on(self):
        self.pair()
        here = vipnode.Here(self.a.node, self.clock, lambda line: None)
        claim = vipnode.signed_claim(here, VIP, 1)
        self.fake.kvs = [
            Value(f"{PREFIX}vip/{VIP}/epoch", claim.raw, 3, None),
            Value(f"{PREFIX}vip/{VIP}/holder", claim.raw, 3, "7"),
            Value(f"{PREFIX}vip/{OTHER_VIP}/epoch", b"not a claim", 4,
                  None)]
        self.assertEqual(etcdauth.from_claims(self.a, self.fake,
                                              MESH.hex()), 1)
        self.assertEqual(list(etcdauth.pairs(self.a.root)), [VIP])
        self.assertIn(f"the claim at {PREFIX}vip/{OTHER_VIP}/epoch gives"
                      " no pair", self.text(0))


class TestTheHolderAfterAuth(Formed):
    def test_a_joining_member_gets_its_user(self):
        """The holder admits a fourth node itself: its user is made with
        its learner, once auth is on"""
        from etcd_helpers import spec

        from keel.mesh import etcd
        self.fake.auth = True
        etcdauth.forget(self.a.root)
        d = self.members(4, etcd=self.fake)[3]
        with open(os.path.join(self.a.root, "instance.yaml"), "w") as fob:
            fob.write(spec(0, 4))
        self.all[:3] = [self.a, self.b, self.c]
        found = etcd.sign_here(self.a, etcd.join_request(d), address(3),
                               KEYS[3], KEYS[0], self.evidence(self.a, 3))
        self.assertIsNotNone(found.learner)
        self.assertIn(etcdstate.name(address(3)), self.fake.users_)
        # a renewal of a member etcd lists adds nothing
        calls = len(self.fake.calls)
        etcd.sign_here(self.a, etcd.join_request(d), address(3), KEYS[3],
                       KEYS[0], self.evidence(self.a, 3))
        self.assertNotIn("add_learner", [one[0] for one in
                                         self.fake.calls[calls:]])

    def test_tend_converges_on_the_holder_and_says_a_failure(self):
        self.fake.auth = True
        etcdauth.forget(self.a.root)
        self.assertEqual(etcdcare.tend(self.a), exits.OK)
        self.assertIn(etcdstate.name(address(2)), self.fake.users_)
        self.fake.refuse["roles"] = "etcdserver: permission denied"
        self.assertEqual(etcdcare.tend(self.a), exits.APPLY_FAILED)
        self.assertIn("users and roles not converged", self.text(0))

    def test_a_revoked_member_s_user_and_member_are_removed(self):
        self.fake.auth = True
        etcdauth.forget(self.a.root)
        etcdauth.reconcile(self.a)
        etcdcare.leave(self.b, address(2), True, KEYS[2])
        self.assertNotIn(etcdstate.name(address(2)), self.fake.users_)
        self.assertIn(f"the user of {address(2)} deleted", self.text(0))
        self.fake.refuse["members"] = "no leader"
        etcdserve.removed_from_etcd(self.a, address(1))
        self.assertIn(f"{address(1)} was not removed from etcd",
                      self.text(0))

    def test_keel_vip_pair_asks_the_holder_for_the_role(self):
        from keel.mesh import vippromote
        here = vipnode.Here(self.b.node, self.clock, lambda line: None,
                            client=self.fake)
        said = []
        with mock.patch("keel.mesh.vippromote.with_etcd", return_value=True), \
                mock.patch("keel.mesh.etcdauth.announce",
                           return_value=["etcd: granted"]) as announce, \
                mock.patch("keel.mesh.vippromote.vipstate.declared",
                           return_value=VIP), \
                mock.patch.object(here, "say", side_effect=lambda kind, at,
                                  body: json.dumps({"pair": self.pair(
                                      keep=False).dumps()}).encode()):
            code = vippromote.pair(here, address(0), said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertEqual(said[-1], "etcd: granted")
        announce.assert_called_once()
        # and reserved the VIP first (keel.mesh.vipreserve)
        self.assertEqual([one.key for one in self.fake.kvs],
                         [f"{PREFIX}vips/{VIP}/pair"])


class TestErrorsReach(Formed):
    def test_an_etcd_error_in_converge_is_raised(self):
        self.fake.refuse["users"] = "no leader"
        with self.assertRaises(EtcdError):
            etcdauth.reconcile(self.a)
