# Copyright (c) 2026 KeelLinux maintainers
"""Every member learns where the mesh's root CA is (keel#105, 0051)

A cloud simple pair whose root is held by a third node, which is not a
pair member (web-1 on the real mesh): neither pair member is an etcd
member, so neither got the holder's address with an etcd certificate,
and each asked the other member, which refused. The holder's address
now travels in every roster as a notice signed by the root's key, and
the root's certificate, the anchor the notice is verified against, is
taken only from a trust root's own roster (tests/vip_helpers.py makes
every other node a trust root).
"""

import os
from datetime import timedelta
from unittest import mock

from pki_clock import NOW as PKI_NOW
from vip_helpers import KEYS, VIP, Pair, address

from keel.mesh import etcd, etcdpki, etcdstate, members, rootholder, sync
from keel.mesh import trust, vippair
from keel.mesh.etcdstate import StateError
from keel.mesh.memberlink import LinkError
from keel.system import dbtls

HOLDER = 2


class RootHolderCase(Pair):
    def setUp(self):
        super().setUp()
        self.nodes(mode="cloud_simple")
        # C, outside the pair, made the mesh and holds its root
        etcd.created(self.member(HOLDER))
        self.assertTrue(etcdstate.holds_root(self.all[HOLDER].root))
        self.mesh_hex = bytes(range(16)).hex()

    def member(self, index: int) -> etcd.Etcd:
        here = self.all[index]
        found = etcd.Etcd(here.node, lambda: PKI_NOW, self.said[index].append)
        found.exchange = self.etcd_exchanger(index)
        return found

    def etcd_exchanger(self, index: int):
        from keel.mesh import etcdserve

        def exchange(host: str, iface: str, body: bytes) -> bytes:
            if host in self.down:
                raise LinkError(f"[{host}]:51821 through {iface}: timed out")
            target = next(one for one in self.all
                          if one.overlay()["address"].startswith(host + "/"))
            answer = etcdserve.answer(self.member(self.all.index(target)),
                                      body, KEYS[index])
            if answer.status != 200:
                raise LinkError(f"[{host}]:51821 refused: {answer.body!r}")
            return answer.body
        return exchange

    def syncer(self, index: int) -> sync.Syncer:
        return sync.Syncer(self.all[index].node, lambda: PKI_NOW,
                           self.said[index].append, fetch=self.fetch)

    def fetch(self, host: str, iface: str) -> members.Roster:
        """GET /v1/members of the node at `host`, through the wire format"""
        if host in self.down:
            raise LinkError(f"[{host}]:51821 through {iface}: timed out")
        index = next(i for i, one in enumerate(self.all)
                     if one.overlay()["address"].startswith(host + "/"))
        return members.loads(members.dumps(sync.roster(self.syncer(index))))

    def leaf(self, index: int) -> str | None:
        here = self.member(index)
        record = vippair.read(here.root, VIP)
        other = address(1 - index)
        return dbtls.ensure(here, address(index), VIP, other, KEYS[index],
                            owner=lambda d, k: None, pair=record)


class TestACloudSimplePairWithAThirdNodesRoot(RootHolderCase):
    def test_the_pair_gets_its_leaves_with_no_file_written_by_hand(self):
        for index in (0, 1):
            self.assertIsNone(etcdstate.holder(self.all[index].root))
        with mock.patch.object(rootholder.memberlink, "fetch", self.fetch):
            for index in (0, 1):
                said = self.leaf(index)
                self.assertIn("signed by the mesh's root", said)
                self.assertEqual(etcdstate.holder(self.all[index].root),
                                 address(HOLDER))
        root = etcdstate.read(self.all[HOLDER].root, etcdstate.ROOT_CERT)
        for index in (0, 1):
            ca = etcdstate.read(self.all[index].root, dbtls.CA)
            self.assertEqual(etcdpki.fingerprint(ca),
                             etcdpki.fingerprint(root))
            self.assertEqual(rootholder.anchor(self.all[index].root), root)
        self.assertIn(f"the root CA's holder is at {address(HOLDER)}",
                      "\n".join(self.said[0]))

    def test_keel_mesh_sync_learns_the_holder_and_the_root(self):
        sync.pull(self.syncer(0))
        self.assertEqual(etcdstate.holder(self.all[0].root), address(HOLDER))
        self.assertIsNotNone(rootholder.kept(self.all[0].root))
        # B learns it relayed by A too, signed by the root all the same
        self.down.add(address(HOLDER))
        sync.pull(self.syncer(1))
        self.assertEqual(etcdstate.holder(self.all[1].root), address(HOLDER))
        # and its leaf then needs no fetch at all
        with mock.patch.object(rootholder.memberlink, "fetch",
                               side_effect=AssertionError("no fetch")):
            self.down.discard(address(HOLDER))
            self.assertIn("signed by the mesh's root", self.leaf(1))

    def test_the_holder_signs_its_notice_once_and_keeps_it(self):
        first = sync.roster(self.syncer(HOLDER))
        second = sync.roster(self.syncer(HOLDER))
        self.assertIsNotNone(first.holder)
        self.assertEqual(first.holder, second.holder)
        self.assertEqual(first.holder["address"], address(HOLDER))
        self.assertEqual(first.root, etcdstate.read(
            self.all[HOLDER].root, etcdstate.ROOT_CERT))
        # the holder learns nothing of itself from others
        self.assertIsNone(rootholder.learn(
            self.all[HOLDER].root, self.mesh_hex, None, first.holder, True,
            PKI_NOW))

    def test_the_roster_carries_them_and_drops_what_cannot_be_read(self):
        found = sync.roster(self.syncer(HOLDER))
        back = members.loads(members.dumps(found))
        self.assertEqual((back.root, back.holder), (found.root, found.holder))
        import json
        data = json.loads(members.dumps(found))
        data["root"] = "not a certificate"
        data["holder"] = {"address": "nowhere"}
        back = members.loads(json.dumps(data).encode())
        self.assertEqual((back.root, back.holder), (None, None))
        del data["root"], data["holder"]
        back = members.loads(json.dumps(data).encode())
        self.assertEqual((back.root, back.holder), (None, None))


class TestNoMemberRedirectsTheRequests(RootHolderCase):
    def forged(self, index: int) -> tuple[str, dict]:
        """A root of B's own making, with the mesh root's very name, and
        a notice naming B signed by it"""
        here = self.all[index].root
        key = etcdstate.key(here, "var/lib/keel/forged.key")
        made = etcdpki.root(key, self.mesh_hex)
        notice = rootholder.signed(key, self.mesh_hex, address(index),
                                   PKI_NOW + timedelta(minutes=1))
        return made, notice

    def test_a_forged_notice_is_refused_once_the_root_is_known(self):
        sync.pull(self.syncer(0))
        made, notice = self.forged(1)
        self.assertIsNone(rootholder.learn(self.all[0].root, self.mesh_hex,
                                           made, notice, True, PKI_NOW))
        self.assertEqual(etcdstate.holder(self.all[0].root), address(HOLDER))
        self.assertNotEqual(rootholder.anchor(self.all[0].root), made)

    def test_a_root_from_a_member_that_is_no_trust_root_is_not_taken(self):
        made, notice = self.forged(1)
        a = self.all[0].root
        # A no longer holds B as a trust root
        store = trust.load(a)
        for key, one in list(store.members.items()):
            if key == KEYS[1]:
                store.members[key] = type(one)(one.sign_key, False,
                                               one.admission)
        trust.save(a, store)
        found = members.Roster(bytes(range(16)), KEYS[1], "x" * 43 + "=",
                               address(1), (), (), None, made, notice)
        rootholder.taken_from(a, self.mesh_hex, [found], trust.load(a),
                              fetched=True, say=lambda line: None,
                              now=PKI_NOW)
        self.assertIsNone(rootholder.anchor(a))
        self.assertIsNone(etcdstate.holder(a))
        # an announcement never gives a root, a trust root's or not
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, made, notice,
                                           False, PKI_NOW))

    def test_the_leaf_must_come_under_the_known_root(self):
        sync.pull(self.syncer(0))
        a = self.all[0].root
        made, _ = self.forged(1)
        key = os.path.join(self.all[1].root, "var/lib/keel/forged.key")
        csr = etcdpki.request(etcdstate.key(a, dbtls.KEY))
        leaf = etcdpki.issue(etcdpki.DATABASE, key, made, csr,
                             etcdstate.database_name(address(0)),
                             (address(0), VIP))
        grant = etcdstate.Grant(leaf, (), made, None, None)
        self.assertIn("another root",
                      dbtls._checked(a, grant, address(0)) or "")

    def test_an_older_notice_or_one_of_another_mesh_is_not_taken(self):
        sync.pull(self.syncer(0))
        a = self.all[0].root
        key = os.path.join(self.all[HOLDER].root, etcdstate.ROOT_KEY)
        older = rootholder.signed(key, self.mesh_hex, address(1),
                                  PKI_NOW - timedelta(days=400))
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, None, older,
                                           True, PKI_NOW))
        other = rootholder.signed(key, "ff" * 16, address(1),
                                  PKI_NOW + timedelta(minutes=1))
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, None, other,
                                           True, PKI_NOW))
        self.assertEqual(etcdstate.holder(a), address(HOLDER))
        # a newer one, signed by the root, moves it
        newer = rootholder.signed(key, self.mesh_hex, address(1),
                                  PKI_NOW + timedelta(minutes=1))
        self.assertIn(address(1), rootholder.learn(a, self.mesh_hex, None,
                                                   newer, False, PKI_NOW))
        self.assertEqual(etcdstate.holder(a), address(1))

    def test_nobody_answers_the_pair_member_is_asked_and_refuses(self):
        self.down.add(address(HOLDER))
        with mock.patch.object(rootholder.memberlink, "fetch", self.fetch):
            with self.assertRaisesRegex(StateError, "does not hold"):
                self.leaf(0)


class TestTheEdges(RootHolderCase):
    def test_what_is_no_notice(self):
        good = sync.roster(self.syncer(HOLDER)).holder
        for change in ({"address": "fd00::0:1"}, {"time": "yesterday"},
                       {"signature": "*"}, {"mesh_id": "zz"},
                       {"signature": "A" * 300}, {"time": 5}):
            with self.subTest(change=change):
                self.assertIsNone(rootholder.notice({**good, **change}))
        self.assertIsNone(rootholder.notice([good]))
        self.assertIsNone(rootholder.certificate(5))

    def test_a_damaged_kept_notice_is_none(self):
        a = self.all[0].root
        etcdstate.write(a, rootholder.NOTICE, "{")
        self.assertIsNone(rootholder.kept(a))

    def test_a_holder_that_cannot_sign_offers_no_notice(self):
        c = self.all[HOLDER].root
        with mock.patch.object(rootholder, "signed",
                               side_effect=etcdpki.PkiError("no openssl")):
            cert, found = rootholder.offered(c, self.mesh_hex,
                                             address(HOLDER), PKI_NOW)
        self.assertIsNone(found)
        self.assertIsNotNone(cert)

    def test_what_is_no_root_of_the_mesh(self):
        self.assertFalse(rootholder.is_root_of("not pem", self.mesh_hex))
        root = etcdstate.read(self.all[HOLDER].root, etcdstate.ROOT_CERT)
        self.assertFalse(rootholder.is_root_of(root, "ff" * 16))
        self.assertTrue(rootholder.is_root_of(root, self.mesh_hex))

    def test_rosters_of_another_mesh_or_another_member_are_left_out(self):
        found = sync.roster(self.syncer(HOLDER))
        a = self.all[0].root
        import dataclasses
        other = dataclasses.replace(found, identity=b"\xff" * 16)
        rootholder.taken_from(a, self.mesh_hex, [other], trust.load(a),
                              True, lambda line: None, PKI_NOW)
        self.assertIsNone(etcdstate.holder(a))

        def liar(host, iface):
            return dataclasses.replace(self.fetch(host, iface),
                                       address="fd00:6b65:1::99")
        rootholder.asked(self.all[0].node, KEYS[0], self.mesh_hex,
                         lambda line: None, PKI_NOW, fetch=liar)
        self.assertIsNone(etcdstate.holder(a))

    def test_a_node_with_no_identity_learns_nothing_before_it_asks(self):
        from keel.mesh import identity
        here = self.member(0)
        held = os.path.join(here.root, identity.IDENTITY)
        os.rename(held, held + ".away")
        self.assertIsNone(dbtls._learned(here))
        os.rename(held + ".away", held)
        with mock.patch.object(rootholder, "asked",
                               side_effect=ValueError("damaged trust")):
            self.assertIsNone(dbtls._learned(here))
        self.assertIn("could not be learned", "\n".join(self.said[0]))


class TestTheNoticeTimeAndRegion(RootHolderCase):
    """The security review of keel#105: a notice dated far ahead would
    pin the holder's address for good; a region names 0051's region"""

    def key(self) -> str:
        return os.path.join(self.all[HOLDER].root, etcdstate.ROOT_KEY)

    def test_a_notice_more_than_five_minutes_ahead_is_refused(self):
        sync.pull(self.syncer(0))
        a = self.all[0].root
        ahead = rootholder.signed(self.key(), self.mesh_hex, address(1),
                                  PKI_NOW + timedelta(minutes=6))
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, None, ahead,
                                           False, PKI_NOW))
        self.assertEqual(etcdstate.holder(a), address(HOLDER))
        # once this node's clock is there, it is taken
        self.assertIsNotNone(rootholder.learn(
            a, self.mesh_hex, None, ahead, False,
            PKI_NOW + timedelta(minutes=2)))
        self.assertEqual(etcdstate.holder(a), address(1))
        within = rootholder.signed(self.key(), self.mesh_hex, address(0),
                                   PKI_NOW + timedelta(minutes=10))
        self.assertIsNotNone(rootholder.learn(
            a, self.mesh_hex, None, within, False,
            PKI_NOW + timedelta(minutes=6)))

    def test_the_region_is_signed_and_only_the_first_region_is_taken(self):
        sync.pull(self.syncer(0))
        a = self.all[0].root
        notice = sync.roster(self.syncer(HOLDER)).holder
        self.assertNotIn(rootholder.REGION, notice)
        named = rootholder.signed(self.key(), self.mesh_hex, address(1),
                                  PKI_NOW + timedelta(minutes=1), "eu")
        self.assertEqual(rootholder.notice(named), named)
        # another region's holder is not this node's, until the bundle
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, None, named,
                                           False, PKI_NOW))
        # the region is signed: taken off, the signature fails
        bare = {k: v for k, v in named.items() if k != rootholder.REGION}
        self.assertIsNone(rootholder.learn(a, self.mesh_hex, None, bare,
                                           False, PKI_NOW))
        self.assertEqual(etcdstate.holder(a), address(HOLDER))
        self.assertIsNone(rootholder.notice({**named, "region": "x" * 65}))
        self.assertIsNone(rootholder.notice({**named, "region": 3}))
