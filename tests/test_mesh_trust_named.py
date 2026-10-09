# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.trust: named roots, bounded to one hop (keel#99)

An operator root (made by `--adopt`, or the inviter of this node's own
invite) names its own operator roots; this node takes them as named
roots. A named root names nobody, has no root-only power, and is a
plain member again once its namer has a tombstone. Real Ed25519 keys,
as tests/test_mesh_trust.py has them.
"""

import json
import os
import shutil
import tempfile

from test_mesh_trust import MESH, NOW, WG_A, WG_B, WG_C, WG_D, Case

from keel.mesh import trust
from keel.mesh.protocol import Peer
from keel.mesh.signing import public


def marked(key: str, address: str) -> Peer:
    return Peer(key, None, address, root=True)


class Named(Case):
    def named_store(self) -> trust.Store:
        """A an operator root, B a root A named, bound to b's key"""
        store = self.store_trusting_a()
        trust.rooted(store, WG_D, (marked(WG_B, "fd00::b"),), WG_A)
        trust.bind_root(store, WG_B, self.sign["b"])
        return store


class TestNaming(Named):
    def test_an_operator_root_names_its_roots_once(self):
        store = self.store_trusting_a()
        said = []
        found = trust.rooted(store, WG_D, (
            Peer(WG_B, "[2001:db8::b]:51820", "fd00::b", root=True),
            Peer(WG_C, None, "fd00::c")), WG_A, said.append)
        self.assertEqual(found, (Peer(WG_B, "[2001:db8::b]:51820",
                                      "fd00::b", None, True),))
        self.assertEqual(store.members[WG_B],
                         trust.Member(None, True, named_by=WG_A))
        self.assertIsNone(store.find(WG_C))
        self.assertTrue(store.is_root(WG_B))
        self.assertFalse(store.is_operator_root(WG_B))
        self.assertEqual(store.operator_roots(), {WG_A})
        self.assertEqual(said, [f"member {WG_B} is a named trust root,"
                                f" named by {WG_A}"])
        # named again: no second line, nothing changes
        trust.rooted(store, WG_D, (marked(WG_B, "fd00::b"),), WG_A,
                     said.append)
        self.assertEqual(len(said), 1)

    def test_a_chain_is_refused_at_hop_two(self):
        """B, a named root, names C: nothing; nor a namer this node does
        not hold as a root"""
        store = self.named_store()
        said = []
        self.assertEqual(trust.rooted(store, WG_D, (
            marked(WG_C, "fd00::c"),), WG_B, said.append), ())
        self.assertEqual(trust.rooted(store, WG_D, (
            marked(WG_C, "fd00::c"),), WG_C, said.append), ())
        self.assertIsNone(store.find(WG_C))
        self.assertEqual(said, [])

    def test_this_node_its_namer_a_tombstone_and_a_known_member(self):
        store = self.store_trusting_a()
        trust.recorded(store, self.of_c)
        store.removed[WG_B] = trust.removal(self.a, MESH, WG_B, NOW)
        found = trust.rooted(store, WG_D, (
            marked(WG_D, "fd00::d"), marked(WG_A, "fd00::a"),
            marked(WG_B, "fd00::b"), marked(WG_C, "fd00::c")), WG_A)
        # a member known here keeps what it is: admitted, not a root
        self.assertEqual([one.public_key for one in found], [WG_C])
        self.assertFalse(store.members[WG_C].root)
        self.assertIsNone(store.find(WG_D))

    def test_the_operator_s_act_makes_a_named_root_an_operator_root(self):
        store = self.named_store()
        trust.make_roots(store, (WG_B,))
        self.assertTrue(store.is_operator_root(WG_B))

    def test_dropped_when_its_namer_has_a_tombstone(self):
        store = self.named_store()
        trust.record_removal(store, trust.removal(self.me, MESH, WG_A, NOW))
        found = store.members[WG_B]
        self.assertEqual((found.root, found.named_by), (False, None))
        # a plain member, its signing key kept: it still signs evidence
        self.assertEqual(found.sign_key, self.sign["b"])
        self.assertIn(self.sign["b"], store.signers(self.sign["me"]))


class TestNoRootOnlyPower(Named):
    """A named root has none of an operator root's powers"""

    def test_it_removes_no_other_node(self):
        store = self.named_store()
        # C, admitted by A, not by B
        trust.recorded(store, trust.admit(
            self.a, MESH, "2123456789abcdef", WG_C, self.sign["c"],
            "fd00::c", None, NOW))
        by_b = trust.removal(self.b, MESH, WG_C, NOW)
        self.assertFalse(trust.may_remove(store, self.sign["me"], by_b))
        by_a = trust.removal(self.a, MESH, WG_C, NOW)
        self.assertTrue(trust.may_remove(store, self.sign["me"], by_a))
        # its own leaving is still its own
        self.assertTrue(trust.may_remove(
            store, self.sign["me"], trust.removal(self.b, MESH, WG_B, NOW)))

    def test_it_is_removed_mesh_wide_by_nobody_as_a_root(self):
        store = self.named_store()
        self.assertFalse(trust.may_remove_everywhere(store, self.sign["me"],
                                                     WG_B))
        self.assertTrue(trust.may_remove_everywhere(store, self.sign["me"],
                                                    WG_A))

    def test_it_is_no_root_for_a_pair_record_the_ca_or_the_anchor(self):
        from keel.mesh import rootholder
        store = self.named_store()
        self.assertEqual(store.operator_roots(), {WG_A})
        self.assertFalse(rootholder.trusted_root(store, WG_B))
        self.assertTrue(rootholder.trusted_root(store, WG_A))


class TestEverywhere(Named):
    """trust.everywhere_problem: roots are not always both ways"""

    def roster(self, key, address, *roots):
        from keel.mesh.members import Roster
        return Roster(MESH, key, self.sign["c"], address,
                      tuple(marked(one, "fd00::9") for one in roots))

    def test_a_member_that_holds_the_root_and_not_this_node(self):
        store = self.store_trusting_a()
        problem = trust.everywhere_problem(
            store, self.sign["me"], WG_D, WG_A,
            [self.roster(WG_C, "fd00::c", WG_A)], 1)
        self.assertIn("member fd00::c holds", problem)
        self.assertIn("does not hold this node as one", problem)
        self.assertIn("nothing was removed", problem)

    def test_members_that_hold_both_or_neither(self):
        store = self.store_trusting_a()
        self.assertIsNone(trust.everywhere_problem(
            store, self.sign["me"], WG_D, WG_A,
            [self.roster(WG_C, "fd00::c", WG_A, WG_D),
             self.roster(WG_B, "fd00::b"),
             self.roster(WG_A, "fd00::a", WG_A)], 3))

    def test_a_peer_that_does_not_answer(self):
        store = self.store_trusting_a()
        problem = trust.everywhere_problem(store, self.sign["me"], WG_D,
                                           WG_A, [], 2)
        self.assertIn("2 peer(s) did not answer", problem)

    def test_a_node_this_node_admitted_needs_no_roster(self):
        store = trust.Store()
        trust.recorded(store, trust.admit(self.me, MESH, "0123456789abcdef",
                                          WG_B, self.sign["b"], "fd00::b",
                                          None, NOW))
        self.assertIsNone(trust.everywhere_problem(
            store, public(self.me), WG_D, WG_B, [], 3))
        self.assertIsNone(trust.everywhere_problem(
            store, public(self.me), WG_D, WG_C, [], 3))


class TestStoreNamed(Named):
    def test_round_trip_and_a_store_from_before(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        store = self.named_store()
        trust.save(root, store)
        self.assertEqual(trust.load(root), store)
        path = os.path.join(root, trust.TRUST)
        with open(path) as fob:
            data = json.load(fob)
        for one in data["members"].values():
            del one["named_by"]
        with open(path, "w") as fob:
            json.dump(data, fob)
        # a store from before keel#99: every root is the operator's
        self.assertTrue(trust.load(root).is_operator_root(WG_B))
        data["members"][WG_B]["named_by"] = "not a key"
        with open(path, "w") as fob:
            json.dump(data, fob)
        with self.assertRaises(ValueError):
            trust.load(root)


class TestCallSites(Named):
    """Where an operator root's power is used, a named root has none"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.store = self.named_store()
        trust.save(self.root, self.store)

    def test_no_revocation_at_the_ca_s_holder(self):
        from keel.mesh import etcdserve
        self.assertFalse(etcdserve.may_revoke(self.root, WG_B, WG_C))
        self.assertTrue(etcdserve.may_revoke(self.root, WG_A, WG_C))

    def test_no_vip_pair_record_signature(self):
        from types import SimpleNamespace

        from keel.mesh import signing, vipnode, vippair
        roots = vipnode.trust_roots(SimpleNamespace(root=self.root))
        self.assertEqual(roots, {WG_A})
        draft = vippair.Pair(MESH.hex(), "fd00::ffff:1", (WG_C, WG_D))
        by_b = vippair.Pair(draft.mesh_id, draft.vip, draft.members, (
            (WG_B, signing.sign(self.b, draft.message())),))

        def signer_of(key):
            found = self.store.find(key)
            return None if found is None else \
                self.store.members[found].sign_key
        self.assertIn("is not signed", vippair.problem(by_b, signer_of,
                                                       roots))
        # what the record would pass with B held as an operator root
        self.assertIsNone(vippair.problem(by_b, signer_of, roots | {WG_B}))

    def test_the_holder_asks_only_operator_roots_for_the_pair(self):
        from unittest import mock

        from keel.mesh import etcdserve, vippair
        pair = vippair.Pair(MESH.hex(), "fd00::ffff:1", (WG_C, WG_D))
        member = mock.Mock(root=self.root)
        message = mock.Mock(body={"pair": pair.record()})
        with mock.patch.object(vippair, "loads", return_value=pair), \
                mock.patch.object(etcdserve.etcd, "own_key",
                                  return_value=None), \
                mock.patch.object(vippair, "problem",
                                  return_value=None) as problem:
            etcdserve.pair_bound(member, message, pair.vip, WG_C)
        self.assertEqual(problem.call_args.args[2], {WG_A})


class TestEtcdAnchor(Named):
    """A node's first etcd grant sets its etcd anchor: only an operator
    root gives it, never a named root"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        trust.save(self.root, self.named_store())

    def taken(self, sender):
        from unittest import mock

        from keel.mesh import etcdserve
        member = mock.Mock(root=self.root)
        member.node.overlay.return_value = {"address": "fd00::d/64"}
        member.node.waiting.return_value = False
        message = mock.Mock(sender=sender, body={})

        class Took(Exception):
            pass
        with mock.patch.object(etcdserve.etcdmsg, "grant",
                               return_value=object()), \
                mock.patch.object(etcdserve.etcdmsg, "cluster",
                                  return_value=None), \
                mock.patch.object(etcdserve.etcdmsg, "ready",
                                  return_value=[]), \
                mock.patch.object(etcdserve.etcdstate, "credentials",
                                  return_value=False), \
                mock.patch.object(etcdserve.etcdstate, "take_grant",
                                  side_effect=Took):
            try:
                etcdserve.taken(member, message)
            except Took:
                return "taken"
            except etcdserve.Refusal as e:
                return e.reason
        return None

    def test_a_named_root_sets_no_anchor(self):
        self.assertIn("only from this node's inviter or an operator trust"
                      " root", self.taken(WG_B))
        self.assertEqual(self.taken(WG_A), "taken")


class TestMakeRoots(Named):
    def test_a_key_with_a_tombstone_is_never_made_a_root(self):
        store = self.store_trusting_a()
        store.removed[WG_C] = trust.removal(self.a, MESH, WG_C, NOW)
        trust.make_roots(store, (WG_C, WG_B))
        self.assertIsNone(store.find(WG_C))
        self.assertTrue(store.is_operator_root(WG_B))
