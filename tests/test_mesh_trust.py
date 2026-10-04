# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.trust: admission evidence, chains of it, roots, tombstones

With real Ed25519 keys (openssl) in scratch roots: A admits B, B
admits C; a node that trusts A takes B, and C through B, and nothing
whose evidence is forged, for another key, mesh or address, by a key it
does not trust, or for a key with a tombstone.
"""

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from keel.mesh import signing, trust
from keel.mesh.protocol import Peer

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
MESH = bytes(range(16))
WG_A = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
WG_B = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
WG_C = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
WG_D = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def node() -> str:
    root = tempfile.mkdtemp()
    signing.ensure(root)
    return root


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a, cls.b, cls.c, cls.me = node(), node(), node(), node()
        cls.sign = {name: signing.public(getattr(cls, name))
                    for name in ("a", "b", "c", "me")}
        cls.of_b = trust.admit(cls.a, MESH, "0123456789abcdef", WG_B,
                               cls.sign["b"], "fd00::b",
                               "[2001:db8::b]:51820", NOW)
        cls.of_c = trust.admit(cls.b, MESH, "1123456789abcdef", WG_C,
                               cls.sign["c"], "fd00::c", None, NOW)

    @classmethod
    def tearDownClass(cls):
        for root in (cls.a, cls.b, cls.c, cls.me):
            shutil.rmtree(root)

    def store_trusting_a(self) -> trust.Store:
        return trust.Store({WG_A: trust.Member(self.sign["a"], True)})

    def entry(self, found, **changed) -> Peer:
        values = dict(public_key=found.public_key, endpoint=found.endpoint,
                      address=found.address, admission=found)
        values.update(changed)
        return Peer(**values)


class TestEvidence(Case):
    def test_signed_by_the_admitting_member(self):
        self.assertEqual(self.of_b.by, self.sign["a"])
        self.assertTrue(signing.verified(self.of_b.by, self.of_b.message(),
                                         self.of_b.signature))

    def test_a_chain_is_followed_whatever_the_order(self):
        store = self.store_trusting_a()
        found = trust.accepted(store, self.sign["me"], MESH, (
            self.entry(self.of_c), self.entry(self.of_b)))
        self.assertEqual({one.public_key for one in found}, {WG_B, WG_C})
        self.assertEqual(store.members[WG_C].sign_key, self.sign["c"])
        self.assertEqual(store.evidence(WG_B), self.of_b)
        # the first evidence is kept
        later = trust.admit(self.a, MESH, "2123456789abcdef", WG_B,
                            self.sign["b"], "fd00::b", None, NOW)
        trust.accepted(store, self.sign["me"], MESH, (self.entry(later),))
        self.assertEqual(store.evidence(WG_B), self.of_b)
        self.assertIsNone(trust.Store().evidence(WG_B))

    def test_what_is_left_out(self):
        forged = replace(self.of_b, address="fd00::99")
        resigned = replace(self.of_b, signature=self.of_c.signature)
        cases = (
            self.entry(self.of_b, admission=None),
            self.entry(self.of_b, public_key=WG_D),
            self.entry(self.of_b, address="fd00::99"),
            self.entry(forged),
            self.entry(resigned),
            self.entry(replace(self.of_b, mesh_id=bytes(16).hex())),
            self.entry(self.of_c))     # by B, whom nothing trusts here
        for one in cases:
            with self.subTest(one=one):
                store = self.store_trusting_a()
                self.assertEqual(trust.accepted(store, self.sign["me"],
                                                MESH, (one,)), ())
                self.assertIsNone(store.find(WG_B))

    def test_a_tombstone_keeps_a_key_out(self):
        store = self.store_trusting_a()
        gone = trust.removal(self.a, MESH, WG_B, NOW)
        self.assertEqual(trust.removals(store, self.sign["me"], MESH,
                                        (gone,)), (WG_B,))
        self.assertEqual(trust.accepted(store, self.sign["me"], MESH,
                                        (self.entry(self.of_b),)), ())

    def test_evidence_without_an_invite_is_no_admission(self):
        store = self.store_trusting_a()
        vouched = trust.admit(self.a, MESH, "", WG_B, self.sign["b"],
                              "fd00::b", None, NOW)
        self.assertEqual(trust.accepted(store, self.sign["me"], MESH,
                                        (self.entry(vouched),)), ())

    def chain(self) -> trust.Store:
        """A root, B admitted by A, C admitted by B, all known"""
        store = self.store_trusting_a()
        trust.accepted(store, self.sign["me"], MESH, (
            self.entry(self.of_b), self.entry(self.of_c)))
        return store

    def test_who_may_remove_a_node(self):
        """its admitter, a root, the node itself, or this node; no other
        member, trusted or not"""
        for remover, key, taken in (
                ("b", WG_C, True),     # B admitted C
                ("a", WG_C, True),     # A is a root
                ("c", WG_C, True),     # C leaves
                ("me", WG_C, True),    # this node
                ("c", WG_B, False),    # C did not admit B
                ("b", WG_D, False)):   # nobody knows D's admitter
            with self.subTest(remover=remover, key=key):
                store = self.chain()
                found = trust.removals(store, self.sign["me"], MESH, (
                    trust.removal(getattr(self, remover), MESH, key, NOW),))
                self.assertEqual(found, (key,) if taken else ())
        store = self.store_trusting_a()
        # a root removes a node this node never knew
        self.assertEqual(trust.removals(store, self.sign["me"], MESH, (
            trust.removal(self.a, MESH, WG_D, NOW),)), (WG_D,))

    def test_tombstones_that_are_not_taken(self):
        store = self.store_trusting_a()
        good = trust.removal(self.a, MESH, WG_B, NOW)
        for one in (replace(good, signature=self.of_b.signature),
                    replace(good, mesh_id=bytes(16).hex())):
            self.assertEqual(trust.removals(store, self.sign["me"], MESH,
                                            (one,)), ())
        self.assertEqual(trust.removals(store, self.sign["me"], MESH,
                                        (good, good)), (WG_B,))

    def test_the_caps(self):
        good = trust.removal(self.a, MESH, WG_C, NOW)
        full = self.store_trusting_a()
        full.removed = {str(n): replace(good, by=f"x{n}")
                        for n in range(trust.MAX_REMOVED)}
        self.assertEqual(trust.removals(full, self.sign["me"], MESH,
                                        (good,)), ())
        per_signer = self.store_trusting_a()
        per_signer.removed = {
            str(n): good for n in range(trust.MAX_REMOVED_PER_SIGNER)}
        self.assertFalse(trust.room_for(per_signer, self.sign["a"]))
        self.assertTrue(trust.room_for(per_signer, self.sign["b"]))
        self.assertEqual(trust.removals(per_signer, self.sign["me"], MESH,
                                        (good,)), ())

    def test_a_removed_member_is_trusted_no_more(self):
        store = self.store_trusting_a()
        store.members[WG_B] = trust.Member(self.sign["b"])
        trust.removals(store, self.sign["me"], MESH,
                       (trust.removal(self.a, MESH, WG_B, NOW),))
        self.assertNotIn(self.sign["b"], store.signers(self.sign["me"]))


class TestKnownMembers(Case):
    def test_a_root_without_a_key_takes_the_one_its_evidence_names(self):
        store = self.store_trusting_a()
        trust.make_roots(store, (WG_B,))
        found = trust.accepted(store, self.sign["me"], MESH, (
            self.entry(self.of_c), self.entry(self.of_b)))
        self.assertEqual(len(found), 2)
        self.assertEqual(store.members[WG_B].sign_key, self.sign["b"])
        self.assertEqual(store.members[WG_B].admission, self.of_b)

    def test_evidence_naming_another_key_trusts_it_not(self):
        store = self.store_trusting_a()
        store.members[WG_B] = trust.Member(self.sign["me"])
        found = trust.accepted(store, self.sign["me"], MESH, (
            self.entry(self.of_c), self.entry(self.of_b)))
        # B is evidenced, but C, signed by the key B was not known by,
        # is not taken
        self.assertEqual([one.public_key for one in found], [WG_B])
        self.assertEqual(store.members[WG_B].sign_key, self.sign["me"])
        self.assertIsNone(store.members[WG_B].admission)


class TestRoots(Case):
    def test_a_root_is_bound_to_the_key_it_gives_once(self):
        store = trust.Store()
        trust.make_roots(store, (WG_A,))
        self.assertTrue(trust.bind_root(store, WG_A, self.sign["a"]))
        self.assertFalse(trust.bind_root(store, WG_A, self.sign["b"]))
        self.assertEqual(store.members[WG_A].sign_key, self.sign["a"])
        self.assertFalse(trust.bind_root(store, WG_B, self.sign["b"]))

    def test_a_known_member_made_a_root(self):
        store = trust.Store({WG_B: trust.Member(self.sign["b"])})
        trust.make_roots(store, (WG_B,))
        self.assertTrue(store.members[WG_B].root)
        self.assertFalse(trust.bind_root(store, WG_B, self.sign["c"]))


class TestStore(Case):
    def test_round_trip(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        self.assertEqual(trust.load(root), trust.Store())
        store = self.store_trusting_a()
        trust.accepted(store, self.sign["me"], MESH, (self.entry(self.of_b),))
        trust.removals(store, self.sign["me"], MESH,
                       (trust.removal(self.a, MESH, WG_C, NOW),))
        trust.save(root, store)
        self.assertEqual(trust.load(root), store)
        self.assertEqual(os.stat(os.path.join(root, trust.TRUST)).st_mode
                         & 0o777, 0o600)

    def test_damaged(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, "var/lib/keel/mesh"))
        for text in ("x", "[]", json.dumps({"members": {"k": {}},
                                            "removed": {}})):
            with open(os.path.join(root, trust.TRUST), "w") as fob:
                fob.write(text)
            with self.assertRaises(ValueError) as raised:
                trust.load(root)
            self.assertIn("damaged", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
