# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.sync: a full mesh before etcd (decision 0048, amended)

A real Node on a scratch root and real Ed25519 evidence
(tests/mesh_sync_helpers.py), the members' channel replaced by
functions: what a pull adds and how it is confirmed, that nothing
without evidence a trusted key signed is ever taken, tombstones, the
trust roots bound and vouched for, the announcement, the backoff, the
announcements applied in one window, and a node without an identity
taking none.
"""

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest import mock

from mesh_helpers import INVITER, JOINER, MESH, NOW, OTHER
from mesh_sync_helpers import (
    FOURTH,
    INVITER_ROOT,
    INVITER_SIGNER,
    SPLIT,
    Case,
    admitted,
    evidence,
    inviter_roster,
)
from mesh_wire import Armed, probes

from keel import exits
from keel.mesh import identity, signing, sync, trust
from keel.mesh.members import Roster
from keel.mesh.protocol import Peer
from keel.network import marker


class TestPull(Case):
    def test_a_member_the_inviter_knows_is_added_and_confirmed(self):
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        self.assertEqual(self.peers()[1], {
            "public_key": OTHER, "endpoint": "[2001:db8:3::30]:51820",
            "allowed_ips": ["fd00:6b65:1::7/128"]})
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(marker.last(self.root).outcome, marker.CONFIRMED)
        self.assertIn("confirming over the overlay…", self.err)
        self.assertIn(f"the overlay was tested: a WireGuard handshake from"
                      f" {OTHER}", self.said())

    def test_a_roster_s_crl_goes_to_etcd(self):
        from dataclasses import replace
        crl = ("-----BEGIN X509 CRL-----\nAAAA\n"
               "-----END X509 CRL-----\n")
        host = "fd00:6b65:1::1"
        self.net.rosters[host] = replace(self.net.rosters[host], crl=crl)
        with mock.patch("keel.mesh.etcdcare.crl_taken") as taken:
            sync.pull(self.syncer)
        self.assertEqual(taken.call_args[0][1], crl)

    def test_the_handshake_is_waited_for_and_asked_for(self):
        self.net.handshakes = {}

        def later(seconds):
            self.later(seconds)
            if len(self.slept) == 2:
                self.net.handshakes[OTHER] = int(self.clock().timestamp())
        self.syncer.sleep = later
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        self.assertEqual(self.net.touched, ["fd00:6b65:1::7"] * 2)

    def test_a_handshake_from_before_the_change_is_no_proof(self):
        self.net.handshakes = {OTHER: int(NOW.timestamp()) - 1}
        self.node.apply = SayingArmed()
        self.assertEqual(sync.pull(self.syncer), exits.NETWORK_NOT_CONFIRMED)
        self.assertTrue(marker.exists(self.root))
        self.assertIn("unless `keel network confirm`", self.said())
        self.assertIn("no member completed a WireGuard handshake",
                      self.err[-1])
        # within the window, retried every RETRY seconds
        self.assertLessEqual(sum(self.slept), 120)

    def test_a_member_that_never_answered_waits_an_hour(self):
        self.net.handshakes = {}
        sync.pull(self.syncer)
        # the spec is put back as the revert puts the overlay back
        self.assertEqual(len(self.peers()), 1)
        marker.clear(self.root)
        self.node.apply = Armed()
        self.clock.now = NOW + timedelta(minutes=30)
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertEqual(len(self.peers()), 1)
        self.assertIn(f"{OTHER} is tried again after", self.said())
        self.clock.now = NOW + timedelta(minutes=70)
        self.net.handshakes = {OTHER: int(self.clock().timestamp())}
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        self.assertEqual(len(self.peers()), 2)
        with open(os.path.join(self.root, sync.UNREACHED)) as fob:
            self.assertEqual(json.load(fob), {})

    def test_the_route_check_refuses(self):
        self.node.probes = lambda: probes("wg0")
        self.assertEqual(sync.pull(self.syncer), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("leaves through wg0", self.said())
        self.assertEqual(len(self.peers()), 1)

    def test_nothing_new(self):
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster()
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("no member this node does not know", self.err[-1])
        self.assertEqual(self.node.apply.documents, [])

    def test_no_member_answers(self):
        self.net.down.add("fd00:6b65:1::1")
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("did not answer", self.err[0])
        self.assertIn("no member answered", self.err[-1])

    def test_a_member_that_answers_as_another(self):
        self.net.rosters["fd00:6b65:1::1"] = Roster(
            MESH, FOURTH, INVITER_SIGNER, "fd00:6b65:1::1", ())
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("answered as another member", self.err[0])

    def test_from_one_member_only(self):
        self.assertEqual(sync.pull(self.syncer, ("fd00:6b65:1::1",)),
                         exits.OK)
        self.assertEqual(sync.pull(self.syncer, ("fd00:6b65:1::9",)),
                         exits.MESH_REFUSED)
        self.assertIn("not a peer of this node", self.err[-1])

    def test_no_mesh_and_no_peer(self):
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\n")
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("in no mesh", self.err[-1])
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                      "      address: fd00:6b65:1::3/64\n")
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("no peer yet", self.err[-1])

    def test_a_change_waiting_defers(self):
        marker.save(self.root, "")
        marker.write(self.root, marker.Pending("eth0", "x", 120))
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertIn("a network change waits", self.err[-1])

    def test_another_sync_running(self):
        with sync.sync_lock(self.root, False) as held:
            self.assertTrue(held)
            self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertIn("another keel mesh sync", self.err[-1])

    def test_the_change_does_not_come_up(self):
        def failing(doc, root, window):
            print("wg-quick up failed")
            return 16
        self.node.apply = failing
        self.assertEqual(sync.pull(self.syncer), exits.APPLY_FAILED)
        self.assertEqual(self.err[-2], "wg-quick up failed")
        self.assertIn("put back as it was", self.err[-1])
        self.assertEqual(len(self.peers()), 1)

    def test_a_spec_that_cannot_be_put_back_is_said(self):
        self.node.apply = Armed(code=16, arms=False)
        real = self.node.write
        calls = []

        def write(doc):
            calls.append(doc)
            if len(calls) > 1:
                raise sync.NodeError("read-only file system")
            real(doc)
        with mock.patch.object(self.node, "write", side_effect=write):
            self.assertEqual(sync.pull(self.syncer), exits.APPLY_FAILED)
        self.assertIn("read-only file system", self.said())

    def test_a_spec_that_cannot_take_them(self):
        with mock.patch.object(self.node, "write",
                               side_effect=sync.NodeError("full")):
            self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "full")

    def test_no_key_to_name_this_node(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")):
            self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "no key")


class TestEvidence(Case):
    """0048: only an admitted join adds a peer"""

    def taken(self, *entries, **changed) -> list:
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(*entries,
                                                            **changed)
        sync.pull(self.syncer)
        return [one["public_key"] for one in self.peers()[1:]]

    def test_an_entry_without_evidence_is_not_taken(self):
        self.assertEqual(self.taken(Peer(OTHER, None, "fd00:6b65:1::7")), [])
        self.assertIn("no member this node does not know", self.err[-1])

    def test_forged_or_mismatched_evidence_is_not_taken(self):
        found = admitted()
        for entry in (
                replace(found, admission=replace(found.admission,
                                                 address="fd00:6b65:1::8")),
                replace(found, address="fd00:6b65:1::8"),
                replace(found, admission=replace(found.admission,
                                                 signature="A" * 86 + "==")),
                admitted(mesh=SPLIT)):
            with self.subTest(entry=entry):
                self.assertEqual(self.taken(entry), [])

    def test_evidence_by_a_key_this_node_does_not_trust(self):
        stranger = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, stranger)
        signing.ensure(stranger)
        self.assertEqual(self.taken(admitted(root=stranger)), [])

    def test_a_chain_of_evidence(self):
        """OTHER, admitted by the inviter, admitted FOURTH"""
        other_root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other_root)
        of_other = admitted(sign_key=signing.ensure(other_root))
        of_fourth = admitted(FOURTH, address="fd00:6b65:1::9",
                             endpoint=None, root=other_root)
        self.net.handshakes[FOURTH] = int(NOW.timestamp())
        self.assertEqual(self.taken(of_fourth, of_other), [OTHER, FOURTH])

    def test_a_tombstone_keeps_a_member_out_here_and_is_kept(self):
        gone = trust.removal(INVITER_ROOT, MESH, OTHER, NOW)
        self.assertEqual(self.taken(admitted(), removed=(gone,)), [])
        self.assertTrue(trust.load(self.root).gone(OTHER))

    def unbound_root(self):
        store = trust.Store()
        trust.make_roots(store, (INVITER,))
        trust.save(self.root, store)

    def test_a_trust_root_is_bound_from_its_own_roster_alone(self):
        self.unbound_root()
        self.assertEqual(self.taken(admitted()), [OTHER])
        found = trust.load(self.root).members[INVITER]
        self.assertEqual(found.sign_key, INVITER_SIGNER)
        # and vouched for by no one
        self.assertIsNone(found.admission)
        self.assertIn("trust root fd00:6b65:1::1 signs with", self.said())

    def test_an_announcement_binds_no_root(self):
        """its source is the listener's word, not a roster this node
        fetched from the root's own address"""
        self.unbound_root()
        sync.announced(self.syncer, [("fd00:6b65:1::1",
                                      inviter_roster(admitted()))])
        self.assertIsNone(trust.load(self.root).members[INVITER].sign_key)
        self.assertEqual(len(self.peers()), 1)

    def test_a_damaged_trust_store(self):
        with open(os.path.join(self.root, trust.TRUST), "w") as fob:
            fob.write("x")
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertIn("damaged", self.err[-1])


class TestTombstones(Case):
    """0048: when a node is removed, the others drop it too"""

    def setUp(self):
        super().setUp()
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        marker.clear(self.root)
        self.node.apply = Armed()
        self.err.clear()
        # the inviter answers over the changed overlay
        self.net.handshakes[INVITER] = int(NOW.timestamp())

    def test_the_admitter_s_tombstone_drops_the_peer_in_one_window(self):
        gone = trust.removal(INVITER_ROOT, MESH, OTHER, NOW)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(removed=(gone,))
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        self.assertEqual([one["public_key"] for one in self.peers()],
                         [INVITER])
        self.assertEqual(len(self.node.apply.documents), 1)
        self.assertIn(f"member {OTHER} removed", self.said())
        self.assertIn(f"a WireGuard handshake from {INVITER}", self.said())
        self.assertTrue(trust.load(self.root).gone(OTHER))

    def test_a_tombstone_from_a_member_that_may_not_remove(self):
        stranger = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, stranger)
        signing.ensure(stranger)
        gone = trust.removal(stranger, MESH, OTHER, NOW)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(removed=(gone,))
        sync.pull(self.syncer)
        self.assertEqual(len(self.peers()), 2)
        self.assertFalse(trust.load(self.root).gone(OTHER))

    def test_the_last_peer_removed_is_confirmed_by_the_route_check(self):
        store = trust.load(self.root)
        trust.record_removal(store, trust.removal(self.root, MESH, OTHER,
                                                  NOW))
        trust.record_removal(store, trust.removal(self.root, MESH, INVITER,
                                                  NOW))
        trust.save(self.root, store)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster()
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        self.assertEqual(self.peers(), [])
        self.assertIn("removed the last peer", self.said())

    def test_peers_it_keeps_that_never_answer(self):
        self.net.handshakes = {}
        gone = trust.removal(INVITER_ROOT, MESH, OTHER, NOW)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(removed=(gone,))
        self.assertEqual(sync.pull(self.syncer), exits.NETWORK_NOT_CONFIRMED)
        # put back; the tombstone stays, and the next sync drops it again
        self.assertEqual(len(self.peers()), 2)
        self.assertTrue(trust.load(self.root).gone(OTHER))


class TestIdentity(Case):
    def test_a_node_without_one_takes_none_from_a_roster(self):
        os.remove(os.path.join(self.root, identity.IDENTITY))
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertIsNone(identity.read(self.root))
        self.assertIn("only a join, or keel mesh create --adopt",
                      self.err[-1])
        self.assertEqual(len(self.peers()), 1)

    def test_a_member_of_another_identity_gives_nothing(self):
        identity.replace(self.root, SPLIT)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(
            admitted(mesh=SPLIT), identity_of=MESH)
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertEqual(len(self.peers()), 1)
        self.assertIn("keel mesh sync --adopt fd00:6b65:1::1",
                      self.said())
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(identity_of=None)
        sync.pull(self.syncer)
        self.assertIn("is in mesh none", self.said())

    def test_a_damaged_identity(self):
        with open(os.path.join(self.root, identity.IDENTITY), "w") as fob:
            fob.write("x\n")
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)
        self.assertIn("does not hold a mesh identity", self.err[-1])


class TestAnnounced(Case):
    """What the members' service applies: every announcement pending,
    in one change"""

    def test_all_pending_in_one_window(self):
        self.net.handshakes[FOURTH] = int(NOW.timestamp())
        code = sync.announced(self.syncer, [
            ("fd00:6b65:1::1", inviter_roster(admitted())),
            ("fd00:6b65:1::1", inviter_roster(admitted(
                FOURTH, address="fd00:6b65:1::9", endpoint=None)))])
        self.assertEqual(code, exits.OK, self.err)
        self.assertEqual(len(self.node.apply.documents), 1)
        self.assertEqual(len(self.peers()), 3)
        self.assertIn("an announcement from fd00:6b65:1::1: 2 member(s)",
                      self.err)

    def test_no_key(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")):
            self.assertEqual(sync.announced(self.syncer, [
                ("fd00:6b65:1::1", inviter_roster())]), exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "no key")


class TestAnnounce(Case):
    def setUp(self):
        super().setUp()
        with open(self.node.path, "a") as fob:
            fob.write(f"      - public_key: {OTHER}\n"
                      "        allowed_ips: [fd00:6b65:1::7/128]\n"
                      f"      - public_key: {FOURTH}\n"
                      "        endpoint: '[2001:db8:4::40]:51820'\n"
                      "        allowed_ips: [fd00:6b65:1::9/128]\n")
        # FOURTH, admitted by this node
        self.fourth = evidence(FOURTH, "fd00:6b65:1::9",
                               "[2001:db8:4::40]:51820", root=self.root)
        store = trust.load(self.root)
        trust.recorded(store, self.fourth)
        trust.save(self.root, store)

    def test_every_other_member_is_told(self):
        self.net.down.add("fd00:6b65:1::7")
        sync.announce(self.syncer, FOURTH)
        [(host, roster)] = self.net.told
        self.assertEqual(host, "fd00:6b65:1::1")
        self.assertEqual(roster.public_key, JOINER)
        self.assertEqual(roster.identity, MESH)
        self.assertIn(Peer(FOURTH, "[2001:db8:4::40]:51820",
                           "fd00:6b65:1::9", self.fourth), roster.members)
        self.assertEqual(roster.sign_key, self.signer)
        self.assertIn("announced", self.err[-2])
        self.assertIn("fd00:6b65:1::7 did not take it", self.err[-1])

    def test_all_told(self):
        sync.announce(self.syncer, FOURTH)
        self.assertEqual(len(self.net.told), 2)
        self.assertEqual(self.err, [f"announced {FOURTH} to 2 of the 2 other"
                                    " member(s) over the overlay"])

    def test_a_node_whose_key_cannot_be_read_announces_nothing(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")):
            sync.announce(self.syncer, FOURTH)
        self.assertEqual(self.net.told, [])
        self.assertIn("no key", self.err[-1])


class TestEdges(Case):
    def test_member_of(self):
        self.assertEqual(sync.member_of(self.node, "fd00:6b65:1::1"),
                         INVITER)
        self.assertIsNone(sync.member_of(self.node, "fd00:6b65:1::2"))
        self.assertIsNone(sync.member_of(self.node, "not an address"))
        with open(self.node.path, "w") as fob:
            fob.write("version: [")
        self.assertIsNone(sync.member_of(self.node, "fd00:6b65:1::1"))
        self.assertEqual(sync.pull(self.syncer), exits.MESH_REFUSED)

    def test_a_backoff_file_keel_did_not_write(self):
        for text in ("[]", '{"x": "y"}', "nope"):
            with open(os.path.join(self.root, sync.UNREACHED), "w") as fob:
                fob.write(text)
            self.assertEqual(sync.unreached(self.root, NOW), {})

    def test_no_other_member_to_announce_to(self):
        sync.announce(self.syncer, INVITER)
        self.assertEqual((self.net.told, self.err), ([], []))

    def test_a_roster_this_node_cannot_give(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")):
            with self.assertRaises(sync.NodeError):
                sync.roster(self.syncer)
            with self.assertRaises(ValueError):
                sync.offered(self.syncer)
        os.remove(os.path.join(self.root, signing.KEY))
        with self.assertRaises(ValueError):
            sync.offered(self.syncer)

    def test_where(self):
        self.assertEqual(sync.where(self.node), ("wg0", "fd00:6b65:1::3"))
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\n")
        self.assertIsNone(sync.where(self.node))
        with open(self.node.path, "w") as fob:
            fob.write("version: [")
        self.assertIsNone(sync.where(self.node))


class SayingArmed(Armed):
    def __call__(self, doc, root, window):
        print(f"keel mesh: bring the overlay wg0 up; it reverts in {window}"
              " s unless `keel network confirm` is run from a new session")
        return super().__call__(doc, root, window)


class TestLock(unittest.TestCase):
    def test_waits_or_not(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        with sync.sync_lock(root, True) as held:
            self.assertTrue(held)
            with sync.sync_lock(root, False) as again:
                self.assertFalse(again)


if __name__ == "__main__":
    unittest.main()
