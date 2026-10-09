# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.remove: a peer out of the spec, and a tombstone that keeps
every sync from adding it again"""

import os
from unittest import mock

from mesh_helpers import INVITER, JOINER, MESH, NOW, OTHER
from mesh_sync_helpers import FOURTH, OTHER_SIGNER, Case
from mesh_wire import Armed

from keel import exits
from keel.mesh import identity, remove, signing, sync, trust
from keel.mesh.members import Roster
from keel.mesh.protocol import Peer
from keel.network import marker


class TestRemove(Case):
    def setUp(self):
        super().setUp()
        self.out = []
        # OTHER is a peer, admitted by the inviter
        self.assertEqual(sync.pull(self.syncer), exits.OK, self.err)
        marker.clear(self.root)
        self.node.apply = Armed()
        self.err.clear()
        # the inviter, kept, answers over the changed overlay
        self.net.handshakes[INVITER] = int(NOW.timestamp())

    def test_removed_confirmed_announced_and_never_synced_back(self):
        self.assertEqual(remove.remove(self.syncer, OTHER, self.out.append),
                         exits.OK, self.err)
        self.assertEqual([one["public_key"] for one in self.peers()],
                         [INVITER])
        self.assertIn("the other members drop it", self.out[0])
        self.assertEqual(marker.last(self.root).outcome, marker.CONFIRMED)
        self.assertIn(f"a WireGuard handshake from {INVITER}", self.said())
        store = trust.load(self.root)
        gone = store.removed[OTHER]
        self.assertEqual(gone.by, self.signer)
        self.assertTrue(signing.verified(gone.by, gone.message(),
                                         gone.signature))
        self.assertIsNone(store.find(OTHER))
        # the inviter is told: the roster it gets carries the tombstone
        [(host, told)] = self.net.told
        self.assertEqual((host, told.removed), ("fd00:6b65:1::1", (gone,)))
        # the inviter still names OTHER, with its evidence: not taken
        self.assertEqual(sync.pull(self.syncer), exits.OK)
        self.assertEqual(len(self.peers()), 1)

    def other_roster(self, *roots):
        self.net.rosters["fd00:6b65:1::7"] = Roster(
            MESH, OTHER, OTHER_SIGNER, "fd00:6b65:1::7",
            tuple(Peer(one, None, "fd00:6b65:1::9", root=True)
                  for one in roots))

    def test_a_root_held_one_way_is_not_removed(self):
        """the inviter is this node's root, and OTHER's, which does not
        hold this node as one: it would not take the tombstone (keel#99)"""
        self.other_roster(INVITER)
        self.assertEqual(remove.remove(self.syncer, INVITER, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("member fd00:6b65:1::7 holds", self.err[-1])
        self.assertIn("nothing was removed", self.err[-1])
        self.assertEqual(len(self.peers()), 2)
        self.assertFalse(trust.load(self.root).gone(INVITER))
        self.net.down.add("fd00:6b65:1::7")
        self.assertEqual(remove.remove(self.syncer, INVITER, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("1 peer(s) did not answer", self.err[-1])

    def test_a_root_held_both_ways_is_removed(self):
        self.net.handshakes[OTHER] = int(NOW.timestamp())
        self.other_roster(INVITER, JOINER)
        self.assertEqual(remove.remove(self.syncer, INVITER, self.out.append),
                         exits.OK, self.err)
        self.assertTrue(trust.load(self.root).gone(INVITER))

    def test_the_root_check_s_edges(self):
        store = trust.load(self.root)
        # a node this node knows nothing of, or admitted, needs no roster
        self.assertIsNone(remove.root_problem(self.syncer, store, FOURTH))
        with mock.patch.object(trust, "admitted_by", return_value=True):
            self.assertIsNone(remove.root_problem(self.syncer, store,
                                                  INVITER))
        with mock.patch.object(self.node, "public_key",
                               return_value=(None, "no key")):
            self.assertEqual(remove.root_problem(self.syncer, store,
                                                 INVITER), "no key")

    def test_by_its_overlay_address(self):
        self.assertEqual(remove.remove(self.syncer, "fd00:6b65:1::7",
                                       self.out.append), exits.OK)
        self.assertEqual(len(self.peers()), 1)

    def test_refused(self):
        for which in ("fd00:6b65:1::9", "not a peer"):
            self.assertEqual(remove.remove(self.syncer, which,
                                           self.out.append),
                             exits.MESH_REFUSED)
            self.assertIn("no peer of this node", self.err[-1])
        marker.save(self.root, "")
        marker.write(self.root, marker.Pending("eth0", "x", 120))
        self.assertEqual(remove.remove(self.syncer, OTHER, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("a network change waits", self.err[-1])
        marker.clear(self.root)
        store = trust.load(self.root)
        full = trust.removal(self.root, MESH, FOURTH, NOW)
        store.removed = {str(n): full
                         for n in range(trust.MAX_REMOVED_PER_SIGNER)}
        trust.save(self.root, store)
        self.assertEqual(remove.remove(self.syncer, OTHER, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("as many as it may", self.err[-1])
        os.remove(os.path.join(self.root, identity.IDENTITY))
        self.assertEqual(remove.remove(self.syncer, OTHER, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("no mesh identity", self.err[-1])
        self.assertEqual(len(self.peers()), 2)

    def test_not_confirmed_the_tombstone_is_kept(self):
        self.net.handshakes = {}
        self.assertEqual(remove.remove(self.syncer, OTHER, self.out.append),
                         exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("the tombstone is kept", self.err[-1])
        self.assertEqual(len(self.peers()), 2)
        self.assertTrue(trust.load(self.root).gone(OTHER))
        self.assertEqual(self.net.told, [])
