# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.remove: a peer out of the spec, and a tombstone that keeps
every sync from adding it again"""

import os

from mesh_helpers import INVITER, MESH, NOW, OTHER
from mesh_sync_helpers import FOURTH, Case
from mesh_wire import Armed

from keel import exits
from keel.mesh import identity, remove, signing, sync, trust
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
