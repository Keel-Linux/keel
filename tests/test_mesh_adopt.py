# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.adopt: the identity and the trust roots, set by the operator

`keel mesh sync --adopt` repairs a split and gives a node of a mesh
built by hand its identity and roots; `keel mesh create --adopt` gives
such a mesh one identity; `keel mesh invite` never makes a second.
"""

import os
from unittest import mock

from mesh_helpers import INVITER, MESH, reserved
from mesh_sync_helpers import (
    FOURTH,
    INVITER_SIGNER,
    SPLIT,
    Case,
    admitted,
    inviter_roster,
)

from keel import exits
from keel.mesh import adopt, identity, signing, trust
from keel.mesh.members import Roster


class TestAdoptFrom(Case):
    """keel mesh sync --adopt ADDRESS"""

    def test_the_split_repaired(self):
        """web-2 made its own identity: it takes web-1's, trusts its
        peers as roots, then syncs"""
        identity.replace(self.root, SPLIT)
        os.remove(os.path.join(self.root, trust.TRUST))
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::1"),
                         exits.OK, self.err)
        self.assertEqual(identity.read(self.root), MESH)
        self.assertIn("this node now holds the mesh identity 00010203",
                      self.said())
        self.assertIn("(was 00000000", self.said())
        found = trust.load(self.root).members[INVITER]
        self.assertTrue(found.root)
        self.assertEqual(found.sign_key, INVITER_SIGNER)
        self.assertEqual(len(self.peers()), 2)

    def test_a_node_with_no_identity_yet(self):
        os.remove(os.path.join(self.root, identity.IDENTITY))
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::1"),
                         exits.OK, self.err)
        self.assertIn("(was none)", self.said())

    def test_refused(self):
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::9"),
                         exits.MESH_REFUSED)
        self.assertIn("not a peer of this node", self.err[-1])
        self.net.down.add("fd00:6b65:1::1")
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::1"),
                         exits.MESH_REFUSED)
        self.assertIn("did not answer", self.err[-1])
        self.net.down.clear()
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(
            identity_of=None)
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::1"),
                         exits.MESH_REFUSED)
        self.assertIn("holds no mesh identity", self.err[-1])
        self.assertEqual(identity.read(self.root), MESH)

    def test_no_repair_while_an_invite_carries_the_old_identity(self):
        reserved(self.root)
        identity.replace(self.root, SPLIT)
        self.assertEqual(adopt.adopt_from(self.syncer, "fd00:6b65:1::1"),
                         exits.MESH_REFUSED)
        self.assertIn("pending invite", self.err[-1])
        self.assertEqual(identity.read(self.root), SPLIT)

    def test_no_key_or_no_signing_key(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")):
            self.assertEqual(adopt.adopt_from(self.syncer,
                                              "fd00:6b65:1::1"),
                             exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "no key")
        with mock.patch("keel.mesh.adopt.signing.ensure",
                        side_effect=signing.SigningError("no openssl")):
            self.assertEqual(adopt.adopt_from(self.syncer,
                                              "fd00:6b65:1::1"),
                             exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "no openssl")


class TestIdentityFile(Case):
    def test_a_damaged_identity_is_replaced_by_the_members(self):
        with open(os.path.join(self.root, identity.IDENTITY), "w") as fob:
            fob.write("x\n")
        self.assertIsNone(identity.replace(self.root, MESH))
        self.assertEqual(identity.read(self.root), MESH)


class TestAdoptMesh(Case):
    """keel mesh create --adopt: one identity for a mesh built by hand"""

    def setUp(self):
        super().setUp()
        os.remove(os.path.join(self.root, identity.IDENTITY))
        os.remove(os.path.join(self.root, trust.TRUST))
        self.out = []
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(
            identity_of=None)

    def test_a_new_identity_when_no_member_has_one(self):
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.OK, self.err)
        made = identity.read(self.root)
        self.assertIsNotNone(made)
        self.assertIn(made.hex(), self.out[0])
        self.assertIn("keel mesh sync --adopt", self.out[1])
        found = trust.load(self.root).members[INVITER]
        # a root, its signing key bound once it answers with the identity
        self.assertTrue(found.root)
        self.assertIsNone(found.sign_key)

    def test_the_identity_a_member_has_and_its_root_bound(self):
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster(admitted())
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.OK)
        self.assertEqual(identity.read(self.root), MESH)
        found = trust.load(self.root).members[INVITER]
        self.assertEqual(found.sign_key, INVITER_SIGNER)
        # bound, and vouched for by no one
        self.assertIsNone(found.admission)

    def test_its_own_kept(self):
        identity.adopt(self.root, SPLIT)
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.OK)
        self.assertEqual(identity.read(self.root), SPLIT)

    def test_refused_on_a_split(self):
        identity.adopt(self.root, SPLIT)
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster()
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("keel mesh sync --adopt", self.err[-1])

    def test_refused_when_members_disagree(self):
        with open(self.node.path, "a") as fob:
            fob.write(f"      - public_key: {FOURTH}\n"
                      "        allowed_ips: [fd00:6b65:1::9/128]\n")
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster()
        self.net.rosters["fd00:6b65:1::9"] = Roster(
            SPLIT, FOURTH, INVITER_SIGNER, "fd00:6b65:1::9", ())
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIsNone(identity.read(self.root))

    def test_no_overlay(self):
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\n")
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("keel mesh create makes", self.err[-1])

    def test_a_damaged_trust_store(self):
        os.makedirs(os.path.dirname(os.path.join(self.root, trust.TRUST)),
                    exist_ok=True)
        with open(os.path.join(self.root, trust.TRUST), "w") as fob:
            fob.write("x")
        self.assertEqual(adopt.adopt_mesh(self.syncer, self.out.append),
                         exits.MESH_REFUSED)
        self.assertIn("damaged", self.err[-1])


class TestInviteIdentity(Case):
    """invite never makes a second identity for a mesh"""

    def setUp(self):
        super().setUp()
        self.net.rosters["fd00:6b65:1::1"] = inviter_roster()

    def test_its_own_when_the_members_agree(self):
        self.assertEqual(adopt.invite_identity(self.syncer), MESH)

    def test_a_node_with_no_peer_makes_one(self):
        os.remove(os.path.join(self.root, identity.IDENTITY))
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                      "      address: fd00:6b65:1::3/64\n")
        self.assertEqual(len(adopt.invite_identity(self.syncer)), 16)

    def test_refused_with_peers_and_no_identity_even_when_they_have_one(
            self):
        os.remove(os.path.join(self.root, identity.IDENTITY))
        with self.assertRaises(adopt.Refused) as raised:
            adopt.invite_identity(self.syncer)
        self.assertIn("keel mesh create --adopt", str(raised.exception))
        self.assertIsNone(identity.read(self.root))

    def test_refused_on_a_split(self):
        identity.replace(self.root, SPLIT)
        with self.assertRaises(adopt.Refused) as raised:
            adopt.invite_identity(self.syncer)
        self.assertIn("keel mesh sync --adopt fd00:6b65:1::1",
                      str(raised.exception))

    def test_members_that_cannot_be_asked_are_warned_about(self):
        self.net.down.add("fd00:6b65:1::1")
        self.assertEqual(adopt.invite_identity(self.syncer), MESH)
        self.assertIn("Warning", self.err[-1])

    def test_no_key(self):
        with mock.patch("keel.mesh.node.wgkeys.public",
                        return_value=(None, "no key")), \
                self.assertRaises(ValueError):
            adopt.invite_identity(self.syncer)
