# Copyright (c) 2026 KeelLinux maintainers
"""A new node's address reserved in etcd by its invite (keel#102)

Two members of one region invite at the same time and neither knows the
other's pending invite: the random draw keeps them apart, and with etcd
the compare-and-swap on the address's key catches the draws that meet.
The join is admitted only while the reservation names its invite.
"""

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest import mock

from mesh_helpers import (
    INVITE,
    INVITER,
    MESH,
    NOW,
    FakeNode,
    join_body,
    reserved,
    signature,
)
from vip_helpers import FakeKv

from keel.mesh import (
    addrreserve,
    commands,
    etcd,
    etcdstate,
    identity,
    invites,
    protocol,
)
from keel.mesh.admit import Admitter, reservation_problem
from keel.mesh.allocate import AllocationError
from keel.mesh.etcdstate import Cluster, Member
from keel.mesh.node import Node
from keel.mesh.token import Token, invite_id

MESH_HEX = MESH.hex()
OVERLAY_A = {"address": "fd00:6b65:1::1/64", "peers": [
    {"public_key": "x", "allowed_ips": ["fd00:6b65:1::2/128"]}]}
OVERLAY_B = {"address": "fd00:6b65:1::7/64", "peers": [
    {"public_key": "y", "allowed_ips": ["fd00:6b65:1::2/128"]}]}
TTL = 3600 + 180
# the invite's hour, its join's window, and a day for sync to tell every
# member of the new peer
CLAIM_TTL = TTL + 86400


def draft(own: str, secret: bytes) -> Token:
    return Token(
        public_key=INVITER, endpoints=("2001:db8:1::10",), port=51821,
        https_port=51820, fingerprint=bytes(32), address=own, assigned="",
        mesh_id=MESH, invite_id=invite_id(secret),
        expires=NOW + timedelta(hours=1), secret=secret, etcd="running",
        etcd_port=2379)


class Inviters(unittest.TestCase):
    """Two inviters of one region, each with its own pending invites,
    and one etcd"""

    def setUp(self):
        self.parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.parent)
        self.roots = []
        for name in ("a", "b"):
            root = os.path.join(self.parent, name)
            os.makedirs(root)
            identity.adopt(root, MESH)
            self.roots.append(root)
        self.kv = FakeKv()

    def claim(self, token: Token):
        return lambda address: addrreserve.reserve(
            self.kv, MESH_HEX, address, token.invite_id, INVITER, TTL)

    def invite(self, index: int, secret: bytes, with_etcd: bool = True):
        token = draft((OVERLAY_A, OVERLAY_B)[index]["address"], secret)
        return commands.invite(
            self.roots[index], NOW, token, (OVERLAY_A, OVERLAY_B)[index],
            ("tls key", "certificate"), (),
            self.claim(token) if with_etcd else None)[0]


class TestTwoConcurrentInviters(Inviters):
    def test_the_same_draw_is_caught_by_etcd_and_drawn_again(self):
        # both inviters draw ::3 first: neither knows the other's invite
        with mock.patch("keel.mesh.allocate.secrets.randbelow",
                        return_value=2):
            first = self.invite(0, bytes(32))
            second = self.invite(1, bytes(range(1, 33)))
        self.assertEqual(first.address, "fd00:6b65:1::3/64")
        self.assertEqual(second.address, "fd00:6b65:1::4/64")
        self.assertTrue(first.etcd_reserved and second.etcd_reserved)
        held = {key: json.loads(value[0]) for key, value in
                self.kv.kvs.items()}
        prefix = f"/keel/{MESH_HEX}/etcd/addresses/"
        self.assertEqual(held[f"{prefix}fd00:6b65:1::3"]["invite"],
                         first.invite_id)
        self.assertEqual(held[f"{prefix}fd00:6b65:1::4"]["invite"],
                         second.invite_id)
        # every reservation has a lease; the losing draw's was revoked
        self.assertTrue(all(value[2] for value in self.kv.kvs.values()))
        self.assertEqual(len(self.kv.leases), 2)

    def test_without_etcd_the_random_draw_alone_keeps_them_apart(self):
        found = {self.invite(index % 2, bytes([index]) * 32, False).address
                 for index in range(2)}
        self.assertEqual(len(found), 2)
        self.assertEqual(self.kv.calls, [])
        made = invites.listed(self.roots[0])[0]
        self.assertFalse(made.etcd_reserved)

    def test_draws_that_etcd_holds_every_time_refuse_the_invite(self):
        with mock.patch("keel.mesh.commands.addrreserve.reserve",
                        return_value=False):
            with self.assertRaises(AllocationError) as raised:
                self.invite(0, bytes(32))
        self.assertIn(f"{addrreserve.TRIES} addresses drawn in a row are"
                      " reserved in etcd", str(raised.exception))
        self.assertEqual(invites.listed(self.roots[0]), [])

    def test_etcd_not_answering_refuses_the_invite(self):
        self.kv.refuse = "grant"
        with self.assertRaises(AllocationError) as raised:
            self.invite(0, bytes(32))
        self.assertIn("etcd did not answer", str(raised.exception))
        self.assertEqual(invites.listed(self.roots[0]), [])


class TestTheReservation(unittest.TestCase):
    def setUp(self):
        self.kv = FakeKv()

    def test_the_key_and_its_lease(self):
        self.assertTrue(addrreserve.reserve(
            self.kv, MESH_HEX, "fd00:6b65:1::3/64", INVITE, INVITER, 0))
        key = f"/keel/{MESH_HEX}/etcd/addresses/fd00:6b65:1::3"
        value, _, lease = self.kv.kvs[key]
        self.assertEqual(json.loads(value), {
            "mesh_id": MESH_HEX, "address": "fd00:6b65:1::3",
            "invite": INVITE, "by": INVITER})
        # never a lease of 0 s
        self.assertEqual(self.kv.leases[lease], 1.0)

    def test_the_admission_check(self):
        address = "fd00:6b65:1::3/64"
        self.assertIn("is gone", addrreserve.problem(
            self.kv, MESH_HEX, address, INVITE))
        addrreserve.reserve(self.kv, MESH_HEX, address, INVITE, INVITER, 60)
        self.assertIsNone(addrreserve.problem(self.kv, MESH_HEX, address,
                                              INVITE))
        self.assertIn("reserved in etcd by another invite (" + INVITE,
                      addrreserve.problem(self.kv, MESH_HEX, address,
                                          "0" * 16))
        self.kv.put(addrreserve.key_of(MESH_HEX, address), b"{")
        self.assertIn("an unreadable reservation", addrreserve.problem(
            self.kv, MESH_HEX, address, INVITE))
        self.kv.refuse = "prefix"
        self.assertIn("etcd did not answer", addrreserve.problem(
            self.kv, MESH_HEX, address, INVITE))

    def test_one_address_s_key_is_not_another_s_prefix(self):
        addrreserve.reserve(self.kv, MESH_HEX, "fd00:6b65:1::30", "1" * 16,
                            INVITER, 60)
        self.assertIn("is gone", addrreserve.problem(
            self.kv, MESH_HEX, "fd00:6b65:1::3", INVITE))

    def test_formed_only_in_a_cluster_whose_spec_runs_etcd(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        self.assertFalse(addrreserve.formed(root, lambda: True))
        etcdstate.save_cluster(root, Cluster("new", (Member(
            INVITER, "fd00:6b65:1::1"),), MESH_HEX))
        self.assertTrue(addrreserve.formed(root, lambda: True))
        self.assertFalse(addrreserve.formed(root, lambda: False))
        with open(os.path.join(root, etcdstate.CLUSTER), "w") as fob:
            fob.write("{")
        self.assertFalse(addrreserve.formed(root, lambda: True))
        with self.assertRaises(ValueError):
            addrreserve.mesh_of(root)


class TestTheInviteCommand(unittest.TestCase):
    """keel mesh invite reserves in etcd only on a formed member"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        identity.adopt(self.root, MESH)
        self.kv = FakeKv()
        self.member = etcd.Etcd(Node(self.root, os.path.join(
            self.root, "absent.yaml")), lambda: NOW, lambda line: None,
            client=self.kv)

    def test_no_claim_before_etcd(self):
        self.assertIsNone(commands.address_claim(
            self.member, draft("fd00:6b65:1::1/64", bytes(32)), NOW))

    def test_a_formed_member_reserves_until_the_join_s_window_ends(self):
        etcdstate.save_cluster(self.root, Cluster("new", (Member(
            INVITER, "fd00:6b65:1::1"),), MESH_HEX))
        token = draft("fd00:6b65:1::1/64", bytes(32))
        with mock.patch("keel.mesh.commands.etcd.ready", return_value=True):
            claim = commands.address_claim(self.member, token, NOW)
        self.assertTrue(claim("fd00:6b65:1::9/64"))
        self.assertEqual(list(self.kv.leases.values()), [CLAIM_TTL])
        with mock.patch("keel.mesh.commands.etcd.ready",
                        side_effect=commands.NodeError("unreadable")):
            self.assertIsNone(commands.address_claim(self.member, token,
                                                     NOW))


class TestTheJoin(unittest.TestCase):
    """the inviter admits a join only while the reservation names it"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        made = reserved(self.root)
        invites.remove(self.root, made.invite_id)
        self.invite = invites.reserve(
            self.root, NOW, lambda others: replace(made, etcd_reserved=True))
        self.kv = FakeKv()
        self.node = FakeNode()
        self.node.root = self.root
        self.member = etcd.Etcd(self.node, lambda: NOW, lambda line: None,
                                client=self.kv)

    def test_the_flag_is_kept_in_the_invite_s_file(self):
        self.assertTrue(invites.read(self.root, INVITE).etcd_reserved)

    def test_an_invite_without_a_reservation_is_not_asked_about(self):
        self.kv.refuse = "all"
        self.assertIsNone(reservation_problem(
            self.member, replace(self.invite, etcd_reserved=False)))

    def test_its_own_reservation_admits_another_s_refuses(self):
        self.member.client = None
        with mock.patch.object(etcd.Etcd, "local", return_value=self.kv):
            self.assertIn("is gone", reservation_problem(self.member,
                                                         self.invite))
            addrreserve.reserve(self.kv, MESH_HEX, self.invite.address,
                                INVITE, INVITER, 60)
            self.assertIsNone(reservation_problem(self.member, self.invite))

    def test_no_certificate_for_etcd_refuses(self):
        self.member.client = None
        self.assertIn("etcd cannot be asked",
                      reservation_problem(self.member, self.invite))

    def test_the_listener_refuses_the_join_and_the_invite_stays(self):
        logged = []
        listener = Admitter(
            self.root, self.invite, INVITER, "fd00:6b65:1::1/64",
            self.node, lambda: NOW, logged.append,
            reservation=lambda invite: reservation_problem(self.member,
                                                           invite))
        body = join_body()
        found = listener.forward(protocol.JOIN, signature(protocol.JOIN,
                                                          body),
                                 body, "::", "2001:db8:2::20")
        self.assertEqual(found.status, 409)
        self.assertIn("is gone", json.loads(found.body)["error"])
        self.assertFalse(invites.read(self.root, INVITE).consumed)
        self.assertEqual(self.node.admitted, [])
        addrreserve.reserve(self.kv, MESH_HEX, self.invite.address, INVITE,
                            INVITER, 60)
        body = join_body()
        found = listener.forward(protocol.JOIN, signature(protocol.JOIN,
                                                          body),
                                 body, "::", "2001:db8:2::20")
        self.assertEqual(found.status, 200, found.body)


if __name__ == "__main__":
    unittest.main()
