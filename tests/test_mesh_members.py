# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.members: the roster members send each other, and the peers
a node takes from it, pure"""

import json
import unittest

from mesh_helpers import INVITER, JOINER, OTHER

from keel.mesh import members
from keel.mesh.protocol import Admission, Peer, ProtocolError, Removal

DOC = {"version": 1, "network": {"overlay": {"wireguard": {
    "address": "fd00:6b65:1::3/64",
    "peers": [{"public_key": INVITER, "endpoint": "[2001:db8:1::10]:51821",
               "allowed_ips": ["fd00:6b65:1::1/128"]}]}}}}


FOURTH = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
EVIDENCE = Admission(
    mesh_id=bytes(range(16)).hex(), invite_id="", public_key=OTHER,
    sign_key=FOURTH, address="fd00:6b65:1::7",
    endpoint="[2001:db8:3::30]:51820", time=5, by=FOURTH,
    signature="A" * 86 + "==")
GONE = Removal(bytes(range(16)).hex(), JOINER, 5, FOURTH, "A" * 86 + "==")


def roster(**changed) -> members.Roster:
    values = dict(identity=bytes(range(16)), public_key=INVITER,
                  sign_key=FOURTH, address="fd00:6b65:1::1",
                  members=(Peer(OTHER, "[2001:db8:3::30]:51820",
                                "fd00:6b65:1::7", EVIDENCE),
                           Peer(JOINER, None, "fd00:6b65:1::3")),
                  removed=(GONE,))
    values.update(changed)
    return members.Roster(**values)


class TestRoster(unittest.TestCase):
    def test_round_trip(self):
        for one in (roster(), roster(identity=None, members=(),
                                     removed=())):
            with self.subTest(one=one):
                self.assertEqual(members.loads(members.dumps(one)), one)

    def test_the_wire_form(self):
        crl = ("-----BEGIN X509 CRL-----\nAAAA\n"
               "-----END X509 CRL-----\n")
        with_crl = members.Roster(None, roster().public_key,
                                  roster().sign_key, roster().address, (),
                                  crl=crl)
        self.assertEqual(members.loads(members.dumps(with_crl)).crl, crl)
        unreadable = json.loads(members.dumps(with_crl))
        unreadable["crl"] = "x"
        self.assertIsNone(members.loads(json.dumps(unreadable).encode()).crl)
        data = json.loads(members.dumps(roster()))
        self.assertEqual(data["identity"], bytes(range(16)).hex())
        self.assertEqual(data["members"][0]["address"], "fd00:6b65:1::7")

    def test_a_trust_root_is_marked_and_an_old_roster_has_none(self):
        """keel#99: a member the sender holds as a trust root says so; a
        roster of a keel before it has no mark, and names no root"""
        marked = roster(members=(Peer(OTHER, None, "fd00:6b65:1::7",
                                      root=True),))
        self.assertTrue(members.loads(members.dumps(marked)).members[0].root)
        data = json.loads(members.dumps(marked))
        del data["members"][0]["root"]
        self.assertFalse(members.loads(
            json.dumps(data).encode()).members[0].root)
        data["members"][0]["root"] = "yes"
        self.assertFalse(members.loads(
            json.dumps(data).encode()).members[0].root)

    def test_malformed(self):
        good = json.loads(members.dumps(roster()))
        for name, value in (("identity", "zz"), ("identity", "00"),
                            ("identity", 5), ("public_key", "x"),
                            ("sign_key", "x"), ("removed", [{}]),
                            ("removed", {}),
                            ("address", "fd00::1/64"), ("members", {}),
                            ("members", [{"public_key": OTHER}]),
                            ("members", [5])):
            with self.subTest(name=name, value=value), \
                    self.assertRaises(ProtocolError):
                members.loads(json.dumps({**good, name: value}).encode())
        with self.assertRaises(ProtocolError):
            members.loads(b"[]")
        with self.assertRaises(ProtocolError):
            members.loads(b"{" * 100)

    def test_too_many_members_or_tombstones(self):
        many = tuple(Peer(OTHER, None, f"fd00:6b65:1::{n:x}")
                     for n in range(members.MAX_MEMBERS + 1))
        with self.assertRaises(ProtocolError):
            members.loads(members.dumps(roster(members=many)))
        with self.assertRaises(ProtocolError):
            members.loads(members.dumps(roster(
                removed=(GONE,) * (members.MAX_REMOVED + 1))))


class TestWithMembers(unittest.TestCase):
    def test_new_members_become_peers(self):
        after, added = members.with_members(
            DOC, (Peer(OTHER, "[2001:db8:3::30]:51820", "fd00:6b65:1::7"),
                  Peer(FOURTH, None, "fd00:6b65:1::9")), JOINER)
        self.assertEqual([one.public_key for one in added], [OTHER, FOURTH])
        peers = after["network"]["overlay"]["wireguard"]["peers"]
        self.assertEqual(peers[1:], [
            {"public_key": OTHER, "endpoint": "[2001:db8:3::30]:51820",
             "allowed_ips": ["fd00:6b65:1::7/128"]},
            {"public_key": FOURTH, "allowed_ips": ["fd00:6b65:1::9/128"]}])
        self.assertEqual(len(DOC["network"]["overlay"]["wireguard"]["peers"]),
                         1, "the document read is not changed")

    def test_what_is_never_taken(self):
        refused = (Peer(JOINER, None, "fd00:6b65:1::8"),     # its own key
                   Peer(INVITER, None, "fd00:6b65:1::9"),    # a known key
                   Peer(OTHER, None, "fd00:6b65:1::1"),      # a taken address
                   Peer(OTHER, None, "fd00:6b65:1::3"),      # its own address
                   Peer(OTHER, None, "fd00:9999::1"))        # another prefix
        after, added = members.with_members(DOC, refused, JOINER)
        self.assertEqual(added, ())
        self.assertIs(after, DOC)

    def test_one_key_or_one_address_once(self):
        _, added = members.with_members(
            DOC, (Peer(OTHER, None, "fd00:6b65:1::7"),
                  Peer(OTHER, None, "fd00:6b65:1::8"),
                  Peer(FOURTH, None, "fd00:6b65:1::7")), JOINER)
        self.assertEqual(added, (Peer(OTHER, None, "fd00:6b65:1::7"),))

    def test_a_peer_routed_a_whole_prefix_takes_it(self):
        doc = {"network": {"overlay": {"wireguard": {
            "address": "fd00:6b65:1::3/64", "peers": [
                {"public_key": INVITER,
                 "allowed_ips": ["fd00:6b65:1::/112"]}]}}}}
        _, added = members.with_members(
            doc, (Peer(OTHER, None, "fd00:6b65:1::7"),), JOINER)
        self.assertEqual(added, ())

    def test_no_overlay_takes_nothing(self):
        after, added = members.with_members(
            {"version": 1}, (Peer(OTHER, None, "fd00:6b65:1::7"),), JOINER)
        self.assertEqual((after, added), ({"version": 1}, ()))


if __name__ == "__main__":
    unittest.main()
