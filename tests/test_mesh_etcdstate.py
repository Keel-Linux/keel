# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdstate: a member's etcd credentials and cluster, kept
under /var/lib/keel/etcd, with the real openssl"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from keel.mesh import etcdpki, etcdstate
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, Grant, Member, StateError

MESH = "ab" * 16
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


class Case(unittest.TestCase):
    def setUp(self):
        self.root = self.scratch()

    def scratch(self) -> str:
        found = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, found)
        return found

    def mode(self, relative: str) -> int:
        return stat.S_IMODE(os.stat(os.path.join(self.root,
                                                 relative)).st_mode)


class TestTheFirstNode(Case):
    def test_the_root_and_its_own_intermediate(self):
        self.assertFalse(etcdstate.credentials(self.root))
        self.assertIsNone(etcdstate.root_fingerprint(self.root))
        self.assertTrue(etcdstate.make_root(self.root, MESH))
        self.assertTrue(etcdstate.credentials(self.root))
        self.assertTrue(etcdstate.holds_root(self.root))
        # made once: a second call keeps what is there
        before = etcdstate.read(self.root, etcdstate.ROOT_CERT)
        self.assertFalse(etcdstate.make_root(self.root, MESH))
        self.assertEqual(etcdstate.read(self.root, etcdstate.ROOT_CERT),
                         before)
        for one in (etcdstate.ROOT_KEY, etcdstate.CA_KEY,
                    etcdstate.ROOT_CERT, etcdstate.CA_CERT):
            self.assertEqual(self.mode(one), 0o600)
        self.assertEqual(self.mode(etcdstate.DIR), 0o700)
        self.assertEqual(etcdstate.root_fingerprint(self.root),
                         etcdpki.fingerprint(before))

    def test_a_node_with_a_grant_makes_no_root(self):
        other = self.scratch()
        etcdstate.make_root(other, MESH)
        grant = etcdstate.grant_for(other, etcdstate.ca_request(self.root),
                                    "keel-b")
        etcdstate.take_grant(self.root, grant)
        self.assertFalse(etcdstate.make_root(self.root, MESH))
        self.assertFalse(etcdstate.holds_root(self.root))


class TestGrants(Case):
    def setUp(self):
        super().setUp()
        self.first = self.scratch()
        etcdstate.make_root(self.first, MESH)

    def test_issued_by_an_intermediate_two_deep(self):
        second = self.scratch()
        etcdstate.take_grant(second, etcdstate.grant_for(
            self.first, etcdstate.ca_request(second), "keel-b"))
        third = self.root
        grant = etcdstate.grant_for(second, etcdstate.ca_request(third),
                                    "keel-c")
        self.assertEqual(len(grant.chain), 2)
        etcdstate.take_grant(third, grant)
        self.assertEqual(etcdstate.root_fingerprint(third),
                         etcdstate.root_fingerprint(self.first))
        self.assertTrue(etcdstate.leaves(third, "fd00::3", NOW))
        member = etcdstate.read(third, etcdstate.MEMBER_CERT)
        chain = etcdpki.blocks(member)
        self.assertEqual(len(chain), 4)  # the leaf, its CA, two issuers
        self.assertTrue(etcdpki.verified(
            chain[0], chain[1:], etcdstate.read(third, etcdstate.ROOT_CERT)))
        self.assertEqual(etcdpki.addresses(chain[0]), ("fd00::3", "::1"))
        client = etcdpki.blocks(etcdstate.read(third, etcdstate.CLIENT_CERT))
        self.assertTrue(etcdpki.verified(
            client[0], client[1:], etcdstate.read(third, etcdstate.ROOT_CERT)))

    def test_a_grant_for_another_key_is_refused(self):
        stranger = self.scratch()
        grant = etcdstate.grant_for(self.first,
                                    etcdstate.ca_request(stranger), "x")
        etcdstate.ca_request(self.root)
        with self.assertRaisesRegex(StateError, "another key"):
            etcdstate.take_grant(self.root, grant)
        self.assertFalse(etcdstate.credentials(self.root))

    def test_a_grant_that_does_not_chain_is_refused(self):
        grant = etcdstate.grant_for(self.first,
                                    etcdstate.ca_request(self.root), "x")
        other = self.scratch()
        etcdstate.make_root(other, MESH)
        forged = Grant(grant.certificate, grant.chain,
                       etcdstate.read(other, etcdstate.ROOT_CERT))
        with self.assertRaisesRegex(StateError, "does not chain"):
            etcdstate.take_grant(self.root, forged)

    def test_a_grant_under_another_root_than_the_one_held(self):
        etcdstate.take_grant(self.root, etcdstate.grant_for(
            self.first, etcdstate.ca_request(self.root), "x"))
        other = self.scratch()
        etcdstate.make_root(other, MESH)
        with self.assertRaisesRegex(StateError, "another root"):
            etcdstate.take_grant(self.root, etcdstate.grant_for(
                other, etcdstate.ca_request(self.root), "x"))

    def test_no_intermediate_no_grant(self):
        with self.assertRaisesRegex(StateError, "holds no etcd CA"):
            etcdstate.grant_for(self.root, etcdstate.ca_request(
                self.scratch()), "x")

    def test_a_request_once_made_is_kept(self):
        first = etcdstate.ca_request(self.root)
        self.assertEqual(etcdpki.request_key(first),
                         etcdpki.request_key(etcdstate.ca_request(self.root)))


class TestLeaves(Case):
    def setUp(self):
        super().setUp()
        etcdstate.make_root(self.root, MESH)

    def test_issued_then_kept_then_renewed(self):
        self.assertTrue(etcdstate.leaves(self.root, "fd00::1", NOW))
        self.assertFalse(etcdstate.leaves(self.root, "fd00::1", NOW))
        self.assertEqual(self.mode(etcdstate.MEMBER_KEY), 0o600)
        # a third of its life left: renewed with the same key
        later = NOW + timedelta(days=etcdpki.LEAF_DAYS * 2 // 3 + 2)
        self.assertTrue(etcdstate.leaves(self.root, "fd00::1", later))

    def test_another_address_reissues(self):
        etcdstate.leaves(self.root, "fd00::1", NOW)
        self.assertTrue(etcdstate.leaves(self.root, "fd00::9", NOW))
        cert = etcdpki.blocks(etcdstate.read(self.root,
                                             etcdstate.MEMBER_CERT))[0]
        self.assertEqual(etcdpki.addresses(cert)[0], "fd00::9")

    def test_without_credentials(self):
        with self.assertRaises(StateError):
            etcdstate.leaves(self.scratch(), "fd00::1", NOW)

    def test_expiry_of_a_missing_leaf(self):
        self.assertIsNone(etcdstate.expires(self.root))
        etcdstate.leaves(self.root, "fd00::1", NOW)
        self.assertIsNotNone(etcdstate.expires(self.root))


class TestCluster(Case):
    def test_names_from_addresses(self):
        self.assertEqual(etcdstate.name("fd2a:9c41:7e03::3"),
                         "keel-fd2a-9c41-7e03--3")
        self.assertEqual(etcdstate.peer_url("fd00::3"),
                         "https://[fd00::3]:2380")
        self.assertEqual(etcdstate.client_url("fd00::3"),
                         "https://[fd00::3]:2379")

    def test_saved_and_read(self):
        self.assertIsNone(etcdstate.cluster(self.root))
        found = Cluster("new", (Member("k1", "fd00::1"),
                                Member("k2", "fd00::2")), MESH)
        etcdstate.save_cluster(self.root, found)
        self.assertEqual(etcdstate.cluster(self.root), found)
        self.assertEqual(self.mode(etcdstate.CLUSTER), 0o600)
        self.assertEqual(found.addresses(), ("fd00::1", "fd00::2"))
        self.assertEqual(found.dumps(), {"state": "new", "token": MESH,
                         "members": [{"public_key": "k1",
                                      "address": "fd00::1"},
                                     {"public_key": "k2",
                                      "address": "fd00::2"}]})
        self.assertEqual(Cluster.loads(found.dumps()), found)

    def test_a_damaged_file(self):
        os.makedirs(os.path.join(self.root, etcdstate.DIR))
        with open(os.path.join(self.root, etcdstate.CLUSTER), "w") as fob:
            fob.write("{")
        with self.assertRaisesRegex(StateError, "damaged"):
            etcdstate.cluster(self.root)
        for bad in ({"state": "maybe", "members": [], "token": MESH},
                    {"state": "new", "members": "x", "token": MESH},
                    {"state": "new", "members": [{"address": "nope",
                                                  "public_key": "k"}],
                     "token": MESH}, []):
            with self.assertRaises(StateError):
                Cluster.loads(bad)

    def test_ready_members(self):
        self.assertEqual(etcdstate.ready(self.root), {})
        etcdstate.add_ready(self.root, {"k1": "fd00::1"})
        etcdstate.add_ready(self.root, {"k2": "fd00::2"})
        self.assertEqual(etcdstate.ready(self.root),
                         {"k1": "fd00::1", "k2": "fd00::2"})
        etcdstate.drop_ready(self.root, "k1")
        self.assertEqual(etcdstate.ready(self.root), {"k2": "fd00::2"})
        with open(os.path.join(self.root, etcdstate.READY), "w") as fob:
            fob.write("[1]")
        self.assertEqual(etcdstate.ready(self.root), {})

    def test_learners_first_seen(self):
        self.assertEqual(etcdstate.learners(self.root, ["1"], NOW),
                         {"1": NOW})
        later = NOW + timedelta(hours=2)
        self.assertEqual(etcdstate.learners(self.root, ["1", "2"], later),
                         {"1": NOW, "2": later})
        self.assertEqual(etcdstate.learners(self.root, ["2"], later),
                         {"2": later})
        with open(os.path.join(self.root, etcdstate.LEARNERS), "w") as fob:
            json.dump({"3": "x"}, fob)
        self.assertEqual(etcdstate.learners(self.root, ["3"], later),
                         {"3": later})


class TestOpensslFailing(Case):
    def test_every_step_says_why(self):
        failing = mock.patch("keel.mesh.etcdpki.openssl",
                             side_effect=PkiError("openssl exited 1"))
        with failing, self.assertRaisesRegex(StateError, "exited 1"):
            etcdstate.make_root(self.root, MESH)
        with failing, self.assertRaisesRegex(StateError, "exited 1"):
            etcdstate.ca_request(self.root)
        first = self.scratch()
        etcdstate.make_root(first, MESH)
        csr = etcdstate.ca_request(self.root)
        with failing, self.assertRaisesRegex(StateError, "cannot be signed"):
            etcdstate.grant_for(first, csr, "x")
        grant = etcdstate.grant_for(first, csr, "x")
        with failing, self.assertRaisesRegex(StateError, "exited 1"):
            etcdstate.take_grant(self.root, grant)
        etcdstate.take_grant(self.root, grant)
        with mock.patch("keel.mesh.etcdpki.issue",
                        side_effect=PkiError("openssl exited 1")), \
                self.assertRaisesRegex(StateError, "exited 1"):
            etcdstate.leaves(self.root, "fd00::1", NOW)

    def test_damaged_bookkeeping_is_started_again(self):
        etcdstate.ensure(self.root)
        for name in (etcdstate.READY, etcdstate.LEARNERS):
            with open(os.path.join(self.root, name), "w") as fob:
                fob.write("{")
        self.assertEqual(etcdstate.ready(self.root), {})
        self.assertEqual(etcdstate.learners(self.root, ["1"], NOW),
                         {"1": NOW})


if __name__ == "__main__":
    unittest.main()
