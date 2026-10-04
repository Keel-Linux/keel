# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh etcd form, and the members' answers to it: three members of
a mesh adopted under keel 0.18, with no CA, in one process"""

import json
import unittest
from datetime import timedelta
from unittest import mock

from etcd_helpers import KEYS, MESH, NOW, FakeEtcd, Mesh, address, voter

from keel import exits
from keel.mesh import etcdform, etcdmsg, etcdpki, etcdserve, etcdstate
from keel.mesh.etcdstate import Cluster, Member


class TestFormOnAnAdoptedMesh(Mesh):
    def test_dry_run_changes_nothing_anywhere(self):
        a, b, c = self.members(3)
        out = []
        self.assertEqual(etcdform.form(a, True, out.append), exits.OK)
        self.assertEqual(out, [
            "would make the mesh's root CA on this node",
            f"would enroll {address(1)}", f"would enroll {address(2)}",
            f"would form a cluster of 3: this node and {address(1)},"
            f" {address(2)}",
            "dry run: nothing was changed on any member"])
        for one in (a, b, c):
            self.assertFalse(etcdstate.credentials(one.root))
            self.assertIsNone(etcdstate.cluster(one.root))
            self.assertEqual(self.applied(one), [])

    def test_formed_from_one_member(self):
        a, b, c = self.members(3)
        out = []
        self.assertEqual(etcdform.form(a, False, out.append), exits.OK,
                         self.said)
        self.assertTrue(etcdstate.holds_root(a.root))
        root = etcdstate.root_fingerprint(a.root)
        for one in (a, b, c):
            self.assertEqual(etcdstate.root_fingerprint(one.root), root)
            cluster = etcdstate.cluster(one.root)
            self.assertEqual(cluster.state, "new")
            self.assertEqual(cluster.addresses(),
                             (address(0), address(1), address(2)))
            self.assertEqual(cluster.token, MESH.hex())
            # each enabled etcd in its own spec, and applied
            self.assertEqual(self.applied(one)[-1]["overlays"]["etcd"],
                             "enabled")
            leaf = etcdpki.blocks(etcdstate.read(one.root,
                                                 etcdstate.MEMBER_CERT))
            self.assertTrue(etcdpki.verified(leaf[0], leaf[1:], etcdstate.read(
                a.root, etcdstate.ROOT_CERT)))
        self.assertFalse(etcdstate.holds_root(b.root))
        self.assertIn("a cluster of 3 formed", out[-1])
        self.assertEqual(len(etcdstate.ready(b.root)), 3)

    def test_run_again_on_a_member_of_the_cluster(self):
        """Every member started: nothing to do; one that never started
        is sent the first cluster again"""
        a, b, c = self.members(3)
        etcdform.form(a, False, lambda line: None)
        client = a.client
        client.members_ = [voter(0), voter(1), voter(2)]
        out = []
        self.assertEqual(etcdform.form(a, False, out.append), exits.OK)
        self.assertEqual(out, ["etcd: every ready member is in the cluster"])
        client.members_ = [voter(0), voter(1), voter(2, name=False)]
        out = []
        self.assertEqual(etcdform.form(a, True, out.append), exits.OK)
        self.assertEqual(out[0], "would send the first cluster again to"
                         f" {address(2)}")
        self.assertEqual(etcdform.form(a, False, out.append), exits.OK)
        with mock.patch("keel.mesh.etcdform.send_cluster",
                        return_value="timed out"):
            self.assertEqual(etcdform.form(a, False, out.append),
                             exits.MESH_REFUSED)

    def test_a_ready_member_not_in_etcd_is_added_as_a_learner(self):
        etcd = FakeEtcd()
        a, b, c, d = self.members(4, etcd=etcd)
        # d was down when the cluster formed
        self.down.add(address(3))
        self.assertEqual(etcdform.form(a, False, lambda line: None),
                         exits.OK)
        self.assertIsNone(etcdstate.cluster(d.root))
        self.down.clear()
        etcd.members_ = [voter(0), voter(1), voter(2)]
        out = []
        self.assertEqual(etcdform.form(a, True, out.append), exits.OK)
        self.assertEqual(out[0], f"would add {address(3)} as a learner")
        with mock.patch("keel.mesh.etcdform.send_cluster",
                        return_value="timed out"):
            self.assertEqual(etcdform.form(a, False, out.append),
                             exits.MESH_REFUSED)
        etcd.members_ = [voter(0), voter(1), voter(2)]
        self.assertEqual(etcdform.form(a, False, out.append), exits.OK)
        self.assertIn(("add_learner", f"https://[{address(3)}]:2380"),
                      etcd.calls)
        found = etcdstate.cluster(d.root)
        self.assertEqual(found.state, "existing")
        self.assertEqual(len(found.members), 4)
        self.assertTrue(etcdstate.credentials(d.root))

    def test_a_member_down_is_left_out_and_said(self):
        a, b, c, d = self.members(4)
        self.down.add(address(3))
        self.assertEqual(etcdform.form(a, False, lambda line: None),
                         exits.OK)
        self.assertIn(f"member {address(3)} did not answer", self.text(0))
        self.assertEqual(len(etcdstate.cluster(a.root).members), 3)


class TestFormRefused(Mesh):
    def test_fewer_than_three_ready_enrolls_and_waits(self):
        a, b, c = self.members(3, modes=("cloud_advanced", "cloud_advanced",
                                         "cloud_simple"))
        out = []
        self.assertEqual(etcdform.form(a, False, out.append), exits.OK)
        self.assertIn("2 of 3 ready members hold their CA", out[-1])
        self.assertTrue(etcdstate.credentials(b.root))
        self.assertFalse(etcdstate.credentials(c.root))
        self.assertIsNone(etcdstate.cluster(a.root))
        self.assertIn("does not run etcd (not cloud advanced)", self.text(0))

    def test_this_node_not_ready(self):
        a, _, _ = self.members(3, modes=("cloud_simple",))
        self.assertEqual(etcdform.form(a, False, print), exits.MESH_REFUSED)
        self.assertIn("does not run etcd", self.text(0))

    def test_no_identity_or_a_damaged_one(self):
        a, _, _ = self.members(3)
        with mock.patch("keel.mesh.identity.read", return_value=None):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.MESH_REFUSED)
        self.assertIn("no mesh identity", self.text(0))
        with mock.patch("keel.mesh.identity.read",
                        side_effect=ValueError("damaged")):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.MESH_REFUSED)

    def test_a_network_change_waiting(self):
        a, _, _ = self.members(3)
        with mock.patch.object(type(a.node), "waiting", return_value=True):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.MESH_REFUSED)
        self.assertIn("waits for its confirmation", self.text(0))

    def test_two_roots(self):
        a, b, c = self.members(3)
        etcdstate.make_root(a.root, MESH.hex())
        etcdstate.make_root(b.root, MESH.hex())
        self.assertEqual(etcdform.form(a, False, print), exits.MESH_REFUSED)
        self.assertIn("different etcd roots", self.text(0))
        self.assertFalse(etcdstate.credentials(c.root))

    def test_another_member_holds_the_root(self):
        a, b, c = self.members(3)
        etcdstate.make_root(b.root, MESH.hex())
        self.assertEqual(etcdform.form(a, False, print), exits.MESH_REFUSED)
        self.assertIn(f"{address(1)} does: run keel mesh etcd form there",
                      self.text(0))
        self.assertEqual(etcdform.form(b, False, lambda line: None),
                         exits.OK)

    def test_a_cluster_this_node_is_not_in(self):
        a, b, c = self.members(3)
        etcdform.form(b, False, lambda line: None)
        import os
        os.remove(os.path.join(a.root, etcdstate.CLUSTER))
        self.assertEqual(etcdform.form(a, False, print), exits.MESH_REFUSED)
        self.assertIn("an etcd cluster exists", self.text(0))

    def test_an_enrollment_that_fails_starts_nothing(self):
        a, b, c = self.members(3)
        with mock.patch("keel.mesh.etcdstate.grant_for",
                        side_effect=etcdstate.StateError("no")):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.MESH_REFUSED)
        self.assertIn("was not enrolled", self.text(0))
        for one in (a, b, c):
            self.assertIsNone(etcdstate.cluster(one.root))
            self.assertEqual(self.applied(one), [])

    def test_a_member_that_does_not_take_the_cluster(self):
        a, b, c = self.members(3)
        real = etcdform.send_cluster

        def failing(etcd_, member, cluster, grant=None):
            if member.address == address(2):
                return "timed out"
            return real(etcd_, member, cluster, grant)
        with mock.patch("keel.mesh.etcdform.send_cluster", failing):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.MESH_REFUSED)
        self.assertIn(f"not reached: {address(2)} (timed out)",
                      self.text(0))
        self.assertIsNotNone(etcdstate.cluster(a.root))

    def test_errors_of_state_or_etcd(self):
        a, _, _ = self.members(3)
        with mock.patch("keel.mesh.etcdform.formed",
                        side_effect=etcdstate.StateError("damaged")):
            self.assertEqual(etcdform.form(a, False, print),
                             exits.APPLY_FAILED)

    def test_a_probe_answering_as_another_member(self):
        a, b, c = self.members(3)
        with mock.patch("keel.mesh.etcdmsg.probe_answer",
                        return_value=etcdmsg.Probe(True, None, False,
                                                   "fd00::99")):
            found = etcdform.probed(a, a.node.peers(KEYS[0]))
        self.assertIn("answers as fd00::99", found[KEYS[1]])
        self.assertEqual(etcdform.probed(a, ()), {})


class TestTheReceiver(Mesh):
    def setUp(self):
        super().setUp()
        self.a, self.b, self.c = self.members(3)

    def message(self, kind=etcdmsg.PROBE, body=None, sender=0, mesh=MESH,
                when=NOW):
        return etcdmsg.signed(self.all[sender].root, kind, mesh.hex(),
                              KEYS[sender], when, body or {})

    def refused(self, body, key=KEYS[0]):
        found = etcdserve.answer(self.b, body, key)
        self.assertGreaterEqual(found.status, 400)
        return json.loads(found.body)["error"]

    def test_a_probe(self):
        found = etcdserve.answer(self.b, self.message(), KEYS[0])
        self.assertEqual(etcdmsg.probe_answer(found.body), etcdmsg.Probe(
            True, None, False, address(1)))

    def test_refusals(self):
        self.assertIn("malformed", self.refused(b"{}"))
        self.assertIn("not the sender's", self.refused(self.message(),
                                                       KEYS[2]))
        self.assertIn("stale", self.refused(self.message(
            when=NOW - timedelta(minutes=10))))
        self.assertIn("another mesh", self.refused(self.message(
            mesh=bytes(16))))
        # c's message, claimed by c, but b does not trust c's key
        from keel.mesh import trust
        store = trust.load(self.b.root)
        del store.members[store.find(KEYS[2])]
        trust.save(self.b.root, store)
        self.assertIn("not signed by a key", self.refused(
            self.message(sender=2), KEYS[2]))
        with open(f"{self.b.root}/{trust.TRUST}", "w") as fob:
            fob.write("{")
        self.assertIn("not signed by a key", self.refused(self.message()))

    def test_no_identity_here(self):
        with mock.patch("keel.mesh.identity.read",
                        side_effect=ValueError("damaged")):
            self.assertIn("another mesh", self.refused(self.message()))

    def test_a_node_that_does_not_run_etcd(self):
        a, b = self.members(2, modes=("cloud_advanced", "cloud_simple"))
        found = etcdserve.answer(b, self.message(etcdmsg.ENROLL), KEYS[0])
        self.assertEqual(found.status, 409)

    def test_cluster_messages_refused(self):
        etcdstate.make_root(self.a.root, MESH.hex())
        other = Cluster("new", (Member(KEYS[0], address(0)),), MESH.hex())
        self.assertIn("does not name this node", self.refused(self.message(
            etcdmsg.CLUSTER, {"cluster": other.dumps()})))
        self.assertIn("malformed cluster", self.refused(self.message(
            etcdmsg.CLUSTER, {"cluster": {"state": "x"}})))
        self.assertIn("holds no etcd CA", self.refused(self.message(
            etcdmsg.CLUSTER, {"ready": {}})))
        mine = Cluster("new", (Member(KEYS[1], address(1)),), "cd" * 16)
        etcdstate.save_cluster(self.b.root, mine)
        theirs = Cluster("new", (Member(KEYS[1], address(1)),), MESH.hex())
        self.assertIn("in a cluster already", self.refused(self.message(
            etcdmsg.CLUSTER, {"cluster": theirs.dumps()})))

    def test_a_cluster_held_is_never_replaced(self):
        """Same mesh, same token, other members: refused (the token is
        always the mesh's identity)"""
        etcdstate.make_root(self.a.root, MESH.hex())
        etcdform.form(self.a, False, lambda line: None)
        rogue = Cluster("new", (Member(KEYS[1], address(1)),
                                Member(KEYS[0], "fd00:6b65:1::99")),
                        MESH.hex())
        self.assertIn("in a cluster already", self.refused(self.message(
            etcdmsg.CLUSTER, {"cluster": rogue.dumps()})))
        held = etcdstate.cluster(self.b.root)
        found = etcdserve.answer(self.b, self.message(
            etcdmsg.CLUSTER, {"cluster": held.dumps()}), KEYS[0])
        self.assertEqual(found.status, 200)

    def test_a_grant_only_from_a_root_and_not_while_waiting(self):
        from keel.mesh import trust
        etcdstate.make_root(self.a.root, MESH.hex())
        grant = etcdstate.grant_for(self.a.root, etcdstate.ca_request(
            self.b.root), "x")
        store = trust.load(self.b.root)
        store.members[store.find(KEYS[0])].root = False
        trust.save(self.b.root, store)
        self.assertIn("only from this node's inviter", self.refused(
            self.message(etcdmsg.CLUSTER,
                         {"grant": etcdmsg.grant_data(grant)})))
        cluster = Cluster("new", (Member(KEYS[1], address(1)),), MESH.hex())
        with mock.patch.object(type(self.b.node), "waiting",
                               return_value=True):
            self.assertIn("network change waits", self.refused(self.message(
                etcdmsg.CLUSTER, {"cluster": cluster.dumps()})))

    def test_ready_members_vetted_against_the_peers(self):
        etcdstate.make_root(self.b.root, MESH.hex())
        found = etcdserve.answer(self.b, self.message(etcdmsg.CLUSTER, {
            "ready": {KEYS[0]: address(0), KEYS[2]: "fd00::77",
                      KEYS[3]: address(3)}}), KEYS[0])
        self.assertEqual(found.status, 200)
        self.assertEqual(etcdstate.ready(self.b.root), {KEYS[0]: address(0)})

    def test_openssl_failing_is_a_503(self):
        etcdstate.make_root(self.b.root, MESH.hex())
        with mock.patch("keel.mesh.etcdstate.ca_request",
                        side_effect=OSError("disk full")):
            found = etcdserve.answer(self.b, self.message(etcdmsg.ENROLL),
                                     KEYS[0])
        self.assertEqual(found.status, 503)

    def test_a_grant_under_another_root(self):
        etcdstate.make_root(self.b.root, MESH.hex())
        etcdstate.make_root(self.a.root, MESH.hex())
        grant = etcdstate.grant_for(self.a.root, etcdstate.ca_request(
            self.c.root), "x")
        self.assertIn("another root", self.refused(self.message(
            etcdmsg.CLUSTER, {"grant": etcdmsg.grant_data(grant)})))

    def test_state_that_cannot_be_read(self):
        with mock.patch("keel.mesh.etcdstate.cluster",
                        side_effect=etcdstate.StateError("damaged")):
            found = etcdserve.answer(self.b, self.message(), KEYS[0])
        self.assertEqual(found.status, 503)

    def test_a_grant_alone_starts_nothing(self):
        etcdstate.make_root(self.a.root, MESH.hex())
        grant = etcdstate.grant_for(self.a.root, etcdstate.ca_request(
            self.b.root), "x")
        found = etcdserve.answer(self.b, self.message(
            etcdmsg.CLUSTER, {"grant": etcdmsg.grant_data(grant),
                              "ready": {KEYS[0]: address(0)}}), KEYS[0])
        self.assertEqual(found.status, 200)
        self.assertTrue(etcdstate.credentials(self.b.root))
        self.assertEqual(etcdstate.ready(self.b.root), {KEYS[0]: address(0)})
        self.assertEqual(self.applied(self.b), [])


if __name__ == "__main__":
    unittest.main()
