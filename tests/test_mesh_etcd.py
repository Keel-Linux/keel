# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcd: a join seen from etcd, tend, leave and status, with
members in one process and a recording etcd (tests/etcd_helpers.py)"""

import unittest
from datetime import timedelta
from unittest import mock

from etcd_helpers import KEYS, MESH, NOW, FakeEtcd, Mesh, address, voter

from keel import exits
from keel.mesh import etcd, etcdca, etcdcare, etcdform, etcdstate
from keel.mesh.etcdclient import Member as EtcdMember
from keel.mesh.etcdstate import Cluster, Member


def sent_through(mesh: Mesh, sender):
    def send(member, cluster):
        return etcdform.send_cluster(sender, member, cluster)
    return send


class TestReady(Mesh):
    def test_cloud_advanced_with_the_overlay(self):
        self.assertTrue(etcd.ready({"installation": {"mode":
                                                     "cloud_advanced"},
                                    "overlays": {"etcd": "disabled"}}))
        self.assertFalse(etcd.ready({"installation": {"mode":
                                                      "cloud_simple"},
                                     "overlays": {"etcd": "disabled"}}))
        self.assertFalse(etcd.ready({"installation": {"mode":
                                                      "cloud_advanced"}}))
        self.assertFalse(etcd.ready({}))


class TestTheFirstNodes(Mesh):
    def test_create_makes_the_root_on_a_ready_node(self):
        a, b = self.members(2, modes=("cloud_advanced", "cloud_simple"))
        etcd.created(a)
        self.assertTrue(etcdstate.holds_root(a.root))
        self.assertIn("holds the mesh's root CA", self.text(0))
        etcd.created(b)
        self.assertFalse(etcdstate.credentials(b.root))

    def test_create_says_why_no_root(self):
        a, = self.members(1)
        with mock.patch("keel.mesh.etcdstate.make_root",
                        side_effect=etcdstate.StateError("no openssl")):
            etcd.created(a)
        self.assertIn("CA was not made (no openssl)", self.text(0))

    def test_token_states(self):
        a, b, c = self.members(3)
        self.assertEqual(etcd.token_state(a), "none")
        etcd.created(a)
        self.assertEqual(etcd.token_state(a), "none")
        etcdstate.add_ready(a.root, {KEYS[1]: address(1)})
        self.assertEqual(etcd.token_state(a), "forms")
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        self.assertEqual(etcd.token_state(a), "running")
        with mock.patch("keel.mesh.etcdstate.cluster",
                        side_effect=etcdstate.StateError("damaged")):
            self.assertEqual(etcd.token_state(a), "none")

    def test_a_join_request_only_from_a_ready_node(self):
        a, b = self.members(2, modes=("cloud_advanced", "cloud_simple"))
        self.assertIn("CERTIFICATE REQUEST", etcd.join_csr(a))
        self.assertIsNone(etcd.join_csr(b))
        with mock.patch("keel.mesh.etcdstate.ca_request",
                        side_effect=etcdstate.StateError("no openssl")):
            self.assertIsNone(etcd.join_csr(a))
        self.assertIn("no request for this node's CA", self.text(0))


class TestJoins(Mesh):
    """a created the mesh; b joins through a; c joins through b"""

    def setUp(self):
        super().setUp()
        self.a, self.b, self.c = self.members(3)
        etcd.created(self.a)

    def joins(self, inviter, joiner, index):
        admission = etcd.admit(inviter, etcd.join_csr(joiner), KEYS[index],
                               address(index))
        line = etcd.joined(joiner, admission.grant, admission.cluster,
                           admission.ready)
        etcd.admitted(inviter, admission, KEYS[index],
                      sent_through(self, inviter))
        return admission, line

    def test_the_second_waits_the_third_forms(self):
        admission, line = self.joins(self.a, self.b, 1)
        self.assertEqual(admission.state, "none")
        self.assertIn("2 of 3 ready members known", line)
        self.assertEqual(etcd.token_state(self.b), "forms")
        admission, line = self.joins(self.a, self.c, 2)
        self.assertEqual(admission.state, "forms")
        self.assertIn("forms with 2 other member(s)", line)
        # b was neither inviter nor joiner: a sent it the cluster, with
        # its record signed by the root
        for one in (self.a, self.b, self.c):
            found = etcdstate.cluster(one.root)
            self.assertEqual(found.state, "new")
            self.assertEqual(sorted(found.addresses()),
                             [address(0), address(1), address(2)])
            self.assertEqual(self.applied(one)[-1]["overlays"]["etcd"],
                             "enabled")
            self.assertIsNone(etcdca.problem(one.root, found))
        self.assertIn(f"the cluster sent to {address(1)}", self.text(0))
        self.assertEqual(etcd.token_state(self.c), "running")

    def test_another_inviter_admits_the_third_and_forms_nothing(self):
        """Only the root's holder forms: b, which is not, admits c to
        the mesh, gives it its CA, and names the holder to the
        operator"""
        self.joins(self.a, self.b, 1)
        admission, line = self.joins(self.b, self.c, 2)
        self.assertEqual(admission.state, "none")
        self.assertIsNotNone(admission.grant)
        self.assertIn(f"run keel mesh etcd form on the root CA's holder"
                      f" ({address(0)})", admission.said)
        self.assertIn(f"on the root CA's holder ({address(0)}) forms", line)
        for one in (self.a, self.b, self.c):
            self.assertIsNone(etcdstate.cluster(one.root))
        # c's intermediate was signed by the root, through b
        self.assertEqual(admission.grant.chain, ())

    def test_two_concurrent_invites_never_make_two_clusters(self):
        """a and b ready; a admits c and d at once (two invites, two
        helpers): one formation is reserved, the other forms nothing,
        before or after the first is confirmed"""
        fake = FakeEtcd()
        a, b, c, d = self.members(4, etcd=fake)
        etcd.created(a)
        self.joins(a, b, 1)
        first = etcd.admit(a, etcd.join_csr(c), KEYS[2], address(2))
        second = etcd.admit(a, etcd.join_csr(d), KEYS[3], address(3))
        self.assertEqual(first.state, "forms")
        self.assertEqual(second.state, "none")
        self.assertIn("a formation is under way", second.said)
        etcd.joined(c, first.grant, first.cluster, first.ready)
        etcd.admitted(a, first, KEYS[2], sent_through(self, a))
        third = etcd.admit(a, etcd.join_csr(d), KEYS[3], address(3))
        self.assertNotEqual(third.state, "forms")
        clusters = {etcdstate.cluster(one.root).record
                    for one in (a, b, c) if etcdstate.cluster(one.root)}
        self.assertEqual(len(clusters), 1)
        self.assertIsNone(etcdstate.cluster(d.root))

    def test_a_formation_whose_join_reverted_is_given_back(self):
        self.joins(self.a, self.b, 1)
        first = etcd.admit(self.a, etcd.join_csr(self.c), KEYS[2],
                           address(2))
        self.assertEqual(first.state, "forms")
        etcd.abandoned(self.a, first)
        again = etcd.admit(self.a, etcd.join_csr(self.c), KEYS[2],
                           address(2))
        self.assertEqual(again.state, "forms")
        etcd.abandoned(self.a, etcd.Admission())

    def test_a_record_the_root_did_not_sign_is_not_started(self):
        self.joins(self.a, self.b, 1)
        first = etcd.admit(self.a, etcd.join_csr(self.c), KEYS[2],
                           address(2))
        from dataclasses import replace
        forged = replace(first.cluster, signature="A" * 96)
        line = etcd.joined(self.c, first.grant, forged, first.ready)
        self.assertIn("not started: the cluster carries no record signed",
                      line)
        self.assertIsNone(etcdstate.cluster(self.c.root))

    def test_a_member_that_does_not_take_the_cluster_is_said(self):
        self.joins(self.a, self.b, 1)
        self.down.add(address(1))
        self.joins(self.a, self.c, 2)
        self.assertIn(f"{address(1)} did not take the cluster", self.text(0))

    def test_a_join_from_a_node_that_cannot_run_etcd(self):
        admission = etcd.admit(self.a, None, KEYS[1], address(1))
        self.assertEqual(admission, etcd.Admission())
        self.assertIn("not on this node", etcd.joined(self.b, None, None,
                                                      {}))
        etcd.admitted(self.a, admission, KEYS[1], None)

    def test_an_inviter_that_cannot_issue(self):
        found = etcd.admit(self.b, etcd.join_csr(self.c), KEYS[2],
                           address(2))
        self.assertIsNone(found.grant)
        with mock.patch("keel.mesh.etcdstate.grant_for",
                        side_effect=etcdstate.StateError("no")):
            found = etcd.admit(self.a, etcd.join_csr(self.c), KEYS[2],
                               address(2))
        self.assertEqual(found, etcd.Admission())
        self.assertIn("gets no etcd CA (no)", self.text(0))

    def test_a_grant_the_joiner_cannot_keep(self):
        admission = etcd.admit(self.a, etcd.join_csr(self.b), KEYS[1],
                               address(1))
        with mock.patch("keel.mesh.etcdstate.take_grant",
                        side_effect=etcdstate.StateError("another key")):
            line = etcd.joined(self.b, admission.grant, admission.cluster,
                               admission.ready)
        self.assertIn("not set up (another key)", line)

    def test_the_fourth_joins_as_a_learner_and_is_promoted(self):
        fake = FakeEtcd([voter(0), voter(1), voter(2)])
        a, b, c, d = self.members(4, etcd=fake)
        etcdform.form(a, False, lambda line: None)
        admission, line = self.joins(a, d, 3)
        self.assertEqual(admission.state, "running")
        self.assertEqual(admission.learner, "101")
        self.assertIn(("add_learner", f"https://[{address(3)}]:2380"),
                      fake.calls)
        self.assertIn(("promote", "101"), fake.calls)
        self.assertIn("joins as a learner with 3 other member(s)", line)
        found = etcdstate.cluster(d.root)
        self.assertEqual(found.state, "existing")
        self.assertEqual(len(found.members), 4)

    def test_too_many_ready_members_form_nothing_at_a_join(self):
        etcd_ = self.a
        with mock.patch("keel.mesh.etcd.known_ready", return_value={
                f"{n:043d}=": f"fd00::{n + 10}" for n in range(8)}):
            found = etcd.admit(etcd_, etcd.join_csr(self.b), KEYS[1],
                               address(1))
        self.assertIsNotNone(found.grant)
        self.assertIsNone(found.cluster)
        self.assertIn("keel mesh etcd form forms it", self.text(0))

    def test_a_learner_that_cannot_be_added(self):
        fake = FakeEtcd([voter(0), voter(1), voter(2)])
        a, b, c, d = self.members(4, etcd=fake)
        etcdform.form(a, False, lambda line: None)
        fake.refuse["add_learner"] = "etcdserver: unhealthy cluster"
        admission = etcd.admit(a, etcd.join_csr(d), KEYS[3], address(3))
        self.assertIsNotNone(admission.grant)
        self.assertIsNone(admission.cluster)
        self.assertIn("not added as a learner (etcdserver: unhealthy",
                      self.text(0))


class TestVetted(Mesh):
    def test_a_node_without_its_key_vets_its_peers_only(self):
        a, b = self.members(2)
        with mock.patch.object(type(a.node), "public_key",
                               return_value=(None, "no key")):
            self.assertEqual(etcd.vetted(a, {KEYS[0]: address(0),
                                             KEYS[1]: address(1)}),
                             {KEYS[1]: address(1)})


class TestStartAndPromote(Mesh):
    def test_apply_failing_is_said(self):
        a, = self.members(1)
        etcd.created(a)
        a.node.apply.code = 16
        self.assertFalse(etcd.start(a))
        self.assertIn("apply exited 16", self.text(0))
        with mock.patch("keel.mesh.etcdstate.leaves",
                        side_effect=etcdstate.StateError("no CA")):
            self.assertFalse(etcd.start(a))
        self.assertIn("not started: no CA", self.text(0))

    def test_promote_tries_then_hands_over(self):
        fake = FakeEtcd()
        a, = self.members(1, etcd=fake)
        self.assertFalse(etcd.promote(a, None, 10))
        fake.refuse["promote"] = "not in sync"
        times = iter(NOW + timedelta(seconds=s) for s in range(0, 600, 5))
        a.clock = lambda: next(times)
        self.assertFalse(etcd.promote(a, "7", 20))
        self.assertGreater(len([c for c in fake.calls if c[0] == "promote"]),
                           1)
        self.assertIn("keel-mesh-etcd.timer tries again", self.text(0))


class TestTend(Mesh):
    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd()
        self.a, = self.members(1, etcd=self.fake)
        etcd.created(self.a)

    def test_nothing_before_a_cluster(self):
        self.assertEqual(etcdcare.tend(self.a), exits.OK)
        self.assertEqual(self.fake.calls, [])

    def test_learners_promoted_or_removed_and_leaves_renewed(self):
        etcdstate.save_cluster(self.a.root, Cluster("new", (
            Member(KEYS[0], address(0)),), MESH.hex()))
        started = EtcdMember("5", "keel-x", ("https://[fd00::5]:2380",), (),
                             True)
        never = EtcdMember("6", "", ("https://[fd00::6]:2380",), (), True)
        self.fake.members_ = [voter(0), started, never]
        self.assertEqual(etcdcare.tend(self.a), exits.OK)
        self.assertIn(("promote", "5"), self.fake.calls)
        self.assertNotIn(("remove", "6"), self.fake.calls)
        # the leaves were issued by the first tend: started, so applied
        self.assertEqual(self.applied(self.a)[-1]["overlays"]["etcd"],
                         "enabled")
        self.a.clock = lambda: NOW + timedelta(hours=2)
        self.fake.refuse["promote"] = "not in sync"
        self.assertEqual(etcdcare.tend(self.a), exits.OK)
        self.assertIn(("remove", "6"), self.fake.calls)
        self.assertIn("learner keel-x: not in sync", self.text(0))

    def test_etcd_or_state_failing(self):
        etcdstate.save_cluster(self.a.root, Cluster("new", (), MESH.hex()))
        self.fake.refuse["connect"] = "no member answered"
        self.assertEqual(etcdcare.tend(self.a), exits.APPLY_FAILED)
        del self.fake.refuse["connect"]
        with mock.patch("keel.mesh.etcdstate.leaves",
                        side_effect=etcdstate.StateError("no CA")):
            self.assertEqual(etcdcare.tend(self.a), exits.APPLY_FAILED)
        self.a.node.apply.code = 16
        self.assertEqual(etcdcare.tend(self.a), exits.APPLY_FAILED)


class TestLeave(Mesh):
    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, = self.members(1, etcd=self.fake)
        etcdstate.save_cluster(self.a.root, Cluster("new", (), MESH.hex()))
        etcdstate.add_ready(self.a.root, {KEYS[2]: address(2)})

    def test_removed_when_this_node_may(self):
        etcdcare.leave(self.a, address(2), True)
        self.assertIn(("remove", "3"), self.fake.calls)
        self.assertEqual(etcdstate.ready(self.a.root), {})
        self.assertIn("removed; 2 voter(s) left", self.text(0))
        self.assertIn("no fault tolerance", self.text(0))

    def test_a_node_that_is_no_member(self):
        etcdcare.leave(self.a, "fd00::99", True)
        self.assertNotIn("remove", [call[0] for call in self.fake.calls])
        self.assertNotIn("removed;", self.text(0))

    def test_local_only_when_it_may_not(self):
        etcdcare.leave(self.a, address(2), False)
        self.assertNotIn(("remove", "3"), self.fake.calls)
        self.assertIn("the removal is local only", self.text(0))

    def test_nothing_without_a_cluster_and_errors_said(self):
        with mock.patch("keel.mesh.etcdstate.cluster", return_value=None):
            etcdcare.leave(self.a, address(2), True)
        self.assertEqual(self.fake.calls, [])
        self.fake.refuse["remove"] = "no quorum"
        etcdcare.leave(self.a, address(2), True)
        self.assertIn("was not removed (no quorum)", self.text(0))
        with mock.patch("keel.mesh.etcdstate.cluster",
                        side_effect=etcdstate.StateError("damaged")):
            etcdcare.leave(self.a, address(2), True)
        self.assertIn("etcd: damaged", self.text(0))


class TestRevocation(Mesh):
    """a holds the root; b and c were enrolled by its form; c leaves"""

    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, self.b, self.c = self.members(3, etcd=self.fake)
        etcdform.form(self.a, False, lambda line: None)
        from keel.mesh import etcdpki
        self.pki = etcdpki
        self.serial = etcdpki.serial(etcdstate.read(self.c.root,
                                                    etcdstate.CA_CERT))

    def revoked(self, root):
        return self.pki.crl_serials(etcdstate.read(root, etcdstate.CRL))

    def test_the_holder_revokes_the_removed_node_s_intermediate(self):
        etcdcare.leave(self.a, address(2), True, KEYS[2])
        self.assertEqual(self.revoked(self.a.root), {self.serial})
        self.assertIn("certificates of fd00:6b65:1::3 revoked", self.text(0))

    def test_another_member_asks_the_holder(self):
        etcdcare.leave(self.b, address(2), True, KEYS[2])
        self.assertEqual(self.revoked(self.b.root), {self.serial})
        self.assertEqual(self.revoked(self.a.root), {self.serial})
        # c takes the CRL from b's roster
        etcdcare.crl_taken(self.c, etcdstate.read(self.b.root,
                                                  etcdstate.CRL))
        self.assertEqual(self.revoked(self.c.root), {self.serial})
        self.assertIn("a newer CRL from the root", self.text(2))

    def test_the_holder_refuses_a_member_that_may_not(self):
        from keel.mesh import trust
        store = trust.load(self.a.root)
        store.members[store.find(KEYS[1])].root = False
        trust.save(self.a.root, store)
        etcdcare.leave(self.b, address(2), True, KEYS[2])
        self.assertIn("were not revoked", self.text(1))
        self.assertEqual(self.revoked(self.a.root), set())
        # the node itself may
        etcdcare.leave(self.b, address(1), True, KEYS[1])

    def test_no_holder_known(self):
        etcdstate.write(self.b.root, etcdstate.HOLDER, "")
        etcdcare.leave(self.b, address(2), True, KEYS[2])
        self.assertIn("does not know the root's holder", self.text(1))

    def test_a_crl_with_no_cluster_or_damaged_state(self):
        found = etcdstate.read(self.a.root, etcdstate.CRL)
        with mock.patch("keel.mesh.etcdstate.take_crl",
                        side_effect=etcdstate.StateError("damaged")):
            etcdcare.crl_taken(self.b, found)
        self.assertIn("etcd: damaged", self.text(1))


class TestRenewal(Mesh):
    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, self.b, self.c = self.members(3, etcd=self.fake)
        etcdform.form(self.a, False, lambda line: None)

    def later(self, member, days):
        """the whole mesh's clock moves"""
        for one in self.all:
            one.clock = lambda: NOW + timedelta(days=days)

    def test_leaves_every_twenty_days_intermediates_from_the_holder(self):
        from keel.mesh import etcdpki
        before = etcdstate.read(self.b.root, etcdstate.CA_CERT)
        self.later(self.b, 21)
        self.assertEqual(etcdcare.tend(self.b), exits.OK)
        self.assertIn("certificates renewed", self.text(1))
        self.assertEqual(etcdstate.read(self.b.root, etcdstate.CA_CERT),
                         before)
        self.later(self.b, 250)
        self.assertEqual(etcdcare.tend(self.b), exits.OK)
        after = etcdstate.read(self.b.root, etcdstate.CA_CERT)
        self.assertNotEqual(after, before)
        self.assertEqual(etcdpki.public(after), etcdpki.public(before))
        self.assertIn("intermediate CA renewed", self.text(1))
        # the holder renews its own, and signs its CRL again
        self.later(self.a, 250)
        self.assertEqual(etcdcare.tend(self.a), exits.OK)
        self.assertIn("intermediate CA renewed", self.text(0))
        self.assertIn("the CRL signed again", self.text(0))

    def test_a_renewal_waits_for_the_holder(self):
        self.later(self.b, 250)
        self.down.add(address(0))
        self.assertEqual(etcdcare.tend(self.b), exits.APPLY_FAILED)
        self.assertIn("the next tend asks again", self.text(1))

    def test_the_holder_unreachable_this_node_signs(self):
        self.down.add(address(0))
        grant = etcd.issued(self.b, etcdstate.ca_request(self.c.root),
                            address(2))
        self.assertEqual(len(grant.chain), 1)
        self.assertIn("did not sign", self.text(1))


class TestStatus(Mesh):
    def test_not_on_this_node(self):
        a, = self.members(1, modes=("cloud_simple",))
        self.assertIn("not on this node (installation.mode cloud_simple",
                      etcdcare.status(a)[0])

    def test_not_formed(self):
        a, = self.members(1)
        etcd.created(a)
        self.assertIn("not formed; 1 of 3 ready", etcdcare.status(a)[0])
        with mock.patch("keel.mesh.etcdstate.cluster",
                        side_effect=etcdstate.StateError("damaged")):
            self.assertEqual(etcdcare.status(a), ["etcd: damaged"])

    def test_members_leader_and_health(self):
        fake = FakeEtcd([voter(0), voter(1), voter(2, name=False)])
        a, = self.members(1, etcd=fake)
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        url = f"https://[{address(1)}]:2379"
        fake.leaders = {f"https://[{address(0)}]:2379": "2", url: "2"}
        fake.healthy[url] = (True, "")
        found = etcdcare.status(a)
        self.assertEqual(found[0], "etcd: 3 voter(s), 0 learner(s)")
        self.assertIn(f"keel-{address(0).replace(':', '-')}", found[1])
        self.assertIn("(not started)", found[3])
        self.assertIn("not started", found[3])
        self.assertEqual(found[4],
                         f"leader: keel-{address(1).replace(':', '-')}")
        fake.leaders[url] = "1"
        self.assertIn("(members disagree)", etcdcare.status(a)[4])
        fake.members_ = [voter(0), voter(1)]
        fake.refuse["status"] = "timed out"
        found = etcdcare.status(a)
        self.assertEqual(found[-2], "leader: none known")
        self.assertIn("no fault tolerance", found[-1])
        fake.refuse["connect"] = "no member answered"
        self.assertIn("does not answer: no member answered",
                      etcdcare.status(a)[0])


if __name__ == "__main__":
    unittest.main()
