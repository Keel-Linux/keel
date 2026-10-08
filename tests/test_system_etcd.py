# Copyright (c) 2026 KeelLinux maintainers
"""apply --system: etcd's configuration, from the state (keel.system.etcd)

The state reader against a scratch root holding real credentials (the
real openssl); the planner as a pure function of an EtcdState, alone and
within the appliance's step for the overlay, over the format's
manifests."""

import os
import shutil
import tempfile
import unittest

from manifest_helpers import ManifestCase
from test_system_appliance import PlanCase, units

from keel.inspect.tree import Tree
from keel.mesh import etcdconf, etcdstate
from keel.mesh.etcdstate import Cluster, Member
from keel.system import etcd
from keel.system.actions import Note, Refuse, Run, WriteFile
from keel.system.appstate import observe_appliance

MESH = "ab" * 16
THREE = Cluster("new", tuple(Member(None, f"fd00::{n}") for n in (1, 2, 3)),
                MESH)
DOC = {"network": {"overlay": {"wireguard": {"address": "fd00::1/64"}}}}
ADVANCED = {"installer": "enabled", "wireguard": "enabled",
            "etcd": "enabled", "crowdsec": "disabled"}


class Root(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(os.path.join(self.root, "etc"))
        with open(os.path.join(self.root, "etc/passwd"), "w") as fob:
            fob.write("root:x:0:0::/root:/bin/sh\n"
                      "etcd:x:120:125::/var/lib/etcd:/usr/sbin/nologin\n")

    def formed(self):
        etcdstate.make_root(self.root, MESH, "fd00::1")
        etcdstate.write(self.root, etcdstate.STARTED, "started\n")
        etcdstate.save_cluster(self.root, THREE)

    def observed(self, doc=DOC):
        return etcd.observe_etcd(Tree(self.root), doc)


class TestObserve(Root):
    def test_before_a_cluster_it_waits(self):
        found = self.observed()
        self.assertIsNone(found.cluster)
        self.assertTrue(etcd.waiting(found))
        self.assertFalse(etcd.waiting(None))
        self.assertEqual(found.address, "fd00::1")
        self.assertEqual(found.iface, "wg0")
        self.assertTrue(found.has_user)
        self.assertFalse(found.initialized)
        actions, restart = etcd.plan_etcd(found, True)
        self.assertIsInstance(actions[0], Note)
        self.assertIn("waits for its cluster", actions[0].describe())
        self.assertFalse(restart)

    def test_a_damaged_cluster_is_refused(self):
        etcdstate.write(self.root, etcdstate.CLUSTER, "{")
        found = self.observed()
        self.assertFalse(etcd.waiting(found))
        actions, _ = etcd.plan_etcd(found, True)
        self.assertIsInstance(actions[0], Refuse)

    def test_formed_writes_every_file_then_nothing(self):
        self.formed()
        actions, restart = etcd.plan_etcd(self.observed(), True)
        written = {one.path: one for one in actions
                   if isinstance(one, WriteFile)}
        self.assertEqual(set(written), {
            etcdconf.ENVIRONMENT, etcdconf.MEMBER_CERT, etcdconf.MEMBER_KEY,
            etcdconf.TRUSTED, etcdconf.CRL, etcdconf.DROP_IN})
        self.assertIn("ETCD_PEER_CRL_FILE=/etc/etcd/keel/crl.pem",
                      written[etcdconf.ENVIRONMENT].content)
        self.assertEqual(written[etcdconf.MEMBER_KEY].owner, "etcd")
        self.assertEqual(written[etcdconf.MEMBER_KEY].mode, 0o600)
        self.assertEqual(written[etcdconf.ENVIRONMENT].mode, 0o644)
        self.assertIsNone(written[etcdconf.ENVIRONMENT].owner)
        self.assertIn(("systemctl", "daemon-reload"),
                      [one.argv for one in actions if isinstance(one, Run)])
        self.assertTrue(restart)
        for one in written.values():
            path = os.path.join(self.root, one.path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fob:
                fob.write(one.content)
        self.assertEqual(etcd.plan_etcd(self.observed(), True), ([], False))

    def test_a_member_keel_never_started_is_refused(self):
        self.formed()
        os.remove(os.path.join(self.root, etcdstate.STARTED))
        os.makedirs(os.path.join(self.root, etcd.INITIALIZED))
        actions, _ = etcd.plan_etcd(self.observed(), True)
        self.assertIn("keel never started", actions[0].describe())
        etcdstate.write(self.root, etcdstate.STARTED, "started\n")
        actions, _ = etcd.plan_etcd(self.observed(), True)
        self.assertNotIsInstance(actions[0], Refuse)

    def test_under_root_no_daemon_reload(self):
        self.formed()
        actions, _ = etcd.plan_etcd(self.observed(), False)
        self.assertNotIn(Run, [type(one) for one in actions])

    def test_no_etcd_user_or_no_certificate(self):
        self.formed()
        with open(os.path.join(self.root, "etc/passwd"), "w") as fob:
            fob.write("root:x:0:0::/root:/bin/sh\n")
        actions, _ = etcd.plan_etcd(self.observed(), True)
        self.assertIn("no etcd user", actions[0].describe())
        other = Root("setUp")
        other.setUp()
        self.addCleanup(shutil.rmtree, other.root, True)
        etcdstate.save_cluster(other.root, THREE)
        actions, _ = etcd.plan_etcd(other.observed(), True)
        self.assertIn("holds no etcd certificate", actions[0].describe())


class TestRestart(unittest.TestCase):
    def test_initial_lines_ignored_once_initialized(self):
        before = "ETCD_NAME=a\nETCD_INITIAL_CLUSTER=x\n"
        after = "ETCD_NAME=a\nETCD_INITIAL_CLUSTER=y\n"
        self.assertTrue(etcd.restarts(before, after, False))
        self.assertFalse(etcd.restarts(before, after, True))
        self.assertTrue(etcd.restarts(before, "ETCD_NAME=b\n", True))
        self.assertTrue(etcd.restarts(None, after, True))


class TestWithinTheAppliance(PlanCase):
    def setUp(self):
        super().setUp()
        self.scratch = Root("setUp")
        self.scratch.setUp()
        self.addCleanup(shutil.rmtree, self.scratch.root, True)

    def etcd_runs(self, state):
        return self.runs(ADVANCED, self.state(etcd=state),
                         field="overlays.etcd")

    def test_waiting_starts_nothing(self):
        found = self.actions(ADVANCED, self.state(
            etcd=self.scratch.observed()), field="overlays.etcd")
        self.assertEqual(len(found), 1)
        self.assertIn("waits for its cluster", found[0].describe())

    def test_formed_is_started_without_blocking(self):
        self.scratch.formed()
        self.assertEqual(self.etcd_runs(self.scratch.observed()), [
            ("systemctl", "daemon-reload"),
            ("systemctl", "enable", "etcd.service"),
            ("systemctl", "start", "--no-block", "etcd.service")])

    def test_a_running_etcd_restarted_on_a_new_configuration(self):
        self.scratch.formed()
        state = self.state(etcd=self.scratch.observed(), units=units(
            "enabled", "active"))
        runs = self.runs(ADVANCED, state, field="overlays.etcd")
        self.assertEqual(runs[-1], ("systemctl", "restart", "--no-block",
                                    "etcd.service"))

    def test_a_refusal_stops_the_step(self):
        etcdstate.write(self.scratch.root, etcdstate.CLUSTER, "{")
        found = self.actions(ADVANCED, self.state(
            etcd=self.scratch.observed()), field="overlays.etcd")
        self.assertEqual([type(one) for one in found], [Refuse])


class TestObservedWithTheAppliance(ManifestCase):
    def test_the_chain_with_etcd_observes_it(self):
        doc = {"appliance": {"name": "core"}, **DOC}
        self.assertIsNotNone(observe_appliance(self.root, doc).etcd)

    def test_a_chain_without_etcd_observes_nothing_of_it(self):
        self.edit("appliances", "core", "  etcd:      {simple: disabled,"
                  " cloud_simple: disabled, cloud_advanced: enabled}\n", "")
        doc = {"appliance": {"name": "core"}, **DOC}
        found = observe_appliance(self.root, doc)
        self.assertIsNotNone(found.resolved, found.problems)
        self.assertIsNone(found.etcd)


if __name__ == "__main__":
    unittest.main()
