# Copyright (c) 2026 KeelLinux maintainers
"""Where etcd meets the rest of keel mesh: the members' channel, the
inviter's confirmation, remove's rule, the CLI and diff"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from etcd_helpers import KEYS, MESH, Mesh, address, spec
from manifest_helpers import ManifestCase

from keel import cli, exits
from keel.diff.appliance import NO_CLUSTER, appliance_fields
from keel.diff.report import NOT_COMPARED
from keel.mesh import etcd, etcdcare, etcdstate, inviting, memberlink, trust
from keel.mesh.etcdstate import Cluster
from keel.mesh.memberd import Members, Pending
from keel.mesh.memberlink import Answer, LinkError
from keel.mesh.node import NodeError


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestTheChannel(unittest.TestCase):
    def test_an_etcd_message_and_its_refusal(self):
        with mock.patch("keel.mesh.memberlink.exchange",
                        return_value=(200, b'{"ok": 1}')) as sent:
            self.assertEqual(memberlink.etcd_exchange("fd00::1", "wg0",
                                                      b"{}"), b'{"ok": 1}')
        self.assertEqual(sent.call_args[0][2:4], ("POST", "/v1/etcd"))
        with mock.patch("keel.mesh.memberlink.exchange",
                        return_value=(403, b'{"error": "stale"}')), \
                self.assertRaisesRegex(LinkError, "stale"):
            memberlink.etcd_exchange("fd00::1", "wg0", b"{}")
        with mock.patch("keel.mesh.memberlink.etcd_exchange",
                        return_value=b"x") as sent:
            self.assertEqual(etcd.over_the_overlay("fd00::1", "wg0", b"{}"),
                             b"x")

    def test_the_root_side_hands_it_to_etcdserve(self):
        asked = []
        handler = Members(lambda: None, lambda source: KEYS[0], Pending(),
                          print, lambda body, key: asked.append((body, key))
                          or Answer(200, b"{}"))
        found = handler.handle("POST", "/v1/etcd", b"{}", "fd00::1")
        self.assertEqual(found.status, 200)
        self.assertEqual(asked, [(b"{}", KEYS[0])])
        self.assertEqual(handler.handle("POST", "/v1/etcd", None,
                                        "fd00::1").status, 404)


class TestTheInviterOnceConfirmed(Mesh):
    def inviter(self, member, **fields):
        return inviting.Inviter(member.node, self.clock, print, print,
                                **fields)

    def test_a_hook_given_is_used(self):
        a, = self.members(1)
        seen = []
        self.inviter(a, etcd_after=seen.append).etcd_joined(None)
        self.assertEqual(seen, [None])

    def test_the_admitter_s_decision_is_carried_out(self):
        a, = self.members(1)
        admitter = mock.Mock(etcd_admission=etcd.Admission())
        with mock.patch("keel.mesh.etcd.admitted") as admitted:
            self.inviter(a).etcd_joined(admitter)
        self.assertEqual(admitted.call_args[0][1], etcd.Admission())
        send = admitted.call_args[0][3]
        with mock.patch("keel.mesh.etcdform.send_cluster",
                        return_value=None) as sent:
            self.assertIsNone(send("member", "cluster"))
        self.assertEqual(sent.call_args[0][1:], ("member", "cluster"))

    def test_a_join_not_confirmed_gives_its_formation_back(self):
        a, = self.members(1)
        admission = etcd.Admission()
        admitter = mock.Mock(etcd_admission=admission, confirmed=False)
        with mock.patch("keel.mesh.etcd.abandoned") as abandoned:
            self.inviter(a).etcd_joined(admitter)
        abandoned.assert_called_once()

    def test_a_fallback_join_through_another_than_the_holder(self):
        a, b = self.members(2)
        etcd.created(a)
        etcdstate.take_grant(b.root, etcdstate.grant_for(
            a.root, etcdstate.member_request(b.root), address(1)),
            address(1))
        said = []
        with mock.patch("keel.mesh.etcdform.form") as form:
            inviting.Inviter(b.node, self.clock, print,
                             said.append).etcd_joined(None)
        form.assert_not_called()
        self.assertIn(f"on the root CA's holder ({address(0)})", said[0])

    def test_the_fallback_s_node_brought_in_by_form(self):
        a, b = self.members(2, modes=("cloud_advanced", "cloud_simple"))
        with mock.patch("keel.mesh.etcdform.form") as form:
            self.inviter(a).etcd_joined(None)
            form.assert_not_called()
            etcd.created(a)
            self.inviter(a).etcd_joined(None)
            self.assertEqual(form.call_count, 1)
            self.inviter(b).etcd_joined(None)
            with mock.patch.object(type(a.node), "document",
                                   side_effect=NodeError("unreadable")):
                self.inviter(a).etcd_joined(None)
            self.assertEqual(form.call_count, 1)


class TestRemovesRule(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def test_admitted_here_or_a_root(self):
        from keel.mesh import signing
        own = signing.ensure(self.root)
        store = trust.Store()
        self.assertFalse(trust.may_remove_everywhere(store, own, KEYS[0]))
        trust.make_roots(store, (KEYS[0],))
        self.assertTrue(trust.may_remove_everywhere(store, own, KEYS[0]))
        found = trust.admit(self.root, MESH, "0123456789abcdef", KEYS[1],
                            KEYS[2], address(1), None,
                            __import__("etcd_helpers").NOW)
        trust.recorded(store, found)
        self.assertTrue(trust.may_remove_everywhere(store, own, KEYS[1]))
        self.assertFalse(trust.may_remove_everywhere(store, KEYS[3],
                                                     KEYS[1]))


class TestTheCli(Mesh):
    def test_form_tend_and_status(self):
        a, = self.members(1, modes=("cloud_simple",))
        root, path = a.root, a.node.path
        code, _, err = run_cli("mesh", "etcd", "form", "--dry-run",
                               "--root", root, "--spec", path)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("does not run etcd", err)
        self.assertEqual(run_cli("mesh", "etcd", "tend", "--root", root,
                                 "--spec", path)[0], exits.OK)
        code, out, _ = run_cli("mesh", "status", "--root", root, "--spec",
                               path)
        self.assertIn("etcd: not on this node", out)

    def test_not_root_on_the_live_system(self):
        with mock.patch("keel.mesh.commands.as_root", return_value=15):
            self.assertEqual(run_cli("mesh", "etcd", "form")[0], 15)
            self.assertEqual(run_cli("mesh", "etcd", "tend")[0], 15)

    def test_status_off_the_live_system_does_not_ask_etcd(self):
        a, = self.members(1)
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        self.assertEqual(etcdcare.status(a, live=False), [
            "etcd: this node is in a cluster of 0 (not the live system:"
            " etcd is not asked)"])

    def test_invite_carries_the_etcd_state(self):
        a, = self.members(1)
        etcdstate.save_cluster(a.root, Cluster("new", (), MESH.hex()))
        with mock.patch("keel.mesh.commands.public_key",
                        return_value=(KEYS[0], 0)), \
                mock.patch("keel.mesh.commands.listening",
                           return_value=("", 0)):
            code, out, err = run_cli(
                "mesh", "invite", "--root", a.root, "--spec", a.node.path,
                "--endpoint", "2001:db8::1")
        self.assertEqual(code, exits.OK, err)
        from datetime import datetime, timezone

        from keel.mesh.token import parse
        found = parse(out.split()[-1], datetime.now(timezone.utc))
        self.assertEqual((found.etcd, found.etcd_port), ("running", 2379))


class TestDiff(ManifestCase):
    def test_certificates_renewed_or_drift(self):
        from datetime import datetime, timedelta, timezone

        from keel.diff.appliance import DRIFT, SAME, etcd_fields
        from keel.inspect.tree import Tree
        tree = Tree(self.root)
        on = {"etcd": "enabled"}
        self.assertEqual(etcd_fields({"etcd": "disabled"}, tree), [])
        self.assertEqual(etcd_fields(on, tree), [])
        etcdstate.save_cluster(self.root, Cluster("new", (), MESH.hex()))
        self.assertEqual(etcd_fields(on, tree)[0].reason,
                         "no member certificate")
        etcdstate.make_root(self.root, MESH.hex(), "fd00::1")
        now = datetime.now(timezone.utc)
        self.assertEqual(etcd_fields(on, tree)[0].status, SAME)
        found = etcd_fields(on, tree, now + timedelta(days=25))[0]
        self.assertEqual(found.status, DRIFT)
        self.assertIn("within 7 days", found.reason)
        etcdstate.write(self.root, etcdstate.RENEWAL,
                        '{"problem": "the holder did not sign"}')
        self.assertEqual(etcd_fields(on, tree)[0].reason,
                         "the holder did not sign")
        os.remove(os.path.join(self.root, etcdstate.CLUSTER))

    def test_etcd_waiting_for_its_cluster_is_not_drift(self):
        import yaml
        doc = yaml.safe_load(spec(0, 1, etcd="enabled"))
        found = {one.field: one for one in appliance_fields(doc, self.root)}
        self.assertEqual(found["overlays.etcd"].status, NOT_COMPARED)
        self.assertEqual(found["overlays.etcd"].reason, NO_CLUSTER)
        etcdstate.save_cluster(self.root, Cluster("new", (), MESH.hex()))
        found = {one.field: one for one in appliance_fields(doc, self.root)}
        self.assertNotEqual(found["overlays.etcd"].status, NOT_COMPARED)
        os.remove(os.path.join(self.root, etcdstate.CLUSTER))


if __name__ == "__main__":
    unittest.main()
