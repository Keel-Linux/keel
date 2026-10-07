# Copyright (c) 2026 KeelLinux maintainers
"""The VIP wired into keel: the members' channel, keel vip's commands,
keel database promote, appliance.vip in the spec, inspect's read back,
and the file apply renders (decision 0049)"""

import contextlib
import io
import os
import shutil
import unittest
from unittest import mock

from vip_helpers import KEYS, VIP, Pair, address

from keel import cli, exits, spec
from keel.inspect import collect, emit
from keel.inspect.report import Inspection
from keel.inspect.tree import Tree
from keel.mesh import memberlink, vipcli, vipnode, vippromote
from keel.mesh import vip as vipstate
from keel.mesh.memberd import Members, Pending
from keel.mesh.memberlink import Answer, LinkError
from keel.system import ovstate


class TestTheChannel(unittest.TestCase):
    def test_a_vip_message_and_its_refusal(self):
        with mock.patch("keel.mesh.memberlink.exchange",
                        return_value=(200, b'{"ok": 1}')) as sent:
            self.assertEqual(memberlink.vip_exchange("fd00::1", "wg0", b"{}"),
                             b'{"ok": 1}')
        self.assertEqual(sent.call_args[0][2:4], ("POST", "/v1/vip"))
        with mock.patch("keel.mesh.memberlink.exchange",
                        return_value=(409, b'{"error": "stale claim"}')), \
                self.assertRaisesRegex(LinkError, "stale claim"):
            memberlink.vip_exchange("fd00::1", "wg0", b"{}")
        with mock.patch("keel.mesh.memberlink.vip_exchange",
                        return_value=b"x"):
            self.assertEqual(vipnode.over_the_overlay("fd00::1", "wg0",
                                                      b"{}"), b"x")

    def test_the_root_side_hands_it_to_vipserve(self):
        asked = []
        handler = Members(lambda: None, lambda source: KEYS[0], Pending(),
                          print, None, lambda body, key: asked.append(
                              (body, key)) or Answer(200, b"{}"))
        found = handler.handle("POST", "/v1/vip", b"{}", "fd00::1")
        self.assertEqual(found.status, 200)
        self.assertEqual(asked, [(b"{}", KEYS[0])])
        front = memberlink.Front(handler, lambda: None, print)
        self.assertEqual(front.handle("POST", "/v1/vip", b"{}",
                                      "fd00::1").status, 200)


class TestTheCommands(Pair):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_root_is_needed_on_the_live_system(self):
        for action in ("promote", "check", "tend"):
            with self.subTest(action=action), \
                    mock.patch("os.geteuid", return_value=1000):
                code, _, err = self.run_cli("vip", action)
                self.assertEqual(code, exits.APPLY_NEEDS_ROOT, err)

    def args(self, index: int, **more) -> list[str]:
        here = self.all[index]
        return ["--spec", here.node.path, "--root", here.root]

    def test_each_action_reaches_its_flow(self):
        self.nodes()
        with mock.patch.object(vipcli, "here_of",
                               side_effect=lambda args: self.all[0]):
            code, out, _ = self.run_cli("vip", "promote", *self.args(0))
            self.assertEqual(code, exits.OK, out)
            self.assertIn("at epoch 1", out)
            code, out, _ = self.run_cli("vip", "check", *self.args(0))
            self.assertEqual(code, exits.OK)
            code, out, _ = self.run_cli("vip", "status", *self.args(0))
            self.assertIn("role: primary", out)
            code, out, _ = self.run_cli("vip", "tend", "--stopped",
                                        *self.args(0))
            self.assertIn("dropped, the controller stopped", out)
            with mock.patch.object(vipcli.vipetcd.Controller, "run") as ran:
                code, _, _ = self.run_cli("vip", "tend", *self.args(0))
            self.assertEqual((code, ran.call_count), (exits.OK, 1))

    def test_here_of_is_this_node(self):
        self.nodes(count=1)
        args = cli.build_parser().parse_args(["vip", "status",
                                              *self.args(0)])
        here = vipcli.here_of(args)
        self.assertEqual(here.root, self.all[0].root)
        vipcli.err("said")

    def test_keel_mesh_status_shows_the_vip(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        code, out, _ = self.run_cli("mesh", "status", *self.args(0))
        self.assertEqual(code, exits.OK)
        self.assertIn(f"vip {VIP}: this node's appliance.vip", out)

    def test_database_promote_moves_the_vip_first(self):
        self.nodes()
        with mock.patch.object(vipcli, "here_of",
                               side_effect=lambda args: self.all[0]), \
                mock.patch("keel.system.observe") as observed, \
                mock.patch("keel.system.plan_promote", return_value=[]):
            observed.return_value.database = None
            code, out, _ = self.run_cli("database", "promote", "--dry-run",
                                        *self.args(0))
            self.assertIn("would move the VIP", out)
            self.assertFalse(self.carried(0))
            code, out, _ = self.run_cli("database", "promote",
                                        *self.args(0))
            self.assertEqual(code, exits.OK, out)
            self.assertTrue(self.carried(0))
            self.down.add(address(0))
            with mock.patch.object(vipcli, "here_of",
                                   side_effect=lambda args: self.all[1]):
                code, out, _ = self.run_cli("database", "promote",
                                            *self.args(1))
            self.assertEqual(code, exits.MESH_REFUSED, out)
            self.assertEqual(observed.call_count, 2)


class TestTheSpec(unittest.TestCase):
    base = {"version": 1, "appliance": {"name": "core", "vip": VIP},
            "network": {"overlay": {"wireguard": {
                "address": f"{address(0)}/64", "peers": [
                    {"public_key": KEYS[1],
                     "allowed_ips": [f"{address(1)}/128"]}]}}}}

    def problems(self, doc: dict) -> list[str]:
        return [one for one in spec.validate(doc, check_secret_files=False)
                if "vip" in one]

    def test_a_vip_of_the_overlay_is_valid(self):
        self.assertEqual(self.problems(self.base), [])

    def test_what_is_refused(self):
        for vip, said in ((f"{VIP}/128", "one IPv6 address"),
                          ("192.0.2.1", "one IPv6 address"),
                          ("fd00:9::1", "outside"),
                          (address(1), "routed at runtime")):
            doc = {**self.base, "appliance": {"name": "core", "vip": vip}}
            with self.subTest(vip=vip):
                self.assertIn(said, " ".join(self.problems(doc)))
        doc = {"version": 1, "appliance": {"name": "core", "vip": VIP}}
        self.assertIn("needs network.overlay", " ".join(self.problems(doc)))
        doc = {**self.base, "appliance": {"name": "core", "vips": VIP}}
        self.assertTrue(any("unknown key" in one for one in spec.validate(
            doc, check_secret_files=False)))


class TestInspectAndApply(Pair):
    def test_peers_are_read_back_without_the_vip(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        here = self.all[2]
        overlay = here.overlay()
        conf = os.path.join(here.root, "etc/wireguard/wg0.conf")
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        from keel.network import wireguard
        with open(conf, "w") as fob:
            fob.write(wireguard.render(vipstate.routed_here(overlay,
                                                            here.root)))
        found, _ = collect.overlay_section(Tree(here.root))
        peers = found["wireguard"]["peers"]
        self.assertEqual([one["allowed_ips"] for one in peers],
                         [[f"{address(0)}/128"], [f"{address(1)}/128"]])
        # apply renders what is there: a move is never an overlay change
        state = ovstate.observe_overlay(here.root, here.node.document())
        with open(conf) as fob:
            self.assertEqual(state.rendered, fob.read())

    def test_the_vip_lines_beside_the_spec(self):
        self.nodes()
        vippromote.promote(self.all[0], False, lambda line: None)
        tree = Tree(self.all[0].root)
        doc = self.all[0].node.document()
        lines = collect.vip_lines(tree, doc)
        self.assertEqual(len(lines), 1)
        self.assertIn("epoch 1", lines[0])
        held = vipnode.current(self.all[0], VIP)
        vipstate.write(self.all[0].root, vipstate.fenced(held))
        self.assertIn("fenced here", collect.vip_lines(tree, doc)[0])
        self.assertIn("role replica", collect.vip_lines(tree, doc)[0])
        with mock.patch.object(collect.paths, "ROOT_DEFAULT", tree.root), \
                mock.patch.object(collect.vipnet, "carried",
                                  return_value=True), \
                mock.patch.object(collect.vipnet, "routed_to",
                                  return_value=None):
            live = collect.vip_lines(tree, {})
        self.assertIn("carried here: yes; routed to no peer", live[0])
        self.assertEqual(collect.vip_lines(Tree(self.parent), {}), ())
        report = emit.report_lines(Inspection("/", "core", {}, (), None,
                                              ("vip x: y",)))
        self.assertEqual(report[0], "vip x: y")

    def test_appliance_vip_from_the_emitted_spec(self):
        self.nodes(count=1)
        root = self.all[0].root
        os.makedirs(os.path.join(root, "etc/keel"), exist_ok=True)
        shutil.copy(self.all[0].node.path,
                    os.path.join(root, "etc/keel/instance.yaml"))
        from keel.inspect.overlays import probe_appliance_sections
        sections, findings = probe_appliance_sections(Tree(root))
        self.assertEqual(sections["appliance"]["vip"], VIP)
        self.assertTrue(any(one.field == "appliance.vip"
                            for one in findings))


if __name__ == "__main__":
    unittest.main()
