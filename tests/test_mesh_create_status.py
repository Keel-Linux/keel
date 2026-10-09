# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh create, keel mesh status, the invite's port, the node seam

create against a real Node on a scratch root (tests/mesh_wire.py),
confirmed by the real keel.network.confirm; status from fixture `wg
show` output; the firewall element through a recording runner.
"""

import ipaddress
import os
import shutil
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

import yaml
from mesh_helpers import INVITE, JOINER, NOW, OTHER, reserved
from mesh_helpers import INVITER as INVITER_KEY
from mesh_wire import INVITER_SPEC, Armed, node, probes
from test_network_window import Recorder

from keel import exits
from keel.mesh import create, identity, invites, ports, status
from keel.mesh.node import (
    Node,
    NodeError,
    live_apply,
    with_overlay,
)
from keel.network import marker


def saying(doc, root, window):
    """apply as the live one prints it"""
    print(f"keel mesh: bring the overlay wg0 up; it reverts in {window} s"
          " unless `keel network confirm` is run from a new session")
    return Armed()(doc, root, window)


class TestCreate(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.node = node(self.root, clients=("2001:db8:9::5",))
        self.out, self.err = [], []

    def create(self):
        return create.create(self.node, self.out.append, self.err.append)

    def overlay(self):
        with open(self.node.path) as fob:
            return yaml.safe_load(fob)["network"]["overlay"]["wireguard"]

    def test_a_random_prefix_this_node_at_one_confirmed_by_itself(self):
        self.assertEqual(self.create(), exits.OK, self.err)
        address = ipaddress.IPv6Interface(self.overlay()["address"])
        self.assertEqual(address.network.prefixlen, 64)
        self.assertEqual(int(address.ip) & 0xFFFF, 1)
        self.assertTrue(str(address).startswith("fd"))
        self.assertIsNotNone(identity.read(self.root))
        self.assertFalse(marker.exists(self.root))
        self.assertEqual(marker.last(self.root).outcome, marker.CONFIRMED)
        self.assertIn("confirmed from keel mesh create", self.err)
        self.assertEqual(self.out, [
            f"created the mesh: this node is {address} on wg0, WireGuard"
            " on UDP 51820",
            "keel mesh invite prints the line that joins the next node"])

    def test_the_operator_session_routed_into_it_reverts_it(self):
        self.node.probes = lambda: probes("wg0")
        self.node.apply = saying
        self.assertEqual(self.create(), exits.NETWORK_NOT_CONFIRMED)
        self.assertTrue(marker.exists(self.root))
        self.assertEqual(self.err[0], "confirming the new overlay…")
        self.assertIn("unless `keel network confirm`", self.err[1])
        self.assertIn("leaves through wg0", self.err[2])

    def test_apply_s_revert_warning_is_not_shown_when_it_confirms(self):
        self.node.apply = saying
        self.assertEqual(self.create(), exits.OK)
        self.assertNotIn("unless", "\n".join(self.err))
        self.assertEqual(self.err[:2], ["confirming the new overlay…",
                                        "confirmed from keel mesh create"])

    def test_a_node_already_in_a_mesh(self):
        with open(self.node.path, "w") as fob:
            fob.write(INVITER_SPEC)
        self.assertEqual(self.create(), exits.MESH_REFUSED)
        self.assertIn("already in a mesh, at fd00:6b65:1::1/64", self.err[0])

    def test_a_spec_that_cannot_be_read(self):
        with open(self.node.path, "w") as fob:
            fob.write("version: [")
        self.assertEqual(self.create(), exits.MESH_REFUSED)

    def test_a_damaged_identity(self):
        os.makedirs(os.path.join(self.root, "var/lib/keel/mesh"))
        with open(os.path.join(self.root, identity.IDENTITY), "w") as fob:
            fob.write("nope\n")
        self.assertEqual(self.create(), exits.MESH_REFUSED)
        self.assertIn("does not hold a mesh identity", self.err[0])

    def test_the_overlay_does_not_come_up(self):
        def failing(doc, root, window):
            print("wg-quick up failed")
            return 16
        self.node.apply = failing
        self.assertEqual(self.create(), exits.APPLY_FAILED)
        self.assertEqual(self.err[0], "wg-quick up failed")
        self.assertIn("apply exited 16", self.err[1])


class TestStatus(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.overlay = {"address": "fd00:6b65:1::1/64", "peers": [
            {"public_key": JOINER, "endpoint": "[2001:db8:2::20]:51820",
             "allowed_ips": ["fd00:6b65:1::3/128"]},
            {"public_key": OTHER, "allowed_ips": ["fd00:6b65:1::7/128"]}]}

    def wg(self, argv):
        return {
            "public-key": "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=\n",
            "endpoints": f"{JOINER}\t[2001:db8:2::21]:51820\n"
                         f"{OTHER}\t(none)\nnot a line\n",
            "latest-handshakes": f"{JOINER}\t"
                                 f"{int(NOW.timestamp()) - 12}\n{OTHER}\t0\n",
        }[argv[-1]]

    def test_the_peers_their_handshakes_and_the_invites(self):
        reserved(self.root)
        identity.adopt(self.root, bytes(range(16)))
        found = status.lines(self.overlay, self.root, NOW, self.wg)
        self.assertEqual(found.pop(1), "mesh identity:"
                         " 000102030405060708090a0b0c0d0e0f")
        self.assertEqual(found[:4], [
            "this node: fd00:6b65:1::1/64 on wg0, WireGuard on UDP 51820",
            "public key: nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=",
            "peers: 2",
            f"  {JOINER}  fd00:6b65:1::3/128  [2001:db8:2::21]:51820"
            "  handshake 12 s ago"])
        self.assertEqual(found[4], f"  {OTHER}  fd00:6b65:1::7/128  no"
                         " endpoint  no handshake yet")
        # keel#117: a peer with no handshake is drift, named
        self.assertEqual(found[5], f"drift: peer {OTHER} has no handshake"
                         " since wg0 came up: it comes once that member has"
                         " this node as a peer too (keel mesh sync on that"
                         " member)")
        self.assertEqual(found[6], "pending invites: 1")
        self.assertIn(f"  {INVITE}  fd00:6b65:1::3/64  TCP 51820  until"
                      " 2026-10-03 13:00:00 UTC  pending", found[7])
        invites.consume(self.root, INVITE, NOW)
        self.assertIn("used, waiting for its confirmation",
                      status.lines(self.overlay, self.root, NOW,
                                   self.wg)[-1])

    def test_no_secret_is_asked_for(self):
        asked = []
        status.lines(self.overlay, self.root, NOW,
                     lambda argv: asked.append(argv) or self.wg(argv))
        for argv in asked:
            self.assertNotIn("dump", argv)
            self.assertNotIn("private-key", argv)

    def test_an_interface_that_is_down(self):
        found = status.lines(self.overlay, self.root, NOW, lambda argv: None)
        self.assertIn("public key: unknown (is the interface up?)", found)
        self.assertIn("no handshake known", found[4])
        self.assertIn(f"drift: peer {JOINER} is not held by wg0: keel mesh"
                      " sync on this node applies it again, or keel spec"
                      " apply --system", found)

    def test_off_the_live_system(self):
        found = status.lines(self.overlay, self.root, NOW, None)
        self.assertEqual(found[2], "not the live system: no handshake read")
        self.assertTrue(found[4].endswith("[2001:db8:2::20]:51820"))

    def test_no_identity_yet_or_a_damaged_one(self):
        found = status.lines(self.overlay, self.root, NOW, None)
        self.assertIn("none yet", found[1])
        self.assertIn("keel mesh create --adopt", found[1])
        os.makedirs(os.path.join(self.root, "var/lib/keel/mesh"))
        with open(os.path.join(self.root, identity.IDENTITY), "w") as fob:
            fob.write("x\n")
        found = status.lines(self.overlay, self.root, NOW, None)
        self.assertIn("does not hold a mesh identity", found[1])

    def test_no_mesh(self):
        for overlay in (None, {}):
            self.assertIn("in no mesh", status.lines(overlay, self.root,
                                                     NOW, None)[0])

    def test_a_handshake_in_the_future_reads_as_now(self):
        self.assertEqual(status.handshake(
            str(int((NOW + timedelta(seconds=5)).timestamp())), NOW),
            "handshake 0 s ago")


class TestPorts(unittest.TestCase):
    def test_opened_where_keel_s_firewall_has_the_set(self):
        run = Recorder()
        line = ports.open_port(51820, 3600, run, lambda argv: "set")
        self.assertEqual(run.calls, [("nft", "add", "element", "inet",
                                      "keel", "mesh_invites",
                                      "{ 51820 timeout 3600s }")])
        self.assertIn("opened in keel's firewall", line)

    def test_nothing_opened_elsewhere(self):
        run = Recorder()
        line = ports.open_port(51820, 3600, run, lambda argv: None)
        self.assertEqual(run.calls, [])
        self.assertIn("keel opened nothing", line)

    def test_an_element_that_cannot_be_added(self):
        line = ports.open_port(51820, 3600, Recorder(fail={"nft": 1}),
                               lambda argv: "set")
        self.assertIn("could not be opened", line)


class TestNode(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def test_an_absent_spec_is_empty(self):
        self.assertEqual(node(self.root).document(), {"version": 1})

    def test_an_invalid_document_is_not_written(self):
        found = node(self.root)
        with self.assertRaises(NodeError) as caught:
            found.write({"version": 1, "network": {"overlay": {
                "wireguard": {"address": "not an address"}}}})
        self.assertIn("instance.yaml", str(caught.exception))
        self.assertFalse(os.path.exists(found.path))

    def test_the_spec_is_written_root_s_alone(self):
        found = node(self.root)
        found.write(with_overlay({"version": 1},
                                 {"address": "fd00:1::1/64"}))
        self.assertEqual(os.stat(found.path).st_mode & 0o777, 0o600)
        self.assertEqual(found.overlay(), {"address": "fd00:1::1/64"})

    def test_a_change_that_is_not_the_overlay_is_not_made(self):
        found = node(self.root, apply=lambda doc, root, window: (
            marker.save(root, ""), marker.write(root, marker.Pending(
                "eth0", "x", 120).up("b1", 1.0)), 0)[-1])
        change = found.change(with_overlay({"version": 1},
                                           {"address": "fd00:1::1/64"}))
        self.assertIsNone(change.made)

    def test_a_peer_is_never_replaced(self):
        found = node(self.root, INVITER_SPEC)
        found.admit({"public_key": JOINER,
                     "allowed_ips": ["fd00:6b65:1::3/128"]})
        with self.assertRaises(NodeError) as caught:
            found.admit({"public_key": JOINER,
                         "allowed_ips": ["fd00:6b65:1::9/128"]})
        self.assertIn("never replaces", str(caught.exception))
        self.assertEqual(len(found.overlay()["peers"]), 1)

    def test_the_peers_the_answer_carries(self):
        found = node(self.root, INVITER_SPEC)
        found.admit({"public_key": JOINER,
                     "allowed_ips": ["fd00:6b65:1::3/128"],
                     "endpoint": "[2001:db8:2::20]:51820"})
        found.admit({"public_key": OTHER, "allowed_ips": ["fd00:6b65:2::/64"]})
        self.assertEqual(found.peers(OTHER)[0].address, "fd00:6b65:1::3")
        self.assertEqual(found.peers(JOINER), ())

    def test_the_live_apply(self):
        with mock.patch("keel.mesh.node.apply_system",
                        return_value=0) as applied:
            self.assertEqual(live_apply({"version": 1}, "/", 150), 0)
        applied.assert_called_once_with(
            {"version": 1}, "/", False, "keel mesh", defer_certificate=True,
            network_window=150, skip_uplink=True)

    def test_apply_s_lines_are_held_by_the_change_not_printed(self):
        def saying(doc, root, window):
            print("it reverts in 120 s unless `keel network confirm`")
            return Armed()(doc, root, window)
        found = node(self.root, INVITER_SPEC, apply=saying)
        with mock.patch("sys.stdout") as out:
            change = found.admit({"public_key": JOINER,
                                  "allowed_ips": ["fd00:6b65:1::3/128"]})
        self.assertFalse(out.write.called)
        self.assertEqual(change.lines,
                         ("it reverts in 120 s unless `keel network"
                          " confirm`",))
        said = []
        change.shown(said.append)
        self.assertEqual(said, list(change.lines))

    def test_a_spec_that_cannot_be_written(self):
        found = node(self.root)
        with mock.patch("keel.mesh.node.write_private",
                        side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(NodeError) as caught:
                found.write({"version": 1})
        self.assertIn("cannot be written: No space left on device",
                      str(caught.exception))

    def test_the_identity_a_node_keeps_is_adopted_again(self):
        identity.adopt(self.root, bytes(16))
        identity.adopt(self.root, bytes(16))
        self.assertEqual(identity.read(self.root), bytes(16))
        with self.assertRaises(ValueError) as caught:
            identity.adopt(self.root, bytes(range(16)))
        self.assertIn("in another mesh", str(caught.exception))
        self.assertEqual(identity.read(self.root), bytes(16))

    def test_the_latest_handshake_of_a_key(self):
        found = node(self.root, INVITER_SPEC)
        asked = []

        def wg(argv):
            asked.append(argv)
            return (f"{OTHER}\t0\n{JOINER}\t1790000000\nnot a line\n"
                    f"{INVITER_KEY}\tsoon\n")
        found.output = wg
        self.assertEqual(found.handshake(JOINER), 1790000000)
        self.assertEqual(asked[0], ("wg", "show", "wg0", "latest-handshakes"))
        for key in (OTHER, INVITER_KEY,
                    "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82F="):
            self.assertIsNone(found.handshake(key))
        found.output = lambda argv: None
        self.assertIsNone(found.handshake(JOINER))

    def test_defaults_are_live(self):
        found = Node("/", "/etc/keel/instance.yaml")
        self.assertIs(found.apply, live_apply)


if __name__ == "__main__":
    unittest.main()
