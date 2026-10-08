# Copyright (c) 2026 KeelLinux maintainers
"""The inviter's side: the listener's unit, serve, and accept (0048)

serve and accept against a scratch root's pending invite and a real
Node (tests/mesh_wire.py), with the socket loop replaced by a function
that plays the new node's requests into the Listener; the unit's argv
through a recording runner.
"""

import os
import shutil
import signal
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from mesh_helpers import (
    ASSIGNED,
    INVITE,
    INVITER,
    JOINER,
    KEY,
    NOW,
    SIGNER,
    Clock,
    confirm_body,
    join_body,
    reserved,
    signature,
)
from mesh_wire import (
    INVITER_SPEC,
    JOINER_OVERLAY,
    Armed,
    node,
    probes,
)
from test_network_window import Recorder

from keel import exits
from keel.mesh import acceptline, invites, inviting, protocol
from keel.mesh.acceptline import Accept
from keel.mesh.node import NodeError
from keel.network import marker

UPLINK = "2001:db8:2::20"


def saying(doc, root, window):
    """apply as the live one prints it"""
    print(f"keel mesh: bring the overlay wg0 up; it reverts in {window} s"
          " unless `keel network confirm` is run from a new session")
    return Armed()(doc, root, window)


class Played:
    """Bridge.run, without a listener: the requests it would forward"""

    def __init__(self, *requests, fail=None):
        self.requests = requests
        self.fail = fail
        self.calls = []
        self.answers = []

    def __call__(self, bridge):
        self.calls.append((bridge.params.host, bridge.params.port))
        self.bridge = bridge
        if self.fail:
            raise self.fail
        for path, body, local, peer in self.requests:
            self.answers.append(bridge.admitter.forward(
                path, signature(path, body), body, local, peer))


def join_request():
    return (protocol.JOIN, join_body(), "2001:db8:1::10", UPLINK)


def confirm_request():
    return (protocol.CONFIRM, confirm_body(), "fd00:6b65:1::1",
            JOINER_OVERLAY)


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.invite = reserved(self.root)
        self.node = node(self.root, INVITER_SPEC)
        self.out, self.err = [], []
        self.run = Recorder()
        self.inviter = inviting.Inviter(
            self.node, Clock(), self.out.append, self.err.append,
            run=self.run, output=lambda argv: "table inet keel {}")
        self.announced = []
        self.inviter.announce = self.announced.append
        keys = mock.patch("keel.mesh.inviting.wgkeys.public",
                          return_value=(INVITER, None))
        self.public = keys.start()
        self.addCleanup(keys.stop)

    def file(self):
        return os.path.join(self.root, invites.INVITES, f"{INVITE}.json")

    def peers(self):
        return self.node.overlay().get("peers")


class TestUnit(unittest.TestCase):
    def test_the_listener_runs_as_a_transient_unit(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        made = reserved(root)
        run = Recorder()
        self.assertIsNone(inviting.start(made, "/etc/keel/instance.yaml",
                                         NOW, run))
        self.assertEqual(run.calls, [(
            "systemd-run", f"--unit=keel-mesh-invite@{INVITE}", "--collect",
            "--quiet", f"--property=RuntimeMaxSec={3600 + inviting.LINGER}",
            f"--description=keel: the listener of mesh invite {INVITE}",
            sys.executable, "-m", "keel", "mesh", "serve", INVITE, "--spec",
            "/etc/keel/instance.yaml")])


class TestServe(Case):
    def test_a_join_and_its_confirmation(self):
        played = Played(join_request(), confirm_request())
        self.inviter.bridged = played
        self.assertEqual(inviting.serve_invite(self.inviter, INVITE),
                         exits.OK)
        self.assertEqual(played.calls, [("::", 51820)])
        self.assertEqual([one.status for one in played.answers], [200, 200])
        self.assertEqual(self.peers()[0]["public_key"], JOINER)
        self.assertFalse(marker.exists(self.root))
        self.assertFalse(os.path.exists(self.file()))
        self.assertIn(("nft", "delete", "element", "inet", "keel",
                       "mesh_invites", "{ 51820 }"), self.run.calls)
        self.assertEqual(self.err[-1], f"invite {INVITE}: joined and"
                         " confirmed")
        self.assertEqual(self.announced, [JOINER])

    def test_apply_s_lines_go_to_the_journal(self):
        self.node.apply = saying
        self.inviter.bridged = Played(join_request(), confirm_request())
        self.assertEqual(inviting.serve_invite(self.inviter, INVITE),
                         exits.OK)
        self.assertIn(f"invite {INVITE}: keel mesh: bring the overlay wg0"
                      " up; it reverts in 120 s unless `keel network"
                      " confirm` is run from a new session", self.err)

    def test_sigterm_ends_through_the_cleanup(self):
        with self.assertRaises(SystemExit):
            inviting.terminated(signal.SIGTERM, None)

    def test_an_invite_that_is_not_pending(self):
        invites.remove(self.root, INVITE)
        self.assertEqual(inviting.serve_invite(self.inviter, INVITE),
                         exits.MESH_REFUSED)
        self.assertIn("not pending", self.err[0])

    def test_no_key_to_answer_with(self):
        self.public.return_value = (None, "wg cannot read the key")
        self.assertEqual(inviting.serve_invite(self.inviter, INVITE),
                         exits.APPLY_FAILED)
        self.assertEqual(self.err, ["wg cannot read the key"])
        self.assertFalse(os.path.exists(self.file()))

    def test_a_port_already_taken(self):
        self.inviter.bridged = Played(fail=OSError(98, "Address in use"))
        self.assertEqual(inviting.serve_invite(self.inviter, INVITE),
                         exits.APPLY_FAILED)
        self.assertIn("Address in use", self.err[1])
        self.assertFalse(os.path.exists(self.file()))
        self.assertIn("expired unused", self.err[-1])
        self.assertEqual(self.announced, [])

    def test_another_invite_on_the_port_keeps_it_open(self):
        reserved(self.root, secret=bytes(32))
        self.inviter.bridged = Played()
        inviting.serve_invite(self.inviter, INVITE)
        self.assertNotIn("delete", [one[1] for one in self.run.calls])


class TestAccept(Case):
    def line(self, key=KEY, **changed):
        values = dict(public_key=JOINER, endpoint="[2001:db8:2::20]:51820",
                      address=ASSIGNED, invite_id=INVITE,
                      time=protocol.seconds(NOW), sign_key=SIGNER)
        values.update(changed)
        return acceptline.encode(Accept(**values), key)

    def accept(self, text=None, played=None):
        self.inviter.bridged = played or Played(confirm_request())
        return inviting.accept(self.inviter, text or self.line())

    def test_the_peer_applied_and_the_mesh_session_on_the_overlay(self):
        played = Played(confirm_request())
        self.assertEqual(self.accept(played=played), exits.OK, self.err)
        self.assertEqual(played.calls, [("fd00:6b65:1::1", 51820)])
        self.assertEqual(self.peers(), [{
            "public_key": JOINER, "allowed_ips": [f"{JOINER_OVERLAY}/128"],
            "persistent_keepalive": 25,
            "endpoint": "[2001:db8:2::20]:51820"}])
        self.assertIn(("systemctl", "stop", f"keel-mesh-invite@{INVITE}"),
                      self.run.calls)
        self.assertIn(("nft", "add", "element", "inet", "keel",
                       "mesh_invites", "{ 51820 timeout 120s }"),
                      self.run.calls)
        self.assertEqual(self.out, [f"accepted: {JOINER} is a peer of this"
                                    f" node at {JOINER_OVERLAY}"])
        self.assertEqual(self.announced, [JOINER])
        self.assertFalse(os.path.exists(self.file()))
        self.assertFalse(marker.exists(self.root))

    def test_a_new_node_without_an_endpoint(self):
        self.assertEqual(self.accept(self.line(endpoint=None)), exits.OK)
        self.assertNotIn("endpoint", self.peers()[0])

    def test_refused_before_anything_is_spent(self):
        for text, code, words in (
                ("keel1:x", exits.MESH_TOKEN_INVALID, "keel1a:"),
                (self.line(key=bytes(32)), exits.MESH_REFUSED,
                 "HMAC does not match"),
                (self.line(address="fd00:6b65:1::9/64"), exits.MESH_REFUSED,
                 "HMAC does not match"),
                (self.line(invite_id="00" * 8), exits.MESH_REFUSED,
                 "no pending invite")):
            with self.subTest(words=words):
                self.err.clear()
                self.assertEqual(self.accept(text), code)
                self.assertIn(words, self.err[0])
                self.assertFalse(invites.read(self.root, INVITE).consumed)
                self.assertEqual(self.node.apply.documents, [])

    def test_a_reservation_in_etcd_that_is_gone_refuses_it(self):
        """keel#102: an invite that reserved its address in etcd is
        accepted only while that reservation names it"""
        invites.remove(self.root, INVITE)
        invites.reserve(self.root, NOW, lambda others: replace(
            self.invite, etcd_reserved=True))
        with mock.patch("keel.mesh.inviting.reservation_problem",
                        return_value="the reservation is gone") as asked:
            self.assertEqual(self.accept(), exits.MESH_REFUSED)
        self.assertEqual(asked.call_args.args[1].invite_id, INVITE)
        self.assertEqual(self.err, ["the reservation is gone"])
        self.assertFalse(invites.read(self.root, INVITE).consumed)
        self.assertEqual(self.node.apply.documents, [])

    def test_the_inviter_s_own_key_is_refused(self):
        self.assertEqual(self.accept(self.line(public_key=INVITER)),
                         exits.MESH_REFUSED)
        self.assertIn("this node's own", self.err[-1])
        self.assertIsNone(self.node.overlay().get("peers"))

    def test_a_change_waiting(self):
        marker.save(self.root, "")
        marker.write(self.root, marker.Pending("eth0", "x", 120))
        self.assertEqual(self.accept(), exits.MESH_REFUSED)
        self.assertIn("a network change waits", self.err[0])

    def test_no_key(self):
        self.public.return_value = (None, "no key")
        self.assertEqual(self.accept(), exits.APPLY_FAILED)
        self.assertFalse(invites.read(self.root, INVITE).consumed)

    def test_an_invite_used_already(self):
        invites.consume(self.root, INVITE, NOW)
        self.assertEqual(self.accept(), exits.MESH_REFUSED)
        self.assertIn("already used", self.err[0])

    def test_the_change_does_not_come_up(self):
        def failing(doc, root, window):
            print("wg-quick up failed")
            return 16
        self.node.apply = failing
        self.assertEqual(self.accept(), exits.APPLY_FAILED)
        self.assertEqual(self.err[-2], "wg-quick up failed")
        self.assertIn("apply exited 16", self.err[-1])
        self.assertFalse(os.path.exists(self.file()))

    def test_a_spec_that_cannot_take_the_peer(self):
        with mock.patch.object(self.node, "write",
                               side_effect=NodeError("full")):
            self.assertEqual(self.accept(), exits.MESH_REFUSED)
        self.assertEqual(self.err[-1], "full; the invite is spent")

    def test_the_new_node_never_comes(self):
        self.node.apply = saying
        self.assertEqual(self.accept(played=Played()),
                         exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("not confirmed", self.err[-1])
        self.assertIn("unless `keel network confirm`", self.err[-2])
        self.assertTrue(marker.exists(self.root))
        self.assertEqual(self.announced, [])

    def test_apply_s_revert_warning_is_not_shown_when_it_confirms(self):
        self.node.apply = saying
        self.assertEqual(self.accept(), exits.OK)
        self.assertNotIn("unless", "\n".join(self.err))

    def test_the_overlay_address_cannot_be_bound(self):
        found = self.accept(played=Played(fail=OSError(99, "not here")))
        self.assertEqual(found, exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("cannot serve [fd00:6b65:1::1]:51820",
                      self.err[-1])

    def test_a_confirmation_the_route_check_refuses(self):
        self.node.probes = lambda: probes("wg0")
        played = Played(confirm_request())
        self.assertEqual(self.accept(played=played),
                         exits.NETWORK_NOT_CONFIRMED)
        answer = protocol.confirm_answer(played.answers[0].body)
        self.assertFalse(answer.confirmed)


class TestClose(Case):
    def test_the_port_closes_with_the_last_invite_on_it(self):
        self.inviter.close(self.invite)
        self.assertFalse(os.path.exists(self.file()))
        self.assertEqual(self.run.calls, [(
            "nft", "delete", "element", "inet", "keel", "mesh_invites",
            "{ 51820 }")])

    def test_the_listener_of_each_invite_and_its_socket(self):
        played = Played()
        self.inviter.bridged = played
        inviting.serve_invite(self.inviter, INVITE)
        found = played.bridge
        self.assertEqual(found.path, os.path.join(
            self.root, "run/keel", f"mesh-listen-{INVITE}", "bridge.sock"))
        self.assertEqual((found.params.host, found.params.overlay,
                          found.params.joined), ("::", "fd00:6b65:1::1",
                                                 None))
        # the listener is never given the invite's HMAC key
        self.assertNotIn("hmac", repr(found.params))
        self.assertEqual((found.certificate, found.tls_key),
                         (self.invite.certificate, self.invite.tls_key))

    def test_the_listener_starts_as_its_unit_unless_told(self):
        started = []
        self.inviter.start = lambda *args: started.append(args) or "unit"
        self.assertEqual(self.inviter.starter(INVITE, 30)("path"), "unit")
        self.assertEqual(started, [(INVITE, "path", 30)])
        self.inviter.start = None
        with mock.patch("keel.mesh.inviting.bridge.start_unit",
                        return_value="unit") as unit:
            self.assertEqual(self.inviter.starter(INVITE, 30)("path"),
                             "unit")
        unit.assert_called_once_with(INVITE, "path", 30, self.run,
                                     self.inviter.output)

    def test_the_announcement_goes_through_keel_mesh_sync(self):
        self.inviter.announce = None
        with mock.patch("keel.mesh.inviting.sync.announce") as announce:
            self.inviter.announced(JOINER)
        syncer, key = announce.call_args.args
        self.assertEqual((syncer.node, key), (self.node, JOINER))

    def test_own(self):
        self.assertEqual(self.inviter.own(), (INVITER, "fd00:6b65:1::1/64"))
        self.public.return_value = (None, "unreadable")
        self.assertEqual(self.inviter.own(), (None, "unreadable"))
        self.assertEqual(self.inviter.root, self.root)


if __name__ == "__main__":
    unittest.main()
