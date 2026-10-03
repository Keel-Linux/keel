# Copyright (c) 2026 KeelLinux maintainers
"""The root side of an invite, its handler a function (decision 0048)

Admitter.forward against a scratch root's pending invite and a node that
records (tests/mesh_helpers.py): every refusal with its status and
reason, checked again whatever the listener checked, one use under the
lock, replays, a key the inviter already knows, the join that admits
the new node and the confirmation that must arrive over the overlay.
"""

import json
import os
import shutil
import tempfile
import unittest
from os.path import join
from unittest import mock

from mesh_helpers import (
    INVITE,
    INVITER,
    JOINER,
    KEY,
    MADE,
    NOW,
    OTHER,
    OWN,
    Clock,
    FakeNode,
    confirm_body,
    join_body,
    reserved,
    signature,
)

from keel.mesh import admit, invites, protocol
from keel.mesh.admit import Admitter, stopped
from keel.mesh.node import NodeError
from keel.mesh.protocol import Peer
from keel.network import session

UPLINK = "2001:db8:2::20"
OVERLAY_OWN = "fd00:6b65:1::1"
OVERLAY_NEW = "fd00:6b65:1::3"


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.invite = reserved(self.root)
        self.node = FakeNode()
        self.clock = Clock()
        self.logged = []
        self.slept = []
        self.listener = Admitter(self.root, self.invite, INVITER, OWN,
                                 self.node, self.clock, self.logged.append,
                                 sleep=self.slept.append)

    def join(self, body=None, sign=None, path=protocol.JOIN, peer=UPLINK):
        body = join_body() if body is None else body
        found = sign if sign is not None else signature(path, body)
        return self.listener.forward(path, found, body, "::", peer)

    def confirm(self, body=None, local=OVERLAY_OWN, peer=OVERLAY_NEW,
                sign=None):
        body = confirm_body() if body is None else body
        found = sign if sign is not None else signature(protocol.CONFIRM,
                                                        body)
        return self.listener.forward(protocol.CONFIRM, found, body,
                                     local, peer)

    def error(self, response):
        return json.loads(response.body)["error"]

    def file(self):
        return join(self.root, invites.INVITES, f"{INVITE}.json")


class TestJoin(Case):
    def test_a_join_admits_the_new_node_and_answers_signed(self):
        self.node.known = (Peer(OTHER, "[2001:db8:3::30]:51820",
                                "fd00:6b65:1::7"),)
        body = join_body()
        found = self.join(body)
        self.assertEqual(found.status, 200, found.body)
        self.assertTrue(protocol.signed(KEY, protocol.ANSWER, protocol.JOIN,
                                        found.body, found.signature))
        answer = protocol.join_answer(found.body)
        self.assertEqual(answer.nonce, json.loads(body)["nonce"])
        self.assertEqual((answer.invite_id, answer.public_key,
                          answer.address, answer.etcd, answer.window),
                         (INVITE, INVITER, OWN, "none", 120))
        self.assertEqual(answer.peers, self.node.known)
        self.assertEqual(self.node.admitted, [{
            "public_key": JOINER, "allowed_ips": [f"{OVERLAY_NEW}/128"],
            "endpoint": "[2001:db8:2::20]:51820"}])
        self.assertTrue(invites.read(self.root, INVITE).consumed)
        self.assertIsNone(self.listener.confirmed)
        self.assertIn(f"invite {INVITE}: join from {UPLINK}, key {JOINER},"
                      f" endpoint [2001:db8:2::20]:51820, at {OVERLAY_NEW}",
                      self.logged)

    def test_a_new_node_without_an_endpoint(self):
        self.assertEqual(self.join(join_body(endpoint=None)).status, 200)
        self.assertNotIn("endpoint", self.node.admitted[0])
        self.assertIn("endpoint none", self.logged[0])

    def test_a_second_join_finds_the_invite_used(self):
        self.join()
        found = self.join()
        self.assertEqual(found.status, 410)
        self.assertIn("already used", self.error(found))
        self.assertEqual(len(self.node.admitted), 1)

    def test_an_invite_consumed_elsewhere_is_refused(self):
        invites.consume(self.root, INVITE, NOW)
        found = self.join()
        self.assertEqual(found.status, 410)
        self.assertIn("already used", self.error(found))
        self.assertEqual(self.node.admitted, [])

    def test_a_change_that_did_not_come_up_spends_the_invite(self):
        self.node.made, self.node.code = None, 16
        found = self.join()
        self.assertEqual(found.status, 500)
        self.assertIn("could not apply", self.error(found))
        self.assertIs(self.listener.confirmed, False)
        self.assertIn("apply exited 16", self.logged[-1])

    def test_a_spec_that_cannot_take_the_peer_spends_the_invite(self):
        def refuse(peer, window=None):
            raise NodeError("instance.yaml cannot be written: disk full")
        self.node.admit = refuse
        found = self.join()
        self.assertEqual(found.status, 500)
        self.assertIs(self.listener.confirmed, False)
        self.assertIn("cannot be written: disk full; the invite is spent",
                      self.logged[-1])

    def test_a_change_waiting_leaves_the_invite_pending(self):
        self.node.is_waiting = True
        found = self.join()
        self.assertEqual(found.status, 409)
        self.assertIn("another network change waits", self.error(found))
        self.assertFalse(invites.read(self.root, INVITE).consumed)
        self.assertIsNone(self.listener.joined)


class TestRefusals(Case):
    def test_each_refusal_with_its_status_and_reason(self):
        good = join_body()
        for kwargs, status, words in (
                (dict(path="/"), 404, "no such request"),
                (dict(body=b"{}"), 400, "malformed request"),
                (dict(body=join_body(invite_id="00" * 8)), 403,
                 "is not the one this listener serves"),
                (dict(body=good, sign="00" * 32), 403, "bad HMAC"),
                (dict(body=good, sign=""), 403, "bad HMAC"),
                (dict(body=join_body(time=protocol.seconds(NOW) - 600)),
                 403, "time is more than"),
                (dict(body=join_body(address="fd00:6b65:1::9/64")), 403,
                 "not the address this invite reserved")):
            with self.subTest(kwargs=list(kwargs)):
                self.setUp()
                found = self.join(**kwargs)
                self.assertEqual(found.status, status)
                self.assertIn(words, self.error(found))
                self.assertIsNone(found.signature)
                self.assertEqual(self.node.admitted, [])
                self.assertFalse(invites.read(self.root, INVITE).consumed)
                self.assertIn("refused a request from 2001:db8:2::20",
                              self.logged[0])

    def test_a_body_longer_than_any_join(self):
        found = self.listener.forward(protocol.JOIN, None, None, "::",
                                      UPLINK)
        self.assertEqual(found.status, 413)

    def test_a_replayed_request_is_refused(self):
        self.node.is_waiting = True
        body = join_body()
        self.assertEqual(self.join(body).status, 409)
        self.node.is_waiting = False
        found = self.join(body)
        self.assertEqual(found.status, 403)
        self.assertIn("replayed", self.error(found))

    def test_a_cancel_removes_the_invite(self):
        self.listener.cancel("5 requests named it and failed its HMAC")
        self.assertFalse(os.path.exists(self.file()))
        self.assertIn("cancelled, 5 requests named it", self.logged[-1])
        self.assertEqual(stopped(self.listener), f"invite {INVITE}: cancelled")

    def test_no_secret_in_the_log(self):
        body = join_body()
        sign = signature(protocol.JOIN, body)
        self.join(body, sign)
        self.join(sign="00" * 32)
        logged = "\n".join(self.logged)
        for secret in (KEY.hex(), sign, self.invite.tls_key):
            self.assertNotIn(secret, logged)


class TestConfirm(Case):
    def test_before_any_join(self):
        found = self.confirm()
        self.assertEqual(found.status, 409)
        self.assertEqual(self.node.origins, [])

    def test_the_handshake_and_the_signed_confirmation(self):
        self.join()
        body = confirm_body()
        found = self.confirm(body)
        self.assertEqual(found.status, 200, found.body)
        self.assertTrue(found.final)
        self.assertTrue(protocol.signed(KEY, protocol.ANSWER,
                                        protocol.CONFIRM, found.body,
                                        found.signature))
        answer = protocol.confirm_answer(found.body)
        self.assertTrue(answer.confirmed)
        self.assertEqual(answer.nonce, json.loads(body)["nonce"])
        [(origin, made)] = self.node.origins
        # the root side's own evidence: the addresses are its own facts
        self.assertEqual((origin.kind, origin.local, origin.peer),
                         (session.MESH, OVERLAY_OWN, OVERLAY_NEW))
        self.assertIn("a WireGuard handshake from the new peer's key",
                      origin.detail)
        self.assertEqual(self.node.asked, [JOINER])
        self.assertEqual(made, MADE)
        self.assertIs(self.listener.confirmed, True)
        self.assertEqual(stopped(self.listener),
                         f"invite {INVITE}: joined and confirmed")

    def test_a_refused_confirmation_is_answered_and_ends_it(self):
        self.join()
        self.node.confirmed = False
        answer = protocol.confirm_answer(self.confirm().body)
        self.assertFalse(answer.confirmed)
        self.assertIs(self.listener.confirmed, False)
        self.assertIn("not confirmed", stopped(self.listener))

    def test_another_key_s_confirmation(self):
        self.join()
        found = self.confirm(body=confirm_body(public_key=OTHER))
        self.assertEqual(found.status, 403)
        self.assertEqual(self.node.origins, [])

    def test_the_handshake_is_waited_for_a_little(self):
        self.join()
        seen = iter([None, None, int(NOW.timestamp())])
        self.node.handshake = lambda key: next(seen)
        self.assertEqual(self.confirm().status, 200)
        self.assertEqual(self.slept, [admit.HANDSHAKE_POLL] * 2)


class TestALyingListener(Case):
    """What a compromised listener can forward, and what it gets: it
    holds no HMAC key, and its addresses decide nothing"""

    def test_it_cannot_choose_the_joiner_s_key(self):
        forged = join_body(public_key=OTHER)
        found = self.listener.forward(protocol.JOIN, "00" * 32, forged,
                                      "::", UPLINK)
        self.assertEqual(found.status, 403)
        self.assertIn("bad HMAC", self.error(found))
        self.assertEqual(self.node.admitted, [])
        self.assertFalse(invites.read(self.root, INVITE).consumed)

    def test_it_cannot_confirm_without_the_tunnel(self):
        """A join was admitted; the new node never came over the tunnel.
        The listener reports the right addresses for a request it forged
        or replayed: no handshake from the key, no confirmation"""
        self.join()
        self.node.handshake_at = None
        found = self.confirm(local=OVERLAY_OWN, peer=OVERLAY_NEW)
        self.assertEqual(found.status, 409)
        self.assertIn("no WireGuard handshake", self.error(found))
        self.assertEqual(self.node.origins, [])
        self.assertIsNone(self.listener.confirmed)
        self.assertEqual(len(self.slept), int(
            admit.HANDSHAKE_WAIT / admit.HANDSHAKE_POLL))

    def test_a_handshake_older_than_the_join_is_not_the_tunnel(self):
        self.join()
        self.node.handshake_at = int(NOW.timestamp()) - 1
        self.assertEqual(self.confirm().status, 409)

    def test_its_addresses_decide_nothing(self):
        self.join()
        found = self.confirm(local="2001:db8:1::10", peer="2001:db8:9::9")
        self.assertEqual(found.status, 200)
        [(origin, _)] = self.node.origins
        self.assertEqual((origin.local, origin.peer),
                         (OVERLAY_OWN, OVERLAY_NEW))

    def test_five_forged_requests_naming_the_invite_cancel_it(self):
        for number in range(5):
            found = self.join(sign="00" * 32)
            self.assertEqual(found.final, number == 4)
        self.assertFalse(os.path.exists(self.file()))
        self.assertTrue(self.listener.cancelled)
        found = self.join()
        self.assertEqual((found.status, found.final), (410, True))

    def test_a_scanner_s_requests_cancel_nothing(self):
        for _ in range(6):
            self.join(body=join_body(invite_id="00" * 8), sign="00" * 32)
            self.join(body=b"{}")
        self.assertFalse(self.listener.cancelled)
        self.assertTrue(os.path.exists(self.file()))


class TestLog(Case):
    def test_the_journal_by_default(self):
        listener = Admitter(self.root, self.invite, INVITER, OWN, self.node,
                            self.clock)
        with mock.patch("builtins.print") as printed:
            listener.forward("/", None, b"", "::", UPLINK)
        self.assertIn("refused a request", printed.call_args.args[0])


class TestKnownKeys(Case):
    def test_a_key_the_inviter_knows_is_refused_before_it_is_spent(self):
        for key in (INVITER, OTHER):
            with self.subTest(key=key):
                self.setUp()
                self.node.overlay_value = {"peers": [{"public_key": OTHER}]}
                found = self.join(join_body(public_key=key))
                self.assertEqual(found.status, 409)
                self.assertIn("a key of its own", self.error(found))
                self.assertFalse(invites.read(self.root, INVITE).consumed)
                self.assertEqual(self.node.admitted, [])


if __name__ == "__main__":
    unittest.main()
