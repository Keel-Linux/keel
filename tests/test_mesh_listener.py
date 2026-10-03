# Copyright (c) 2026 KeelLinux maintainers
"""The unprivileged listener's checks, before anything reaches root

Listener.handle with a backend that records: what is forwarded (the
signature unchecked: the listener has no HMAC key) and what is refused,
what a refusal counts towards (the source's limit), what the root
side's answers teach the listener (its `final` ends it), and when it
is finished.
"""

import io
import json
import socket
import unittest
from datetime import timedelta
from unittest import mock

from mesh_helpers import (
    INVITE,
    JOINER,
    NOW,
    Clock,
    confirm_body,
    join_body,
    signature,
)

from keel.mesh import listener, protocol
from keel.mesh.admit import Response
from keel.mesh.listener import Capped, Limiter, Listener, Params

UPLINK = "2001:db8:2::20"
OVERLAY = "fd00:6b65:1::1"
JOINER_OVERLAY = "fd00:6b65:1::3"
ANSWER = protocol.dumps(protocol.JoinAnswer(
    invite_id=INVITE, nonce="00" * 16,
    public_key="nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=",
    address="fd00:6b65:1::1/64", peers=(), etcd="none", window=120))


def params(**changed) -> Params:
    values = dict(invite_id=INVITE,
                  expires=NOW + timedelta(hours=1), host="::", port=51820,
                  overlay=OVERLAY)
    values.update(changed)
    return Params(**values)


class Backend:
    def __init__(self, status=200, body=ANSWER, final=False):
        self.status = status
        self.body = body
        self.final = final
        self.forwarded = []

    def forward(self, path, signature, body, local, peer):
        self.forwarded.append((path, signature, local, peer))
        return Response(self.status, self.body, "sig", self.final)


class Case(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.backend = Backend()
        self.logged = []
        self.listener = Listener(params(), self.backend, self.clock,
                                 self.logged.append)

    def join(self, body=None, sign=None, method="POST", path=protocol.JOIN,
             peer=UPLINK):
        body = join_body() if body is None else body
        found = sign if sign is not None else signature(path, body)
        return self.listener.handle(method, path, found, body, "::", peer)

    def confirm(self, local=OVERLAY, peer=JOINER_OVERLAY, body=None):
        body = confirm_body() if body is None else body
        return self.listener.handle(
            "POST", protocol.CONFIRM, signature(protocol.CONFIRM, body),
            body, local, peer)


class TestForwarded(Case):
    def test_a_good_join_is_forwarded_and_its_answer_learnt(self):
        body = join_body()
        found = self.join(body)
        self.assertEqual(found.status, 200)
        self.assertEqual(self.backend.forwarded,
                         [(protocol.JOIN, signature(protocol.JOIN, body),
                           "::", UPLINK)])
        self.assertEqual(self.listener.joined,
                         (JOINER, JOINER_OVERLAY, NOW + timedelta(
                             seconds=120)))
        self.assertEqual(self.join().status, 410)

    def test_the_confirmation_over_the_overlay_only(self):
        self.join()
        self.backend.body = protocol.dumps(protocol.ConfirmAnswer(
            invite_id=INVITE, nonce="00" * 16, confirmed=True, detail=""))
        for local, peer in ((UPLINK, JOINER_OVERLAY), (OVERLAY, UPLINK)):
            self.assertEqual(self.confirm(local, peer).status, 403)
        self.assertEqual(self.confirm().status, 200)
        self.assertTrue(self.listener.confirmed)
        self.assertTrue(self.listener.finished)

    def test_no_confirmation_before_a_join(self):
        self.assertEqual(self.confirm().status, 409)
        self.assertEqual(self.backend.forwarded, [])

    def test_a_refusal_from_the_root_side_is_passed_on(self):
        self.backend.status, self.backend.body = 409, b'{"error": "x"}'
        self.assertEqual(self.join().status, 409)
        self.assertIsNone(self.listener.joined)
        self.assertFalse(self.listener.finished)

    def test_an_answer_it_cannot_read_ends_it(self):
        self.backend.body = b"{}"
        self.assertEqual(self.join().status, 200)
        self.assertTrue(self.listener.finished)
        self.assertIn("cannot be read", self.logged[-1])

    def test_a_final_answer_or_a_root_side_gone_ends_it(self):
        for status, final in ((500, True), (410, True), (503, False)):
            with self.subTest(status=status):
                self.setUp()
                self.backend.status, self.backend.final = status, final
                self.join()
                self.assertTrue(self.listener.finished)

    def test_a_signature_is_the_root_side_s_to_check(self):
        """Without the key the listener forwards a forged request, and
        the root side refuses it"""
        self.backend.status, self.backend.body = 403, b'{"error": "x"}'
        self.assertEqual(self.join(sign="00" * 32).status, 403)
        self.assertEqual(len(self.backend.forwarded), 1)
        self.assertEqual(self.backend.forwarded[0][1], "00" * 32)


class TestRefused(Case):
    def test_nothing_unchecked_reaches_the_root_side(self):
        for kwargs in (dict(path="/"), dict(method="GET"),
                       dict(body=b"{}"),
                       dict(body=join_body(invite_id="00" * 8)),
                       dict(body=join_body(
                           time=protocol.seconds(NOW) - 600))):
            with self.subTest(kwargs=list(kwargs)):
                self.assertGreaterEqual(self.join(**kwargs).status, 400)
        self.assertEqual(self.backend.forwarded, [])

    def test_a_replay_is_refused_here(self):
        body = join_body()
        self.backend.status = 409
        self.join(body)
        found = self.join(body)
        self.assertEqual(found.status, 403)
        self.assertIn("replayed", json.loads(found.body)["error"])

    def test_a_scanner_does_not_cancel_the_invite(self):
        for kwargs in (dict(path="/"), dict(body=b"{}"),
                       dict(body=join_body(invite_id="00" * 8),
                            sign="00" * 32)) * 3:
            self.join(peer="2001:db8:9::1", **kwargs)
        self.assertEqual(self.backend.forwarded, [])
        self.assertFalse(self.listener.finished)

    def test_the_root_side_s_refusals_count_for_the_source(self):
        self.backend.status, self.backend.body = 403, b'{"error": "x"}'
        for _ in range(5):
            self.join()
        self.assertTrue(self.listener.blocked(UPLINK))

    def test_a_source_refused_five_times_is_not_answered(self):
        for _ in range(5):
            self.assertFalse(self.listener.blocked(UPLINK))
            self.join(path="/")
        self.assertTrue(self.listener.blocked(UPLINK))
        self.assertFalse(self.listener.blocked("2001:db8:9::1"))
        self.clock.now += timedelta(seconds=61)
        self.assertFalse(self.listener.blocked(UPLINK))

    def test_each_refusal_is_logged_with_its_source(self):
        self.join(path="/")
        self.assertIn(f"invite {INVITE}: refused a request from {UPLINK}",
                      self.logged[0])


class TestFinished(Case):
    def test_at_the_expiry_unused(self):
        self.assertFalse(self.listener.finished)
        self.clock.now = NOW + timedelta(hours=1)
        self.assertTrue(self.listener.finished)

    def test_a_join_waits_one_window_for_its_confirmation(self):
        self.clock.now = NOW + timedelta(minutes=59, seconds=50)
        self.join(join_body(time=protocol.seconds(self.clock.now)))
        self.clock.now += timedelta(seconds=119)
        self.assertFalse(self.listener.finished)
        self.clock.now += timedelta(seconds=1)
        self.assertTrue(self.listener.finished)

    def test_accept_s_listener_serves_the_confirmation_alone(self):
        found = Listener(params(joined=(JOINER, JOINER_OVERLAY,
                                        NOW + timedelta(seconds=120))),
                         self.backend, self.clock)
        self.assertEqual(found.name, f"invite {INVITE}")
        with mock.patch("builtins.print") as printed:
            self.assertEqual(found.handle(
                "POST", protocol.JOIN, None, b"", "::", UPLINK).status, 410)
        self.assertIn("already used", printed.call_args.args[0])


class TestCapped(unittest.TestCase):
    def test_the_budget_covers_lines_and_bodies(self):
        reader = Capped(io.BytesIO(b"line\n" + b"x" * 20), 15)
        self.assertEqual(reader.readline(), b"line\n")
        self.assertEqual(reader.read(10), b"x" * 10)
        with self.assertRaises(ValueError):
            reader.read(10)
        reader.close()
        self.assertTrue(reader.inner.closed)


class TestSockets(unittest.TestCase):
    def test_a_port_already_taken(self):
        first = listener.bound("::1", 0)
        with first, self.assertRaises(OSError):
            listener.bound("::1", first.getsockname()[1])

    def test_the_deadline_on_a_socket_already_gone(self):
        gone = socket.socket()
        gone.close()
        listener.shut([gone])


class TestLimiter(unittest.TestCase):
    def test_old_refusals_are_forgotten(self):
        clock = Clock()
        found = Limiter(clock)
        for _ in range(4):
            found.refused("a")
        clock.now += listener.PERIOD + timedelta(seconds=1)
        found.refused("a")
        self.assertFalse(found.blocked("a"))
        self.assertEqual(len(found.seen["a"]), 1)


if __name__ == "__main__":
    unittest.main()
