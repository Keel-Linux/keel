# Copyright (c) 2026 KeelLinux maintainers
"""The pinned HTTPS channel, end to end on the loopback

The real unprivileged listener's server (keel.mesh.listener.run) with
the invite's real certificate from openssl, in front of the real
Admitter, served from a thread on [::1], and the real client
(keel.mesh.channel.post): the pin checked before anything is sent, the
answer's HMAC, each failure told apart; and against someone holding
the port, the reading's deadline, the slots, the slots kept for the
overlay, the size cap and the sources refused too often.
"""

import contextlib
import json
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from mesh_helpers import (
    INVITER,
    KEY,
    OWN,
    FakeNode,
    join_body,
    reserved,
    tls,
)

from keel.mesh import certificate, channel, listener, protocol
from keel.mesh.admit import Admitter, Response
from keel.mesh.channel import ChannelError, Forged, Refused, Unreachable
from keel.mesh.listener import Listener, Params, bound, run


def free_port() -> int:
    with socket.socket(socket.AF_INET6) as probe:
        probe.bind(("::1", 0))
        return probe.getsockname()[1]


class Served(unittest.TestCase):
    """A listener on [::1] for the length of one test"""

    listener_class = Listener
    host = "::1"
    overlay = "fd00:6b65:1::1"
    constants: dict = {}

    def setUp(self):
        for name, value in self.constants.items():
            patcher = mock.patch.object(listener, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.port = free_port()
        now = datetime.now(timezone.utc)
        self.invite = reserved(self.root, port=self.port,
                               expires=now + timedelta(hours=1))
        self.node = FakeNode()
        self.logged = []
        admitter = Admitter(self.root, self.invite, INVITER, OWN, self.node,
                            lambda: now, self.logged.append)
        self.listener = self.listener_class(
            Params(self.invite.invite_id,
                   self.invite.expires, self.host, self.port, self.overlay),
            admitter, lambda: now, self.logged.append)
        context = channel.server_context(self.invite.certificate,
                                         self.invite.tls_key)
        server = bound(self.host, self.port)
        self.thread = threading.Thread(
            target=run, args=(server, self.listener, context),
            kwargs={"poll": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.pin = certificate.fingerprint(self.invite.certificate)

    def stop(self):
        self.listener.ended = True
        self.thread.join(10)

    def settled(self, within: float = 10.0) -> None:
        """Every connection the listener took is served and its slot
        given back. The listener takes one connection per source at a
        time and gives the slot back after it sent the answer: a client
        in this process that posts again at once from [::1] can come
        before that, and its connection is closed unanswered"""
        deadline = time.monotonic() + within
        while any(one.name.endswith("(serve_one)")
                  for one in threading.enumerate()):
            self.assertLess(time.monotonic(), deadline,
                            "the listener still serves a connection")
            time.sleep(0.01)

    def post(self, body=None, path=protocol.JOIN, key=KEY, pin=None,
             host="::1"):
        now = protocol.seconds(datetime.now(timezone.utc))
        body = join_body(time=now) if body is None else body
        # the answer is waited for as the joiner waits for it: the join
        # signs and checks its evidence with openssl processes, which a
        # loaded CI runner can make slower than a few seconds (keel#94)
        return channel.post(host, self.port, path, body, key,
                            pin or self.pin, connect_timeout=2,
                            answer_timeout=channel.ANSWER_TIMEOUT)

    def held(self, source=None, host="127.0.0.1"):
        """A connection that never starts its TLS handshake"""
        raw = socket.create_connection(
            (host, self.port), timeout=5,
            source_address=(source, 0) if source else None)
        self.addCleanup(raw.close)
        return raw

    def dropped(self, source):
        """Whether a connection from `source` is closed unanswered"""
        raw = self.held(source)
        try:
            channel.client_context().wrap_socket(raw)
        except OSError:
            return True
        return False


class TestPost(Served):
    def test_a_join_round_trip_through_the_admitter(self):
        reply = self.post()
        self.assertEqual((reply.local, reply.peer), ("::1", "::1"))
        answer = protocol.join_answer(reply.body)
        self.assertEqual(answer.public_key, INVITER)
        self.assertEqual(len(self.node.admitted), 1)

    def test_another_certificate_is_refused_before_anything_is_sent(self):
        other = certificate.fingerprint(certificate.make()[1])
        with self.assertRaises(Forged) as caught:
            self.post(pin=other)
        self.assertIn("not the one the token pins", str(caught.exception))
        self.assertEqual(self.logged, [])

    def test_a_refusal_says_why(self):
        with self.assertRaises(Refused) as caught:
            self.post(key=bytes(32))
        self.assertIn("bad HMAC", str(caught.exception))

    def test_a_body_too_long_is_refused_unread(self):
        """Refused without reading it; the client may see the refusal or,
        as the unread body is discarded, a reset first"""
        with self.assertRaises(ChannelError):
            self.post(body=b"x" * (protocol.MAX_BODY + 1))
        self.stop()
        self.assertIn("longer than any join", self.logged[-1])

    def test_a_bad_content_length(self):
        context = channel.client_context()
        with socket.create_connection(("::1", self.port), timeout=5) as raw, \
                context.wrap_socket(raw) as conn:
            conn.sendall(b"POST /v1/join HTTP/1.1\r\nHost: x\r\n"
                         b"Content-Length: many\r\n\r\n")
            self.assertIn(b" 413 ", conn.recv(4096))

    def test_a_client_without_tls_does_not_stop_the_listener(self):
        with socket.create_connection(("::1", self.port), timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
            with contextlib.suppress(OSError):
                raw.recv(100)
        self.settled()
        self.assertEqual(protocol.join_answer(self.post().body).public_key,
                         INVITER)


class TestHeld(Served):
    constants = {"REQUEST_DEADLINE": 0.5}

    def test_a_slow_client_is_cut_at_the_deadline(self):
        context = channel.client_context()
        with socket.create_connection(("::1", self.port), timeout=5) as raw, \
                context.wrap_socket(raw) as conn:
            conn.sendall(b"POST /v1/join HTTP/1.1\r\n")
            self.assertEqual(conn.recv(100), b"")

    def test_headers_longer_than_the_cap_are_not_read(self):
        context = channel.client_context()
        with socket.create_connection(("::1", self.port), timeout=5) as raw, \
                context.wrap_socket(raw) as conn:
            with contextlib.suppress(OSError):
                conn.sendall(b"POST /v1/join HTTP/1.1\r\n" + b"X-A: "
                             + b"a" * 9000 + b"\r\n\r\n")
            with contextlib.suppress(OSError):
                self.assertNotIn(b"HTTP/1", conn.recv(100))


class TestSlots(Served):
    """Sources on the IPv4 loopback, 127.0.0.2 and up, take the slots;
    [::1] is this test's overlay address"""

    constants = {"SLOTS": 1}
    host = "::"
    overlay = "::1"

    def test_the_slots_and_those_kept_for_the_overlay(self):
        self.held("127.0.0.2")
        self.assertTrue(self.dropped("127.0.0.3"))
        # the overlay's connections have slots of their own
        answer = protocol.join_answer(self.post().body)
        self.assertEqual(answer.public_key, INVITER)


class TestPerSource(Served):
    host = "::"

    def test_one_connection_at_a_time_from_one_source(self):
        self.held("127.0.0.2")
        self.assertTrue(self.dropped("127.0.0.2"))
        self.assertFalse(self.dropped("127.0.0.3"))


class TestBlocked(Served):
    def test_a_source_refused_too_often_is_not_answered(self):
        for _ in range(listener.MAX_REFUSED):
            self.settled()
            with self.assertRaises(Refused):
                self.post(body=b"{}")
        self.settled()
        with self.assertRaises(ChannelError) as caught:
            self.post()
        self.assertNotIsInstance(caught.exception, Refused)


class TestUnreachable(unittest.TestCase):
    def test_nothing_listening(self):
        with self.assertRaises(Unreachable) as caught:
            channel.post("::1", free_port(), protocol.JOIN, b"{}", KEY,
                         bytes(32), connect_timeout=2)
        self.assertIn("[::1]:", str(caught.exception))

    def test_not_tls(self):
        with socket.socket(socket.AF_INET6) as server:
            server.bind(("::1", 0))
            server.listen()
            port = server.getsockname()[1]

            def close_at_once():
                conn, _ = server.accept()
                conn.close()
            threading.Thread(target=close_at_once, daemon=True).start()
            with self.assertRaises(Forged) as caught:
                channel.post("::1", port, protocol.JOIN, b"{}", KEY,
                             bytes(32), connect_timeout=2)
        self.assertIn("TLS handshake failed", str(caught.exception))


class Unsigned(Listener):
    def handle(self, *args):
        return Response(200, b"{}", "00" * 32)


class TestForgedAnswer(Served):
    listener_class = Unsigned

    def test_an_answer_not_signed_with_the_key(self):
        with self.assertRaises(Forged) as caught:
            self.post()
        self.assertIn("not signed with this invite's key",
                      str(caught.exception))


class TooLong(Listener):
    def handle(self, *args):
        return Response(200, b"x" * (protocol.MAX_ANSWER + 1), None)


class TestTooLongAnswer(Served):
    listener_class = TooLong

    def test_an_answer_longer_than_the_protocol_allows(self):
        with self.assertRaises(ChannelError) as caught:
            self.post()
        self.assertIn("longer than any", str(caught.exception))


class Silent(Listener):
    def handle(self, *args):
        raise ConnectionResetError("gone")


class TestCutShort(Served):
    listener_class = Silent

    def test_an_exchange_cut_short(self):
        with self.assertRaises(ChannelError) as caught:
            self.post()
        self.assertIn("did not answer", str(caught.exception))


class TestHelpers(unittest.TestCase):
    def test_reason(self):
        for data, found in ((b'{"error": "expired"}', "expired"),
                            (b"<html>", "HTTP 502"),
                            (b'{"error": 5}', "HTTP 502"),
                            (b'{"error": "a\\u0007"}', "HTTP 502"),
                            (b"[]", "HTTP 502")):
            with self.subTest(data=data):
                self.assertEqual(channel.reason(data, 502), found)

    def test_plain(self):
        self.assertEqual(channel.plain("::ffff:192.0.2.5"), "192.0.2.5")
        self.assertEqual(channel.plain("fe80::1%eth0"), "fe80::1")
        self.assertEqual(channel.plain("fd00::1"), "fd00::1")

    def test_the_server_context_loads_the_invite_pair(self):
        key, cert = tls()
        context = channel.server_context(cert, key)
        self.assertIsInstance(context, ssl.SSLContext)
        with self.assertRaises(ssl.SSLError):
            channel.server_context(cert, certificate.make()[0])

    def test_shown(self):
        self.assertEqual(channel.shown("192.0.2.1", 5), "192.0.2.1:5")
        self.assertEqual(json.loads('"x"'), "x")


if __name__ == "__main__":
    unittest.main()
