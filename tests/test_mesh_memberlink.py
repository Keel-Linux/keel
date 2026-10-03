# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.memberlink: the members' channel, with real sockets

On the loopback, which stands for the overlay's interface: both ends
bound to `lo` as they are to wg0. The listener's front applies its
limits (a deadline per request, slots, one connection per source, size
caps, sources refused too often) and hands what passed to a backend
that stands for the root side (keel.mesh.memberd.Members).
"""

import socket
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

from mesh_helpers import INVITER, OTHER, SIGNER

from keel.mesh import memberlink, members
from keel.mesh.memberlink import Answer, Front, LinkError, refused
from keel.mesh.protocol import Peer

ROSTER = members.Roster(bytes(range(16)), INVITER, SIGNER, "fd00:6b65:1::1",
                        (Peer(OTHER, None, "fd00:6b65:1::7"),))


def free_port() -> int:
    with socket.socket(socket.AF_INET6) as found:
        found.bind(("::1", 0))
        return found.getsockname()[1]


class Backend:
    """The root side, as the front sees it: the roster, announcements
    taken, or a refusal when told"""

    def __init__(self):
        self.calls = []
        self.refuse = False

    def handle(self, method, path, body, source):
        self.calls.append((method, path, source))
        if self.refuse:
            return refused(403, "not a member of this node's mesh")
        if method == "GET":
            return Answer(200, members.dumps(ROSTER))
        return Answer(memberlink.ACCEPTED, b'{"queued": true}')


class Served(unittest.TestCase):
    """The listener's server on [::1]:port through lo, in a thread"""

    def setUp(self):
        self.port = free_port()
        self.logged = []
        self.backend = Backend()
        self.front = Front(self.backend,
                           lambda: datetime.now(timezone.utc),
                           self.logged.append)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=memberlink.serve, args=(
            self.front, "lo", "::1", self.stop, self.port, 0.05))
        self.thread.start()
        self.addCleanup(self.thread.join, 10)
        self.addCleanup(self.stop.set)
        for _ in range(100):
            try:
                socket.create_connection(("::1", self.port), 1).close()
                break
            except OSError:
                self.stop.wait(0.02)

    def raw(self, request: bytes) -> bytes:
        """What the server answers, b"" for a connection it closed"""
        data = b""
        with socket.create_connection(("::1", self.port), 5) as raw:
            try:
                raw.sendall(request)
                while chunk := raw.recv(4096):
                    data += chunk
            except ConnectionResetError:
                pass
        return data


class TestChannel(Served):
    def test_a_member_pulls_the_roster(self):
        self.assertEqual(memberlink.fetch("::1", "lo", self.port), ROSTER)
        self.assertEqual(self.backend.calls, [("GET", "/v1/members",
                                               "::1")])

    def test_a_member_announces(self):
        memberlink.tell("::1", "lo", ROSTER, self.port)
        self.assertEqual(self.backend.calls[0][:2], ("POST", "/v1/announce"))

    def test_refused_by_the_root_side(self):
        self.backend.refuse = True
        with self.assertRaises(LinkError) as raised:
            memberlink.fetch("::1", "lo", self.port)
        self.assertIn("not a member", str(raised.exception))
        with self.assertRaises(LinkError):
            memberlink.tell("::1", "lo", ROSTER, self.port)
        self.assertIn("refused GET '/v1/members' from ::1: 403",
                      self.logged)

    def test_what_never_reaches_the_root_side(self):
        for request, words in (
                (b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close"
                 b"\r\n\r\n", b"no such request"),
                (f"POST /v1/announce HTTP/1.1\r\nHost: x\r\n"
                 f"Content-Length: {members.MAX_BODY + 1}\r\n"
                 "Connection: close\r\n\r\n".encode(),
                 b"longer than any roster"),
                (b"POST /v1/announce HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Length: x\r\nConnection: close\r\n\r\n",
                 b"longer than any roster")):
            with self.subTest(request=request[:20]):
                self.assertIn(words, self.raw(request))
        self.assertEqual(self.backend.calls, [])

    def test_a_source_refused_too_often_is_not_answered(self):
        self.backend.refuse = True
        for _ in range(5):
            with self.assertRaises(LinkError):
                memberlink.fetch("::1", "lo", self.port)
        self.assertEqual(self.raw(b"GET /v1/members HTTP/1.1\r\n\r\n"),
                         b"")
        self.assertEqual(len(self.backend.calls), 5)

    def test_headers_beyond_the_cap_are_not_answered(self):
        data = self.raw(b"GET /v1/members HTTP/1.1\r\nX: "
                        + b"a" * 9000 + b"\r\n\r\n")
        self.assertEqual(data, b"")
        self.assertEqual(memberlink.fetch("::1", "lo", self.port), ROSTER)

    def test_connections_per_source_are_capped(self):
        for _ in range(memberlink.PER_SOURCE):
            held = socket.create_connection(("::1", self.port), 5)
            self.addCleanup(held.close)
            held.sendall(b"GET /v1/members HTTP/1.1\r\n")
        self.stop.wait(0.2)
        self.assertEqual(self.raw(b"GET /v1/members HTTP/1.1\r\n\r\n"),
                         b"")

    def test_a_probe_raises_nothing(self):
        memberlink.touch("::1", "lo", self.port)
        memberlink.touch("::1", "lo", free_port())


class TestDeadline(unittest.TestCase):
    def test_a_request_read_too_slowly_is_dropped(self):
        with mock.patch("keel.mesh.memberlink.REQUEST_DEADLINE", 0.3):
            test = TestChannel("test_a_member_pulls_the_roster")
            test.setUp()
            try:
                self.assertEqual(test.raw(b"GET /v1/members HTTP/1.1\r\n"),
                                 b"")
            finally:
                test.doCleanups()


class TestSlots(unittest.TestCase):
    def test_a_slot_per_connection_one_per_source(self):
        slots = memberlink.Slots()
        taken = [slots.take(f"fd00::{n}") for n in range(memberlink.SLOTS)]
        self.assertTrue(all(taken))
        self.assertIsNone(slots.take("fd00::99"))
        taken[0]()
        self.assertIsNotNone(slots.take("fd00::1"))
        self.assertIsNone(slots.take("fd00::0"))
        other = memberlink.Slots()
        for _ in range(memberlink.PER_SOURCE):
            self.assertIsNotNone(other.take("fd00::1"))
        self.assertIsNone(other.take("fd00::1"))


class Raw(threading.Thread):
    """A server that answers one connection with `reply`, as given"""

    def __init__(self, reply: bytes):
        super().__init__()
        self.reply = reply
        self.server = socket.socket(socket.AF_INET6)
        self.server.bind(("::1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.start()

    def run(self):
        with self.server:
            raw, _ = self.server.accept()
            with raw:
                raw.recv(65536)
                raw.sendall(self.reply)


def http(body: bytes, status: str = "200 OK") -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode() + body


class TestClient(unittest.TestCase):
    def test_nothing_listens(self):
        with self.assertRaises(LinkError) as raised:
            memberlink.fetch("::1", "lo", free_port())
        self.assertIn("through lo", str(raised.exception))

    def test_no_such_interface(self):
        with self.assertRaises(LinkError):
            memberlink.fetch("::1", "wg-none", free_port())

    def test_a_malformed_roster(self):
        server = Raw(http(b"{}"))
        with self.assertRaises(LinkError) as raised:
            memberlink.fetch("::1", "lo", server.port)
        self.assertIn("malformed", str(raised.exception))
        server.join(5)

    def test_an_answer_longer_than_any_roster(self):
        server = Raw(http(b"x" * (members.MAX_BODY + 1)))
        with self.assertRaises(LinkError) as raised:
            memberlink.fetch("::1", "lo", server.port)
        self.assertIn("longer than any roster", str(raised.exception))
        server.join(5)

    def test_not_an_http_answer(self):
        server = Raw(b"garbage\r\n\r\n")
        with self.assertRaises(LinkError) as raised:
            memberlink.fetch("::1", "lo", server.port)
        self.assertIn("did not answer", str(raised.exception))
        server.join(5)

    def test_an_announcement_not_taken(self):
        server = Raw(http(b'{"error": "busy"}', "409 Conflict"))
        with self.assertRaises(LinkError) as raised:
            memberlink.tell("::1", "lo", ROSTER, server.port)
        self.assertIn("refused: busy", str(raised.exception))
        server.join(5)


class TestIndex(unittest.TestCase):
    def test_an_interface_s_index_or_none(self):
        self.assertEqual(memberlink.index("lo"), socket.if_nametoindex("lo"))
        self.assertIsNone(memberlink.index("wg-none"))


class TestServeLoop(unittest.TestCase):
    """The socket follows the overlay: bound once it exists, again when
    the interface comes back as another"""

    def front(self):
        return Front(Backend(), lambda: datetime.now(timezone.utc),
                     lambda line: None)

    def test_bound_when_the_interface_appears_and_again_when_it_changes(
            self):
        stop = threading.Event()
        indexes = iter([None, 1, 1, 2, 2])

        def index(iface):
            value = next(indexes, 2)
            if value == 2 and not stop.is_set():
                threading.Timer(0.3, stop.set).start()
            return value
        with mock.patch("keel.mesh.memberlink.index", side_effect=index):
            memberlink.serve(self.front(), "lo", "::1", stop, free_port(),
                             0.02)
        self.assertTrue(stop.is_set())

    def test_an_address_that_cannot_be_bound_yet(self):
        stop = threading.Event()
        threading.Timer(0.2, stop.set).start()
        memberlink.serve(self.front(), "lo", "fd00:6b65:9::1", stop,
                         free_port(), 0.01)
        self.assertTrue(stop.is_set())

    def test_a_socket_that_fails_is_bound_again(self):
        stop = threading.Event()
        real = memberlink.bound
        made = []

        class Failing:
            def __init__(self, inner):
                self.inner = inner

            def settimeout(self, value):
                self.inner.settimeout(value)

            def accept(self):
                raise OSError(9, "Bad file descriptor")

            def close(self):
                self.inner.close()

        def bound(iface, address, number):
            made.append(1)
            if len(made) > 1:
                stop.set()
            return Failing(real(iface, address, number))
        with mock.patch("keel.mesh.memberlink.bound", side_effect=bound):
            memberlink.serve(self.front(), "lo", "::1", stop, free_port(),
                             0.01)
        self.assertEqual(len(made), 2)


if __name__ == "__main__":
    unittest.main()
