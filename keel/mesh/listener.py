# Copyright (c) 2026 KeelLinux maintainers
"""The invite's listener, the only part that faces the network (0048)

It runs without privileges: as a DynamicUser unit with no capability
(keel.mesh.bridge starts it), it holds the invite's TLS key in memory
only, never the invite's HMAC key, and it can change nothing on the
machine. It does TLS, reads one HTTP request per connection, and checks
what it can without the key (keel.mesh.admit.parsed: the shape, the
invite id, the time; and the nonce); it hands what passed, as the bytes
it received, to its backend, the Admitter behind the bridge, which
verifies the HMAC, checks the rest again and decides. A compromised
listener can therefore forge nothing the root side accepts.

Against someone scanning or holding the port:

- a request's whole reading, TLS handshake included, has a deadline
  (REQUEST_DEADLINE), and every read a timeout;
- at most SLOTS connections are read at once, and OVERLAY_SLOTS more
  are kept for connections to this node's overlay address, which only
  the mesh's peers reach, so a join's confirmation is never starved;
  and one source has one connection at a time (PER_SOURCE), so no one
  address fills the slots;
- the request line and headers are capped (MAX_HEADERS), the body by
  the protocol (MAX_BODY);
- a source refused MAX_REFUSED times within PERIOD is not answered
  until the period has passed;
- only a request that names this invite and fails its HMAC counts
  towards cancelling it, on the root side: that is someone who knows
  the invite and not its key, while a scanner learns nothing and costs
  the operator nothing. The root side's `final` answer stops the
  listener.
"""

import ipaddress
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler

from keel.mesh import protocol
from keel.mesh.admit import (
    Refusal,
    Response,
    default_log,
    parsed,
    parser,
    refusal,
)
from keel.mesh.channel import plain

MAX_REFUSED = 5
PERIOD = timedelta(seconds=60)
REQUEST_DEADLINE = 15
READ_TIMEOUT = 5
SLOTS = 4
OVERLAY_SLOTS = 2
PER_SOURCE = 1
MAX_HEADERS = 8192
POLL = 1.0
# how long the threads of the last connections are waited for
DRAIN = 5


@dataclass(frozen=True)
class Params:
    """What the root side hands the listener: no path, no file

    `overlay` is this node's overlay address, whose connections have
    slots of their own; `joined` is set for accept, which serves the
    confirmation alone: (public key, address, until).
    """

    invite_id: str
    expires: datetime
    host: str
    port: int
    overlay: str
    joined: tuple[str, str, datetime] | None = None


class Limiter:
    """The sources refused too often lately, and until when"""

    def __init__(self, clock: Callable[[], datetime]):
        self.clock = clock
        self.seen: dict[str, list[datetime]] = {}

    def recent(self, source: str) -> list[datetime]:
        since = self.clock() - PERIOD
        found = [one for one in self.seen.get(source, []) if one > since]
        self.seen[source] = found
        return found

    def refused(self, source: str) -> None:
        self.seen[source] = self.recent(source) + [self.clock()]

    def blocked(self, source: str) -> bool:
        return len(self.recent(source)) >= MAX_REFUSED


class Listener:
    """The front of one invite; `clock` gives an aware UTC datetime

    `backend` is the root side: keel.mesh.admit.Admitter in one process,
    keel.mesh.bridge.Remote across the bridge; both have forward(path,
    signature, body, local, peer) -> Response.
    """

    def __init__(self, params: Params, backend,
                 clock: Callable[[], datetime],
                 log: Callable[[str], None] | None = None):
        self.params = params
        self.backend = backend
        self.clock = clock
        self.log = log or default_log
        self.lock = threading.Lock()
        self.limiter = Limiter(clock)
        self.nonces: set[str] = set()
        self.joined = params.joined
        self.confirmed: bool | None = None
        self.ended = False

    @property
    def name(self) -> str:
        return f"invite {self.params.invite_id}"

    @property
    def finished(self) -> bool:
        if self.ended or self.confirmed is not None:
            return True
        until = self.joined[2] if self.joined else self.params.expires
        return self.clock() >= until

    def blocked(self, source: str) -> bool:
        with self.lock:
            return self.limiter.blocked(source)

    def handle(self, method: str, path: str, signature: str | None,
               body: bytes | None, local: str, peer: str) -> Response:
        """The answer to one request; never raises"""
        with self.lock:
            try:
                return self.checked(method, path, signature, body, local,
                                    peer)
            except Refusal as e:
                return self.refuse(e, peer)

    def refuse(self, refused: Refusal, peer: str) -> Response:
        self.limiter.refused(peer)
        self.log(f"{self.name}: refused a request from {peer}:"
                 f" {refused.reason}")
        return refusal(refused.status, refused.reason)

    def checked(self, method: str, path: str, signature: str | None,
                body: bytes | None, local: str, peer: str) -> Response:
        if method != protocol.METHOD or path not in (protocol.JOIN,
                                                     protocol.CONFIRM):
            raise Refusal(404, f"{method} {path[:64]!r}: no such request")
        if path == protocol.JOIN and self.joined is not None:
            raise Refusal(410, f"{self.name} was already used")
        if path == protocol.CONFIRM and self.joined is None:
            raise Refusal(409, "no join to confirm yet")
        request = parsed(self.params.invite_id, path, body, self.clock(),
                         parser(path))
        if request.nonce in self.nonces:
            raise Refusal(403, "replayed request: its nonce was seen")
        self.nonces.add(request.nonce)
        if path == protocol.CONFIRM and (local, peer) != (
                self.params.overlay, self.joined[1]):
            raise Refusal(403, f"the confirmation must come over the"
                          f" overlay, from {self.joined[1]} to"
                          f" {self.params.overlay}")
        found = self.backend.forward(path, signature, body, local, peer)
        self.learn(path, request, found, peer)
        return found

    def learn(self, path: str, request, found: Response, peer: str) -> None:
        """What the root side's answer says about this invite's state"""
        if found.final or found.status == 503:
            self.ended = True
        if found.status not in (200, 409):
            self.limiter.refused(peer)
        if found.status != 200:
            return
        try:
            if path == protocol.JOIN:
                answer = protocol.join_answer(found.body)
                address = str(ipaddress.IPv6Interface(request.address).ip)
                self.joined = (request.public_key, address, self.clock()
                               + timedelta(seconds=answer.window))
            else:
                self.confirmed = protocol.confirm_answer(
                    found.body).confirmed
        except protocol.ProtocolError as e:
            self.ended = True
            self.log(f"{self.name}: the root side's answer cannot be read"
                     f" ({e}); the listener stops")


class Capped:
    """A request's reader that gives out `budget` bytes: MAX_HEADERS for
    the request line and the headers, then MAX_BODY for the body"""

    def __init__(self, inner, budget: int):
        self.inner = inner
        self.budget = budget

    def spend(self, count: int) -> None:
        self.budget -= count
        if self.budget < 0:
            raise ValueError("the request is longer than any join")

    def readline(self, limit: int = -1) -> bytes:
        found = self.inner.readline(limit)
        self.spend(len(found))
        return found

    def read(self, count: int = -1) -> bytes:
        found = self.inner.read(count)
        self.spend(len(found))
        return found

    def close(self) -> None:
        self.inner.close()


@dataclass
class Connection:
    """What a handler needs of the connection it serves"""

    listener: Listener
    local: str
    read: threading.Timer


class Handler(BaseHTTPRequestHandler):
    server_version = "keel-mesh"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile = Capped(self.rfile, MAX_HEADERS)

    def answer(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        self.rfile.budget = protocol.MAX_BODY
        body = (self.rfile.read(length)
                if 0 <= length <= protocol.MAX_BODY else None)
        # read whole: the deadline is for reading, not for the apply
        self.server.read.cancel()
        found = self.server.listener.handle(
            self.command, self.path, self.headers.get(protocol.SIGNATURE),
            body, self.server.local, self.client_address[0])
        self.send_response(found.status)
        self.send_header("Content-Type", protocol.CONTENT_TYPE)
        self.send_header("Content-Length", str(len(found.body)))
        if found.signature:
            self.send_header(protocol.SIGNATURE, found.signature)
        self.end_headers()
        self.wfile.write(found.body)

    do_POST = do_GET = do_PUT = answer

    def log_message(self, format, *args):  # noqa: A002
        """The listener logs each request itself, and no header"""


def shut(held: list[socket.socket]) -> None:
    """The reading's deadline: whatever was being read fails. `held` is
    the connection's socket now: the raw one, then its TLS wrapper,
    which takes the raw one's descriptor"""
    try:
        held[-1].shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def bound(host: str, port: int) -> socket.socket:
    """IPv6 and IPv4 on one socket; raises OSError when the port is
    taken or the address is not this machine's"""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        server.bind((host, port))
        server.listen(16)
    except OSError:
        server.close()
        raise
    return server


def serve_one(listener: Listener, context, raw: socket.socket, source: str,
              local: str, release: Callable[[], None]) -> None:
    held = [raw]
    read = threading.Timer(REQUEST_DEADLINE, shut, (held,))
    read.start()
    try:
        raw.settimeout(READ_TIMEOUT)
        held.append(context.wrap_socket(raw, server_side=True))
        Handler(held[-1], (source, 0), Connection(listener, local, read))
    except (OSError, ValueError):
        pass
    finally:
        read.cancel()
        held[-1].close()
        release()


def run(server: socket.socket, listener: Listener, context,
        poll: float = POLL) -> None:
    """Answer until the listener is finished, then close the port"""
    slots = threading.BoundedSemaphore(SLOTS)
    overlay_slots = threading.BoundedSemaphore(OVERLAY_SLOTS)
    active: dict[str, int] = {}
    guard = threading.Lock()
    threads: list[threading.Thread] = []
    server.settimeout(poll)
    with server:
        while not listener.finished:
            try:
                raw, address = server.accept()
            except TimeoutError:
                continue
            source, local = plain(address[0]), plain(raw.getsockname()[0])
            slot = overlay_slots if local == listener.params.overlay \
                else slots
            with guard:
                held = active.get(source, 0)
            if held >= PER_SOURCE or listener.blocked(source) or \
                    not slot.acquire(blocking=False):
                raw.close()
                continue
            with guard:
                active[source] = held + 1

            def release(slot=slot, source=source):
                slot.release()
                with guard:
                    active[source] -= 1
            thread = threading.Thread(target=serve_one, args=(
                listener, context, raw, source, local, release),
                daemon=True)
            thread.start()
            threads = [one for one in threads if one.is_alive()] + [thread]
    for thread in threads:
        thread.join(DRAIN)
