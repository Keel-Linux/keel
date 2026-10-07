# Copyright (c) 2026 KeelLinux maintainers
"""The members' channel: HTTP on the overlay, WireGuard its proof

What `keel mesh sync` pulls and what the inviter announces
(keel.mesh.members), what members say of etcd (`POST /v1/etcd`,
keel.mesh.etcdmsg) and of a VIP (`POST /v1/vip`, keel.mesh.vipmsg),
goes between two members' overlay addresses, on TCP 51821, and both
ends bind their socket to the overlay's interface (SO_BINDTODEVICE):
the server takes only what arrived through
WireGuard, and the client's request leaves, and its answer comes back,
only through it. WireGuard accepts a packet on that interface only when
it was decrypted with the key of the peer whose allowed_ips hold its
source address. So the root side knows which member asks by the source
address, and refuses any other; the client knows the answer came from
the member it asked. What a roster says about other members is taken
only with admission evidence (keel.mesh.trust): the channel
authenticates who speaks, not what it vouches for.

The server is the unprivileged listener's (keel.mesh.memberd), and is
bounded as the invite's listener is (keel.mesh.listener): at most 4
connections at once and one per source, each request read under a
deadline of 15 seconds and each read a timeout of 5, the request line
and headers capped at 8 KiB and the body at 64 KiB, and a source
refused 5 times within a minute not answered until the minute has
passed. What passed goes to the root side (`Front.backend`). When the
overlay goes down and up, as each apply of it does, the interface
comes back as another one and the socket is bound again.
"""

import http.client
import json
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler

from keel.mesh import members
from keel.mesh.channel import plain, reason, shown
from keel.mesh.etcdmsg import PATH as ETCD
from keel.mesh.listener import (
    DRAIN,
    MAX_HEADERS,
    READ_TIMEOUT,
    Capped,
    Limiter,
    shut,
)
from keel.mesh.members import ANNOUNCE, LIST, MAX_BODY, PORT, Roster
from keel.mesh.vipmsg import PATH as VIP
from keel.mesh.protocol import CONTENT_TYPE, ProtocolError

# two lost SYNs on a poor link still connect (keel.mesh.channel)
CONNECT_TIMEOUT = 10
ANSWER_TIMEOUT = 30
# what a probe waits: it only makes WireGuard start a handshake
TOUCH_TIMEOUT = 2
POLL = 1.0
GET, POST = "GET", "POST"
ACCEPTED = 202
SLOTS = 4
PER_SOURCE = 2
REQUEST_DEADLINE = 15


class LinkError(Exception):
    """The exchange with a member did not complete, and why"""


def connected(host: str, iface: str, port: int,
              timeout: float) -> socket.socket:
    """A TCP connection to `host` through `iface` alone"""
    raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                       iface.encode())
        raw.settimeout(timeout)
        raw.connect((host, port))
    except OSError as e:
        raw.close()
        raise LinkError(f"{shown(host, port)} through {iface}:"
                        f" {e.strerror or e}") from None
    return raw


def exchange(host: str, iface: str, method: str, path: str,
             body: bytes = b"", port: int = PORT,
             connect_timeout: float = CONNECT_TIMEOUT,
             answer_timeout: float = ANSWER_TIMEOUT) -> tuple[int, bytes]:
    """(status, body) of one request; raises LinkError"""
    raw = connected(host, iface, port, connect_timeout)
    raw.settimeout(answer_timeout)
    connection = http.client.HTTPConnection(host, port)
    connection.sock = raw
    try:
        connection.request(method, path, body or None,
                           {"Content-Type": CONTENT_TYPE,
                            "Connection": "close"})
        response = connection.getresponse()
        data = response.read(MAX_BODY + 1)
    except (OSError, http.client.HTTPException) as e:
        raise LinkError(f"{shown(host, port)} did not answer: {e}") \
            from None
    finally:
        connection.close()
    if len(data) > MAX_BODY:
        raise LinkError(f"the answer from {shown(host, port)} is longer than"
                        " any roster")
    return response.status, data


def fetch(host: str, iface: str, port: int = PORT) -> Roster:
    """The roster of the member at `host`; raises LinkError"""
    status, data = exchange(host, iface, GET, LIST, port=port)
    if status != 200:
        raise LinkError(f"{shown(host, port)} refused: {reason(data, status)}")
    try:
        return members.loads(data)
    except ProtocolError as e:
        raise LinkError(f"the roster from {shown(host, port)} is"
                        f" malformed: {e}") from None


def tell(host: str, iface: str, roster: Roster, port: int = PORT) -> None:
    """Announce `roster` to the member at `host`; raises LinkError"""
    status, data = exchange(host, iface, POST, ANNOUNCE,
                            members.dumps(roster), port=port)
    if status != ACCEPTED:
        raise LinkError(f"{shown(host, port)} refused: {reason(data, status)}")


def etcd_exchange(host: str, iface: str, body: bytes,
                  port: int = PORT) -> bytes:
    """The answer of the member at `host` to a signed etcd message
    (keel.mesh.etcdmsg); raises LinkError"""
    status, data = exchange(host, iface, POST, ETCD, body, port=port)
    if status != 200:
        raise LinkError(f"{shown(host, port)} refused: {reason(data, status)}")
    return data


def vip_exchange(host: str, iface: str, body: bytes,
                 port: int = PORT) -> bytes:
    """The answer of the member at `host` to a signed VIP message
    (keel.mesh.vipmsg); raises LinkError"""
    status, data = exchange(host, iface, POST, VIP, body, port=port)
    if status != 200:
        raise LinkError(f"{shown(host, port)} refused: {reason(data, status)}")
    return data


def touch(host: str, iface: str, port: int = PORT) -> None:
    """Send `host` a packet through `iface`, so that WireGuard starts a
    handshake with its peer; whatever answers, or nothing"""
    try:
        connected(host, iface, port, TOUCH_TIMEOUT).close()
    except LinkError:
        pass


@dataclass(frozen=True)
class Answer:
    status: int
    body: bytes


def refused(status: int, why: str) -> Answer:
    return Answer(status, json.dumps({"error": why}).encode())


class Front:
    """The listener's checks before the root side, per source

    `backend` is the root side (keel.mesh.memberd.Members in one
    process, memberd.Remote across the bridge): handle(method, path,
    body, source) -> Answer.
    """

    def __init__(self, backend, clock: Callable[[], datetime],
                 log: Callable[[str], None]):
        self.backend = backend
        self.log = log
        self.lock = threading.Lock()
        self.limiter = Limiter(clock)

    def blocked(self, source: str) -> bool:
        with self.lock:
            return self.limiter.blocked(source)

    def handle(self, method: str, path: str, body: bytes | None,
               source: str) -> Answer:
        if (method, path) not in ((GET, LIST), (POST, ANNOUNCE),
                                  (POST, ETCD), (POST, VIP)):
            found = refused(404, "no such request")
        elif body is None:
            found = refused(413, "longer than any roster")
        else:
            found = self.backend.handle(method, path, body, source)
        if found.status >= 400:
            with self.lock:
                self.limiter.refused(source)
            self.log(f"refused {method} {path[:64]!r} from {source}:"
                     f" {found.status}")
        return found


@dataclass
class Connection:
    """What a handler needs of the connection it serves"""

    front: Front
    read: threading.Timer


class Handler(BaseHTTPRequestHandler):
    server_version = "keel-mesh-members"
    sys_version = ""

    def setup(self):
        super().setup()
        self.rfile = Capped(self.rfile, MAX_HEADERS)

    def answer(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        self.rfile.budget = MAX_BODY
        body = self.rfile.read(length) if 0 <= length <= MAX_BODY else None
        # read whole: the deadline is for reading
        self.server.read.cancel()
        found = self.server.front.handle(self.command, self.path, body,
                                         plain(self.client_address[0]))
        self.send_response(found.status)
        self.send_header("Content-Type", CONTENT_TYPE)
        self.send_header("Content-Length", str(len(found.body)))
        self.end_headers()
        self.wfile.write(found.body)

    do_GET = do_POST = do_PUT = answer

    def log_message(self, format, *args):  # noqa: A002
        """The front logs what it refuses, and no header"""


def serve_one(front: Front, raw: socket.socket, source: str,
              release: Callable[[], None]) -> None:
    read = threading.Timer(REQUEST_DEADLINE, shut, ([raw],))
    read.start()
    try:
        raw.settimeout(READ_TIMEOUT)
        Handler(raw, (source, 0), Connection(front, read))
    except (OSError, ValueError):
        pass
    finally:
        read.cancel()
        raw.close()
        release()


def bound(iface: str, address: str, port: int) -> socket.socket:
    """The server's socket on `address`, through `iface` alone; raises
    OSError while either is missing"""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                          iface.encode())
        server.bind((address, port))
        server.listen(16)
    except OSError:
        server.close()
        raise
    return server


def index(iface: str) -> int | None:
    try:
        return socket.if_nametoindex(iface)
    except OSError:
        return None


class Slots:
    """At most SLOTS connections at once, PER_SOURCE from one source"""

    def __init__(self):
        self.free = threading.BoundedSemaphore(SLOTS)
        self.guard = threading.Lock()
        self.active: dict[str, int] = {}

    def take(self, source: str) -> Callable[[], None] | None:
        with self.guard:
            if self.active.get(source, 0) >= PER_SOURCE or \
                    not self.free.acquire(blocking=False):
                return None
            self.active[source] = self.active.get(source, 0) + 1

        def release():
            with self.guard:
                self.active[source] -= 1
            self.free.release()
        return release


def serve(front: Front, iface: str, address: str, stop: threading.Event,
          port: int = PORT, poll: float = POLL) -> None:
    """Answer members on `address` through `iface` until `stop`, the
    socket bound again whenever the interface comes back as another"""
    server, at = None, None
    slots = Slots()
    threads: list[threading.Thread] = []
    while not stop.is_set():
        if server is not None and index(iface) != at:
            server.close()
            server = None
        if server is None:
            at = index(iface)
            try:
                if at is None:
                    raise OSError(f"no interface {iface}")
                server = bound(iface, address, port)
                server.settimeout(poll)
            except OSError:
                server = None
                stop.wait(poll)
                continue
        try:
            raw, found = server.accept()
        except TimeoutError:
            continue
        except OSError:
            server.close()
            server = None
            continue
        source = plain(found[0])
        release = None if front.blocked(source) else slots.take(source)
        if release is None:
            raw.close()
            continue
        thread = threading.Thread(target=serve_one, args=(
            front, raw, source, release), daemon=True)
        thread.start()
        threads = [one for one in threads if one.is_alive()] + [thread]
    if server is not None:
        server.close()
    for thread in threads:
        thread.join(DRAIN)
