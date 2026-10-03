# Copyright (c) 2026 KeelLinux maintainers
"""keel-mesh-members: the members' channel, split as an invite's is

As keel#75 splits an invite (keel.mesh.bridge), the members' channel is
two processes:

- **the root helper**, `keel mesh members` in keel-mesh-members.service,
  which alone holds the spec, the trust store and this node's signing
  key. It starts the listener as its own unit, keel-mesh-members-listen,
  with a dynamic user, no capability and the sandbox of
  keel.mesh.bridge.LISTENER_PROPERTIES, connects to the unix socket the
  listener binds in its RuntimeDirectory (/run/keel/mesh-members, 0700,
  the socket 0600), checks with SO_PEERCRED that the other end is the
  unit's MainPID and not root, and sends the overlay's interface,
  address and port, which hold no key;
- **the listener**, `keel mesh members-listen SOCKET`, which refuses to
  run with any capability, binds TCP 51821 through the overlay's
  interface, applies keel.mesh.memberlink's limits, and forwards what
  passed to the root side, as one JSON message per line.

The root side (`Members`) treats what the listener forwards as
untrusted: the source must be in a spec peer's allowed_ips, an
announcement must parse whole and name its sender's key. It answers the
roster at once and queues an announcement (`Pending`): one per sender,
the latest replacing an earlier one, at most MAX_PENDING senders. One
worker applies everything pending in one change, under one window
(keel.mesh.sync.announced), after verifying each entry's evidence
(keel.mesh.trust).
"""

import base64
import binascii
import json
import os
import socket
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime

from keel import exits
from keel.mesh import bridge, memberlink, members, signing, sync
from keel.mesh.bridge import BridgeError, Unit, capabilities, line, send
from keel.mesh.memberlink import ANNOUNCE, GET, LIST, POST, Answer, refused
from keel.mesh.members import PORT, Roster
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.network.wireguard import same_key

UNIT = "keel-mesh-members-listen"
RUNTIME = "keel/mesh-members"
SOCKET = "bridge.sock"
MAX_PENDING = 64
WORKER_POLL = 0.2
# how long the worker waits after the last announcement before it
# applies: the answer must reach the sender before the overlay goes
# down and up, which the sockets bound to the old interface would not
# survive, and announcements close together share one window
SETTLE = 10.0
WAIT_OVERLAY = 2.0


class Pending:
    """The announcements waiting: the latest per sender, MAX_PENDING
    senders at most, given out once none came for `settle` seconds"""

    def __init__(self, limit: int = MAX_PENDING, settle: float = SETTLE,
                 clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.settle = settle
        self.clock = clock
        self.ready = threading.Condition()
        self.waiting: dict[str, Roster] = {}
        self.last = 0.0

    def put(self, source: str, found: Roster) -> bool:
        with self.ready:
            if source not in self.waiting and \
                    len(self.waiting) >= self.limit:
                return False
            self.waiting[source] = found
            self.last = self.clock()
            self.ready.notify()
            return True

    def take(self, timeout: float) -> list[tuple[str, Roster]]:
        """Everything waiting, at once, once it settled; empty after
        `timeout` otherwise"""
        with self.ready:
            if not self.waiting:
                self.ready.wait(timeout)
            quiet = self.last + self.settle - self.clock()
            if not self.waiting or quiet > 0:
                if self.waiting:
                    self.ready.wait(min(quiet, timeout))
                return []
            found = list(self.waiting.items())
            self.waiting.clear()
        return found


class Members:
    """The root side's answers, as a function of the request

    `roster` gives this node's roster now, or raises ValueError;
    `member_of` the key of the peer whose allowed_ips hold a source
    address, None for any other.
    """

    def __init__(self, roster: Callable[[], Roster],
                 member_of: Callable[[str], str | None], pending: Pending,
                 log: Callable[[str], None]):
        self.roster = roster
        self.member_of = member_of
        self.pending = pending
        self.log = log

    def handle(self, method: str, path: str, body: bytes | None,
               source: str) -> Answer:
        key = self.member_of(source)
        if key is None:
            self.log(f"refused {method} {path[:64]!r} from {source}: not a"
                     " peer of this node")
            return refused(403, "not a member of this node's mesh")
        if (method, path) == (GET, LIST):
            try:
                return Answer(200, members.dumps(self.roster()))
            except ValueError as e:
                self.log(f"cannot answer {source}: {e}")
                return refused(503, "this node cannot give its roster now")
        if (method, path) != (POST, ANNOUNCE) or body is None:
            return refused(404, "no such request")
        try:
            found = members.loads(body)
        except ProtocolError as e:
            return refused(400, f"malformed roster: {e}")
        if not same_key(found.public_key, key):
            self.log(f"refused an announcement from {source}: it names"
                     f" {found.public_key}, and {source} is {key}'s")
            return refused(403, "the roster is not the sender's")
        if not self.pending.put(source, found):
            return refused(503, "too many announcements wait here: the"
                           " next keel mesh sync brings yours")
        return Answer(memberlink.ACCEPTED, b'{"queued": true}')


def answered(handler: Members, data: bytes) -> dict:
    """The root side's answer to one message; raises BridgeError"""
    try:
        found = json.loads(data.decode())
        if found.get("op") != "member":
            raise ValueError(f"unknown operation {found.get('op')!r}")
        body = found.get("body")
        answer = handler.handle(
            str(found["method"]), str(found["path"]),
            None if body is None else base64.b64decode(body, validate=True),
            bridge.address(found["source"]))
    except (ValueError, KeyError, TypeError, AttributeError,
            binascii.Error) as e:
        raise BridgeError(f"the listener sent what it should not: {e}") \
            from None
    return {"status": answer.status,
            "body": base64.b64encode(answer.body).decode()}


class Remote:
    """The listener's backend: the root side, over the bridge; one
    question at a time. A root side gone stops the listener."""

    def __init__(self, sock: socket.socket, stop: threading.Event):
        self.sock = sock
        self.stop = stop
        self.lock = threading.Lock()

    def handle(self, method: str, path: str, body: bytes | None,
               source: str) -> Answer:
        with self.lock:
            try:
                send(self.sock, {"op": "member", "method": method,
                                 "path": path, "source": source,
                                 "body": None if body is None else
                                 base64.b64encode(body).decode()})
                found = line(self.sock)
            except (OSError, BridgeError):
                found = None
        if found is None:
            self.stop.set()
            return refused(503, "the root side is gone")
        data = json.loads(found.decode())
        return Answer(int(data["status"]), base64.b64decode(data["body"]))


def socket_path(root: str) -> str:
    return os.path.join(root, "run", RUNTIME, SOCKET)


def listener_command(path: str) -> tuple[str, ...]:
    return (sys.executable, "-m", "keel", "mesh", "members-listen", path)


def start_unit(path: str, run: Callable[[tuple[str, ...]], str | None],
               output: Callable[[tuple[str, ...]], str | None]) -> Unit:
    """Start keel-mesh-members-listen; raises BridgeError"""
    run(("systemctl", "stop", UNIT))
    problem = run(("systemd-run", f"--unit={UNIT}", "--collect", "--quiet",
                   f"--property=RuntimeDirectory={RUNTIME}",
                   "--property=RuntimeDirectoryMode=0700",
                   *(f"--property={one}"
                     for one in bridge.LISTENER_PROPERTIES),
                   "--description=keel: the unprivileged listener of the"
                   " mesh members' channel", *listener_command(path)))
    if problem:
        raise BridgeError(f"the listener could not start: {problem}")
    return Unit(UNIT, run, output)


def listen(path: str, clock: Callable[[], datetime],
           log: Callable[[str], None], status: str = bridge.STATUS,
           poll: float = memberlink.POLL,
           stop: threading.Event | None = None) -> int:
    """`keel mesh members-listen`: the unprivileged listener's life"""
    with open(status) as fob:
        found = capabilities(fob.read())
    if found != 0:
        log(f"the members' listener runs without capabilities, and this"
            f" process has {found:#x}: refused")
        return exits.APPLY_FAILED
    sock = bridge.helper(path, os.getuid())
    if sock is None:
        log(f"no root helper came to {path} within {bridge.CONNECT_WAIT} s")
        return exits.APPLY_FAILED
    with sock:
        try:
            params = json.loads((line(sock) or b"").decode())
            iface, address = str(params["iface"]), str(params["address"])
            port = int(params["port"])
        except (ValueError, KeyError, TypeError, BridgeError) as e:
            log(f"the root side sent no parameters the listener can use"
                f" ({e or 'nothing'}): refused")
            return exits.APPLY_FAILED
        stop = stop or threading.Event()
        log(f"the members' channel on [{address}]:{port} through {iface},"
            " without capabilities")
        memberlink.serve(memberlink.Front(Remote(sock, stop), clock, log),
                         iface, address, stop, port, poll)
    return exits.OK


def message(conn: socket.socket, stop: threading.Event,
            poll: float = memberlink.POLL) -> bytes | None:
    """The listener's next message; None once it is gone or `stop` is
    set, which is looked at between messages"""
    conn.settimeout(poll)
    while not stop.is_set():
        try:
            first = conn.recv(1)
        except TimeoutError:
            continue
        if not first:
            return None
        conn.settimeout(None)
        rest = b"" if first == b"\n" else line(conn)
        return None if rest is None else first + rest
    return None


def overlay_of(where: Callable[[], tuple[str, str] | None],
               stop: threading.Event) -> tuple[str, str] | None:
    """The overlay's interface and address, waited for"""
    while not stop.is_set():
        found = where()
        if found is not None:
            return found
        stop.wait(WAIT_OVERLAY)
    return None


def work(syncer: sync.Syncer, pending: Pending,
         stop: threading.Event) -> None:
    """The worker: everything pending, in one change at a time"""
    while not stop.is_set():
        waiting = pending.take(WORKER_POLL)
        if waiting:
            sync.announced(syncer, waiting)


def serve(syncer: sync.Syncer, stop: threading.Event,
          start: Callable[[str], object] | None = None,
          where: Callable[[], tuple[str, str] | None] | None = None,
          port: int = PORT, path: str | None = None,
          sleep: Callable[[float], None] = time.sleep,
          settle: float = SETTLE) -> int:
    """`keel mesh members`: the root helper, until `stop` or the listener
    is gone"""
    try:
        signing.ensure(syncer.root)
    except SigningError as e:
        syncer.err(str(e))
        return exits.APPLY_FAILED
    found = overlay_of(where or (lambda: sync.where(syncer.node)), stop)
    if found is None:
        return exits.OK
    path = path or socket_path(syncer.root)
    pending = Pending(settle=settle)
    worker = threading.Thread(target=work, args=(syncer, pending, stop))
    worker.start()
    handler = Members(lambda: sync.offered(syncer),
                      lambda source: sync.member_of(syncer.node, source),
                      pending, syncer.err)
    code = exits.OK
    started = None
    try:
        started = (start or (lambda where_to: start_unit(
            where_to, syncer.node.run, syncer.node.output)))(path)
        with bridge.connected(path, started, sleep, lambda pid, uid: (
                syncer.err(f"the members' listener (pid {pid}, uid {uid})"
                           f" serves [{found[1]}]:{port}")),
                lambda pid, uid: syncer.err(
                    f"skipped process {pid} (uid {uid}) at {path}: it is"
                    " not the members' listener")) as conn:
            send(conn, {"iface": found[0], "address": found[1],
                        "port": port})
            while (data := message(conn, stop)) is not None:
                send(conn, answered(handler, data))
    except (BridgeError, OSError) as e:
        syncer.err(f"the members' channel stopped: {e}")
        code = exits.APPLY_FAILED
    finally:
        if started is not None:
            started.stop()
        stop.set()
        worker.join()
    return code
