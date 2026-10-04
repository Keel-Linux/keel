# Copyright (c) 2026 KeelLinux maintainers
"""Between the unprivileged listener and the root side (decision 0048)

The root helper (`keel mesh serve` in keel-mesh-invite@<id>, or `keel
mesh accept` in the foreground) starts the listener as its own unit,
keel-mesh-listen@<id>, with a dynamic user, no capability and the
sandbox of LISTENER_PROPERTIES. The listener binds the bridge's unix
socket in its RuntimeDirectory, /run/keel/mesh-listen-<id>, mode 0700
and its dynamic user's, so no other user can reach it; the socket is
0600. The helper connects, and checks with SO_PEERCRED that the other
end is the unit's MainPID, as systemd names it, and not root; a socket
held by anything else is skipped, and the helper tries again until the
listener shows. It then sends the listener's parameters, which hold no
key, and the invite's certificate and TLS key as two memfds over
SCM_RIGHTS, so the TLS key is never written to a file. The invite's
HMAC key never leaves the root side. The listener accepts the helper
only as root (or as itself, in a test).

From then on the listener forwards each request that passed its checks,
as the bytes it received, and the helper answers with the Admitter's
response (keel.mesh.admit), which verifies the HMAC and decides.
Messages are JSON, one per line, at most MAX_MESSAGE bytes; bodies in
base64. The helper treats everything it reads as untrusted: a message
it cannot read ends the exchange.
"""

import base64
import binascii
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone

from keel import exits
from keel.mesh.admit import Admitter, Response
from keel.mesh.channel import context_from_paths, pem_fds
from keel.mesh.listener import Listener, Params, bound, run

UNIT = "keel-mesh-listen@{id}"
# the listener's RuntimeDirectory, under /run
RUNTIME = "keel/mesh-listen-{id}"
SOCKET = "bridge.sock"
MAX_MESSAGE = 65536
CONNECT_WAIT = 30
RETRY = 0.05
PEERCRED = struct.Struct("3i")
STATUS = "/proc/self/status"
# the listener's unit: a dynamic user, no capability, nothing writable,
# IP and unix sockets only, the system calls of a service
LISTENER_PROPERTIES = (
    "DynamicUser=yes",
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
    "SystemCallFilter=@system-service",
    "SystemCallArchitectures=native",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "MemoryMax=64M",
    "TasksMax=32",
    "LimitNOFILE=64",
)


class BridgeError(Exception):
    """The listener could not be started, trusted, or understood"""


def unit(invite_id: str) -> str:
    return UNIT.format(id=invite_id)


def socket_path(root: str, invite_id: str) -> str:
    return os.path.join(root, "run", RUNTIME.format(id=invite_id), SOCKET)


def listener_command(path: str) -> tuple[str, ...]:
    return (sys.executable, "-m", "keel", "mesh", "listen", path)


@dataclass
class Unit:
    """A listener started as its unit"""

    name: str
    run: Callable[[tuple[str, ...]], str | None]
    output: Callable[[tuple[str, ...]], str | None]

    def trusted(self, pid: int, uid: int) -> bool:
        """Not root, and the unit's main process as systemd knows it"""
        found = (self.output(("systemctl", "show", "--property=MainPID",
                              "--value", self.name)) or "").strip()
        return uid != 0 and found.isdigit() and int(found) == pid

    def stop(self) -> None:
        self.run(("systemctl", "stop", self.name))


def start_unit(invite_id: str, path: str, seconds: int,
               run: Callable[[tuple[str, ...]], str | None],
               output: Callable[[tuple[str, ...]], str | None]) -> Unit:
    """Start keel-mesh-listen@<id>; raises BridgeError"""
    name = unit(invite_id)
    problem = run(("systemd-run", f"--unit={name}", "--collect", "--quiet",
                   f"--property=RuntimeMaxSec={seconds}",
                   f"--property=RuntimeDirectory={RUNTIME.format(id=invite_id)}",
                   "--property=RuntimeDirectoryMode=0700",
                   *(f"--property={one}" for one in LISTENER_PROPERTIES),
                   f"--description=keel: the unprivileged listener of mesh"
                   f" invite {invite_id}", *listener_command(path)))
    if problem:
        raise BridgeError(f"the listener could not start: {problem}")
    return Unit(name, run, output)


def params_json(params: Params) -> bytes:
    data = {"invite_id": params.invite_id,
            "expires": int(params.expires.timestamp()),
            "host": params.host, "port": params.port,
            "overlay": params.overlay,
            "joined": None if params.joined is None else [
                params.joined[0], params.joined[1],
                int(params.joined[2].timestamp())]}
    return json.dumps(data).encode()


def params_of(data: bytes) -> Params:
    found = json.loads(data.decode())
    joined = found["joined"]
    return Params(
        invite_id=str(found["invite_id"]),
        expires=datetime.fromtimestamp(found["expires"], timezone.utc),
        host=str(found["host"]), port=int(found["port"]),
        overlay=str(found["overlay"]),
        joined=None if joined is None else (
            str(joined[0]), str(joined[1]),
            datetime.fromtimestamp(joined[2], timezone.utc)))


def line(sock: socket.socket) -> bytes | None:
    """One message, None at the end; raises BridgeError past the cap"""
    found = bytearray()
    while not found.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            return None
        found += chunk
        if len(found) > MAX_MESSAGE:
            raise BridgeError("a message longer than any the bridge has")
    return bytes(found)


def send(sock: socket.socket, data: dict) -> None:
    sock.sendall(json.dumps(data).encode() + b"\n")


def address(value: object) -> str:
    return str(ipaddress.ip_address(str(value)))


def answered(admitter: Admitter, data: bytes) -> dict:
    """The helper's answer to one message; raises BridgeError"""
    try:
        found = json.loads(data.decode())
        if found.get("op") != "forward":
            raise ValueError(f"unknown operation {found.get('op')!r}")
        body = found.get("body")
        signature = found.get("signature")
        response = admitter.forward(
            str(found["path"]),
            signature if isinstance(signature, str) else None,
            None if body is None else base64.b64decode(body, validate=True),
            address(found["local"]), address(found["peer"]))
    except (ValueError, KeyError, TypeError, AttributeError,
            binascii.Error) as e:
        raise BridgeError(f"the listener sent what it should not: {e}") \
            from None
    return {"status": response.status,
            "body": base64.b64encode(response.body).decode(),
            "signature": response.signature, "final": response.final}


def connected(path: str, started, sleep: Callable[[float], None],
              trusted: Callable[[int, int], None],
              skipped: Callable[[int, int], None]) -> socket.socket:
    """The socket at `path`, its peer checked with SO_PEERCRED against
    `started.trusted(pid, uid)`; untrusted ones are skipped until the
    listener shows or CONNECT_WAIT passes. Raises BridgeError"""
    deadline = time.monotonic() + CONNECT_WAIT
    while time.monotonic() < deadline:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(path)
        except OSError:
            conn.close()
            sleep(RETRY)
            continue
        pid, uid, _ = PEERCRED.unpack(conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size))
        if started.trusted(pid, uid):
            trusted(pid, uid)
            return conn
        conn.close()
        skipped(pid, uid)
        sleep(RETRY)
    raise BridgeError(f"the listener did not connect within"
                      f" {CONNECT_WAIT} s")


@dataclass
class Bridge:
    """The root helper of one invite

    `start(path)` starts the listener, which binds `path`, and returns
    what can tell its process (trusted(pid, uid)) and stop it (stop()).
    """

    admitter: Admitter
    params: Params
    certificate: str
    tls_key: str
    path: str
    start: Callable[[str], object]
    log: Callable[[str], None]
    sleep: Callable[[float], None] = time.sleep

    def run(self) -> None:
        """Until the listener is done; raises BridgeError"""
        started = self.start(self.path)
        try:
            with self.connected(started) as conn:
                self.exchange(conn)
        finally:
            started.stop()

    def connected(self, started) -> socket.socket:
        """The listener's socket, its peer checked; untrusted ones are
        skipped until the listener shows or CONNECT_WAIT passes"""
        name = f"invite {self.params.invite_id}"
        return connected(self.path, started, self.sleep, lambda pid, uid: (
            self.log(f"{name}: the listener (pid {pid}, uid {uid}) serves"
                     f" TCP port {self.params.port}")), lambda pid, uid: (
            self.log(f"{name}: skipped process {pid} (uid {uid}) at"
                     f" {self.path}: it is not the listener")))

    def exchange(self, conn: socket.socket) -> None:
        with pem_fds(self.certificate, self.tls_key) as fds:
            socket.send_fds(conn, [params_json(self.params) + b"\n"], fds)
        while True:
            data = line(conn)
            if data is None:
                return
            send(conn, answered(self.admitter, data))


class Remote:
    """The listener's backend: the root side, over the bridge"""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def ask(self, data: dict) -> dict:
        try:
            send(self.sock, data)
            found = line(self.sock)
        except OSError as e:
            raise BridgeError(f"the root side is gone: {e}") from None
        if found is None:
            raise BridgeError("the root side is gone")
        return json.loads(found.decode())

    def forward(self, path: str, signature: str | None, body: bytes | None,
                local: str, peer: str) -> Response:
        try:
            found = self.ask({
                "op": "forward", "path": path, "signature": signature,
                "body": None if body is None else base64.b64encode(
                    body).decode(), "local": local, "peer": peer})
        except BridgeError as e:
            return Response(503, json.dumps({"error": str(e)}).encode())
        return Response(int(found["status"]),
                        base64.b64decode(found["body"]),
                        found.get("signature"), bool(found.get("final")))


def capabilities(text: str) -> int:
    """CapEff of /proc/PID/status, as an integer"""
    for one in text.splitlines():
        if one.startswith("CapEff:"):
            return int(one.split()[1], 16)
    return -1


def helper(path: str, own_uid: int) -> socket.socket | None:
    """The root helper's connection to the socket the listener binds at
    `path`, 0600 in its 0700 directory; None when none came. A peer that
    is neither root nor this user is dropped"""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with suppress(FileNotFoundError):
        os.remove(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        os.chmod(path, 0o600)
        server.listen(1)
        server.settimeout(CONNECT_WAIT)
        while True:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                return None
            _, uid, _ = PEERCRED.unpack(conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size))
            if uid in (0, own_uid):
                # one helper: nothing else will connect
                os.remove(path)
                return conn
            conn.close()


def listen(path: str, clock: Callable[[], datetime],
           log: Callable[[str], None], status: str = STATUS,
           poll: float = 1.0) -> int:
    """`keel mesh listen`: the unprivileged listener's whole life"""
    with open(status) as fob:
        found = capabilities(fob.read())
    if found != 0:
        log(f"the mesh listener runs without capabilities, and this"
            f" process has {found:#x}: refused")
        return exits.APPLY_FAILED
    sock = helper(path, os.getuid())
    if sock is None:
        log(f"no root helper came to {path} within {CONNECT_WAIT} s")
        return exits.APPLY_FAILED
    with sock:
        message, fds, _, _ = socket.recv_fds(sock, MAX_MESSAGE, 2)
        try:
            params = params_of(message)
            context = context_from_paths(*(f"/proc/self/fd/{one}"
                                           for one in fds))
        except (ValueError, KeyError, TypeError, OSError) as e:
            log(f"the root side sent no parameters the listener can use"
                f" ({e or 'nothing'}): refused")
            return exits.APPLY_FAILED
        finally:
            for one in fds:
                os.close(one)
        listener = Listener(params, Remote(sock), clock, log)
        log(f"invite {params.invite_id}: listening on TCP port"
            f" {params.port}, without capabilities")
        run(bound(params.host, params.port), listener, context, poll)
    return exits.OK
