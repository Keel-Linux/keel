# Copyright (c) 2026 KeelLinux maintainers
"""keel-vip.service, split as keel#75 splits an invite (decision 0049)

- **the root helper**, `keel vip tend` in keel-vip.service (with
  CAP_NET_ADMIN alone, keel-overlay-vip's unit), which alone holds the
  spec, the state under /var/lib/keel/vip, the trust store and this
  node's signing key, and alone adds or removes the VIP on wg0 and sets
  a peer's allowed-ips, each after checking it against the pair record
  (keel.mesh.vipetcd.Ops). It starts the controller as the transient
  unit keel-vip-control, with a dynamic user, no capability, the
  sandbox of keel.mesh.bridge.LISTENER_PROPERTIES and the helper's own
  network namespace, connects to the abstract unix socket the controller
  binds in that namespace, checks with SO_PEERCRED that the other end is
  the unit's MainPID and not root (an abstract socket has no file mode:
  the check is the credentials, as the controller's is of the helper),
  and sends it what it needs: the facts, and etcd's root certificate,
  this member's client certificate and its key as memfds, so the key is
  written nowhere the controller could keep it;
- **the controller**, `keel vip control SOCKET`, which refuses to run
  with any capability, faces etcd and the overlay (keel.mesh.vipetcd's
  Controller), and asks the root side for every change of the machine,
  one JSON message per line; the root side treats each as untrusted.
"""

import base64
import binascii
import hashlib
import json
import os
import socket
import ssl
import sys
import threading
import time
from collections.abc import Callable

from keel import exits
from keel.mesh import bridge, etcdstate, memberd, vipetcd
from keel.mesh.bridge import BridgeError, Unit, capabilities, line, send
from keel.mesh.channel import pem_fds
from keel.mesh.etcdclient import Client
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.vip import Held
from keel.mesh.vipetcd import Facts, Ops
from keel.mesh.vipnode import Here, VipError
from keel.network.marker import path as rooted

UNIT = "keel-vip-control"
CREDENTIALS = 3
OPS = ("facts", "held", "take", "sign", "hold", "carry", "drop", "carried")


def names(root: str) -> tuple[str, str]:
    """The controller's unit and its socket's abstract name:
    keel-vip-control for the live system, and their own for another
    root, so several nodes' helpers can run on one host (the tests)"""
    if os.path.abspath(root) == "/":
        return UNIT, f"@{UNIT}"
    digest = hashlib.sha256(os.path.abspath(root).encode()).hexdigest()[:8]
    return f"{UNIT}-{digest}", f"@{UNIT}-{digest}"


def address_of(path: str) -> str:
    """A socket's address: `@name` is the abstract `name` (a NUL first,
    which no command line can carry), anything else a file"""
    return "\0" + path[1:] if path.startswith("@") else path


def socket_path(root: str) -> str:
    """Where the controller listens, as `@name`: an abstract unix socket
    of the
    network namespace it shares with the helper. It has no file, so no
    mode keeps anyone off it: the helper takes it only from the
    controller's unit's MainPID, a dynamic user, by SO_PEERCRED, and the
    controller takes only root or itself; nothing else of the machine
    needs to reach a file the other one owns"""
    return names(root)[1]


def control_command(path: str) -> tuple[str, ...]:
    return (sys.executable, "-m", "keel", "vip", "control", path)


def start_unit(path: str, run: Callable[[tuple[str, ...]], str | None],
               output: Callable[[tuple[str, ...]], str | None],
               unit: str = UNIT) -> Unit:
    """Start keel-vip-control in this process's network namespace (the
    host's on a machine), with this process's PYTHONPATH when it has
    one; raises BridgeError"""
    found = f"/proc/{os.getpid()}/ns/net"
    pythonpath = os.environ.get("PYTHONPATH")
    run(("systemctl", "stop", unit))
    problem = run(("systemd-run", f"--unit={unit}", "--collect", "--quiet",
                   f"--property=NetworkNamespacePath={found}",
                   *(f"--property={one}"
                     for one in bridge.LISTENER_PROPERTIES),
                   *((f"--setenv=PYTHONPATH={pythonpath}",)
                     if pythonpath else ()),
                   "--description=keel: the VIP's unprivileged controller",
                   *control_command(path)))
    if problem:
        raise BridgeError(f"the controller could not start: {problem}")
    return Unit(unit, run, output)


def held_data(held: Held) -> dict:
    return {"vip": held.vip, "fenced": held.fenced, "lease": held.lease,
            "released": held.released,
            "claim": None if held.claim is None
            else base64.b64encode(held.claim.raw).decode()}


def held_of(data: dict) -> Held:
    from keel.mesh import vipmsg
    raw = data.get("claim")
    claim = None if raw is None else vipmsg.claim_of(
        base64.b64decode(raw, validate=True))
    return Held(str(data["vip"]), claim, bool(data["fenced"]),
                data.get("lease"), bool(data.get("released")))


def answered(ops: Ops, data: bytes) -> dict:
    """The root side's answer to one message; never raises for what the
    controller sends, which is untrusted"""
    try:
        found = json.loads(data.decode())
        op = found.get("op")
        if op not in OPS:
            raise ValueError(f"unknown operation {op!r}")
        if op == "facts":
            facts = ops.facts()
            return {"ok": {"own_key": facts.own_key,
                           "mesh_id": facts.mesh_id, "vip": facts.vip,
                           "iface": facts.iface,
                           "peers": list(facts.peers)}}
        if op == "held":
            return {"ok": [held_data(one) for one in ops.held()]}
        if op == "take":
            return {"ok": ops.take(raw(found))}
        if op == "sign":
            lease = found.get("lease")
            made = ops.sign(str(found["vip"]), int(found["epoch"]),
                            None if lease is None else str(lease))
            return {"ok": base64.b64encode(made.raw).decode()}
        if op == "hold":
            ops.hold(raw(found), str(found["lease"]))
            return {"ok": None}
        if op == "carry":
            return {"ok": ops.carry(str(found["vip"]),
                                    float(found["age"]))}
        if op == "drop":
            lease = found.get("lease")
            ops.drop(str(found["vip"]), bool(found["fence"]),
                     str(found["why"])[:200],
                     None if lease is None else str(lease))
            return {"ok": None}
        return {"ok": ops.carried(str(found["vip"]))}
    except (ValueError, KeyError, TypeError, AttributeError,
            binascii.Error, ProtocolError, VipError, NodeError,
            OSError) as e:
        return {"error": str(e)[:400] or type(e).__name__}


def raw(found: dict) -> bytes:
    return base64.b64decode(str(found["raw"]), validate=True)


class Remote(Ops):
    """The root side, as the controller asks it over the bridge; one
    question at a time. An error there is a VipError here."""

    def __init__(self, sock: socket.socket, stop: threading.Event):
        self.sock = sock
        self.stop = stop
        self.lock = threading.Lock()

    def ask(self, op: str, **body) -> object:
        with self.lock:
            try:
                send(self.sock, {"op": op, **body})
                found = line(self.sock)
            except (OSError, BridgeError) as e:
                found = None
                why = str(e)
            else:
                why = "it closed the bridge"
        if found is None:
            self.stop.set()
            raise VipError(f"the root side is gone: {why}")
        data = json.loads(found.decode())
        if "error" in data:
            raise VipError(data["error"])
        return data["ok"]

    def facts(self) -> Facts:
        found = self.ask("facts")
        return Facts(found["own_key"], found["mesh_id"], found["vip"],
                     found["iface"], tuple(found["peers"]))

    def held(self) -> list[Held]:
        return [held_of(one) for one in self.ask("held")]

    def take(self, raw_claim: bytes) -> str | None:
        return self.ask("take", raw=base64.b64encode(raw_claim).decode())

    def sign(self, vip: str, epoch: int, lease: str | None = None):
        from keel.mesh import vipmsg
        return vipmsg.claim_of(base64.b64decode(
            self.ask("sign", vip=vip, epoch=epoch, lease=lease)))

    def hold(self, raw_claim: bytes, lease: str) -> None:
        self.ask("hold", raw=base64.b64encode(raw_claim).decode(),
                 lease=lease)

    def carry(self, vip: str, age: float) -> bool:
        return bool(self.ask("carry", vip=vip, age=age))

    def drop(self, vip: str, fence: bool, why: str,
             lease: str | None = None) -> None:
        self.ask("drop", vip=vip, fence=fence, why=why, lease=lease)

    def carried(self, vip: str) -> bool | None:
        return self.ask("carried", vip=vip)


def credentials(root: str) -> tuple[str, str, str]:
    """etcd's root certificate, this member's client certificate and its
    key, as text; raises OSError without them"""
    found = []
    for relative in (etcdstate.ROOT_CERT, etcdstate.CLIENT_CERT,
                     etcdstate.CLIENT_KEY):
        with open(rooted(root, relative)) as fob:
            found.append(fob.read())
    return found[0], found[1], found[2]


def serve(here: Here, stop: threading.Event,
          start: Callable[[str], object] | None = None,
          path: str | None = None,
          sleep: Callable[[float], None] = time.sleep) -> int:
    """`keel vip tend`: the root helper, until `stop` or the controller
    is gone; every VIP this node carries is dropped when it ends"""
    try:
        texts = credentials(here.root)
    except OSError as e:
        here.err(f"vip: this member holds no etcd client certificate: {e}")
        return exits.APPLY_FAILED
    path = path or socket_path(here.root)
    ops = Ops(here)
    code = exits.OK
    started = None
    try:
        started = (start or (lambda where: start_unit(
            where, here.node.run, here.node.output,
            names(here.root)[0])))(path)
        with bridge.connected(address_of(path), started, sleep,
                              lambda pid, uid: (
                here.err(f"vip: the controller (pid {pid}, uid {uid})"
                         " runs")), lambda pid, uid: here.err(
                f"vip: skipped process {pid} (uid {uid}) at {path}: it is"
                " not the controller")) as conn:
            with pem_fds(*texts) as fds:
                socket.send_fds(conn, [json.dumps({
                    "endpoint": etcdstate.client_url(
                        etcdstate.LOOPBACK)}).encode() + b"\n"], fds)
            while (data := memberd.message(conn, stop)) is not None:
                send(conn, answered(ops, data))
    except (BridgeError, OSError) as e:
        here.err(f"vip: the controller stopped: {e}")
        code = exits.APPLY_FAILED
    finally:
        if started is not None:
            started.stop()
        stop.set()
        vipetcd.stopped(here)
    return code


PR_SET_NO_NEW_PRIVS = 38


def no_new_privileges(err: Callable[[str], None],
                      status: str = bridge.STATUS,
                      prctl=None) -> bool:
    """This process and its children never gain privileges, whatever
    the unit set (keel-vip.service sets NoNewPrivileges=yes); says so
    when it was not set already. Whether it is set now"""
    with open(status) as fob:
        found = next((line.split()[1] for line in fob
                      if line.startswith("NoNewPrivs:")), "0")
    if found == "1":
        return True
    err("vip: this process could gain privileges (NoNewPrivs 0): setting"
        " it now")
    if prctl is None:
        import ctypes
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0


def control(path: str, err: Callable[[str], None],
            status: str = bridge.STATUS,
            stop: threading.Event | None = None) -> int:
    """`keel vip control`: the unprivileged controller's life"""
    with open(status) as fob:
        found = capabilities(fob.read())
    if found != 0:
        err(f"the VIP's controller runs without capabilities, and this"
            f" process has {found:#x}: refused")
        return exits.APPLY_FAILED
    sock = listened(path, os.getuid())
    if sock is None:
        err(f"no root helper came to {path!r} within"
            f" {bridge.CONNECT_WAIT} s")
        return exits.APPLY_FAILED
    with sock:
        message, fds, _, _ = socket.recv_fds(sock, bridge.MAX_MESSAGE,
                                             CREDENTIALS)
        try:
            endpoint = str(json.loads(message.decode())["endpoint"])
            tls = context(*(f"/proc/self/fd/{one}" for one in fds))
        except (ValueError, KeyError, TypeError, OSError,
                ssl.SSLError) as e:
            err(f"the root side sent nothing the controller can use"
                f" ({e or 'nothing'}): refused")
            return exits.APPLY_FAILED
        finally:
            for one in fds:
                os.close(one)
        client = Client((endpoint,), tls, vipetcd.CALL_TIMEOUT)
        err("the VIP's controller runs, without capabilities")
        stop = stop or threading.Event()
        vipetcd.Controller(Remote(sock, stop), lambda: client, stop,
                           err).run()
    return exits.OK


def listened(path: str, own_uid: int,
             wait: float = bridge.CONNECT_WAIT) -> socket.socket | None:
    """The root helper's connection to the controller's socket at `path`
    (abstract when it starts with a NUL); None when none came. A peer
    that is neither root nor this user is dropped"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(address_of(path))
        server.listen(1)
        server.settimeout(wait)
        while True:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                return None
            _, uid, _ = bridge.PEERCRED.unpack(conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, bridge.PEERCRED.size))
            if uid in (0, own_uid):
                return conn
            conn.close()


def context(ca: str, certificate: str, key: str) -> ssl.SSLContext:
    """TLS trusting the mesh's root alone, with this member's client
    certificate; raises ssl.SSLError, OSError"""
    found = ssl.create_default_context(cafile=ca)
    found.load_cert_chain(certificate, key)
    found.minimum_version = ssl.TLSVersion.TLSv1_3
    return found
