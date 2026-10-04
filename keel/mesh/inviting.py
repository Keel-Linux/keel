# Copyright (c) 2026 KeelLinux maintainers
"""The inviter's side: the listener's unit, and accept (decision 0048)

`keel mesh invite` starts the invite's root helper as a transient unit,
`keel-mesh-invite@<id>`, so the command returns and the invite closes
by itself even if nothing else runs again: the unit's RuntimeMaxSec is
the time left to the expiry, plus the window a join made just before
it needs to be confirmed in. The unit runs `keel mesh serve <id>`
(`serve` here), which starts the unprivileged listener on the invite's
TCP port, on every address, and answers what it forwards through
keel.mesh.bridge; when it ends, however it ends, it stops the listener
and removes the invite's file and its port from keel's firewall. A join
confirmed is then announced to this node's other peers over the overlay
(keel.mesh.sync), so the mesh stays a full one.

`keel mesh accept keel1a:...` is the fallback's other half: the new node
could not reach the port, applied its own side, and printed the line.
accept checks the line's HMAC with the invite's key, consumes the
invite, adds the new node as a peer (with a keepalive, since this node
may be the one that has to initiate), applies, and then, in the
foreground, does what serve does, with the listener on its overlay
address alone, until the new node confirms or the window ends.
"""

import ipaddress
import ssl
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from keel import exits
from keel.mesh import (
    acceptline,
    bridge,
    etcd,
    etcdform,
    etcdstate,
    invites,
    ports,
    sync,
)
from keel.mesh.admit import Admitter, Joined, admitted, stopped
from keel.mesh.bridge import Bridge, BridgeError, socket_path
from keel.mesh.listener import Params
from keel.mesh.node import Node, NodeError
from keel.mesh.signing import SigningError
from keel.network import live, wgkeys, wireguard
from keel.system import DEFAULT_WINDOW

UNIT = "keel-mesh-invite@{id}"
# a join accepted just before the expiry is confirmed within its window
LINGER = DEFAULT_WINDOW + 60
KEEPALIVE = 25
EVERY_ADDRESS = "::"


def unit(invite_id: str) -> str:
    return UNIT.format(id=invite_id)


def serve_command(invite_id: str, spec: str) -> tuple[str, ...]:
    """What the unit runs: this interpreter, so no PATH is involved"""
    return (sys.executable, "-m", "keel", "mesh", "serve", invite_id,
            "--spec", spec)


def start(made: invites.Pending, spec: str, now: datetime,
          run: Callable[[tuple[str, ...]], str | None]) -> str | None:
    """Start the invite's listener; None, or why it could not be"""
    seconds = int((made.expires - now).total_seconds()) + LINGER
    return run((
        "systemd-run", f"--unit={unit(made.invite_id)}", "--collect",
        "--quiet", f"--property=RuntimeMaxSec={seconds}",
        f"--description=keel: the listener of mesh invite {made.invite_id}",
        *serve_command(made.invite_id, spec)))


@dataclass
class Inviter:
    """This node as the inviter; the outside world as fields"""

    node: Node
    clock: Callable[[], datetime]
    out: Callable[[str], None]
    err: Callable[[str], None]
    run: Callable[[tuple[str, ...]], str | None] = field(default=live.run)
    # starts the listener: (invite id, socket path, seconds) -> what can
    # tell its process and stop it (keel.mesh.bridge.Unit)
    start: Callable[[str, str, int], object] | None = None
    bridged: Callable[[Bridge], None] = Bridge.run
    output: Callable[[tuple[str, ...]], str | None] = field(
        default=live.output)
    # tells the other members of a confirmed join (keel.mesh.sync)
    announce: Callable[[str], None] | None = None
    # etcd once a join is confirmed: the admitter of a join through the
    # listener, None for the fallback's (keel.mesh.etcd)
    etcd_after: Callable[[Admitter | None], None] | None = None

    @property
    def root(self) -> str:
        return self.node.root

    def announced(self, key: str) -> None:
        """The new node `key` announced to this node's other peers"""
        if self.announce is not None:
            self.announce(key)
            return
        sync.announce(sync.Syncer(self.node, self.clock, self.err), key)

    def etcd_joined(self, admitter: Admitter | None) -> None:
        """etcd, once a join is confirmed: what the admitter decided
        (keel.mesh.etcd.admitted); for the fallback's join, whose line
        carries no request, keel mesh etcd form brings the node in"""
        if self.etcd_after is not None:
            self.etcd_after(admitter)
            return
        member = etcd.Etcd(self.node, self.clock, self.err)
        if admitter is not None and not admitter.confirmed:
            etcd.abandoned(member, admitter.etcd_admission)
            return
        if admitter is not None:
            etcd.admitted(member, admitter.etcd_admission,
                          admitter.joined.public_key,
                          lambda one, cluster: etcdform.send_cluster(
                              member, one, cluster))
            return
        try:
            if not etcd.ready(self.node.document()) or \
                    not etcdstate.credentials(self.root):
                return
        except NodeError:
            return
        if not etcdstate.holds_root(self.root):
            self.err("etcd: keel mesh etcd form on the root CA's holder"
                     f" ({etcdstate.holder(self.root) or 'the first node'})"
                     " brings the new node into etcd")
            return
        self.err("etcd: bringing the new node in (keel mesh etcd form)")
        etcdform.form(member, False, self.err)

    def own(self) -> tuple[str | None, str]:
        """(public key, overlay address with its length); key None and
        the reason when it cannot be read"""
        overlay = self.node.overlay()
        address = str(overlay.get("address") or "")
        key = wireguard.key_path(overlay)
        public, problem = wgkeys.public(f"{self.root.rstrip('/')}/"
                                        f"{key.lstrip('/')}")
        return public, (str(problem) if public is None else address)

    def starter(self, invite_id: str, seconds: int) -> Callable[[str], object]:
        if self.start is not None:
            return lambda path: self.start(invite_id, path, seconds)
        return lambda path: bridge.start_unit(invite_id, path, seconds,
                                              self.run, self.output)

    def bridge(self, admitter: Admitter, invite: invites.Pending,
               params: Params) -> None:
        """The listener with `params`, until it is done; raises
        BridgeError"""
        seconds = int((params.joined[2] if params.joined else
                       params.expires).timestamp()
                      - self.clock().timestamp()) + 1
        self.bridged(Bridge(
            admitter, params, invite.certificate, invite.tls_key,
            socket_path(self.root, invite.invite_id),
            self.starter(invite.invite_id, max(seconds, 1)), self.err))

    def close(self, invite: invites.Pending) -> None:
        """The invite is done: its file and its port go"""
        invites.remove(self.root, invite.invite_id)
        others = [one for one in invites.pending(self.root, self.clock())
                  if one.https_port == invite.https_port]
        if not others:
            ports.close_port(invite.https_port, self.run)


def terminated(signum, frame):
    """systemctl stop and RuntimeMaxSec send SIGTERM: end through the
    `finally` that removes the invite (keel.mesh.commands.mesh_serve
    installs it)"""
    raise SystemExit(0)


def serve_invite(inviter: Inviter, invite_id: str) -> int:
    """`keel mesh serve`: what the unit runs, until the invite is done"""
    found = invites.find(inviter.root, invite_id, inviter.clock())
    if found is None:
        inviter.err(f"invite {invite_id}: not pending (used, cancelled or"
                    " expired); nothing to serve")
        return exits.MESH_REFUSED
    public, address = inviter.own()
    if public is None:
        inviter.err(address)
        inviter.close(found)
        return exits.APPLY_FAILED
    admitter = Admitter(inviter.root, found, public, address, inviter.node,
                        inviter.clock, inviter.err)
    own = str(ipaddress.IPv6Interface(address).ip)
    inviter.err(f"invite {invite_id}: serving TCP port {found.https_port}"
                f" until {found.expires:%H:%M:%S} UTC")
    code = exits.OK
    try:
        inviter.bridge(admitter, found, Params(
            found.invite_id, found.expires, EVERY_ADDRESS,
            found.https_port, own))
    except (BridgeError, OSError, ssl.SSLError) as e:
        inviter.err(f"invite {invite_id}: {e}")
        code = exits.APPLY_FAILED
    finally:
        inviter.close(found)
    inviter.err(stopped(admitter))
    if admitter.confirmed:
        inviter.announced(admitter.joined.public_key)
    if admitter.joined is not None:
        inviter.etcd_joined(admitter)
    return code


def accept(inviter: Inviter, text: str) -> int:
    """`keel mesh accept keel1a:...`: the fallback, on the inviter"""
    try:
        sealed = acceptline.parse(text)
    except acceptline.AcceptError as e:
        inviter.err(str(e))
        return exits.MESH_TOKEN_INVALID
    line = sealed.accept
    now = inviter.clock()
    found = invites.find(inviter.root, line.invite_id, now)
    if found is None:
        inviter.err(f"no pending invite {line.invite_id} on this node: it"
                    " expired, was used, or was made by another node")
        return exits.MESH_REFUSED
    if not sealed.authentic(found.hmac_key) or line.address != found.address:
        inviter.err(f"the line is not the answer to invite {line.invite_id}:"
                    " its HMAC does not match the invite's key")
        return exits.MESH_REFUSED
    if inviter.node.waiting():
        inviter.err("a network change waits for its confirmation on this"
                    " node: confirm or revert it, then accept again")
        return exits.MESH_REFUSED
    public, address = inviter.own()
    if public is None:
        inviter.err(address)
        return exits.APPLY_FAILED
    try:
        spent = invites.consume(inviter.root, line.invite_id, now)
    except invites.InviteError as e:
        inviter.err(str(e))
        return exits.MESH_REFUSED
    # the invite's listener holds the port on every address: it goes
    inviter.run(("systemctl", "stop", unit(line.invite_id)))
    try:
        return accepted(inviter, spent, line, public, address)
    finally:
        inviter.close(spent)


def accepted(inviter: Inviter, spent: invites.Pending,
             line: acceptline.Accept, public: str, address: str) -> int:
    joiner = str(ipaddress.IPv6Interface(line.address).ip)
    peer = {"public_key": line.public_key,
            "allowed_ips": [f"{joiner}/128"],
            "persistent_keepalive": KEEPALIVE}
    if line.endpoint:
        peer["endpoint"] = line.endpoint
    inviter.err(f"invite {spent.invite_id}: accepting key {line.public_key},"
                f" endpoint {line.endpoint or 'none'}, at {joiner}")
    if wireguard.same_key(line.public_key, public):
        inviter.err("that key is this node's own: a new node joins with a"
                    " key of its own; the invite is spent")
        return exits.MESH_REFUSED
    since = int(inviter.clock().timestamp())
    try:
        admitted(inviter.root, spent.invite_id, line.public_key,
                 line.sign_key, joiner, line.endpoint, inviter.clock())
        change = inviter.node.admit(peer)
    except (NodeError, ValueError, SigningError) as e:
        inviter.err(f"{e}; the invite is spent")
        return exits.MESH_REFUSED
    if change.made is None:
        change.shown(inviter.err)
        inviter.err(f"this node's change did not come up (apply exited"
                    f" {change.code}); the invite is spent")
        return exits.APPLY_FAILED
    window = change.made.window
    until = inviter.clock() + timedelta(seconds=window)
    admitter = Admitter(
        inviter.root, spent, public, address, inviter.node, inviter.clock,
        inviter.err, joined=Joined(line.public_key, joiner, change.made,
                                   until, since))
    own = str(ipaddress.IPv6Interface(address).ip)
    inviter.err(ports.open_port(spent.https_port, window, inviter.run,
                                inviter.output))
    inviter.err(f"waiting up to {window} s for the new node over the"
                f" overlay, at [{own}]:{spent.https_port}")
    try:
        inviter.bridge(admitter, spent, Params(
            spent.invite_id, spent.expires, own,
            spent.https_port, own, (line.public_key, joiner, until)))
    except (BridgeError, OSError, ssl.SSLError) as e:
        change.shown(inviter.err)
        inviter.err(f"cannot serve [{own}]:{spent.https_port}: {e}; this"
                    " node's change reverts by itself")
        return exits.NETWORK_NOT_CONFIRMED
    if not admitter.confirmed:
        # apply's lines, held while this node confirmed itself
        change.shown(inviter.err)
        inviter.err(stopped(admitter))
        return exits.NETWORK_NOT_CONFIRMED
    inviter.announced(line.public_key)
    inviter.out(f"accepted: {line.public_key} is a peer of this node at"
                f" {joiner}")
    inviter.etcd_joined(None)
    return exits.OK
