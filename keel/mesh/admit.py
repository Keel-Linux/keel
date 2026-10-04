# Copyright (c) 2026 KeelLinux maintainers
"""The root side of an invite: admit the new node, once (decision 0048)

The network faces an unprivileged listener (keel.mesh.listener), which
hands each request that passed its checks of shape, invite id, time and
nonce, as the bytes it received, to the Admitter in the root helper
(keel.mesh.bridge). The listener never holds the invite's HMAC key: the
HMAC is verified here alone, in constant time, with the shape, the id,
the time and the nonce checked again. Five requests that name the
invite and fail its HMAC cancel it, here too; the response then says
so (`final`), and the listener stops.

A join is then checked against the address the invite reserved, a key
this node already knows (its own, or a peer's: a join never replaces an
entry), and a network change waiting in its window. The invite is
consumed under the mesh's lock, so a second request finds it used, the
new node is written into the spec as a peer and applied under decision
0018's window, and the answer goes back signed. The confirmation
rests on what this side sees itself, never on the addresses the
listener reports: the confirmation request signed with the invite's
key, and a WireGuard handshake from the new node's key since it was
admitted (`wg show <if> latest-handshakes`), which only the holder of
that key, reaching this node over the new tunnel, can make. It confirms
this node's window.

`handle` is a function of the path, the signature header, the body and
the connection's two addresses, so every decision is tested without a
socket. Nothing logged holds the secret, a token, an HMAC or a key.
"""

import ipaddress
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from keel.mesh import identity, invites, protocol, signing, trust
from keel.mesh.node import Node, NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.network import marker, session
from keel.network.wireguard import same_key

# how a refusal is counted by the listener (keel.mesh.listener)
SHAPE = "shape"
HMAC = "hmac"
MAX_FORGED = 5
# how long a confirmation waits for the new peer's handshake to show
HANDSHAKE_WAIT = 10
HANDSHAKE_POLL = 0.5


@dataclass(frozen=True)
class Response:
    """`final`: the invite is done with, and the listener stops"""

    status: int
    body: bytes
    signature: str | None = None
    final: bool = False


@dataclass(frozen=True)
class Joined:
    """The join that was accepted: who, where, the change, and until when
    its confirmation is waited for"""

    public_key: str
    address: str
    made: marker.Pending | None
    until: datetime
    # when it was admitted, in seconds since the epoch: a handshake from
    # its key at or after this was made over the new tunnel
    since: int = 0


class Refusal(Exception):
    def __init__(self, status: int, reason: str, kind: str = SHAPE):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.kind = kind


def refusal(status: int, reason: str) -> Response:
    return Response(status, json.dumps({"error": reason}).encode())


def parsed(invite_id: str, path: str, body: bytes | None, now: datetime,
           parse: Callable[[bytes], object]):
    """The request, if it is this invite's and fresh: what the listener
    can check without the HMAC key. Raises Refusal"""
    if body is None:
        raise Refusal(413, "the request is longer than any join")
    try:
        request = parse(body)
    except ProtocolError as e:
        raise Refusal(400, f"malformed request: {e}") from None
    if request.invite_id != invite_id:
        raise Refusal(403, f"invite {request.invite_id} is not the one"
                      " this listener serves")
    if not protocol.fresh(request.time, now):
        raise Refusal(403, "the request's time is more than"
                      f" {protocol.SKEW} from this node's clock")
    return request


def verify(invite_id: str, key: bytes, path: str, signature: str | None,
           body: bytes | None, now: datetime,
           parse: Callable[[bytes], object]):
    """The request, if it is this invite's, fresh, and signed with its
    key. Raises Refusal; one of kind HMAC is a request that names this
    invite and is not signed with its key"""
    request = parsed(invite_id, path, body, now, parse)
    if not protocol.signed(key, protocol.METHOD, path, body, signature):
        raise Refusal(403, "bad HMAC: the request is not signed with this"
                      " invite's key", HMAC)
    return request


def parser(path: str) -> Callable[[bytes], object]:
    return (protocol.join_request if path == protocol.JOIN
            else protocol.confirm_request)


def default_log(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


class Admitter:
    """One invite, on the root side; `clock` gives an aware UTC datetime"""

    def __init__(self, root: str, invite: invites.Pending, public_key: str,
                 address: str, node: Node, clock: Callable[[], datetime],
                 log: Callable[[str], None] | None = None,
                 joined: Joined | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.root = root
        self.invite = invite
        self.public_key = public_key
        self.address = address
        self.node = node
        self.clock = clock
        self.log = log or default_log
        self.joined = joined
        self.sleep = sleep
        self.nonces: set[str] = set()
        self.forged = 0
        self.confirmed: bool | None = None
        self.cancelled = False

    @property
    def name(self) -> str:
        return f"invite {self.invite.invite_id}"

    def forward(self, path: str, signature: str | None, body: bytes | None,
                local: str, peer: str) -> Response:
        """The answer to one request; never raises

        `local` and `peer` are what the listener reports: for the log,
        never for a decision.
        """
        try:
            if self.cancelled:
                raise Refusal(410, f"{self.name} was cancelled")
            if path == protocol.JOIN:
                return self.join(signature, body, peer)
            if path == protocol.CONFIRM:
                return self.confirm(signature, body)
            raise Refusal(404, f"{path[:64]!r}: no such request")
        except Refusal as e:
            self.log(f"{self.name}: refused a request from {peer}:"
                     f" {e.reason}")
            if e.kind == HMAC:
                self.forged += 1
                if self.forged >= MAX_FORGED and self.joined is None:
                    self.cancel(f"{MAX_FORGED} requests named it and"
                                " failed its HMAC")
            found = refusal(e.status, e.reason)
            return Response(found.status, found.body,
                            final=self.cancelled or self.confirmed is False)

    def cancel(self, reason: str) -> None:
        """The invite is given up on: it goes"""
        invites.remove(self.root, self.invite.invite_id)
        self.cancelled = True
        self.log(f"{self.name}: cancelled, {reason}; run keel mesh invite"
                 " again")

    def checked(self, path: str, signature: str | None, body: bytes | None):
        request = verify(self.invite.invite_id, self.invite.hmac_key, path,
                         signature, body, self.clock(), parser(path))
        if request.nonce in self.nonces:
            raise Refusal(403, "replayed request: its nonce was seen")
        self.nonces.add(request.nonce)
        return request

    def join(self, signature: str | None, body: bytes | None,
             peer: str) -> Response:
        if self.joined is not None:
            raise Refusal(410, f"{self.name} was already used")
        request = self.checked(protocol.JOIN, signature, body)
        if request.address != self.invite.address:
            raise Refusal(403, f"{request.address} is not the address this"
                          " invite reserved")
        if self.known(request.public_key):
            raise Refusal(409, "that key is already this node's or one of"
                          " its peers': a new node joins with a key of its"
                          " own")
        if self.node.waiting():
            self.log(f"{self.name}: a network change waits for its"
                     " confirmation here; the invite stays")
            return refusal(409, "another network change waits for its"
                           " confirmation on the inviter; try again once"
                           " it is confirmed or reverted")
        try:
            invites.consume(self.root, self.invite.invite_id, self.clock())
        except invites.InviteError as e:
            raise Refusal(410, str(e)) from None
        return self.admitted(request, peer)

    def known(self, key: str) -> bool:
        """This node's own key, or a peer's of its spec"""
        if same_key(key, self.public_key):
            return True
        return any(same_key(str(one.get("public_key")), key)
                   for one in self.node.overlay().get("peers") or [])

    def admitted(self, request: protocol.JoinRequest, peer: str) -> Response:
        """The invite is spent: the new node becomes a peer, applied"""
        address = str(ipaddress.IPv6Interface(request.address).ip)
        self.log(f"{self.name}: join from {peer}, key {request.public_key},"
                 f" endpoint {request.endpoint or 'none'}, at {address}")
        entry = {"public_key": request.public_key,
                 "allowed_ips": [f"{address}/128"]}
        since = int(self.clock().timestamp())
        if request.endpoint:
            entry["endpoint"] = request.endpoint
        try:
            evidence = self.evidence(request.public_key, request.sign_key,
                                     address, request.endpoint)
            change = self.node.admit(entry)
            for line in change.lines:
                self.log(f"{self.name}: {line}")
            problem = None if change.made else (
                f"this node's change did not come up (apply exited"
                f" {change.code})")
        except (NodeError, ValueError, SigningError) as e:
            problem = str(e)
        if problem:
            self.confirmed = False
            self.log(f"{self.name}: {problem}; the invite is spent")
            found = refusal(500, "the inviter could not apply the new peer;"
                            " ask it for a new invite")
            return Response(found.status, found.body, final=True)
        window = change.made.window
        self.joined = Joined(request.public_key, address, change.made,
                             self.clock() + timedelta(seconds=window), since)
        answer = protocol.JoinAnswer(
            invite_id=self.invite.invite_id, nonce=request.nonce,
            public_key=self.public_key, address=self.address,
            peers=evidenced(self.root, self.node.peers(request.public_key)),
            etcd="none", window=window, sign_key=evidence.by,
            admission=evidence)
        self.log(f"{self.name}: peer applied; waiting {window} s for the"
                 " new node over the overlay")
        return self.signed(protocol.JOIN, protocol.dumps(answer))

    def evidence(self, key: str, sign_key: str, address: str,
                 endpoint: str | None) -> protocol.Admission:
        """The new node's admission, signed with this node's key and
        kept in its trust store (keel.mesh.trust); raises ValueError or
        SigningError"""
        return admitted(self.root, self.invite.invite_id, key, sign_key,
                        address, endpoint, self.clock())

    def confirm(self, signature: str | None,
                body: bytes | None) -> Response:
        if self.joined is None:
            raise Refusal(409, "no join to confirm yet")
        request = self.checked(protocol.CONFIRM, signature, body)
        if request.public_key != self.joined.public_key:
            raise Refusal(403, "the confirmation is not the new node's")
        try:
            # the answer names it: the fallback's node learns it so
            signer = signing.public(self.root)
        except SigningError as e:
            raise Refusal(500, f"this node cannot name its signing key"
                          f" ({e})") from None
        seen = self.handshake()
        if seen is None:
            raise Refusal(409, f"no WireGuard handshake from"
                          f" {self.joined.public_key} since it was admitted:"
                          " the tunnel is not up yet")
        own = str(ipaddress.IPv6Interface(self.address).ip)
        origin = session.Origin(
            session.MESH, f"a WireGuard handshake from the new peer's key"
            f" ({seen}) and the confirmation of {self.name}", None, own,
            self.joined.address)
        confirmed, lines = self.node.confirm(origin, self.joined.made)
        for line in lines:
            self.log(f"{self.name}: {line}")
        self.confirmed = confirmed
        answer = protocol.ConfirmAnswer(
            invite_id=self.invite.invite_id, nonce=request.nonce,
            confirmed=confirmed, detail="; ".join(lines), sign_key=signer)
        found = self.signed(protocol.CONFIRM, protocol.dumps(answer))
        return Response(found.status, found.body, found.signature, True)

    def handshake(self) -> str | None:
        """When the new peer's key last completed a handshake with this
        node, if it did since it was admitted; waited for a little, as the
        request that comes over the tunnel can come right after it"""
        waited = 0.0
        while True:
            seen = self.node.handshake(self.joined.public_key)
            if seen is not None and seen >= self.joined.since:
                return datetime.fromtimestamp(
                    seen, self.clock().tzinfo).strftime("%H:%M:%S UTC")
            if waited >= HANDSHAKE_WAIT:
                return None
            self.sleep(HANDSHAKE_POLL)
            waited += HANDSHAKE_POLL

    def signed(self, path: str, body: bytes) -> Response:
        return Response(200, body, protocol.sign(
            self.invite.hmac_key, protocol.ANSWER, path, body))


def admitted(root: str, invite_id: str, key: str, sign_key: str,
             address: str, endpoint: str | None,
             now: datetime) -> protocol.Admission:
    """Evidence that this node admits `key` by the invite, signed and
    kept; raises ValueError (no identity, a damaged store) or
    SigningError"""
    mesh_id = identity.read(root)
    if mesh_id is None:
        raise ValueError("this node holds no mesh identity to admit into")
    signing.ensure(root)
    found = trust.admit(root, mesh_id, invite_id, key, sign_key, address,
                        endpoint, now)
    store = trust.load(root)
    trust.recorded(store, found)
    trust.save(root, store)
    return found


def evidenced(root: str, peers: tuple[protocol.Peer, ...]) -> tuple[
        protocol.Peer, ...]:
    """`peers` with the evidence this node keeps for each, if any"""
    try:
        store = trust.load(root)
    except ValueError:
        store = trust.Store()
    return tuple(replace(one, admission=store.evidence(one.public_key))
                 for one in peers)


def stopped(admitter: Admitter) -> str:
    """How the invite ended, in one line for the log"""
    if admitter.cancelled:
        return f"{admitter.name}: cancelled"
    if admitter.confirmed:
        return f"{admitter.name}: joined and confirmed"
    if admitter.joined is not None or admitter.confirmed is False:
        return (f"{admitter.name}: joined, not confirmed; its change"
                " reverts when its window ends")
    return f"{admitter.name}: expired unused"
