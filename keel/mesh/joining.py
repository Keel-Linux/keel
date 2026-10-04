# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh join TOKEN: the new node's side (decision 0048)

1. The token is read whole (keel.mesh.token), the spec checked to take
   it (keel.mesh.join), and nothing waits in 0018's window here.
2. The node keeps the mesh's identity, makes its key pair if it has
   none, and finds a route to the inviter's endpoint; without one it
   says so and names the rendezvous point (0024), applying nothing.
3. It sends the join request to the inviter's HTTPS port, pinning the
   certificate the token names: its key, its endpoint, the reserved
   address, a nonce and the time, under an HMAC with the invite's key.
4. With the signed answer, it writes its own spec (its address, the
   inviter and the other members it names as peers) and applies it
   under the window.
5. It opens the mesh session over the overlay, to the inviter's overlay
   address: the inviter confirms its own window on receiving it, and
   this node confirms its own on the inviter's signed answer.

When the HTTPS port gives no TCP answer, this node applies its own side
under a window lengthened to the invite's remaining time (up to 15
minutes), prints `keel mesh accept keel1a:...` for the inviter, and
waits for the inviter over the overlay, as in step 5; then it pulls
the other members from the inviter (keel mesh sync), which the line
could not carry.

The answer of a join carries the other members the inviter knows: they
are peers of this node from its first change, and the inviter announces
this node to them (keel.mesh.sync).
"""

import ipaddress
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from keel import exits
from keel.mesh import (
    acceptline,
    channel,
    identity,
    join,
    members,
    protocol,
    signing,
    sync,
    trust,
)
from keel.mesh.acceptline import Accept
from keel.mesh.channel import ChannelError, Forged, Refused, Unreachable
from keel.mesh.endpoint import Choice
from keel.mesh.node import Change, Node, NodeError, static_addresses
from keel.mesh.token import Token, hmac_key, shown
from keel.network import live, session, wgkeys, wireguard
from keel.system.ovstate import overlay_of

# how often the mesh session is tried while the tunnel comes up
RETRY = 2.0
FALLBACK_LONGEST = 900
FALLBACK_SHORTEST = 30
TWO_NODES = ("the mesh is up with 2 nodes; etcd starts when a third node"
             " joins, because 2 etcd members cannot lose one and keep a"
             " majority")
RENDEZVOUS = ("the way in is the rendezvous point of decision 0024, which"
              " the operator runs")


@dataclass
class Joiner:
    """The new node's side; every function the outside world answers is
    a field, so the flow is tested without a network"""

    node: Node
    token: Token
    clock: Callable[[], datetime]
    out: Callable[[str], None]
    err: Callable[[str], None]
    post: Callable[..., channel.Reply] = channel.post
    sleep: Callable[[float], None] = time.sleep
    route_dev: Callable[[str], str | None] = field(default=live.route_dev)
    # pulls the members from the inviter at its overlay address
    learn: Callable[[str], int] | None = None

    @property
    def key(self) -> bytes:
        return hmac_key(self.token.secret)

    def learned(self, inviter: str) -> int:
        """keel mesh sync from the inviter alone (keel.mesh.sync)"""
        if self.learn is not None:
            return self.learn(inviter)
        return sync.pull(sync.Syncer(self.node, self.clock, self.err),
                         (inviter,))

    def refused(self, message: str, code: int = exits.MESH_REFUSED) -> int:
        self.err(message)
        return code


def run(joiner: Joiner, endpoint: str | None) -> int:
    """Join; `endpoint` is where the inviter reaches this node, or None"""
    token = joiner.token
    try:
        doc = joiner.node.document()
        after = join.merged(doc, join.change(overlay_of(doc), token))
    except (NodeError, join.JoinError) as e:
        return joiner.refused(str(e))
    problems = joiner.node.problems(after)
    if problems:
        return joiner.refused("; ".join(f"{joiner.node.path}, once joined:"
                                        f" {one}" for one in problems))
    if joiner.node.waiting():
        return joiner.refused(
            "a network change waits for its confirmation on this node:"
            " confirm or revert it (keel network confirm, keel network"
            " revert), then join")
    reach = [host for host in token.endpoints
             if joiner.route_dev(host) is not None]
    if not reach:
        return joiner.refused(
            f"this node has no route to the inviter at"
            f" {', '.join(token.endpoints)}: {RENDEZVOUS}; nothing was"
            " applied")
    try:
        kept = identity.read(joiner.node.root)
    except ValueError as e:
        return joiner.refused(str(e))
    if kept not in (None, token.mesh_id):
        return joiner.refused(f"this node is in another mesh:"
                              f" /{identity.IDENTITY} names another one"
                              " than the token's")
    overlay = overlay_of(after)
    public, problem = own_key(joiner.node.root, overlay)
    if public is None:
        return joiner.refused(problem, exits.APPLY_FAILED)
    try:
        signer = signing.ensure(joiner.node.root)
    except signing.SigningError as e:
        return joiner.refused(str(e), exits.APPLY_FAILED)
    own = f"{endpoint_text(endpoint)}:{wireguard.port(overlay)}" \
        if endpoint else None
    request = protocol.JoinRequest(
        invite_id=token.invite_id, public_key=public, endpoint=own,
        address=token.assigned, nonce=protocol.new_nonce(),
        time=protocol.seconds(joiner.clock()), sign_key=signer)
    return requested(joiner, after, request, reach)


def requested(joiner: Joiner, after: dict, request: protocol.JoinRequest,
              reach: list[str]) -> int:
    token = joiner.token
    body = protocol.dumps(request)
    for host in reach:
        try:
            reply = joiner.post(host, token.https_port, protocol.JOIN, body,
                                joiner.key, token.fingerprint)
            break
        except Unreachable as e:
            joiner.err(f"no answer from the inviter's port: {e}")
        except ChannelError as e:
            return joiner.refused(f"the inviter refused the join: {e}"
                                  if isinstance(e, Refused) else str(e))
    else:
        return fallback(joiner, after, request)
    try:
        answer = protocol.join_answer(reply.body)
    except protocol.ProtocolError as e:
        return joiner.refused(f"the inviter's answer is malformed: {e}")
    if (answer.invite_id, answer.nonce, answer.address) != (
            token.invite_id, request.nonce, token.address) or \
            not wireguard.same_key(answer.public_key, token.public_key):
        return joiner.refused("the inviter's answer is not the answer to"
                              " this request")
    if not admitted_by(answer, request, token):
        return joiner.refused("the inviter's answer carries no valid"
                              " evidence of this node's admission")
    # kept only once the inviter has admitted this node
    identity.adopt(joiner.node.root, token.mesh_id)
    # the other members the inviter knows, peers of this node too, those
    # whose admission it can verify: the inviter announces this node to
    # them (keel.mesh.sync)
    try:
        taken = trusting(joiner, answer.sign_key, request.sign_key,
                         answer.peers)
    except ValueError as e:
        return joiner.refused(str(e))
    after, _ = members.with_members(after, taken, request.public_key)
    change = applied(joiner, after)
    if change is None:
        return exits.APPLY_FAILED
    return confirmed(joiner, change, request.public_key, answer.peers)


def admitted_by(answer: protocol.JoinAnswer, request: protocol.JoinRequest,
                token: Token) -> bool:
    """Whether the answer's evidence is this node's admission, signed by
    the inviter's signing key the answer names"""
    found = answer.admission
    return (found.by == answer.sign_key
            and wireguard.same_key(found.public_key, request.public_key)
            and found.sign_key == request.sign_key
            and found.address == str(ipaddress.IPv6Interface(
                token.assigned).ip)
            and found.invite_id == token.invite_id
            and found.mesh_id == token.mesh_id.hex()
            and signing.verified(found.by, found.message(),
                                 found.signature))


def trusting(joiner: Joiner, inviter_signer: str, own_signer: str,
             peers: tuple[protocol.Peer, ...]) -> tuple[protocol.Peer, ...]:
    """The inviter trusted as this node's root, its signing key as the
    invite's HMAC authenticated it; the members of `peers` whose evidence
    chains to it. Raises ValueError for a damaged trust store"""
    root = joiner.node.root
    store = trust.load(root)
    trust.make_roots(store, (joiner.token.public_key,))
    trust.bind_root(store, joiner.token.public_key, inviter_signer)
    taken = trust.accepted(store, own_signer, joiner.token.mesh_id, peers)
    trust.save(root, store)
    return taken


def fallback(joiner: Joiner, after: dict,
             request: protocol.JoinRequest) -> int:
    """No TCP answer: apply this side, print the line for the inviter"""
    token = joiner.token
    if request.endpoint is None:
        return joiner.refused(
            "neither node can reach the other: the inviter's port gave no"
            " answer and this node has no endpoint the inviter could"
            f" reach; {RENDEZVOUS}; nothing was applied")
    left = int((token.expires - joiner.clock()).total_seconds())
    window = min(left, FALLBACK_LONGEST)
    if window < FALLBACK_SHORTEST:
        return joiner.refused(f"the token expires at {shown(token.expires)},"
                              " too soon to wait for the inviter; ask it"
                              " for a new invite")
    identity.adopt(joiner.node.root, token.mesh_id)
    change = applied(joiner, after, window)
    if change is None:
        return exits.APPLY_FAILED
    line = acceptline.encode(Accept(
        public_key=request.public_key, endpoint=request.endpoint,
        address=token.assigned, invite_id=token.invite_id,
        time=protocol.seconds(joiner.clock()), sign_key=request.sign_key),
        joiner.key)
    joiner.out(f"keel mesh accept {line}")
    joiner.err(f"the inviter's TCP port {token.https_port} gave no answer:"
               " run the line above on the inviter within"
               f" {window // 60} minutes. This node waits for it over the"
               " overlay, and its change reverts by itself if it never"
               " comes")
    code = confirmed(joiner, change, request.public_key, ())
    if code == exits.OK:
        # the accept line carries no answer, so no member: pulled now
        joiner.err("learning the other members from the inviter…")
        joiner.learned(str(ipaddress.IPv6Interface(token.address).ip))
    return code


def applied(joiner: Joiner, after: dict,
            window: int | None = None) -> Change | None:
    """This node's change, applied and waiting in its window; None when
    it did not come up"""
    try:
        change = joiner.node.change(after, window)
    except NodeError as e:
        joiner.err(str(e))
        return None
    if change.made is None:
        change.shown(joiner.err)
        joiner.err(f"this node's overlay did not come up under the window"
                   f" (apply exited {change.code}); the token is spent and"
                   " the inviter's change reverts by itself: ask it for a"
                   " new invite")
        return None
    return change


def unconfirmed(joiner: Joiner, change: Change, message: str) -> int:
    """apply's own lines, its revert warning among them, then why"""
    change.shown(joiner.err)
    return joiner.refused(message, exits.NETWORK_NOT_CONFIRMED)


def confirmed(joiner: Joiner, change: Change, public: str,
              peers: tuple[protocol.Peer, ...]) -> int:
    """The mesh session over the overlay, then this node's confirmation

    apply's lines are held (keel.mesh.node.Change): this node confirms
    its change itself, so "unless `keel network confirm`" is shown only
    when it could not.
    """
    token = joiner.token
    made = change.made
    inviter = str(ipaddress.IPv6Interface(token.address).ip)
    deadline = joiner.clock().timestamp() + made.window
    joiner.err("confirming over the overlay…")
    while True:
        request = protocol.ConfirmRequest(
            invite_id=token.invite_id, public_key=public,
            nonce=protocol.new_nonce(),
            time=protocol.seconds(joiner.clock()))
        body = protocol.dumps(request)
        try:
            reply = joiner.post(inviter, token.https_port, protocol.CONFIRM,
                                body, joiner.key, token.fingerprint,
                                connect_timeout=RETRY)
            break
        except (Refused, Forged) as e:
            return unconfirmed(joiner, change, f"the mesh session was"
                               f" refused: {e}; this node's change reverts"
                               " by itself")
        except ChannelError:
            if joiner.clock().timestamp() + RETRY >= deadline:
                return unconfirmed(
                    joiner, change, f"the inviter did not answer over the"
                    f" overlay at [{inviter}]:{token.https_port} within the"
                    " window; this node's change reverts by itself")
            joiner.sleep(RETRY)
    try:
        answer = protocol.confirm_answer(reply.body)
    except protocol.ProtocolError as e:
        return unconfirmed(joiner, change,
                           f"the inviter's answer is malformed: {e}")
    if (answer.invite_id, answer.nonce) != (token.invite_id, request.nonce):
        return unconfirmed(joiner, change, "the inviter's answer is not the"
                           " answer to this mesh session; this node's change"
                           " reverts by itself")
    if not answer.confirmed:
        return unconfirmed(
            joiner, change, f"the inviter did not keep its change"
            f" ({answer.detail}); this node's change reverts by itself")
    try:
        # the fallback's node learns the inviter's signing key here
        trusting(joiner, answer.sign_key, public_signer(joiner), ())
    except (ValueError, signing.SigningError) as e:
        return unconfirmed(joiner, change, str(e))
    origin = session.Origin(
        session.MESH, f"the inviter's answer over the overlay (invite"
        f" {token.invite_id})", None, reply.local, reply.peer)
    kept, lines = joiner.node.confirm(origin, made)
    if not kept:
        change.shown(joiner.err)
    for line in lines:
        joiner.err(line)
    if not kept:
        return exits.NETWORK_NOT_CONFIRMED
    summary(joiner, peers)
    return exits.OK


def public_signer(joiner: Joiner) -> str:
    return signing.public(joiner.node.root)


def summary(joiner: Joiner, peers: tuple[protocol.Peer, ...]) -> None:
    """What `join` prints at the end, and confconsole shows"""
    token = joiner.token
    overlay = joiner.node.overlay()
    inviter = ipaddress.IPv6Interface(token.address).ip
    joiner.out(f"joined the mesh: this node is {token.assigned} on"
               f" {wireguard.interface(overlay)}")
    joiner.out(f"peer: {token.public_key} at {inviter}, through"
               f" {token.endpoint()}")
    if not peers:
        joiner.out(TWO_NODES)
        return
    joiner.out(f"the mesh has {len(peers) + 2} nodes: this node has them all"
               f" as peers, and the inviter announces this node to the"
               f" {len(peers)} other(s) over the overlay (one offline now"
               " learns of it at its next keel mesh sync); etcd is not part"
               " of this keel")


def own_key(root: str, overlay: dict) -> tuple[str | None, str]:
    """This node's public key, the pair made first when there is none
    (keel-core#8: on the machine itself)"""
    path = os.path.join(root, wireguard.key_path(overlay).lstrip("/"))
    if not os.path.exists(path):
        problem = wgkeys.generate(path)
        if problem:
            return None, problem
    public, problem = wgkeys.public(path)
    return public, str(problem or "")


def endpoint_text(address: str) -> str:
    found = ipaddress.ip_address(address)
    return f"[{found}]" if found.version == 6 else str(found)


def own_endpoint(declared: str | None, doc: dict,
                 found: Choice | None) -> str | None:
    """Where the inviter reaches this node: `--endpoint`, else a static
    address network.interfaces declares, else the one `found` on the
    uplink (keel.mesh.endpoint); IPv6 first, None without one another
    node could reach"""
    if declared:
        return str(ipaddress.ip_address(declared))
    hosts = sorted(static_addresses(doc), key=lambda one: one.version,
                   reverse=True)
    if hosts:
        return str(hosts[0])
    return found.addresses[0] if found and found.addresses else None
