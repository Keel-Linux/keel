# Copyright (c) 2026 KeelLinux maintainers
"""A full mesh before etcd: keel mesh sync and the announcement (0048)

"Until etcd exists, members learn about each other through the
inviter." Three things make every member a peer of every other one:

- the join's answer carries the members the inviter knows, with their
  admission evidence, and the new node takes those it can verify as
  peers in the same change (keel.mesh.joining);
- the inviter, once the join is confirmed, announces the new node to
  each of its other peers over the overlay (`announce`);
- a member that was offline then, or one that joined by the fallback,
  pulls the roster of its peers with `keel mesh sync` (`pull`), at boot
  and from a timer (keel-mesh-sync.timer).

What a member is told goes over the members' channel
(keel.mesh.memberlink), which WireGuard authenticates: only a peer's key
can use its overlay address. That says who speaks, not whom it may
vouch for: a roster's entry is taken only with admission evidence that
chains to a key this node trusts (keel.mesh.trust), and never for a key
with a tombstone, so one member cannot make the others take a peer no
member admitted. What it takes is keel.mesh.members.with_members:
members it does not know, never one that would replace or shadow a peer
of its spec. It writes them into its own spec (0013) and applies the
change under 0018's window, all of them in one change, and the change
is confirmed by a WireGuard handshake from a key it added since the
change was made, which only that member, reaching this node over the
new configuration, can complete; this node sends each one a packet to
start it. The route check of apply.md runs first, as for any overlay
change. A change no new member answers within the window is left to
revert, the spec is put back as it was, and those members are not
tried again for an hour (`UNREACHED`), so an offline node does not
cost the mesh an overlay change at every timer.

The mesh's identity travels with each roster, and a roster of another
mesh gives nothing. A node with no identity takes none from a roster:
only a join or an operator's `--adopt` sets it (keel.mesh.adopt).
"""

import fcntl
import ipaddress
import json
import os
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from keel import exits
from keel.mesh import (
    DIR,
    FILE_MODE,
    etcd,
    etcdcare,
    etcdstate,
    identity,
    invites,
    memberlink,
    members,
    signing,
    trust,
)
from keel.mesh.memberlink import LinkError
from keel.mesh.members import Roster
from keel.mesh.node import Node, NodeError, without_peer
from keel.mesh.protocol import Peer
from keel.mesh.signing import SigningError
from keel.network import session, wireguard
from keel.network.marker import path, write_private
from keel.network.wireguard import allowed, same_key

# how often a handshake is looked for, and each new member sent a packet
RETRY = 2.0
# how long a member that never answered is left out
BACKOFF = timedelta(hours=1)
UNREACHED = f"{DIR}/unreached.json"
SYNC_LOCK = f"{DIR}/sync.lock"
PARALLEL = 8


@dataclass
class Syncer:
    """This node as a member; the members' channel as fields"""

    node: Node
    clock: Callable[[], datetime]
    err: Callable[[str], None]
    fetch: Callable[[str, str], Roster] = memberlink.fetch
    tell: Callable[[str, str, Roster], None] = memberlink.tell
    touch: Callable[[str, str], None] = memberlink.touch
    sleep: Callable[[float], None] = time.sleep

    @property
    def root(self) -> str:
        return self.node.root

    def iface(self) -> str:
        return wireguard.interface(self.node.overlay())


@contextmanager
def sync_lock(root: str, wait: bool) -> Iterator[bool]:
    """Whether this process holds the lock of the members' changes: one
    sync at a time. Not the mesh's own lock, which an invite takes."""
    invites.ensure(root)
    fd = os.open(path(root, SYNC_LOCK), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def short(found: bytes) -> str:
    return f"{found.hex()[:8]}…"


def roster(syncer: Syncer) -> Roster:
    """This node's roster: its peers with the evidence it keeps, and its
    tombstones; raises NodeError when a key cannot be read, ValueError
    for a damaged store"""
    public, problem = syncer.node.public_key()
    if public is None:
        raise NodeError(problem)
    try:
        signer = signing.public(syncer.root)
    except SigningError as e:
        raise NodeError(str(e)) from None
    store = trust.load(syncer.root)
    overlay = syncer.node.overlay()
    return Roster(
        identity.read(syncer.root), public, signer,
        str(ipaddress.IPv6Interface(str(overlay["address"])).ip),
        tuple(Peer(one.public_key, one.endpoint, one.address,
                   store.evidence(one.public_key))
              for one in syncer.node.peers(public)),
        tuple(store.removed.values()),
        etcdstate.read(syncer.root, etcdstate.CRL))


def offered(syncer: Syncer) -> Roster:
    """What the members' service answers; ValueError when it cannot"""
    try:
        return roster(syncer)
    except NodeError as e:
        raise ValueError(str(e)) from None


def member_of(node: Node, source: str) -> str | None:
    """The key of the peer whose allowed_ips hold `source`"""
    try:
        address = ipaddress.ip_address(source)
        peers = node.overlay().get("peers") or []
    except (ValueError, NodeError):
        return None
    for peer in peers:
        if any(address in ipaddress.ip_network(net) for net in allowed(peer)):
            return str(peer.get("public_key"))
    return None


def where(node: Node) -> tuple[str, str] | None:
    """The overlay's interface and this node's address on it"""
    try:
        overlay = node.overlay()
    except NodeError:
        return None
    if not overlay.get("address"):
        return None
    return (wireguard.interface(overlay),
            str(ipaddress.IPv6Interface(str(overlay["address"])).ip))


def asked(syncer: Syncer, peers: tuple[Peer, ...]) -> list[Roster]:
    """The rosters of `peers`, asked at once; those that do not answer,
    or answer as another member, are said and left out"""
    iface = syncer.iface()

    def one(peer: Peer) -> Roster | str:
        try:
            found = syncer.fetch(peer.address, iface)
        except LinkError as e:
            return f"member {peer.address} did not answer: {e}"
        if not same_key(found.public_key, peer.public_key) or \
                found.address != peer.address:
            return (f"member {peer.address} answered as another member"
                    f" ({found.public_key} at {found.address}); its roster"
                    " is left out")
        return found
    if not peers:
        return []
    with ThreadPoolExecutor(min(PARALLEL, len(peers))) as pool:
        answers = list(pool.map(one, peers))
    found = []
    for answer in answers:
        if isinstance(answer, str):
            syncer.err(answer)
        else:
            found.append(answer)
    return found


def pull(syncer: Syncer, hosts: tuple[str, ...] = ()) -> int:
    """`keel mesh sync`: the members this node's peers know, added"""
    try:
        overlay = syncer.node.overlay()
    except NodeError as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    if not overlay.get("address"):
        syncer.err("this node is in no mesh: nothing to sync")
        return exits.OK
    public, problem = syncer.node.public_key()
    if public is None:
        syncer.err(problem)
        return exits.MESH_REFUSED
    known = syncer.node.peers(public)
    if not known:
        syncer.err("this node has no peer yet: nothing to sync")
        return exits.OK
    chosen = known
    if hosts:
        chosen = tuple(peer for peer in known if peer.address in hosts)
        strangers = set(hosts) - {peer.address for peer in chosen}
        if strangers:
            syncer.err(f"{', '.join(sorted(strangers))}: not a peer of this"
                       " node; keel mesh sync asks its peers only")
            return exits.MESH_REFUSED
    with sync_lock(syncer.root, False) as held:
        if not held:
            syncer.err("another keel mesh sync is adding members; this one"
                       " leaves it to finish")
            return exits.OK
        rosters = asked(syncer, chosen)
        if not rosters:
            syncer.err("no member answered over the overlay; nothing was"
                       " changed, and the next keel mesh sync asks again")
            return exits.OK
        return absorb(syncer, rosters, public, fetched=True)


def mismatch(own: bytes, other: Roster) -> str:
    return (f"member {other.address} is in mesh"
            f" {short(other.identity) if other.identity else 'none'},"
            f" this node in {short(own)}: nothing is taken from it. If this"
            f" node is the odd one, keel mesh sync --adopt {other.address}"
            " takes that member's identity in place of its own")


@dataclass
class Taken:
    """What the rosters gave: the members whose evidence verified, the
    keys a tombstone removed, and the exit code so far"""

    members: tuple[Peer, ...]
    removed: tuple[str, ...]
    code: int


def verified(syncer: Syncer, rosters: list[Roster], own: bytes,
             store: trust.Store, fetched: bool) -> Taken:
    """The members of `rosters` whose evidence chains to a key this node
    trusts, and the tombstones it takes (keel.mesh.trust). A trust root's
    signing key is bound only from a roster `fetched` by this node from
    the root's own address (`pull`), never from an announcement"""
    signer = signing.public(syncer.root)
    code, entries, gone = exits.OK, [], []
    for one in rosters:
        if one.identity != own:
            syncer.err(mismatch(own, one))
            code = exits.MESH_REFUSED
            continue
        if fetched and trust.bind_root(store, one.public_key, one.sign_key):
            syncer.err(f"trust root {one.address} signs with {one.sign_key}")
        entries += one.members
        gone += one.removed
    found = trust.accepted(store, signer, own, entries)
    removed = trust.removals(store, signer, own, gone)
    for one in rosters:
        if one.identity == own and one.crl:
            etcdcare.crl_taken(etcd.Etcd(syncer.node, syncer.clock,
                                         syncer.err), one.crl)
    return Taken(tuple(one for one in found
                       if not store.gone(one.public_key)), removed, code)


def absorb(syncer: Syncer, rosters: list[Roster], public: str,
           fetched: bool = False) -> int:
    """The members `rosters` name, with evidence, that this node does not
    know, and the peers their tombstones remove: written, applied in one
    change, and confirmed by a handshake"""
    try:
        own = identity.read(syncer.root)
        if own is None:
            raise ValueError("this node holds no mesh identity: only a"
                             " join, or keel mesh create --adopt or keel"
                             " mesh sync --adopt, sets it; nothing is"
                             " taken")
        store = trust.load(syncer.root)
        taken = verified(syncer, rosters, own, store, fetched)
        trust.save(syncer.root, store)
        doc = syncer.node.document()
    except (ValueError, NodeError, SigningError) as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    now = syncer.clock()
    resting = unreached(syncer.root, now)
    candidates = []
    for member in taken.members:
        if member.public_key in resting:
            syncer.err(f"{member.public_key} is tried again after"
                       f" {resting[member.public_key]:%H:%M} UTC: it"
                       " did not answer the last time")
            continue
        candidates.append(member)
    after, added = members.with_members(doc, tuple(candidates), public)
    dropped = tuple(one.public_key for one in syncer.node.peers(public)
                    if store.gone(one.public_key))
    for key in dropped:
        after = without_peer(after, key)
    if not added and not dropped:
        syncer.err("no member this node does not know: it is a peer of"
                   " every admitted member its peers know")
        return taken.code
    if syncer.node.waiting():
        syncer.err("a network change waits for its confirmation on this"
                   " node: the members are added, or removed, by the next"
                   " keel mesh sync, once it is confirmed or reverted")
        return exits.MESH_REFUSED
    found = changed_and_confirmed(syncer, doc, after, added, dropped)
    return found if found != exits.OK else taken.code


def announced(syncer: Syncer, waiting: list[tuple[str, Roster]]) -> int:
    """What the members' service applies: every announcement pending,
    in one change, under one window"""
    for source, found in waiting:
        syncer.err(f"an announcement from {source}: {len(found.members)}"
                   " member(s)")
    public, problem = syncer.node.public_key()
    if public is None:
        syncer.err(problem)
        return exits.MESH_REFUSED
    with sync_lock(syncer.root, True):
        return absorb(syncer, [found for _, found in waiting], public,
                      fetched=False)


def put_back(syncer: Syncer, doc: dict) -> None:
    """The spec as it was before the members were added: the revert puts
    the overlay back, and the spec says what the machine runs, so the
    next sync finds them new again"""
    try:
        syncer.node.write(doc)
    except NodeError as e:
        syncer.err(str(e))


def changed_and_confirmed(syncer: Syncer, doc: dict, after: dict,
                          added: tuple[Peer, ...],
                          dropped: tuple[str, ...]) -> int:
    """`after` written and applied under the window, and confirmed by a
    WireGuard handshake since the change: from a member it added, else,
    when it only removes, from any peer it keeps; with no peer left, by
    the route check alone, as `keel mesh create` confirms a mesh with no
    peer. Not confirmed, the spec is put back as it was"""
    since = int(syncer.clock().timestamp())
    try:
        change = syncer.node.change(after)
    except NodeError as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    if change.made is None:
        change.shown(syncer.err)
        put_back(syncer, doc)
        syncer.err(f"this node's overlay did not come up (apply exited"
                   f" {change.code}); the spec is put back as it was")
        return exits.APPLY_FAILED
    for member in added:
        syncer.err(f"member {member.public_key} added at {member.address},"
                   f" through {member.endpoint or 'no endpoint (it reaches'
                   ' this node)'}")
    for key in dropped:
        syncer.err(f"member {key} removed: a tombstone signed by a key that"
                   " may remove it names it")
    proof = added or syncer.node.peers("")
    syncer.err("confirming over the overlay…")
    if proof:
        seen = handshake(syncer, proof, since, since + change.made.window)
        if seen is None:
            return unconfirmed(syncer, change, doc, added)
        member, at = seen
        origin = session.Origin(
            session.MESH, f"a WireGuard handshake from {member.public_key}"
            f" ({at:%H:%M:%S} UTC), a member of the changed overlay", None,
            where(syncer.node)[1], member.address)
    else:
        origin = session.Origin(session.SELF, "keel mesh, which removed"
                                " the last peer,")
    kept, lines = syncer.node.confirm(origin, change.made)
    if not kept:
        change.shown(syncer.err)
        put_back(syncer, doc)
    for line in lines:
        syncer.err(line)
    if not kept:
        return exits.NETWORK_NOT_CONFIRMED
    forget(syncer.root, added)
    return exits.OK


def unconfirmed(syncer: Syncer, change, doc: dict,
                added: tuple[Peer, ...]) -> int:
    change.shown(syncer.err)
    put_back(syncer, doc)
    remember(syncer.root, added, syncer.clock())
    syncer.err("no member completed a WireGuard handshake within the"
               " window: the change reverts by itself, the spec is put"
               " back as it was, and keel mesh sync tries again (a new"
               " member after an hour)")
    return exits.NETWORK_NOT_CONFIRMED


def handshake(syncer: Syncer, added: tuple[Peer, ...], since: int,
              deadline: int) -> tuple[Peer, datetime] | None:
    """The first member of `added` to complete a WireGuard handshake
    since the change, each sent a packet every RETRY seconds"""
    iface = syncer.iface()
    while True:
        for member in added:
            at = syncer.node.handshake(member.public_key)
            if at is not None and at >= since:
                return member, datetime.fromtimestamp(at, timezone.utc)
        if syncer.clock().timestamp() + RETRY >= deadline:
            return None
        for member in added:
            syncer.touch(member.address, iface)
        syncer.sleep(RETRY)


def unreached(root: str, now: datetime) -> dict[str, datetime]:
    """The members that did not answer within the last BACKOFF, and when
    each may be tried again"""
    try:
        with open(path(root, UNREACHED)) as fob:
            data = json.load(fob)
    except (OSError, ValueError):
        return {}
    found = {}
    for key, at in (data.items() if isinstance(data, dict) else ()):
        if isinstance(at, int):
            again = datetime.fromtimestamp(at, timezone.utc) + BACKOFF
            if again > now:
                found[key] = again
    return found


def write_unreached(root: str, data: dict[str, int]) -> None:
    invites.ensure(root)
    write_private(root, UNREACHED, json.dumps(data, sort_keys=True) + "\n")


def remember(root: str, added: tuple[Peer, ...], now: datetime) -> None:
    data = {key: int((again - BACKOFF).timestamp())
            for key, again in unreached(root, now).items()}
    data.update({one.public_key: int(now.timestamp()) for one in added})
    write_unreached(root, data)


def forget(root: str, added: tuple[Peer, ...]) -> None:
    now = datetime.now(timezone.utc)
    data = {key: int((again - BACKOFF).timestamp())
            for key, again in unreached(root, now).items()
            if key not in {one.public_key for one in added}}
    write_unreached(root, data)


def announce(syncer: Syncer, key: str, what: str = "the new node") -> None:
    """This node's roster, to each of its peers but `key`: once a join is
    confirmed, it names the new node with its evidence; once a node is
    removed, it carries the tombstone"""
    try:
        mine = roster(syncer)
    except (NodeError, ValueError) as e:
        syncer.err(f"{what} is not announced: {e}; the other members"
                   " learn of it at their next keel mesh sync")
        return
    iface = syncer.iface()
    others = [one for one in mine.members
              if not same_key(one.public_key, key)]

    def one(peer: Peer) -> str | None:
        try:
            syncer.tell(peer.address, iface, mine)
        except LinkError as e:
            return f"{peer.address} did not take it ({e})"
        return None
    if not others:
        return
    with ThreadPoolExecutor(min(PARALLEL, len(others))) as pool:
        missed = [found for found in pool.map(one, others) if found]
    syncer.err(f"announced {key} to {len(others) - len(missed)} of the"
               f" {len(others)} other member(s) over the overlay")
    if missed:
        syncer.err(f"{'; '.join(missed)}: it learns of {what} at its next"
                   " keel mesh sync")
