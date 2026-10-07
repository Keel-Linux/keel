# Copyright (c) 2026 KeelLinux maintainers
"""The service VIP on the mesh: what a node knows of it (decision 0049)

A replicated appliance pair has one VIP, `appliance.vip` in the spec of
each of its two nodes: a /128 of the overlay prefix. The primary is the
node that holds the VIP (0049, third round, point 2): it carries the
address on wg0, and every other node routes it to the primary by
listing it in the allowed_ips of the primary's peer entry.

Who holds it is decided by **claims**. A claim is a message the holder
signs with its Ed25519 key (keel.mesh.vipmsg): the VIP, the holder's
overlay address and an **epoch**, a counter that only grows. A node
takes a claim only when it is newer than the one it holds: a higher
epoch, or the same epoch and a lower public key (two promotes at once,
0049). A stale claim, an older epoch, is refused wherever it arrives:
on the members' channel, in an answer to the epoch check, or in etcd,
whose compare-and-swap on the counter refuses it before it is written
(keel.mesh.vipetcd).

What a node knows is state, never the spec (0049, "What keel inspect
and keel diff show"), one file per VIP under /var/lib/keel/vip, root's
and 0600: the newest claim it took, verbatim, so it can be shown to
another node and checked there; whether this node is fenced, which a
node that lost the VIP without letting it go is until an operator
promotes it again (it never claims by itself: "an old primary ... must
never re-claim"); whether it released it when asked; and, on the holder
with etcd, the lease that holds its claim and when it was last renewed.

Everything here but the files is pure.
"""

import base64
import binascii
import contextlib
import fcntl
import ipaddress
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, replace

from keel.network.marker import path, write_private
from keel.network.wireguard import allowed, key_bytes, same_key

DIR = "var/lib/keel/vip"
LOCK = f"{DIR}/lock"
SUFFIX = ".json"
DIR_MODE = 0o700
FILE_MODE = 0o600
HOST = 128
PRIMARY, REPLICA = "primary", "replica"


@dataclass(frozen=True)
class Claim:
    """One signed claim: `holder` is the sender's WireGuard key, `raw`
    the message as it was signed and sent (keel.mesh.vipmsg)"""

    vip: str
    epoch: int
    holder: str
    address: str
    raw: bytes


@dataclass(frozen=True)
class Held:
    """What this node knows of one VIP

    `claim` is the newest claim it took (None before any); `fenced`
    whether this node lost it without letting it go (cut off, or gone
    while another took it), and so claims it again only by a promote run
    here; `released` whether this node let it go when the other node of
    the pair asked, its claim still the newest until that node's comes;
    `lease` the etcd lease of this node's own claim, and `renewed` when
    it was last renewed, as the send time of the renewal etcd answered,
    on the system's monotonic clock.
    """

    vip: str
    claim: Claim | None = None
    fenced: bool = False
    lease: str | None = None
    renewed: float | None = None
    released: bool = False

    @property
    def epoch(self) -> int:
        return self.claim.epoch if self.claim else 0

    @property
    def holder(self) -> str | None:
        return self.claim.holder if self.claim else None

    def held_by(self, key: str | None) -> bool:
        return bool(key) and self.holder is not None and \
            same_key(self.holder, key)

    def holds(self, key: str | None) -> bool:
        """Whether the node of `key` is the primary by this: its claim the
        newest, neither fenced nor released"""
        return self.held_by(key) and not self.fenced and not self.released


def address(value: object) -> str:
    """A VIP or an overlay address, as keel writes it; ValueError"""
    if not isinstance(value, str):
        raise ValueError(f"{value!r} is not an IPv6 address")
    found = ipaddress.IPv6Address(value.split("/")[0] if
                                  value.endswith(f"/{HOST}") else value)
    return str(found)


def declared(doc: dict) -> str | None:
    """This node's `appliance.vip`, or None: a node that replicates
    nothing has none"""
    appliance = doc.get("appliance")
    value = appliance.get("vip") if isinstance(appliance, dict) else None
    return None if value is None else address(value)


def newer(claim: Claim, held: Held | None) -> bool:
    """Whether `claim` wins over what this node holds: a higher epoch,
    or the same epoch and a lower public key"""
    if held is None or held.claim is None:
        return True
    if claim.epoch != held.epoch:
        return claim.epoch > held.epoch
    if same_key(claim.holder, held.holder):
        return False
    return key_bytes(claim.holder) < key_bytes(held.holder)


def role(doc: dict, held: Held | None, own_key: str | None) -> str | None:
    """The role keel observes: primary on the node of the pair that
    holds the VIP, replica on the other; None on a node that declares
    no VIP (0049, third round, point 2)"""
    vip = declared(doc)
    if vip is None:
        return None
    if held is not None and held.vip == vip and held.holds(own_key):
        return PRIMARY
    return REPLICA


def file_of(vip: str) -> str:
    return f"{DIR}/{vip}{SUFFIX}"


def ensure(root: str) -> None:
    os.makedirs(path(root, DIR), mode=DIR_MODE, exist_ok=True)


@contextlib.contextmanager
def locked(root: str) -> Iterator[None]:
    """One writer at a time: the members' channel, the controller, a
    promote and the check all change these files"""
    ensure(root)
    fd = os.open(path(root, LOCK), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def dumps(held: Held) -> str:
    claim = held.claim
    return json.dumps({
        "vip": held.vip, "fenced": held.fenced, "lease": held.lease,
        "renewed": held.renewed, "released": held.released,
        "claim": None if claim is None
        else base64.b64encode(claim.raw).decode()}, sort_keys=True) + "\n"


def read(root: str, vip: str) -> Held | None:
    """The file of `vip`; None when there is none. One that cannot be
    read is ValueError: keel does not guess who holds a VIP"""
    from keel.mesh import vipmsg
    try:
        with open(path(root, file_of(vip))) as fob:
            data = json.load(fob)
        raw = data["claim"]
        claim = None if raw is None else vipmsg.claim_of(
            base64.b64decode(raw, validate=True))
        lease = data["lease"]
        renewed = data["renewed"]
        released = data.get("released", False)
        if data["vip"] != vip or type(data["fenced"]) is not bool or \
                type(released) is not bool or \
                not (lease is None or isinstance(lease, str)) or \
                not (renewed is None or isinstance(renewed, (int, float))) \
                or (claim is not None and claim.vip != vip):
            raise ValueError(vip)
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise ValueError(f"/{file_of(vip)} is damaged: keel does not guess"
                         " who holds a VIP; remove it, and keel vip check"
                         " learns the holder from the peers") from None
    return Held(vip, claim, data["fenced"], lease, renewed, released)


def write(root: str, held: Held) -> None:
    ensure(root)
    write_private(root, file_of(held.vip), dumps(held))


def known(root: str) -> tuple[str, ...]:
    """The VIPs this node has a file for, sorted"""
    try:
        names = os.listdir(path(root, DIR))
    except FileNotFoundError:
        return ()
    found = []
    for name in names:
        if not name.endswith(SUFFIX):
            continue
        try:
            found.append(address(name[:-len(SUFFIX)]))
        except ValueError:
            continue
    return tuple(sorted(found))


def held_all(root: str) -> list[Held]:
    """Every VIP's file that can be read"""
    found = []
    for vip in known(root):
        try:
            one = read(root, vip)
        except ValueError:
            continue
        if one is not None:
            found.append(one)
    return found


def fenced(held: Held) -> Held:
    """`held` once this node lost the VIP without letting it go"""
    return replace(held, fenced=True, lease=None, renewed=None)


def released(held: Held) -> Held:
    """`held` once this node let the VIP go when asked"""
    return replace(held, released=True, lease=None, renewed=None)


def routed(overlay: dict, holders: dict[str, str]) -> dict:
    """`overlay` with each VIP in the allowed_ips of the peer that holds
    it, as a new document: `holders` maps a VIP to its holder's key. A
    VIP whose holder is not a peer (this node, or one the spec lacks) is
    routed to no peer."""
    peers = []
    for peer in overlay.get("peers") or []:
        nets = allowed(peer)
        extra = [f"{vip}/{HOST}" for vip, key in sorted(holders.items())
                 if same_key(str(peer.get("public_key")), key)
                 and f"{vip}/{HOST}" not in nets]
        peers.append({**peer, "allowed_ips": nets + extra} if extra
                     else peer)
    if not peers:
        return overlay
    return {**overlay, "peers": peers}


def holders_of(root: str) -> dict[str, str]:
    """VIP to holder's key, from this node's files"""
    return {one.vip: one.holder for one in held_all(root) if one.holder}


def routed_here(overlay: dict, root: str) -> dict:
    """What apply renders: the spec's overlay, each VIP routed to its
    holder, so a VIP move is never a change of the overlay to apply"""
    return routed(overlay, holders_of(root))


def unrouted(section: dict, vips: tuple[str, ...]) -> dict:
    """A wg-quick file read back, each VIP's /128 taken out of the
    peers' allowed_ips, so a peer read back is the peer the spec
    declares and a move is never drift"""
    if not vips:
        return section
    taken = {f"{vip}/{HOST}" for vip in vips}
    peers = []
    for peer in section.get("peers") or []:
        nets = [one for one in peer.get("allowed_ips") or []
                if str(one) not in taken]
        peers.append({**peer, "allowed_ips": nets})
    if "peers" not in section:
        return section
    return {**section, "peers": peers}


def problem(vip: str, overlay: dict) -> str | None:
    """Why `vip` cannot be this overlay's VIP: outside the prefix, this
    node's own address, or inside a peer's allowed_ips"""
    if not overlay.get("address"):
        return "appliance.vip needs network.overlay.wireguard.address"
    own = ipaddress.IPv6Interface(str(overlay["address"]))
    found = ipaddress.IPv6Address(vip)
    if found not in own.network:
        return (f"appliance.vip: {vip} is outside the overlay prefix"
                f" {own.network}")
    if found == own.ip:
        return f"appliance.vip: {vip} is this node's own overlay address"
    for peer in overlay.get("peers") or []:
        for net in allowed(peer):
            if found in ipaddress.ip_network(net):
                return (f"appliance.vip: {vip} is inside {net}, which"
                        f" {peer.get('public_key')} is given: the VIP is"
                        " routed at runtime, never in the spec")
    return None
