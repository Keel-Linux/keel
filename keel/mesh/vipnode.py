# Copyright (c) 2026 KeelLinux maintainers
"""This node and the VIPs: taking a claim, releasing, carrying (0049)

The flows every actor shares, whoever moved the VIP: the members'
channel answering a peer (keel.mesh.vipserve), `keel vip promote` and
`keel vip check` (keel.mesh.vippromote), and the etcd controller
(keel.mesh.vipetcd).

- `verified`: a claim is taken only signed by the signing key this
  node's trust store holds for its holder (or this node's own), for
  this mesh, by a member this node has as a peer at the address the
  claim names. That a claim is for the holder's own `appliance.vip` is
  its signed word: keel signs one only for the VIP its spec declares
  (0049, third round, point 3).
- `take`: a newer claim is recorded, this node drops the VIP if it
  carried it (and is fenced: "an old primary ... must never re-claim"),
  and routes the VIP to the holder. A claim that is not newer changes
  nothing and is refused by the caller as stale.
- `release`: the holder asked to let go drops the address first, and
  only then says so (release before take); with etcd it also revokes
  its own lease, so the other node's compare-and-swap can succeed. A
  node that released is a replica, not fenced: it lost nothing.
- `hold`: this node's own claim, recorded and, when asked, carried.
"""

import ipaddress
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime

from keel.mesh import etcdclient, etcdserve, identity, signing
from keel.mesh import vip as vipstate
from keel.mesh import vipmsg, vipnet
from keel.mesh.etcdclient import Client
from keel.mesh.node import Node
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.mesh.vip import Claim, Held
from keel.network import wireguard
from keel.network.wireguard import same_key


def over_the_overlay(host: str, iface: str, body: bytes) -> bytes:
    """The members' channel (keel.mesh.memberlink imports the listener,
    which imports the admitter, which imports keel.mesh.node)"""
    from keel.mesh import memberlink
    return memberlink.vip_exchange(host, iface, body)


class VipError(Exception):
    """This node cannot do what was asked of the VIP, and why"""


@dataclass
class Here:
    """This node as an actor on its VIPs; the channel, etcd and the
    clocks as fields, so each flow is tested without them"""

    node: Node
    clock: Callable[[], datetime]
    err: Callable[[str], None]
    exchange: Callable[[str, str, bytes], bytes] = over_the_overlay
    client: Callable[[], Client] | None = None
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep

    @property
    def root(self) -> str:
        return self.node.root

    def overlay(self) -> dict:
        return self.node.overlay()

    def iface(self) -> str:
        return wireguard.interface(self.overlay())

    def own_key(self) -> str:
        found, why = self.node.public_key()
        if found is None:
            raise VipError(f"this node's WireGuard key: {why}")
        return found

    def own_address(self) -> str:
        overlay = self.overlay()
        if not overlay.get("address"):
            raise VipError("this node is in no mesh")
        return str(ipaddress.IPv6Interface(str(overlay["address"])).ip)

    def mesh_id(self) -> str:
        try:
            found = identity.read(self.root)
        except ValueError as e:
            raise VipError(str(e)) from None
        if found is None:
            raise VipError("this node holds no mesh identity yet (keel mesh"
                           " create, join or sync gives it one)")
        return found.hex()

    def local(self) -> Client:
        """This member's etcd; raises EtcdError"""
        return self.client() if self.client else etcdclient.local(self.root)

    def say(self, kind: str, at: str, body: dict) -> bytes:
        """The answer of the member at `at` to one signed message;
        raises LinkError, SigningError or VipError"""
        message = vipmsg.signed(self.root, kind, self.mesh_id(),
                                self.own_key(), self.clock(), body)
        return self.exchange(at, self.iface(), message)


def peer_at(here: Here, key: str) -> str | None:
    """The overlay address the spec gives the peer `key`, or None"""
    for one in here.node.peers(""):
        if same_key(one.public_key, key):
            return one.address
    return None


def verified(here: Here, claim: Claim) -> str | None:
    """Why `claim` is not taken, or None: its signature, its mesh, its
    VIP in this overlay's prefix, its holder this node or a peer at the
    address the claim names"""
    try:
        message = vipmsg.loads(claim.raw)
        own = here.own_key()
        mesh = here.mesh_id()
    except (ProtocolError, VipError) as e:
        return str(e)
    if message.mesh_id != mesh:
        return "the claim is for another mesh"
    if same_key(claim.holder, own):
        signer = signing.public(here.root)
        at = here.own_address()
    else:
        signer = etcdserve.sign_key(here.root, claim.holder)
        at = peer_at(here, claim.holder)
    if at != claim.address:
        return (f"{claim.holder} is not a peer of this node at"
                f" {claim.address}")
    prefix = ipaddress.IPv6Interface(str(here.overlay()["address"])).network
    if ipaddress.IPv6Address(claim.vip) not in prefix:
        return f"{claim.vip} is outside this mesh's prefix {prefix}"
    if signer is None or not message.verified(signer):
        return ("the claim is not signed by a key this node trusts for its"
                " holder (keel mesh sync learns its trust roots' keys)")
    return None


def current(here: Here, vip: str) -> Held:
    try:
        found = vipstate.read(here.root, vip)
    except ValueError as e:
        raise VipError(str(e)) from None
    return found or Held(vip)


def take(here: Here, claim: Claim) -> bool:
    """Record a claim newer than what this node holds, drop the VIP if
    this node carried it, and route it to the holder; whether it was
    newer. The claim is verified by the caller."""
    own = here.own_key()
    with vipstate.locked(here.root):
        held = current(here, claim.vip)
        if not vipstate.newer(claim, held):
            return False
        mine = same_key(claim.holder, own)
        lost = held.holds(own) and not mine
        if not mine:
            problem = vipnet.drop(here.iface(), claim.vip, here.node.run,
                                  here.node.output)
            if problem:
                here.err(f"vip {claim.vip}: cannot drop it: {problem}")
        after = replace(held, claim=claim, released=False)
        if lost:
            after = vipstate.fenced(after)
        vipstate.write(here.root, after)
        routed(here, claim.vip, claim.holder)
    here.err(f"vip {claim.vip}: epoch {claim.epoch}, held by"
             f" {claim.holder} at {claim.address}"
             f"{'; this node no longer holds it' if lost else ''}")
    return True


def routed(here: Here, vip: str, holder: str | None) -> None:
    """The live table and wg0.conf, the VIP routed to `holder`"""
    overlay = here.overlay()
    try:
        own = here.own_key()
    except VipError:
        own = None
    to = None if holder is None or (own and same_key(holder, own)) \
        else holder
    for problem in vipnet.route(here.iface(), overlay, vip, to,
                                here.node.run, here.node.output):
        here.err(f"vip {vip}: {problem}")
    problem = vipnet.written(here.root, overlay)
    if problem:
        here.err(f"vip {vip}: {problem}")


def release(here: Here, vip: str, revoke: Callable[[str], None]) -> Held:
    """Drop the VIP here, then record that this node released it; with
    a lease, `revoke` it (this node's own lease, never another's).
    Raises VipError when the address cannot be dropped: then nothing is
    acknowledged."""
    with vipstate.locked(here.root):
        held = current(here, vip)
        problem = vipnet.drop(here.iface(), vip, here.node.run,
                              here.node.output)
        if problem:
            raise VipError(f"the VIP could not be dropped: {problem}")
        after = vipstate.released(held)
        vipstate.write(here.root, after)
    if held.lease:
        try:
            revoke(held.lease)
        except etcdclient.EtcdError as e:
            here.err(f"vip {vip}: the lease could not be revoked ({e}); it"
                     " expires within its TTL")
    here.err(f"vip {vip}: released by this node; it is no longer the"
             " primary")
    return after


def hold(here: Here, claim: Claim, carry: bool, lease: str | None = None,
         renewed: float | None = None) -> Held:
    """This node's own claim recorded, unfenced, and the VIP carried
    when `carry`; raises VipError when it cannot be carried"""
    with vipstate.locked(here.root):
        held = current(here, claim.vip)
        after = Held(claim.vip, claim, False, lease, renewed)
        if held.claim is not None and not vipstate.newer(claim, held) and \
                held.claim.raw != claim.raw:
            raise VipError(f"epoch {held.epoch} is known here, newer than"
                           f" this claim's {claim.epoch}")
        vipstate.write(here.root, after)
        routed(here, claim.vip, claim.holder)
        if carry:
            problem = vipnet.carry(here.iface(), claim.vip, here.node.run)
            if problem:
                raise VipError(f"the VIP could not be added to"
                               f" {here.iface()}: {problem}")
    return after


def carry_held(here: Here, vip: str) -> bool:
    """Carry the VIP this node holds by its own claim, unfenced; whether
    it is carried now"""
    with vipstate.locked(here.root):
        held = current(here, vip)
        if not held.holds(here.own_key()):
            return False
        problem = vipnet.carry(here.iface(), vip, here.node.run)
    if problem:
        here.err(f"vip {vip}: cannot carry it: {problem}")
        return False
    return True


def drop_fenced(here: Here, vip: str, why: str) -> None:
    """The holder's own fence: drop the address and never claim again by
    itself; what the controller does when it cannot renew its lease"""
    with vipstate.locked(here.root):
        held = current(here, vip)
        problem = vipnet.drop(here.iface(), vip, here.node.run,
                              here.node.output)
        vipstate.write(here.root, vipstate.fenced(held))
    here.err(f"vip {vip}: dropped, {why}"
             f"{'; ' + problem if problem else ''}")


def announce(here: Here, claim: Claim) -> dict[str, str]:
    """The claim told to every peer at once, as the new holder does; each
    peer's address to what it said ("applied", "known" or why not)"""
    peers = [one.address for one in here.node.peers("")]

    def one(at: str) -> str:
        try:
            found = vipmsg.loaded(here.exchange(at, here.iface(), claim.raw))
        except Exception as e:  # noqa: BLE001 - every failure is said
            return str(e) or type(e).__name__
        return "applied" if found.get("applied") else "known"
    if not peers:
        return {}
    with ThreadPoolExecutor(max_workers=min(len(peers), 16)) as pool:
        return dict(zip(peers, pool.map(one, peers)))


def epochs(here: Here, vip: str) -> dict[str, Claim | None | str]:
    """Every peer asked, at once, for the newest claim it took of `vip`:
    its address to that claim, verified, None for none, or why not"""
    peers = [one.address for one in here.node.peers("")]

    def one(at: str) -> Claim | None | str:
        try:
            found = vipmsg.answer_claim(here.say(vipmsg.EPOCH, at,
                                                {"vip": vip}))
        except Exception as e:  # noqa: BLE001 - every failure is said
            return str(e) or type(e).__name__
        if found is None:
            return None
        if found.vip != vip:
            return "an answer for another VIP"
        problem = verified(here, found)
        return problem if problem else found
    if not peers:
        return {}
    with ThreadPoolExecutor(max_workers=min(len(peers), 16)) as pool:
        return dict(zip(peers, pool.map(one, peers)))


def newest(claims: list[Claim]) -> Claim | None:
    found = None
    for claim in claims:
        if found is None or vipstate.newer(claim, Held(claim.vip, found)):
            found = claim
    return found


def signed_claim(here: Here, vip: str, epoch: int) -> Claim:
    try:
        return vipmsg.claim(here.root, here.mesh_id(), here.own_key(),
                            here.clock(), vip, epoch, here.own_address())
    except SigningError as e:
        raise VipError(str(e)) from None
