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
from dataclasses import dataclass, field, replace
from datetime import datetime

from keel.mesh import etcdclient, etcdserve, identity, signing, trust
from keel.mesh import vip as vipstate
from keel.mesh import vipmsg, vipnet, vippair
from keel.mesh.etcdclient import Client
from keel.mesh.memberlink import LinkError
from keel.mesh.node import Node
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.mesh.vip import Claim, Held
from keel.network import wireguard
from keel.network.wireguard import same_key


def boottime() -> float:
    """Seconds since boot, suspend included (CLOCK_BOOTTIME): a holder
    that slept through its deadline is past it when it wakes"""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def over_the_overlay(host: str, iface: str, body: bytes) -> bytes:
    """The members' channel (keel.mesh.memberlink imports the listener,
    which imports the admitter, which imports keel.mesh.node)"""
    from keel.mesh import memberlink
    return memberlink.vip_exchange(host, iface, body)


# how far above the epoch a node knows a claim may be: a node that missed
# a few moves takes the newest; a claim far above is refused, so none
# can push the epoch out of every honest node's reach
MAX_STEP = 64


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
    monotonic: Callable[[], float] = field(default=lambda: boottime())
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
    """Why `claim` is not taken, or None

    Its signature by the key this node trusts for its holder, for this
    mesh, by a member this node has as a peer at the address the claim
    names (or itself); the pair record it carries signed by both members
    (or a trust root), naming its holder and its VIP, the same members
    as a record this node kept for that VIP; the VIP nobody's address
    and inside the members' region; and an epoch at most MAX_STEP above
    the one this node holds, so no claim freezes the VIP out of reach."""
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
    return paired(here, claim) or stepped(here, claim)


def signer_of(here: Here):
    """The signing key this node trusts for a member, its own for itself"""
    own = here.own_key()

    def found(key: str) -> str | None:
        if same_key(key, own):
            return signing.public(here.root)
        return etcdserve.sign_key(here.root, key)
    return found


def trust_roots(here: Here) -> set[str]:
    try:
        store = trust.load(here.root)
    except ValueError:
        return set()
    # a named root signs no pair record (keel#99)
    return store.operator_roots()


def addresses(here: Here) -> dict[str, str]:
    """Every member this node knows, by key: itself and its peers"""
    found = {one.public_key: one.address for one in here.node.peers("")}
    found[here.own_key()] = here.own_address()
    return found


def prefix(here: Here) -> ipaddress.IPv6Network:
    """The overlay prefix this node is in; VipError in no mesh"""
    overlay = here.overlay()
    if not overlay.get("address"):
        raise VipError("this node is in no mesh")
    return ipaddress.IPv6Interface(str(overlay["address"])).network


def record_problem(here: Here, pair: vippair.Pair) -> str | None:
    """Why the pair record is not taken here, or None

    A VIP outside the VIP range is taken for a pair made before the
    range (0.23.3): one whose record this node keeps, or, on a node that
    keeps none, one whose VIP is where every record signed before the
    range had it, inside the /112 of a member's address. A new pair's
    VIP is in the range: `keel vip pair` and the other member's
    signature check that (`new_pair_problem`)."""
    if pair.mesh_id != here.mesh_id():
        return "the pair record is for another mesh"
    problem = vippair.problem(pair, signer_of(here), trust_roots(here))
    if problem:
        return problem
    try:
        kept = vippair.read(here.root, pair.vip)
    except ValueError as e:
        return str(e)
    if kept is not None and not kept.same_members(pair):
        return (f"this node keeps another pair for {pair.vip}:"
                f" {', '.join(kept.members)}")
    found = addresses(here)
    return vippair.placed(pair, found, prefix(here), legacy=(
        kept is not None or vippair.signed_before_range(pair, found)))


def new_pair_problem(here: Here, pair: vippair.Pair) -> str | None:
    """Why this node does not sign `pair`, or None: its VIP is in the VIP
    range, unless this node keeps the same pair's record from before the
    range (0.23.3), so an upgraded pair may sign again"""
    try:
        kept = vippair.read(here.root, pair.vip)
    except ValueError as e:
        return str(e)
    return vippair.placed(pair, addresses(here), prefix(here), legacy=(
        kept is not None and kept.same_members(pair)))


def paired(here: Here, claim: Claim) -> str | None:
    """Why the claim's pair record does not let its holder hold it"""
    pair = claim.pair
    if not isinstance(pair, vippair.Pair):
        return "the claim carries no pair record"
    if pair.vip != claim.vip or not pair.has(claim.holder):
        return (f"{claim.holder} is not a member of the pair of"
                f" {claim.vip}: only the pair's nodes hold its VIP")
    return record_problem(here, pair)


def stepped(here: Here, claim: Claim) -> str | None:
    """Why the claim's epoch is too far above this node's, or None"""
    try:
        held = current(here, claim.vip)
    except VipError as e:
        return str(e)
    if held.claim is not None and claim.epoch > held.epoch + MAX_STEP:
        return (f"epoch {claim.epoch} jumps more than {MAX_STEP} above the"
                f" {held.epoch} this node knows")
    return None


def kept(here: Here, vip: str) -> vippair.Pair:
    """The pair record this node keeps for `vip`; VipError without one"""
    try:
        found = vippair.read(here.root, vip)
    except ValueError as e:
        raise VipError(str(e)) from None
    if found is None:
        raise VipError(f"no pair record for {vip}: run keel vip pair with"
                       " the other node's overlay address on one node of"
                       " the pair")
    return found


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
        if isinstance(claim.pair, vippair.Pair) and \
                vippair.read(here.root, claim.vip) is None:
            vippair.write(here.root, claim.pair)
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


def hold(here: Here, claim: Claim, carry: bool,
         lease: str | None = None) -> Held:
    """This node's own claim recorded, unfenced, and the VIP carried
    when `carry`; raises VipError when it cannot be carried"""
    with vipstate.locked(here.root):
        held = current(here, claim.vip)
        after = Held(claim.vip, claim, False, lease)
        if held.claim is not None and not vipstate.newer(claim, held) and \
                held.claim.raw != claim.raw:
            raise VipError(f"epoch {held.epoch} is known here, newer than"
                           f" this claim's {claim.epoch}")
        if isinstance(claim.pair, vippair.Pair) and \
                vippair.read(here.root, claim.vip) is None:
            vippair.write(here.root, claim.pair)
        vipstate.write(here.root, after)
        routed(here, claim.vip, claim.holder)
        if carry:
            problem = vipnet.carry(here.iface(), claim.vip, here.node.run)
            if problem:
                raise VipError(f"the VIP could not be added to"
                               f" {here.iface()}: {problem}")
    return after


def carry_held(here: Here, vip: str, age: float | None = None) -> bool:
    """Carry the VIP this node holds by its own claim, neither fenced nor
    released; whether it is carried now. A claim on an etcd lease is
    carried only with `age`, the time since the last renewal the
    majority confirmed, and for what is left of RELEASE_AFTER after it
    (keel.mesh.vipnet.lifetime): the kernel ends it by then"""
    with vipstate.locked(here.root):
        held = current(here, vip)
        if not held.holds(here.own_key()):
            return False
        valid = None
        if held.lease:
            # the kernel removes it by the release deadline, whatever
            # becomes of the controller
            valid = None if age is None else vipnet.lifetime(age)
            if valid is None:
                return False
        before = vipnet.carried(here.iface(), vip, here.node.output)
        problem = vipnet.carry(here.iface(), vip, here.node.run, valid)
        if not problem and before is False:
            # the VIP on wg0 is the proof keel database follow waits for
            # before the server takes writes (keel#104): the state
            # written again, so that keel-database-follow.path runs it
            vipstate.write(here.root, held)
    if problem:
        here.err(f"vip {vip}: cannot carry it: {problem}")
        return False
    return True


def drop_fenced(here: Here, vip: str, why: str,
                lease: str | None = None) -> None:
    """The holder's own fence: drop the address and never claim again by
    itself; what the controller does when its lease is gone. With
    `lease`, only while this node still holds the VIP on that lease: a
    node that released it meanwhile, or took a newer claim, lost nothing
    and is not fenced"""
    with vipstate.locked(here.root):
        held = current(here, vip)
        if lease is not None and (held.lease != lease or
                                  not held.holds(here.own_key())):
            problem = vipnet.drop(here.iface(), vip, here.node.run,
                                  here.node.output)
            here.err(f"vip {vip}: its lease {lease} is gone, and this node"
                     " no longer holds the VIP on it: not fenced"
                     f"{'; ' + problem if problem else ''}")
            return
        # fenced first, so that what follows the state (keel database
        # follow turning the database read only) starts before the
        # address is gone, never after
        vipstate.write(here.root, vipstate.fenced(held))
        problem = vipnet.drop(here.iface(), vip, here.node.run,
                              here.node.output)
    here.err(f"vip {vip}: dropped, {why}"
             f"{'; ' + problem if problem else ''}")


def announce(here: Here, claim: Claim) -> dict[str, str]:
    """The claim told to every peer at once, as the new holder does; each
    peer's address to what it said: "applied", "known" (both accepted
    it), "refused: why" (it answered no) or "unreachable: why"
    """
    peers = [one.address for one in here.node.peers("")]

    def one(at: str) -> str:
        try:
            found = vipmsg.loaded(here.exchange(at, here.iface(), claim.raw))
        except LinkError as e:
            said = str(e)
            return f"refused: {said}" if " refused: " in said \
                else f"unreachable: {said}"
        except (ProtocolError, OSError) as e:
            return f"unreachable: {e}"
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


def signed_claim(here: Here, vip: str, epoch: int,
                 lease: str | None = None) -> Claim:
    """This node's claim, with the pair record it keeps and, with etcd,
    the lease that holds it; VipError"""
    pair = kept(here, vip)
    if not pair.has(here.own_key()):
        raise VipError(f"this node is not a member of the pair of {vip}")
    try:
        return vipmsg.claim(here.root, here.mesh_id(), here.own_key(),
                            here.clock(), vip, epoch, here.own_address(),
                            pair, lease)
    except SigningError as e:
        raise VipError(str(e)) from None
