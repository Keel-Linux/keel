# Copyright (c) 2026 KeelLinux maintainers
"""The VIP with etcd: the lease is the fence (decisions 0049, 0025)

Two keys per VIP, under the mesh's prefix in etcd, each holding a
signed claim (keel.mesh.vipmsg):

    /keel/<mesh id>/vip/<vip>/epoch    the newest claim, kept for good:
                                       the counter
    /keel/<mesh id>/vip/<vip>/holder   the same claim, attached to the
                                       holder's lease

A node claims only by one transaction: the epoch key still at the
revision it read (no claim came in between) and no holder key (no lease
alive), then both keys written, the holder's on a new lease of TTL
seconds, the epoch one higher than the counter's. A stale claim, made
from a counter another claim has since moved, fails that comparison and
is never written.

The controller (`Controller`) runs on every cloud advanced member, as
the unprivileged half of keel-vip.service (keel.mesh.vipbridge): it
faces etcd and the overlay, and asks the root half (`Ops`) for every
change of the machine, which checks it against the pair record:

- **the holder renews its lease** every RENEW seconds, and **carries the
  address only while the last renewal the majority confirmed is less
  than RELEASE_AFTER seconds old**, counted from the renewal's send on
  CLOCK_BOOTTIME (suspend counts), in this process's memory: a
  controller that starts, after a restart or a reboot, carries nothing
  until it renewed the lease itself. A renewal counts once a
  linearizable read, which needs the majority, finds the holder's key on
  this lease with this node's claim: etcd's leader renews leases by
  itself, so a leader cut off answers renewals until it steps down. Any
  error of etcd is no renewal. etcd cannot expire the lease before TTL
  seconds after that send, so a holder cut off from the majority has
  dropped the VIP RELEASE_AFTER seconds before any other node can win
  it. Against etcd's 5 s election timeout (keel.mesh.etcdconf): a
  re-election in the majority takes 5 to 10 s, during which renewals
  fail, but etcd gives every lease its TTL again on a leader change, so
  10 s rides out one re-election without a move. A lease etcd says is
  gone, or a holder key that is not this lease's, fences the node: it
  never claims again by itself (0049: an old primary "must never
  re-claim");
- **every node follows the keys**: a newer claim is taken as one from
  the members' channel is (keel.mesh.vipnode.take), so the VIP is routed
  to its holder on every member;
- **the other node of the pair claims when no valid holder key is
  left**, the lease expired, once it has taken the counter's claim and
  is not fenced (0020's automatic failover, which etcd's three voters
  make possible). A holder key whose value is not a valid claim counts
  as none: the transaction compares its revision, so a key written by
  anything else neither holds the VIP nor blocks the failover;
- only the controller adds the address on a node with etcd, once its own
  claim stands and its lease is fresh, so a VIP is never carried by a
  node whose lease nobody renews.

The new holder also announces its claim on the members' channel, for the
nodes that are not cloud advanced (0049, third round, point 4).
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass, replace

from keel.mesh import vipmsg, vipnet, vipnode
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import Client, EtcdError, absent, modified
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.vip import RELEASE_AFTER, TTL, Claim, Held
from keel.mesh.vipnode import Here, VipError
from keel.network.wireguard import same_key

__all__ = ["RELEASE_AFTER", "TTL"]

RENEW = 2.0
# one call to this member's etcd: a renewal that takes longer is not
# one the holder can count on
CALL_TIMEOUT = 2.0
TICK = 1.0
HOLD_TICK = 0.2
EPOCH, HOLDER = "epoch", "holder"
# what a turn of the controller survives, said: a spec being edited, a
# damaged state file, a key not readable for a moment, the root half
# gone a moment
FAILURES = (VipError, NodeError, ValueError, OSError)


def prefix(mesh_id: str) -> str:
    return f"/keel/{mesh_id}/vip/"


def key_of(mesh_id: str, vip: str, which: str) -> str:
    return f"{prefix(mesh_id)}{vip}/{which}"


@dataclass(frozen=True)
class Seen:
    """One VIP's keys: the counter's claim and its revision (0 when it
    has none); the holder's claim and lease, None when no valid one is
    alive; and the holder key's revision, valid or not (0 when there is
    no key)"""

    vip: str
    epoch: Claim | None = None
    revision: int = 0
    holder: Claim | None = None
    lease: str | None = None
    holder_revision: int = 0


def seen(client: Client, mesh_id: str,
         err=lambda line: None) -> dict[str, Seen]:
    """Every VIP's keys; raises EtcdError. A value that is not a claim
    for its own key is left out and said; a holder key's revision is
    kept whatever its value, so a claim can replace a value that is not
    one."""
    found: dict[str, Seen] = {}
    base = prefix(mesh_id)
    for value in client.prefix(base):
        vip, _, which = value.key[len(base):].partition("/")
        try:
            vip = vipstate.address(vip)
        except ValueError:
            err(f"vip: etcd's {value.key} is not a VIP's key")
            continue
        now = found.get(vip) or Seen(vip)
        if which == HOLDER:
            now = replace(now, holder_revision=value.mod_revision)
        try:
            claim = vipmsg.claim_of(value.value)
            if claim.vip != vip or which not in (EPOCH, HOLDER):
                raise ProtocolError("a claim for another key")
        except ProtocolError as e:
            err(f"vip: etcd's {value.key} is not a claim: {e}")
            found[vip] = now
            continue
        if which == EPOCH:
            now = replace(now, epoch=claim, revision=value.mod_revision)
        else:
            now = replace(now, holder=claim, lease=value.lease)
        found[vip] = now
    return found


def local(here: Here) -> Client:
    """This member's etcd, asked with a short timeout; raises EtcdError"""
    client = here.local()
    client.timeout = CALL_TIMEOUT
    return client


def claim(client: Client, mesh_id: str, vip: str, now: Seen,
          known: int, sign: Callable[[str, int], Claim],
          clock: Callable[[], float]) -> tuple[Claim, str, float] | None:
    """A claim by compare-and-swap on the counter: the claim `sign`
    makes, its lease and when the lease was asked for; None when another
    claim came first or a valid holder key appeared. `known` is the epoch
    this node holds. Raises EtcdError, VipError."""
    epoch = max(now.epoch.epoch if now.epoch else 0, known) + 1
    made = sign(vip, epoch)
    asked = clock()
    lease = client.grant(TTL)
    ok = client.swap(
        [modified(key_of(mesh_id, vip, EPOCH), now.revision),
         modified(key_of(mesh_id, vip, HOLDER), now.holder_revision)],
        [(key_of(mesh_id, vip, EPOCH), made.raw, None),
         (key_of(mesh_id, vip, HOLDER), made.raw, lease)])
    if not ok:
        try:
            client.revoke(lease)
        except EtcdError:
            pass
        return None
    return made, lease, asked


def stale(client: Client, mesh_id: str, vip: str, made: Claim,
          revision: int) -> bool:
    """Whether a claim written against an older counter `revision` is
    refused: what a node that missed a move would try"""
    return not client.swap(
        [modified(key_of(mesh_id, vip, EPOCH), revision),
         absent(key_of(mesh_id, vip, HOLDER))],
        [(key_of(mesh_id, vip, EPOCH), made.raw, None)])


@dataclass(frozen=True)
class Facts:
    """What the controller needs of this node: its key, its mesh, the
    VIP its spec declares (None for none), its overlay's interface, and
    its peers' overlay addresses"""

    own_key: str
    mesh_id: str
    vip: str | None
    iface: str
    peers: tuple[str, ...]


class Ops:
    """The root half, as the controller asks it (keel.mesh.vipbridge
    carries each call over the bridge; tests call it in one process).
    Every change is checked here, never trusted from the controller."""

    def __init__(self, here: Here):
        self.here = here

    def facts(self) -> Facts:
        here = self.here
        try:
            vip = vipstate.declared(here.node.document())
        except ValueError:
            vip = None
        return Facts(here.own_key(), here.mesh_id(), vip, here.iface(),
                     tuple(one.address for one in here.node.peers("")))

    def held(self) -> list[Held]:
        return vipstate.held_all(self.here.root)

    def take(self, raw: bytes) -> str | None:
        """A claim from etcd, taken when verified and newer; why not"""
        try:
            found = vipmsg.claim_of(raw)
        except ProtocolError as e:
            return str(e)
        problem = vipnode.verified(self.here, found)
        if problem:
            return problem
        vipnode.take(self.here, found)
        return None

    def sign(self, vip: str, epoch: int) -> Claim:
        """This node's claim of its own VIP, above every epoch it knows"""
        if vip != self.facts().vip:
            raise VipError(f"{vip} is not this node's appliance.vip")
        held = vipnode.current(self.here, vip)
        if not held.epoch < epoch <= held.epoch + vipnode.MAX_STEP:
            raise VipError(f"epoch {epoch} is not above {held.epoch}")
        return vipnode.signed_claim(self.here, vip, epoch)

    def hold(self, raw: bytes, lease: str) -> None:
        """This node's own claim, as etcd took it, recorded with its lease"""
        found = vipmsg.claim_of(raw)
        if not same_key(found.holder, self.here.own_key()):
            raise VipError("not this node's claim")
        problem = vipnode.verified(self.here, found)
        if problem:
            raise VipError(problem)
        vipnode.hold(self.here, found, False, lease)

    def carry(self, vip: str, age: float) -> bool:
        return vipnode.carry_held(self.here, vip, age)

    def drop(self, vip: str, fence: bool, why: str,
             lease: str | None = None) -> None:
        """The address dropped; with `fence`, the node fenced too, only
        while it still holds the VIP on `lease`"""
        if fence:
            vipnode.drop_fenced(self.here, vip, why, lease)
            return
        here = self.here
        problem = vipnet.drop(here.iface(), vip, here.node.run,
                              here.node.output)
        here.err(f"vip {vip}: dropped, {why}"
                 f"{'; ' + problem if problem else ''}")

    def carried(self, vip: str) -> bool | None:
        return vipnet.carried(self.here.iface(), vip, self.here.node.output)


class Controller:
    """Renew, carry, follow and fail over; `ops` is the root half,
    `client` gives this member's etcd, `exchange` the members' channel"""

    def __init__(self, ops: Ops, client: Callable[[], Client],
                 stop: threading.Event, err: Callable[[str], None],
                 clock: Callable[[], float] = vipnode.boottime,
                 exchange: Callable[[str, str, bytes], bytes] =
                 vipnode.over_the_overlay):
        self.ops = ops
        self.client = client
        self.stop = stop
        self.err = err
        self.clock = clock
        self.exchange = exchange
        self.renewed: dict[str, float] = {}
        self.tried: dict[str, float] = {}

    def own(self, facts: Facts) -> list[Held]:
        """The VIPs this node holds by its own claim on a lease"""
        return [one for one in self.ops.held()
                if one.lease and one.holds(facts.own_key)]

    def holding(self) -> None:
        """One turn of the holder's duty, for each VIP it holds"""
        facts = self.ops.facts()
        for held in self.own(facts):
            vip = held.vip
            now = self.clock()
            if now - self.tried.get(vip, float("-inf")) >= RENEW:
                self.tried[vip] = now
                if not self.renew(facts, held, now):
                    continue
            base = self.renewed.get(vip)
            age = None if base is None else self.clock() - base
            if age is None or not 0 <= age < RELEASE_AFTER:
                if self.ops.carried(vip):
                    self.ops.drop(vip, False, (
                        "not renewed since this controller started" if base
                        is None else f"no renewal the majority confirmed for"
                        f" {RELEASE_AFTER:g} s: this node may be cut off"))
                continue
            if self.ops.carried(vip) is False:
                self.ops.carry(vip, age)

    def renew(self, facts: Facts, held: Held, sent: float) -> bool:
        """One renewal; False when the lease is gone and the VIP was
        dropped. It counts once a linearizable read finds the holder's
        key on this lease, with this node's claim; any error of etcd is
        no renewal."""
        try:
            client = self.client()
            ttl = client.keepalive(held.lease)
            if ttl > 0:
                key = key_of(facts.mesh_id, held.vip, HOLDER)
                found = client.prefix(key)
                if not any(one.key == key and one.lease == held.lease and
                           one.value == held.claim.raw for one in found):
                    ttl = 0
        except EtcdError:
            return True
        if ttl <= 0:
            self.ops.drop(held.vip, True, "its lease is gone", held.lease)
            self.renewed.pop(held.vip, None)
            return False
        self.renewed[held.vip] = sent
        return True

    def following(self) -> None:
        """One turn of following etcd's keys, and of failing over"""
        facts = self.ops.facts()
        try:
            client = self.client()
            keys = seen(client, facts.mesh_id, self.err)
        except EtcdError:
            return
        for now in keys.values():
            for one in (now.epoch, now.holder):
                if one is None:
                    continue
                problem = self.ops.take(one.raw)
                if problem:
                    self.err(f"vip {now.vip}: etcd's claim refused:"
                             f" {problem}")
        self.fail_over(facts, client, keys)

    def fail_over(self, facts: Facts, client: Client,
                  keys: dict[str, Seen]) -> None:
        """Claim this node's VIP when no valid holder key is left"""
        vip = facts.vip
        now = keys.get(vip) if vip else None
        if now is None or now.holder is not None or now.epoch is None:
            return
        held = next((one for one in self.ops.held() if one.vip == vip),
                    None)
        if held is None or held.fenced or held.epoch < now.epoch.epoch or \
                same_key(now.epoch.holder, facts.own_key):
            return
        try:
            made = claim(client, facts.mesh_id, vip, now, held.epoch,
                         self.ops.sign, self.clock)
        except (EtcdError, VipError) as e:
            self.err(f"vip {vip}: the claim failed: {e}")
            return
        if made is None:
            return
        self.ops.hold(made[0].raw, made[1])
        self.renewed[vip] = made[2]
        self.tried[vip] = made[2]
        self.err(f"vip {vip}: claimed at epoch {made[0].epoch}: the"
                 " holder's lease expired")
        threading.Thread(target=self.announce, args=(facts, made[0]),
                         daemon=True).start()

    def announce(self, facts: Facts, made: Claim) -> None:
        """The claim told to every peer, for those without etcd"""
        for at in facts.peers:
            try:
                self.exchange(at, facts.iface, made.raw)
            except Exception as e:  # noqa: BLE001 - each is said
                self.err(f"vip {made.vip}: {at} did not take the claim:"
                         f" {e}")

    def run(self) -> None:
        """Until `stop`: the holder's duty every HOLD_TICK, the keys every
        TICK, in two threads"""
        def hold() -> None:
            while not self.stop.is_set():
                try:
                    self.holding()
                except FAILURES as e:
                    self.err(f"vip: {e}")
                self.stop.wait(HOLD_TICK)
        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        while not self.stop.is_set():
            try:
                self.following()
            except FAILURES as e:
                self.err(f"vip: {e}")
            self.stop.wait(TICK)
        holder.join()


def stopped(here: Here) -> list[str]:
    """What the unit's ExecStopPost runs: every VIP this node carries
    dropped, so a controller that died never leaves one behind it,
    unrenewed; the VIPs dropped. Not fenced: a controller started again
    carries it once it renewed its lease."""
    found = []
    for held in vipstate.held_all(here.root):
        if vipnet.carried(here.iface(), held.vip,
                          here.node.output) is not False:
            problem = vipnet.drop(here.iface(), held.vip, here.node.run,
                                  here.node.output)
            if problem:
                here.err(f"vip {held.vip}: {problem}")
            found.append(held.vip)
    return found
