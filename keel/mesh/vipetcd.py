# Copyright (c) 2026 KeelLinux maintainers
"""The VIP with etcd: the lease is the fence (decisions 0049, 0025)

A claim with etcd carries, signed into it, the ID of the lease that
holds it. Two keys per VIP, under the mesh's prefix in etcd:

    /keel/<mesh id>/vip/<vip>/epoch    the newest claim, kept for good:
                                       the counter
    /keel/<mesh id>/vip/<vip>/holder   the same claim, attached to its
                                       lease; shown, and read by no
                                       decision

A node claims only by one transaction: a new lease, the claim signed
with it at the next epoch, both keys written only when the counter is
still at the revision the node read. A stale claim, from a counter
another write has since moved, fails that comparison and is never
written.

Once keel mesh etcd reissue has turned etcd's auth on (keel#83,
keel.mesh.etcdauth), only the pair's two members may write or delete
these keys, or revoke a lease attached to them. etcd checks no
permission for a lease's keep-alive, and auth may be off (before the
reissue, or after its rollback), so what a member outside the pair can
do is also bounded by what each node checks, as defence in depth:

- no node takes a claim it cannot verify (signed by a member of the
  pair record, newer than what it holds): an old or forged value is
  ignored, wherever it is written;
- **the holder decides only by its own lease**: it renews it every
  RENEW seconds, and carries the address only while the last renewal
  the majority confirmed is less than RELEASE_AFTER seconds old,
  counted from the renewal's send on CLOCK_BOOTTIME (suspend counts),
  in this process's memory, and the address itself carries the rest of
  that time as its lifetime (keel.mesh.vipnet.lifetime), so the kernel
  removes it by then whatever becomes of this process: a controller that
  starts, after a restart, extends nothing until it renewed the lease
  itself, and one after a reboot finds nothing to extend. A
  renewal counts once a linearizable read, which needs the majority,
  answers after it (etcd's leader renews leases by itself, so a leader
  cut off answers renewals until it steps down); any error of etcd is no
  renewal. A lease etcd says is gone fences the node when it expired (the
  node was cut off past RELEASE_AFTER): it never claims again by itself
  (0049: an old primary "must never re-claim"). One gone while the node
  still renewed it with the majority was revoked, by anyone: the node
  drops the address, lost nothing, and claims again at the next epoch by
  the counter's transaction, which serialises it with any claim of the
  other node. A value written to a key neither fences it nor keeps it;
- **the other node of the pair claims only once the lease of the newest
  claim it verified is gone**, asked of etcd by the ID signed into the
  claim (TimeToLive, -1: `gone`; 0 is a lease in its last second,
  which a renewal still keeps): never because the holder key was
  deleted or rewritten. A lease that ends before its TTL ran out was revoked, and
  the holder learns that only at its next renewal, so the other node
  waits GRACE first. etcd cannot expire the lease before TTL seconds
  after the last renewal it answered, so a holder cut off from the
  majority has dropped the VIP RELEASE_AFTER seconds before any other
  node can win it. Against etcd's 5 s election timeout
  (keel.mesh.etcdconf): a re-election in the majority takes 5 to 10 s,
  during which renewals fail, but etcd gives every lease its TTL again
  on a leader change, so RELEASE_AFTER (15 s) rides out one re-election
  without a move (keel#167: 10 s did not, under loss).
  This is 0020's automatic failover, which etcd's three voters make
  possible;
- every node follows the counter, and only the counter, and takes a
  newer verified claim as one from the members' channel
  (keel.mesh.vipnode.take), so the VIP is routed to its holder on every
  member;
- only the controller adds the address on a node with etcd, once its own
  claim stands and its lease is fresh.

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
# a holder with no renewal the majority confirmed for this long marks its
# doubt, and keel database follow turns a MariaDB holder read only until
# a renewal is confirmed (keel#195): after the longest normal gap (a
# renewal period and a call), well before a dump thread to a cut replica
# ends (tcp_retries2 = 5: about 12.6 s) or the release (RELEASE_AFTER)
DOUBT = 6.0
# one call to this member's etcd: a renewal that takes longer is not
# one the holder can count on
CALL_TIMEOUT = 2.0
TICK = 1.0
HOLD_TICK = 0.2
# a lease gone this much before it was due ended early: revoked
EARLY = 2.0
# how long after a lease ended early the other node waits before it
# claims: the longest a holder goes on carrying the VIP after its last
# confirmed renewal (RELEASE_AFTER), a renewal period and a call late
GRACE = RELEASE_AFTER + RENEW + CALL_TIMEOUT
EPOCH, HOLDER = "epoch", "holder"
EXPIRED_SAID = (" (expired at its due time: the old primary is gone, so a"
                " PostgreSQL primary commits alone, decision 0054)")
# what a turn of the controller survives, said: a spec being edited, a
# damaged state file, a key not readable for a moment, the root half
# gone a moment
FAILURES = (VipError, NodeError, ValueError, OSError)


def gone(ttl: int) -> bool:
    """Whether etcd's time to live says a lease is gone for good. etcd
    gives it in whole seconds, rounded down, so 0 is a lease in its last
    second, which a renewal still keeps; only -1 is gone (keel#126)"""
    return ttl < 0


def prefix(mesh_id: str) -> str:
    return f"/keel/{mesh_id}/vip/"


def key_of(mesh_id: str, vip: str, which: str) -> str:
    return f"{prefix(mesh_id)}{vip}/{which}"


@dataclass(frozen=True)
class Seen:
    """One VIP's keys: the counter's claim and its revision, the
    revision whatever its value is (0 when there is no key), and the
    holder key's claim and lease, which are shown and decide nothing"""

    vip: str
    epoch: Claim | None = None
    revision: int = 0
    holder: Claim | None = None
    lease: str | None = None


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
        if which == EPOCH:
            now = replace(now, revision=value.mod_revision)
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


# a claim's transaction that etcd did not answer in time is tried again
# (keel#135): at most CLAIM_TRIES times, and none started CLAIM_WITHIN
# seconds after the first; a lease older than FRESH is replaced before a
# try, so the claim that wins has most of its TTL left
CLAIM_TRIES = 3
CLAIM_WITHIN = 30.0
FRESH = TTL / 2


def claim(client: Client, mesh_id: str, vip: str, now: Seen,
          known: int, sign: Callable[[str, int, str], Claim],
          clock: Callable[[], float]) -> tuple[Claim, str, float] | None:
    """A claim by compare-and-swap on the counter: a new lease, the
    claim `sign` makes with it, at the next epoch, written in one
    transaction that holds only when the counter is still at the
    revision read; the claim, its lease and when the lease was asked
    for, or None when another write came first. `known` is the epoch
    this node holds. The holder key is written beside it, for show: no
    decision reads it. Raises EtcdError, VipError.

    A transaction that etcd did not answer in time may have committed
    (keel#135). So before another try the counter is read: this node's
    own claim at the epoch is the claim made; another claim, or any
    other write, ends it (None); an unchanged counter is tried again
    with the same comparison, on the revision read before the first
    try, never a blind write. Every lease of a try that did not win is
    revoked, so a late transaction with it fails in etcd."""
    epoch = max(now.epoch.epoch if now.epoch else 0, known) + 1
    compare = [modified(key_of(mesh_id, vip, EPOCH), now.revision)]
    started = clock()
    tried: dict[str, tuple[Claim, float]] = {}
    current = None
    problem: EtcdError | None = None
    for turn in range(CLAIM_TRIES):
        if turn and clock() - started >= CLAIM_WITHIN:
            break
        if current is None or clock() - tried[current][1] >= FRESH:
            current = _leased(client, vip, epoch, sign, clock, tried)
        made = tried[current][0]
        try:
            if client.swap(compare, [
                    (key_of(mesh_id, vip, EPOCH), made.raw, None),
                    (key_of(mesh_id, vip, HOLDER), made.raw, current)]):
                return _won(client, tried, current)
            answered = True
        except EtcdError as e:
            problem, answered = e, False
        found = _landed(client, mesh_id, vip, now.revision, tried)
        if found == OTHER or (answered and found == UNCHANGED):
            _revoked(client, tried, None)
            return None
        if found not in (UNCHANGED, UNKNOWN):
            return _won(client, tried, found)
    found = _landed(client, mesh_id, vip, now.revision, tried)
    if found not in (UNCHANGED, UNKNOWN, OTHER):
        return _won(client, tried, found)
    _revoked(client, tried, None)
    if found == OTHER:
        return None
    raise problem or EtcdError("etcd did not take the claim")


OTHER, UNCHANGED, UNKNOWN = "other", "unchanged", "unknown"


def _leased(client: Client, vip: str, epoch: int, sign, clock,
            tried: dict) -> str:
    """A new lease and the claim signed with it, kept in `tried`; the
    lease. Raises EtcdError, VipError (the lease revoked then)"""
    asked = clock()
    lease = client.grant(TTL)
    try:
        tried[lease] = (sign(vip, epoch, lease), asked)
    except VipError:
        try:
            client.revoke(lease)
        except EtcdError:
            pass
        _revoked(client, tried, None)
        raise
    return lease


def _landed(client: Client, mesh_id: str, vip: str, revision: int,
            tried: dict) -> str:
    """What the counter holds after a try: the lease of this node's own
    claim of `tried` when one of them landed, OTHER for any other write,
    UNCHANGED when it is still at `revision`, UNKNOWN when etcd did not
    answer"""
    try:
        now = seen(client, mesh_id).get(vip) or Seen(vip)
    except EtcdError:
        return UNKNOWN
    if now.revision == revision:
        return UNCHANGED
    for lease, (made, _) in tried.items():
        if now.epoch is not None and now.epoch.raw == made.raw:
            return lease
    return OTHER


def _won(client: Client, tried: dict, lease: str) -> tuple[Claim, str, float]:
    _revoked(client, tried, lease)
    made, asked = tried[lease]
    return made, lease, asked


def _revoked(client: Client, tried: dict, kept: str | None) -> None:
    """Every lease of `tried` but `kept` revoked, as far as etcd answers"""
    for lease in list(tried):
        if lease == kept:
            continue
        try:
            client.revoke(lease)
        except EtcdError:
            pass


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

    def sign(self, vip: str, epoch: int, lease: str | None = None) -> Claim:
        """This node's claim of its own VIP, above every epoch it knows,
        with the lease that will hold it"""
        if vip != self.facts().vip:
            raise VipError(f"{vip} is not this node's appliance.vip")
        held = vipnode.current(self.here, vip)
        if not held.epoch < epoch <= held.epoch + vipnode.MAX_STEP:
            raise VipError(f"epoch {epoch} is not above {held.epoch}")
        return vipnode.signed_claim(self.here, vip, epoch, lease)

    def hold(self, raw: bytes, lease: str, expired: bool = False) -> None:
        """This node's own claim, as etcd took it, recorded with its
        lease. `expired` is the controller's word that it claimed because
        the lease of the newest claim expired (keel#165): the statement
        that the old primary is gone is written first, so the follow that
        the claim starts reads it. The root half cannot ask etcd again,
        so it trusts the word of its own helper for this one statement,
        and checks the claim: verified, this node's own, the epoch above
        the one it held (decision 0054, amendment of 2026-10-15)"""
        found = vipmsg.claim_of(raw)
        if not same_key(found.holder, self.here.own_key()):
            raise VipError("not this node's claim")
        problem = vipnode.verified(self.here, found)
        if problem:
            raise VipError(problem)
        if expired:
            self.state_gone(found)
        vipnode.hold(self.here, found, False, lease)

    def state_gone(self, found: Claim) -> None:
        """The statement of keel#165, when the claim is above the epoch
        held and the previous holder another node; one that cannot be
        written is said, and the claim stands all the same (keel#178)"""
        before = vipnode.current(self.here, found.vip)
        if found.epoch <= before.epoch or before.claim is None or \
                same_key(before.claim.holder, found.holder):
            return
        try:
            vipstate.state_gone(self.here.root, before.epoch, found.epoch)
        except OSError as e:
            self.here.err(f"vip {found.vip}: the statement that the old"
                          f" primary is gone could not be written ({e});"
                          " the claim stands, and its commits wait for a"
                          " standby or for the operator")

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

    def doubt(self, vip: str, on: bool) -> None:
        """The doubt of the lease of this node's own claim, marked or
        cleared (keel#195); only for this node's own VIP"""
        if vipstate.address(vip) != self.facts().vip:
            raise VipError(f"{vip} is not this node's appliance.vip")
        if vipstate.mark_unconfirmed(self.here.root, vip, on):
            self.here.err(
                f"vip {vip}: no renewal the majority confirmed for"
                f" {DOUBT:g} s: this node may be cut off, and a MariaDB"
                " server here acknowledges no write until one is (keel#195)"
                if on else
                f"vip {vip}: a renewal is confirmed again: the doubt is"
                " cleared (keel#195)")

    def bounded(self, vip: str) -> bool | None:
        return vipnet.bounded(self.here.iface(), vip, self.here.node.output)


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
        # when each lease seen alive was due to expire, and when each
        # was first seen gone, on this process's clock
        self.alive: dict[str, float] = {}
        self.gone: dict[str, float] = {}
        # this node's VIPs whose lease was revoked while it renewed it
        self.reclaim: set[str] = set()
        # the renewal each VIP's address last took its lifetime from
        self.lifted: dict[str, float] = {}
        # the VIPs whose doubt this process marked, and those whose mark
        # it cleared since (a mark an earlier process left goes at the
        # first renewal this one has confirmed, keel#195)
        self.doubted: set[str] = set()
        self.cleared: set[str] = set()
        # when this process first saw each claim of its own that it has
        # not renewed yet: a controller that starts cut off doubts too
        self.began: dict[str, float] = {}

    def own(self, facts: Facts) -> list[Held]:
        """The VIPs this node holds by its own claim on a lease"""
        return [one for one in self.ops.held()
                if one.lease and one.holds(facts.own_key)]

    def holding(self) -> None:
        """One turn of the holder's duty, for each VIP it holds"""
        facts = self.ops.facts()
        owned = self.own(facts)
        # a mark goes with the claim: a node that no longer holds it does
        # not start a later claim read only
        for vip in sorted(self.doubted - {one.vip for one in owned}):
            self.mark(vip, False)
        for held in owned:
            vip = held.vip
            if vip in self.reclaim:
                continue
            now = self.clock()
            if now - self.tried.get(vip, float("-inf")) >= RENEW:
                self.tried[vip] = now
                if not self.renew(facts, held, now):
                    continue
            base = self.renewed.get(vip)
            if base is None:
                self.started_with(vip)
                began = self.began.setdefault(vip, self.clock())
                if self.clock() - began >= DOUBT:
                    self.doubt(vip, self.clock() - began)
                continue
            self.began.pop(vip, None)
            age = self.clock() - base
            self.doubt(vip, age)
            if not 0 <= age < RELEASE_AFTER:
                if self.ops.carried(vip):
                    self.ops.drop(vip, False, (
                        f"no renewal the majority confirmed for"
                        f" {RELEASE_AFTER:g} s: this node may be cut off"))
                continue
            # each confirmed renewal gives the address a new lifetime,
            # what is left of the release time after it
            if self.lifted.get(vip) != base or \
                    self.ops.carried(vip) is False:
                if self.ops.carry(vip, age):
                    self.lifted[vip] = base

    def doubt(self, vip: str, age: float) -> None:
        """The holder's doubt marked once its last confirmed renewal is
        DOUBT s old, cleared once a renewal is confirmed again"""
        if not 0 <= age < DOUBT:
            if vip not in self.doubted:
                self.mark(vip, True)
            return
        if vip in self.doubted or vip not in self.cleared:
            self.mark(vip, False)

    def mark(self, vip: str, on: bool) -> None:
        """The mark of the doubt, best effort: a mark that cannot be
        written is said, and never stops the release (keel#195)"""
        try:
            self.ops.doubt(vip, on)
        except FAILURES as e:
            self.err(f"vip {vip}: doubt not marked: {e}")
            return
        if on:
            self.doubted.add(vip)
            self.cleared.discard(vip)
        else:
            self.doubted.discard(vip)
            self.cleared.add(vip)

    def started_with(self, vip: str) -> None:
        """Before this controller's first renewal: an address a previous
        one left with a lifetime is the kernel's to end, by the release
        deadline of that one's last confirmed renewal, and is not
        extended; one with none (an older keel's) is dropped"""
        if self.ops.carried(vip) and self.ops.bounded(vip) is False:
            self.ops.drop(vip, False, "not renewed since this controller"
                          " started")

    def renew(self, facts: Facts, held: Held, sent: float) -> bool:
        """One renewal; False when the lease is gone and the VIP was
        dropped. It counts once a linearizable read, which needs the
        majority, answers after it; any error of etcd is no renewal.
        What the keys hold decides nothing here: only this node's lease,
        which no write to a key can bring back or take away."""
        try:
            client = self.client()
            ttl = client.keepalive(held.lease)
            if ttl > 0:
                client.prefix(key_of(facts.mesh_id, held.vip, EPOCH))
        except EtcdError:
            return True
        if ttl <= 0:
            base = self.renewed.pop(held.vip, None)
            if base is not None and sent - base < RELEASE_AFTER:
                # gone while this node renewed it with the majority: not
                # expired, so revoked, by anyone; this node lost nothing
                # and claims again at the next epoch, through the
                # counter's transaction, which no other claim can share
                self.ops.drop(held.vip, False, "its lease was revoked:"
                              " claiming again at the next epoch")
                self.reclaim.add(held.vip)
                return False
            self.ops.drop(held.vip, True, "its lease is gone", held.lease)
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
        # the counter alone: the holder key is shown, and decides nothing
        for now in keys.values():
            if now.epoch is None:
                continue
            problem = self.ops.take(now.epoch.raw)
            if problem:
                self.err(f"vip {now.vip}: etcd's claim refused: {problem}")
        self.claim_again(facts, client, keys)
        self.fail_over(facts, client, keys)

    def fail_over(self, facts: Facts, client: Client,
                  keys: dict[str, Seen]) -> None:
        """Claim this node's VIP once the lease of the newest claim this
        node verified has expired

        The newest claim is this node's own record of it, never what the
        holder key says; its lease is the one signed into it, asked of
        etcd by its ID. A lease that ends before its TTL ran out was
        revoked: the holder learns it only at its next renewal, so this
        node waits GRACE first, the longest a holder can go on carrying
        the VIP after its last renewal the majority confirmed."""
        vip = facts.vip
        held = next((one for one in self.ops.held() if one.vip == vip),
                    None) if vip else None
        if held is None or held.fenced or held.claim is None or \
                same_key(held.claim.holder, facts.own_key) or \
                held.claim.lease is None:
            return
        now = keys.get(vip) or Seen(vip)
        if now.epoch is not None and now.epoch.epoch > held.epoch:
            return
        lease = held.claim.lease
        try:
            ttl = client.time_to_live(lease)
        except EtcdError:
            return
        moment = self.clock()
        if not gone(ttl):
            self.alive[lease] = moment + ttl
            return
        expected = self.alive.get(lease)
        first = self.gone.setdefault(lease, moment)
        # expired: first seen gone at its due time, not before it; a
        # lease gone early stays revoked however long this node waits
        expired = expected is not None and first >= expected - EARLY
        if not expired and moment - first < GRACE:
            return
        self.claimed(facts, client, now, held, expired)

    def claim_again(self, facts: Facts, client: Client,
                    keys: dict[str, Seen]) -> None:
        """This node's VIP claimed again after its lease was revoked while
        it renewed it: still in the pair, its own claim still the newest
        it verified, by the counter's transaction at the next epoch, so a
        claim of the other node can only come first, never beside it"""
        for vip in sorted(self.reclaim):
            held = next((one for one in self.ops.held() if one.vip == vip),
                        None)
            if held is None or not held.holds(facts.own_key):
                self.reclaim.discard(vip)
                continue
            now = keys.get(vip) or Seen(vip)
            if now.epoch is not None and now.epoch.epoch > held.epoch:
                self.reclaim.discard(vip)
                continue
            if self.claimed(facts, client, now, held):
                self.reclaim.discard(vip)

    def claimed(self, facts: Facts, client: Client, now: Seen,
                held: Held, expired: bool = False) -> bool:
        """A claim at the next epoch; `expired` when the lease of `held`
        ran out at its due time, seen alive before: that states the old
        primary gone (keel#165), never a revoked lease or one of an
        unknown end"""
        vip = held.vip
        try:
            made = claim(client, facts.mesh_id, vip, now, held.epoch,
                         self.ops.sign, self.clock)
        except (EtcdError, VipError) as e:
            self.err(f"vip {vip}: the claim failed: {e}")
            return False
        if made is None:
            return False
        self.ops.hold(made[0].raw, made[1], expired)
        self.renewed[vip] = made[2]
        self.tried[vip] = made[2]
        self.err(f"vip {vip}: claimed at epoch {made[0].epoch}: the"
                 f" lease of epoch {held.epoch} is gone"
                 f"{EXPIRED_SAID if expired else ''}")
        threading.Thread(target=self.announce, args=(facts, made[0]),
                         daemon=True).start()
        return True

    def announce(self, facts: Facts, made: Claim) -> None:
        """The claim told to every peer, for those without etcd, each in
        its own thread: one after the other, a dead old holder's timeout
        delayed the route on every other node (keel#235)"""
        def tell(at: str) -> None:
            try:
                self.exchange(at, facts.iface, made.raw)
            except Exception as e:  # noqa: BLE001 - each is said
                self.err(f"vip {made.vip}: {at} did not take the claim:"
                         f" {e}")
        told = [threading.Thread(target=tell, args=(at,), daemon=True)
                for at in facts.peers]
        for each in told:
            each.start()
        for each in told:
            each.join()

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


def stopped(here: Here, restarting: bool = False,
            client: Callable[[], Client] | None = None,
            clock: Callable[[], float] = vipnode.boottime
            ) -> tuple[list[str], list[str]]:
    """What the unit's ExecStopPost runs: every VIP this node carries
    dropped, so a helper that stopped never leaves one behind it,
    unrenewed; but while the unit is `restarting` (an upgrade's
    try-restart, or Restart= after a crash), an address with a lifetime
    is kept: the kernel ends it by the release deadline of the last
    confirmed renewal, and the next controller extends it only once it
    renewed the same lease itself. An address with no lifetime is always
    dropped. The VIPs dropped and kept. Never fenced: a controller
    started again carries it once it renewed its lease.

    A kept address is renewed once first (`handed_over`): on a slow
    link, the next controller's start and first renewal took longer
    than what the old one's last renewal had left, and the kernel
    removed the address for a moment (vip-upgrade / trixie, keel#87)."""
    dropped, kept = [], []
    for held in vipstate.held_all(here.root):
        if vipnet.carried(here.iface(), held.vip,
                          here.node.output) is False:
            continue
        if restarting and vipnet.bounded(here.iface(), held.vip,
                                         here.node.output) and \
                handed_over(here, held, client or (lambda: local(here)),
                            clock):
            kept.append(held.vip)
            continue
        problem = vipnet.drop(here.iface(), held.vip, here.node.run,
                              here.node.output)
        if problem:
            here.err(f"vip {held.vip}: {problem}")
        dropped.append(held.vip)
    return dropped, kept


def handed_over(here: Here, held: Held, client: Callable[[], Client],
                clock: Callable[[], float]) -> bool:
    """One renewal of this node's lease, as the controller makes it (a
    keep-alive, then a linearizable read, which needs the majority), and
    the address given the lifetime that renewal leaves; whether the
    address stays. With no answer it stays as it is, the kernel's to end
    by the last renewal's deadline; a lease gone drops it.

    A single deadline (CALL_TIMEOUT) caps the two calls: on a 250 ms
    link the whole sequence takes about 1.5 s, which gains the new
    controller a fresh lifetime; anything longer costs more restart time
    than the lifetime it gains (keel#87)"""
    if not held.lease or not held.holds(here.own_key()):
        return True
    sent = clock()
    deadline = sent + CALL_TIMEOUT
    try:
        etcd = client()
        etcd.timeout = max(0.5, deadline - clock())
        ttl = etcd.keepalive(held.lease)
        if ttl > 0:
            left = deadline - clock()
            if left < 0.5:
                here.err(f"vip {held.vip}: keepalive took"
                         f" {clock() - sent:.2f} s, no time for the"
                         " prefix; the kernel ends the address by the"
                         " last renewal's deadline")
                return True
            etcd.timeout = left
            etcd.prefix(key_of(here.mesh_id(), held.vip, EPOCH))
    except (EtcdError, *FAILURES) as e:
        here.err(f"vip {held.vip}: not renewed as the unit restarts ({e});"
                 f" {clock() - sent:.2f} s in;"
                 " the kernel ends the address by the last renewal's"
                 " deadline")
        return True
    if ttl <= 0:
        return False
    age = clock() - sent
    if not vipnode.carry_held(here, held.vip, age):
        here.err(f"vip {held.vip}: renewed as the unit restarts, but not"
                 " carried again")
    return True
