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

`keel vip tend`, the controller (keel-vip.service of keel-overlay-vip),
runs on every cloud advanced member:

- **the holder renews its lease** every RENEW seconds, and **drops the
  address when no renewal was answered for RELEASE_AFTER seconds**,
  counted from the send of the last renewal etcd answered. etcd cannot
  expire the lease before TTL seconds after that send, so a holder cut
  off from the majority has dropped the VIP RELEASE_AFTER seconds before
  any other node can win it. Against etcd's 5 s election timeout
  (keel.mesh.etcdconf): a re-election in the majority takes 5 to 10 s,
  during which renewals fail, but etcd gives every lease its TTL again on
  a leader change, so 10 s rides out one re-election without a move.
  A holder that dropped it this way is fenced: it never claims again by
  itself (0049: an old primary "must never re-claim");
- **every node follows the keys**: a newer claim is taken as one from
  the members' channel is (keel.mesh.vipnode.take), so the VIP is routed
  to its holder on every member;
- **the other node of the pair claims when the holder key is gone**, the
  lease expired, once it has taken the counter's claim and is not fenced
  (0020's automatic failover, which etcd's three voters make possible);
- only the controller adds the address on a node with etcd, once its own
  claim stands and its lease is fresh, so a VIP is never carried by a
  node whose lease nobody renews.

The new holder also announces its claim on the members' channel, for the
nodes that are not cloud advanced (0049, third round, point 4).
"""

import threading
from dataclasses import dataclass, replace

from keel.mesh import vipmsg, vipnet, vipnode
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import Client, EtcdError, absent, modified
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.vip import Claim
from keel.mesh.vipnode import Here, VipError
from keel.network.wireguard import same_key

TTL = 20
RELEASE_AFTER = 10.0
RENEW = 2.0
# one call to this member's etcd: a renewal that takes longer is not
# one the holder can count on
CALL_TIMEOUT = 2.0
TICK = 1.0
HOLD_TICK = 0.2
EPOCH, HOLDER = "epoch", "holder"
# what a turn of the controller survives, said: a spec being edited, a
# damaged state file, a key not readable for a moment
FAILURES = (VipError, NodeError, ValueError, OSError)


def prefix(mesh_id: str) -> str:
    return f"/keel/{mesh_id}/vip/"


def key_of(mesh_id: str, vip: str, which: str) -> str:
    return f"{prefix(mesh_id)}{vip}/{which}"


@dataclass(frozen=True)
class Seen:
    """One VIP's keys: the counter's claim and its revision (0 when it
    has none), and the holder's claim and lease, None when no lease is
    alive"""

    vip: str
    epoch: Claim | None = None
    revision: int = 0
    holder: Claim | None = None
    lease: str | None = None


def seen(client: Client, mesh_id: str,
         err=lambda line: None) -> dict[str, Seen]:
    """Every VIP's keys; raises EtcdError. A value that is not a claim
    for its own key is left out and said."""
    found: dict[str, Seen] = {}
    base = prefix(mesh_id)
    for value in client.prefix(base):
        vip, _, which = value.key[len(base):].partition("/")
        try:
            vip = vipstate.address(vip)
            claim = vipmsg.claim_of(value.value)
            if claim.vip != vip or which not in (EPOCH, HOLDER):
                raise ProtocolError("a claim for another key")
        except (ValueError, ProtocolError) as e:
            err(f"vip: etcd's {value.key} is not a claim: {e}")
            continue
        now = found.get(vip) or Seen(vip)
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


def claim(here: Here, client: Client, vip: str,
          now: Seen) -> tuple[Claim, str, float] | None:
    """This node's claim, by compare-and-swap on the counter: the claim,
    its lease and when the lease was asked for; None when another claim
    came first or a lease is alive. Raises EtcdError, VipError."""
    mesh = here.mesh_id()
    held = vipnode.current(here, vip)
    epoch = max(now.epoch.epoch if now.epoch else 0, held.epoch) + 1
    made = vipnode.signed_claim(here, vip, epoch)
    asked = here.monotonic()
    lease = client.grant(TTL)
    ok = client.swap(
        [modified(key_of(mesh, vip, EPOCH), now.revision),
         absent(key_of(mesh, vip, HOLDER))],
        [(key_of(mesh, vip, EPOCH), made.raw, None),
         (key_of(mesh, vip, HOLDER), made.raw, lease)])
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


class Controller:
    """`keel vip tend`: renew, fence, follow and fail over"""

    def __init__(self, here: Here, stop: threading.Event):
        self.here = here
        self.stop = stop
        self.renewed: dict[str, float] = {}
        self.tried: dict[str, float] = {}

    def own(self) -> list[vipstate.Held]:
        """The VIPs this node holds by its own claim, with a lease, and
        is not fenced from"""
        key = self.here.own_key()
        return [one for one in vipstate.held_all(self.here.root)
                if one.lease and one.holds(key)]

    def holding(self) -> None:
        """One turn of the holder's duty, for each VIP it holds"""
        for held in self.own():
            vip = held.vip
            base = max(self.renewed.get(vip, 0.0), held.renewed or 0.0)
            now = self.here.monotonic()
            if now - self.tried.get(vip, 0.0) >= RENEW:
                self.tried[vip] = now
                base = self.renew(held, now, base)
                if base is None:
                    continue
            if self.here.monotonic() - base >= RELEASE_AFTER:
                vipnode.drop_fenced(self.here, vip, (
                    f"no renewal of its lease for {RELEASE_AFTER:g} s: this"
                    " node may be cut off from etcd's majority"))
                continue
            if vipnet.carried(self.here.iface(), vip,
                              self.here.node.output) is False:
                vipnode.carry_held(self.here, vip)

    def renew(self, held: vipstate.Held, sent: float,
              base: float) -> float | None:
        """One renewal; the base the deadline counts from, None when the
        lease is gone and the VIP was dropped"""
        try:
            ttl = local(self.here).keepalive(held.lease)
        except EtcdError:
            return base
        if ttl <= 0:
            vipnode.drop_fenced(self.here, held.vip, "its lease is gone")
            return None
        self.renewed[held.vip] = sent
        with vipstate.locked(self.here.root):
            after = vipnode.current(self.here, held.vip)
            if after.lease == held.lease and after.holds(held.holder):
                vipstate.write(self.here.root, replace(after, renewed=sent))
        return sent

    def following(self) -> None:
        """One turn of following etcd's keys, and of failing over"""
        here = self.here
        try:
            client = local(here)
            keys = seen(client, here.mesh_id(), here.err)
        except (EtcdError, VipError, NodeError):
            return
        for now in keys.values():
            for one in (now.epoch, now.holder):
                if one is None:
                    continue
                problem = vipnode.verified(here, one)
                if problem:
                    here.err(f"vip {now.vip}: etcd's claim refused:"
                             f" {problem}")
                    continue
                vipnode.take(here, one)
        self.fail_over(client, keys)

    def fail_over(self, client: Client, keys: dict[str, Seen]) -> None:
        """Claim this node's VIP when its holder's lease is gone"""
        here = self.here
        try:
            vip = vipstate.declared(here.node.document())
        except (ValueError, NodeError):
            return
        now = keys.get(vip) if vip else None
        if now is None or now.holder is not None or now.epoch is None:
            return
        held = vipnode.current(here, vip)
        own = here.own_key()
        if held.fenced or held.epoch < now.epoch.epoch or \
                same_key(now.epoch.holder, own):
            return
        try:
            made = claim(here, client, vip, now)
        except (EtcdError, VipError) as e:
            here.err(f"vip {vip}: the claim failed: {e}")
            return
        if made is None:
            return
        vipnode.hold(here, made[0], False, made[1], made[2])
        self.renewed[vip] = made[2]
        here.err(f"vip {vip}: claimed at epoch {made[0].epoch}: the"
                 " holder's lease expired")
        threading.Thread(target=vipnode.announce, args=(here, made[0]),
                         daemon=True).start()

    def run(self) -> None:
        """Until `stop`: the holder's duty every HOLD_TICK, the keys every
        TICK, in two threads"""
        def hold() -> None:
            while not self.stop.is_set():
                try:
                    self.holding()
                except FAILURES as e:
                    self.here.err(f"vip: {e}")
                self.stop.wait(HOLD_TICK)
        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        while not self.stop.is_set():
            try:
                self.following()
            except FAILURES as e:
                self.here.err(f"vip: {e}")
            self.stop.wait(TICK)
        holder.join()


def stopped(here: Here) -> list[str]:
    """What the unit's ExecStopPost runs: every VIP this node carries
    dropped, so a controller that died never leaves one behind it,
    unrenewed; the VIPs dropped. Not fenced: a controller started again
    carries it while its lease lives."""
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

