# Copyright (c) 2026 KeelLinux maintainers
"""keel vip promote, check and status (decision 0049, third round)

**`keel vip promote`**, on the node that is to become the primary, with
or without a database (`keel database promote` calls it):

1. it finds the newest claim: before etcd, every peer is asked its epoch
   at once and each answer's claim is checked; with etcd, the counter;
2. when another node holds the VIP, it asks that node to release it, for
   the next epoch, and waits for the answer: the old primary drops the
   address first (release before take). **When the old primary does not
   answer, it refuses, unless `--old-primary-gone`**: only the operator
   knows that. With etcd and `--old-primary-gone`, it waits for the old
   primary's lease to expire, up to its TTL, and never revokes it
   (third round, point 5);
3. it claims at the next epoch: before etcd, signed and carried at once;
   with etcd, by the counter's compare-and-swap, carried by the
   controller once the claim stands;
4. it announces the claim to every peer on the members' channel; each
   routes the VIP to this node with one `wg set`.

No step is under 0018's window (0029, 0049): only WireGuard's table of
which peer owns the VIP's /128 changes, and the address on the holder.

**`keel vip check`**, at boot and on keel-vip-check.timer: every VIP this
node knows or declares, each peer asked its epoch; a newer claim is
taken (an old primary that comes back drops the address at once), the
table and wg0.conf set again from what this node holds, and the address
dropped from a node that does not hold it. Without etcd, the holder
carries it again after a restart once a peer answered and none knows a
newer claim; with etcd, that is the controller's.

**`keel vip status`**, also part of `keel mesh status`: each VIP, the role,
the epoch and holder, whether this node carries it, which peer the table
routes it to, whether this node is fenced, and the lease.
"""

from collections.abc import Callable
from datetime import datetime

from keel import exits
from keel.mesh import etcd, etcdstate, vipetcd, vipnet, vipnode
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import EtcdError
from keel.mesh.memberlink import LinkError
from keel.mesh.node import NodeError
from keel.mesh.signing import SigningError
from keel.mesh.vip import Claim
from keel.mesh.vipnode import Here, VipError
from keel.network.wireguard import same_key

# how long a promote with etcd waits for the controller to carry the VIP
CARRY_WAIT = 15.0
# how long it waits for the old holder's key to go: a lease revoked by a
# release goes at once; one left to expire goes within its TTL, which a
# leader change extends by an election timeout
GONE_WAIT = vipetcd.TTL + 20.0
POLL = 0.5


def with_etcd(here: Here) -> bool:
    """Whether this node moves its VIP through etcd: a cloud advanced
    member of a formed cluster"""
    try:
        return etcd.ready(here.node.document()) and \
            etcdstate.cluster(here.root) is not None
    except (NodeError, etcdstate.StateError):
        return False


def promote(here: Here, gone: bool, out: Callable[[str], None]) -> int:
    """`keel vip promote`: this node becomes the VIP's holder"""
    try:
        vip = vipstate.declared(here.node.document())
        if vip is None:
            out("this node declares no appliance.vip: it replicates nothing,"
                " and has no VIP to take")
            return exits.MESH_REFUSED
        problem = vipstate.problem(vip, here.overlay())
        if problem:
            out(problem)
            return exits.MESH_REFUSED
        if with_etcd(here):
            return promoted_etcd(here, vip, gone, out)
        return promoted(here, vip, gone, out)
    except (VipError, NodeError, ValueError, SigningError) as e:
        out(f"keel vip promote: {e}")
        return exits.APPLY_FAILED


def released(here: Here, vip: str, newest: Claim, epoch: int, gone: bool,
             out: Callable[[str], None]) -> bool:
    """The old holder asked to release; whether to go on"""
    out(f"asking the primary, {newest.holder} at {newest.address}, to"
        f" release {vip}…")
    try:
        here.say("release", newest.address, {"vip": vip, "epoch": epoch})
    except (LinkError, VipError, SigningError) as e:
        if not gone:
            out(f"the primary at {newest.address} did not release it: {e}."
                " Nothing was changed. Only you know whether that node is"
                " gone: if it is, run keel vip promote --old-primary-gone")
            return False
        out(f"the primary at {newest.address} did not answer ({e});"
            " --old-primary-gone: it will drop the VIP when it learns the"
            " newer claim")
        return True
    out(f"released by {newest.address}")
    return True


def promoted(here: Here, vip: str, gone: bool,
             out: Callable[[str], None]) -> int:
    """Before etcd: release, take, announce"""
    own = here.own_key()
    held = vipnode.current(here, vip)
    answers = vipnode.epochs(here, vip)
    claims = [one for one in answers.values() if isinstance(one, Claim)]
    newest = vipnode.newest(claims + ([held.claim] if held.claim else []))
    for at, one in answers.items():
        if isinstance(one, str):
            out(f"  {at}: {one}")
    if newest is not None and same_key(newest.holder, own) and \
            held.holds(own) and vipnet.carried(
                here.iface(), vip, here.node.output):
        out(f"this node holds {vip} already, at epoch {newest.epoch}")
        return exits.OK
    epoch = (newest.epoch if newest else 0) + 1
    if newest is not None and not same_key(newest.holder, own) and \
            not released(here, vip, newest, epoch, gone, out):
        return exits.MESH_REFUSED
    made = vipnode.signed_claim(here, vip, epoch)
    vipnode.hold(here, made, True)
    out(f"this node holds {vip} at epoch {epoch}, on {here.iface()}")
    return told(here, made, out)


def told(here: Here, made: Claim, out: Callable[[str], None]) -> int:
    said = vipnode.announce(here, made)
    for at, what in sorted(said.items()):
        out(f"  {at}: {what}")
    missed = [at for at, what in said.items()
              if what not in ("applied", "known")]
    if missed:
        out(f"{len(missed)} peer(s) did not take the claim now; each takes"
            " it at its next keel vip check, and routes the VIP to the old"
            " primary until then")
    return exits.OK


def gone_key(here: Here, vip: str, wait: float) -> vipetcd.Seen | None:
    """The VIP's keys once no holder key is left, waited for; None when
    it stays"""
    deadline = here.monotonic() + wait
    while True:
        try:
            now = vipetcd.seen(vipetcd.local(here), here.mesh_id(),
                               here.err).get(vip) or vipetcd.Seen(vip)
        except EtcdError:
            now = None
        if now is not None and now.holder is None:
            return now
        if here.monotonic() >= deadline:
            return None
        here.sleep(POLL)


def promoted_etcd(here: Here, vip: str, gone: bool,
                  out: Callable[[str], None]) -> int:
    """With etcd: release, compare-and-swap, the controller carries"""
    own = here.own_key()
    try:
        now = vipetcd.seen(vipetcd.local(here), here.mesh_id(),
                           here.err).get(vip) or vipetcd.Seen(vip)
    except EtcdError as e:
        out(f"etcd did not answer: {e}. With etcd, the VIP moves only"
            " through it")
        return exits.APPLY_FAILED
    holder = now.holder
    if holder is not None and same_key(holder.holder, own):
        out(f"this node holds {vip} already, at epoch {holder.epoch}")
        return exits.OK
    if holder is not None:
        epoch = max(now.epoch.epoch if now.epoch else 0,
                    vipnode.current(here, vip).epoch) + 1
        if not released(here, vip, holder, epoch, gone, out):
            return exits.MESH_REFUSED
        out("waiting for the primary's lease to go"
            f" (at most {GONE_WAIT:g} s)…")
        now = gone_key(here, vip, GONE_WAIT)
        if now is None:
            out("the primary's lease is still alive: nothing was claimed."
                " keel never revokes another node's lease")
            return exits.MESH_REFUSED
    try:
        made = vipetcd.claim(here, vipetcd.local(here), vip, now)
    except EtcdError as e:
        out(f"etcd did not take the claim: {e}")
        return exits.APPLY_FAILED
    if made is None:
        return raced(here, vip, own, out)
    vipnode.hold(here, made[0], False, made[1], made[2])
    out(f"this node holds {vip} at epoch {made[0].epoch}, by etcd's lease"
        f" {made[1]}")
    if not carried_soon(here, vip):
        out(f"keel-vip.service did not add {vip} to {here.iface()} within"
            f" {CARRY_WAIT:g} s: is it running? Its lease expires"
            f" {vipetcd.TTL} s after its last renewal")
        return exits.APPLY_FAILED
    return told(here, made[0], out)


def raced(here: Here, vip: str, own: str,
          out: Callable[[str], None]) -> int:
    """The compare-and-swap lost: to this node's own controller, which
    claims as soon as the released lease is gone, or to another node"""
    try:
        now = vipetcd.seen(vipetcd.local(here), here.mesh_id(),
                           here.err).get(vip)
    except EtcdError as e:
        out(f"etcd did not answer: {e}")
        return exits.APPLY_FAILED
    if now is None or now.holder is None or \
            not same_key(now.holder.holder, own):
        out("another claim came first: nothing was claimed here; keel vip"
            " status says who holds it")
        return exits.MESH_REFUSED
    out(f"this node holds {vip} at epoch {now.holder.epoch}, claimed by its"
        " controller once the lease was released")
    if not carried_soon(here, vip):
        out(f"keel-vip.service did not add {vip} to {here.iface()} within"
            f" {CARRY_WAIT:g} s: is it running?")
        return exits.APPLY_FAILED
    return exits.OK


def carried_soon(here: Here, vip: str) -> bool:
    deadline = here.monotonic() + CARRY_WAIT
    while not vipnet.carried(here.iface(), vip, here.node.output):
        if here.monotonic() >= deadline:
            return False
        here.sleep(POLL)
    return True


def check(here: Here, out: Callable[[str], None]) -> int:
    """`keel vip check`: learn newer claims, set the table again"""
    try:
        own_vip = vipstate.declared(here.node.document())
        vips = sorted(set(vipstate.known(here.root)) |
                      ({own_vip} if own_vip else set()))
        etcd_mode = with_etcd(here)
        for vip in vips:
            checked(here, vip, etcd_mode, out)
    except (VipError, NodeError, ValueError) as e:
        out(f"keel vip check: {e}")
        return exits.APPLY_FAILED
    return exits.OK


def checked(here: Here, vip: str, etcd_mode: bool,
            out: Callable[[str], None]) -> None:
    answers = vipnode.epochs(here, vip)
    claims = [one for one in answers.values() if isinstance(one, Claim)]
    newest = vipnode.newest(claims)
    if newest is not None and vipnode.take(here, newest):
        out(f"vip {vip}: took epoch {newest.epoch}, held by"
            f" {newest.holder}")
    held = vipnode.current(here, vip)
    mine = held.holds(here.own_key())
    live = vipnet.carried(here.iface(), vip, here.node.output)
    if live and not mine:
        problem = vipnet.drop(here.iface(), vip, here.node.run,
                              here.node.output)
        out(f"vip {vip}: dropped, this node does not hold it"
            f"{': ' + problem if problem else ''}")
    elif mine and not live and not etcd_mode and \
            any(not isinstance(one, str) for one in answers.values()):
        if vipnode.carry_held(here, vip):
            out(f"vip {vip}: carried again, epoch {held.epoch}")
    vipnode.routed(here, vip, held.holder)


def lines(here: Here, live: bool, now: datetime | None = None) -> list[str]:
    """What status prints of the VIPs; `live` False off the live system"""
    try:
        doc = here.node.document()
        own_vip = vipstate.declared(doc)
    except (NodeError, ValueError) as e:
        return [f"vip: {e}"]
    vips = sorted(set(vipstate.known(here.root)) |
                  ({own_vip} if own_vip else set()))
    if not vips:
        return ["vip: none (this node declares no appliance.vip and routes"
                " no other pair's)"]
    try:
        own = here.own_key()
    except VipError:
        own = None
    found = []
    for vip in vips:
        try:
            held = vipnode.current(here, vip)
        except VipError as e:
            found.append(f"vip {vip}: {e}")
            continue
        found += one_vip(here, vip, held, doc, own, own_vip, live)
    return found


def one_vip(here: Here, vip: str, held: vipstate.Held, doc: dict,
            own: str | None, own_vip: str | None, live: bool) -> list[str]:
    whose = "this node's appliance.vip" if vip == own_vip else \
        "another pair's, routed"
    found = [f"vip {vip}: {whose}"]
    if vip == own_vip:
        found.append(f"  role: {vipstate.role(doc, held, own)}")
    if held.claim is None:
        found.append("  holder: none known yet")
    else:
        found.append(f"  epoch {held.epoch}, held by {held.holder} at"
                     f" {held.claim.address}")
    if held.fenced:
        found.append("  fenced: this node lost it while cut off or away, and"
                     " takes it again only by keel vip promote here")
    if held.released:
        found.append("  released: this node let it go when asked, and waits"
                     " for the new holder's claim")
    if held.lease:
        found.append(f"  etcd lease {held.lease}")
    if not live:
        found.append("  not the live system: wg0 not read")
        return found
    carried = vipnet.carried(here.iface(), vip, here.node.output)
    to = vipnet.routed_to(here.iface(), vip, here.node.output)
    found.append("  carried here: " + {True: "yes", False: "no"}.get(
        carried, "unknown (ip did not answer)"))
    found.append(f"  routed to: {to or 'no peer'}")
    return found

