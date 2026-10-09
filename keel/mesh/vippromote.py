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

import json
from collections.abc import Callable
from datetime import datetime

from keel import exits
from keel.mesh import etcd, etcdstate, signing, vipetcd, vipmsg, vipnet
from keel.mesh import vipnode, vippair, vipreserve
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import EtcdError
from keel.mesh.memberlink import LinkError
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.mesh.vip import Claim
from keel.mesh.vipnode import Here, VipError
from keel.network.wireguard import same_key

# a promote asks this member's etcd with keel's usual timeout (10 s), not
# the controller's short one: a member just back from a partition answers
# once it caught up, and an operator's command can wait for it. On a link
# of 250 ms with 2% loss, that took more than 20 s (keel#94): the first
# read is tried again until CATCH_UP
CATCH_UP = 60.0
# how long a promote with etcd waits for the controller to carry the VIP
CARRY_WAIT = 15.0
# how long it waits for the old holder's key to go: a lease revoked by a
# release goes at once; one left to expire goes within its TTL, which a
# leader change extends by an election timeout
GONE_WAIT = vipetcd.TTL + 20.0
POLL = 0.5
ACCEPTED = ("applied", "known")


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
        problem = vipstate.problem(vip, here.overlay(),
                                   vippair.kept_vips(here.root))
        if problem:
            out(problem)
            return exits.MESH_REFUSED
        if with_etcd(here):
            return promoted_etcd(here, vip, gone, out)
        return promoted(here, vip, gone, out)
    except (VipError, NodeError, ValueError, SigningError) as e:
        out(f"keel vip promote: {e}")
        return exits.APPLY_FAILED


def pair(here: Here, at: str, out: Callable[[str], None]) -> int:
    """`keel vip pair ADDRESS`: the pair record of this node's VIP with
    the peer at ADDRESS, signed by both and kept by both"""
    try:
        vip = vipstate.declared(here.node.document())
        if vip is None:
            out("this node declares no appliance.vip: there is no pair to"
                " record")
            return exits.MESH_REFUSED
        peer = next((one.public_key for one in here.node.peers("")
                     if one.address == at), None)
        if peer is None:
            out(f"{at} is no peer of this node")
            return exits.MESH_REFUSED
        own = here.own_key()
        draft = vippair.made(here.mesh_id(), vip, (own, peer))
        problem = vipnode.new_pair_problem(here, draft)
        if problem:
            out(problem)
            return exits.MESH_REFUSED
        etcd_mode = with_etcd(here)
        if etcd_mode:
            # the VIP is one pair's across the mesh: reserved by a
            # compare-and-swap before the other member is asked to sign
            problem = vipreserve.reserve(
                vipetcd.local(here), draft, own, signer(here),
                vipnode.signer_of(here))
            if problem:
                out(problem)
                return exits.MESH_REFUSED
        mine = vippair.sign(here.root, draft, own)
        answer = here.say(vipmsg.PAIR, at, {"pair": mine.dumps()})
        both = vippair.loads(json.loads(answer.decode()).get("pair"))
        if both.record() != draft.record():
            raise VipError("the peer answered another pair record")
        problem = vipnode.record_problem(here, both)
        if problem:
            raise VipError(problem)
        vippair.write(here.root, both)
    except (LinkError, VipError, NodeError, ValueError, SigningError,
            ProtocolError) as e:
        out(f"keel vip pair: {e}")
        return exits.MESH_REFUSED
    out(f"{vip} is the VIP of {own} and {peer}, signed by both")
    if not etcd_mode:
        return exits.OK
    return paired_in_etcd(here, both, own, out)


def signer(here: Here) -> Callable[[bytes], str]:
    return lambda message: signing.sign(here.root, message)


def paired_in_etcd(here: Here, both: vippair.Pair, own: str,
                   out: Callable[[str], None]) -> int:
    """With etcd, once both members signed: the reservation kept for
    good, and the pair's role asked of the root's holder"""
    try:
        problem = vipreserve.kept(vipetcd.local(here), both, own,
                                  signer(here), vipnode.signer_of(here))
    except (EtcdError, SigningError) as e:
        problem = str(e)
    if problem:
        out(f"the reservation of {both.vip} in etcd is not kept for good"
            f" ({problem}): it ends {vipreserve.TTL // 3600} h after it"
            " was made. Run keel vip pair again: it finds this pair's"
            " reservation and keeps it")
        return exits.APPLY_FAILED
    # the pair's two members alone may write its keys in etcd: the
    # root's holder grants the role (keel.mesh.etcdauth)
    from keel.mesh import etcdauth
    for line in etcdauth.announce(etcd.Etcd(here.node, here.clock,
                                            here.err)):
        out(line)
    return exits.OK


def unpair(here: Here, text: str, out: Callable[[str], None]) -> int:
    """`keel vip unpair VIP`: this pair's reservation of a VIP no longer
    used released in etcd, so another pair may reserve it"""
    try:
        vip = vipstate.address(text)
        if vipstate.declared(here.node.document()) == vip:
            out(f"this node's appliance.vip is {vip}: remove it from the"
                " spec of both members and apply, then release it")
            return exits.MESH_REFUSED
        if not with_etcd(here):
            out("this node is in no formed etcd cluster: nothing is"
                " reserved, so nothing is released")
            return exits.OK
        problem = vipreserve.release(vipetcd.local(here), here.mesh_id(),
                                     vip, here.own_key(),
                                     vipnode.signer_of(here))
    except EtcdError as e:
        out(f"etcd did not answer: {e}")
        return exits.APPLY_FAILED
    except (VipError, NodeError, ValueError, SigningError) as e:
        out(f"keel vip unpair: {e}")
        return exits.MESH_REFUSED
    if problem:
        out(problem)
        return exits.MESH_REFUSED
    out(f"{vip}: its reservation in etcd is released. Each node keeps"
        " the pair record it holds")
    return exits.OK


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
    vipnode.hold(here, made, False)
    said = told(here, made, out)
    accepted = sum(1 for what in said.values() if what in ACCEPTED)
    answered = accepted + sum(1 for what in said.values()
                              if what.startswith("refused"))
    # a majority of the peers that answered refusing it, or none
    # answering, is no acceptance; with --old-primary-gone, none answering
    # is what the operator said (in a two-node mesh, the only peer is the
    # one that is gone), and the flag is the acceptance
    if (answered and accepted * 2 <= answered) or (not answered and
                                                   not gone):
        vipnode.release(here, vip, lambda lease: None)
        out(f"the claim at epoch {epoch} was taken by {accepted} of the"
            f" {answered} peer(s) that answered: not a majority, so this"
            f" node does not carry {vip}. Nothing routes it here but the"
            " peers that took it; keel vip status on them says which")
        return exits.MESH_REFUSED
    if not vipnode.carry_held(here, vip):
        out(f"the VIP could not be added to {here.iface()}")
        return exits.APPLY_FAILED
    out(f"this node holds {vip} at epoch {epoch}, on {here.iface()},"
        f" taken by {accepted} of {answered} peer(s)")
    return exits.OK


def told(here: Here, made: Claim,
         out: Callable[[str], None]) -> dict[str, str]:
    said = vipnode.announce(here, made)
    for at, what in sorted(said.items()):
        out(f"  {at}: {what}")
    missed = [at for at, what in said.items() if what not in ACCEPTED]
    if missed:
        out(f"{len(missed)} peer(s) did not take the claim now; each takes"
            " it at its next keel vip check, and routes the VIP to the old"
            " primary until then")
    return said


def current_claim(here: Here, vip: str,
                  now: vipetcd.Seen) -> Claim | None:
    """The newest claim this node knows: its own record, or the
    counter's when that one is newer and verified here"""
    held = vipnode.current(here, vip).claim
    found = now.epoch
    if found is not None and (held is None or found.epoch > held.epoch) \
            and vipnode.verified(here, found) is None:
        return found
    return held


def gone_lease(here: Here, vip: str, lease: str | None,
               wait: float) -> vipetcd.Seen | None:
    """The VIP's keys once `lease` is gone, or once this node's own
    controller claimed meanwhile, waited for; None when it lives on"""
    own = here.own_key()
    deadline = here.monotonic() + wait
    while True:
        try:
            client = here.local()
            now = vipetcd.seen(client, here.mesh_id(),
                               here.err).get(vip) or vipetcd.Seen(vip)
            if now.epoch is not None and same_key(now.epoch.holder, own):
                return now
            if lease is None or client.time_to_live(lease) <= 0:
                return now
        except EtcdError:
            pass
        if here.monotonic() >= deadline:
            return None
        here.sleep(POLL)


def caught_up(here: Here, vip: str,
              out: Callable[[str], None]) -> vipetcd.Seen:
    """The VIP's keys, read from this member's etcd, asked again until
    CATCH_UP: a member back from a partition answers once it caught up
    with the leader. Raises the last EtcdError"""
    deadline = here.monotonic() + CATCH_UP
    told_once = False
    while True:
        try:
            return vipetcd.seen(here.local(), here.mesh_id(),
                                here.err).get(vip) or vipetcd.Seen(vip)
        except EtcdError as e:
            if here.monotonic() >= deadline:
                raise
            if not told_once:
                out(f"etcd did not answer yet ({e}): waiting for this"
                    f" member's etcd to catch up (at most {CATCH_UP:g} s)…")
                told_once = True
        here.sleep(POLL)


def promoted_etcd(here: Here, vip: str, gone: bool,
                  out: Callable[[str], None]) -> int:
    """With etcd: release, compare-and-swap, the controller carries"""
    own = here.own_key()
    try:
        now = caught_up(here, vip, out)
    except EtcdError as e:
        out(f"etcd did not answer: {e}. With etcd, the VIP moves only"
            " through it")
        return exits.APPLY_FAILED
    holder = current_claim(here, vip, now)
    if holder is not None and same_key(holder.holder, own) and \
            vipnode.current(here, vip).holds(own):
        out(f"this node holds {vip} already, at epoch {holder.epoch}")
        return exits.OK
    if holder is not None and not same_key(holder.holder, own):
        epoch = max(now.epoch.epoch if now.epoch else 0, holder.epoch) + 1
        if not released(here, vip, holder, epoch, gone, out):
            return exits.MESH_REFUSED
        out("waiting for the primary's lease to go"
            f" (at most {GONE_WAIT:g} s)…")
        now = gone_lease(here, vip, holder.lease, GONE_WAIT)
        if now is None:
            out("the primary's lease is still alive: nothing was claimed."
                " keel never revokes another node's lease")
            return exits.MESH_REFUSED
        if now.epoch is not None and same_key(now.epoch.holder, own):
            return raced(here, vip, own, out)
    try:
        made = vipetcd.claim(
            here.local(), here.mesh_id(), vip, now,
            vipnode.current(here, vip).epoch,
            lambda which, epoch, lease: vipnode.signed_claim(
                here, which, epoch, lease), here.monotonic)
    except EtcdError as e:
        out(f"etcd did not take the claim: {e}")
        return exits.APPLY_FAILED
    if made is None:
        return raced(here, vip, own, out)
    vipnode.hold(here, made[0], False, made[1])
    out(f"this node holds {vip} at epoch {made[0].epoch}, by etcd's lease"
        f" {made[1]}")
    if not carried_soon(here, vip):
        out(f"keel-vip.service did not add {vip} to {here.iface()} within"
            f" {CARRY_WAIT:g} s: is it running? Its lease expires"
            f" {vipetcd.TTL} s after its last renewal")
        return exits.APPLY_FAILED
    told(here, made[0], out)
    return exits.OK


def raced(here: Here, vip: str, own: str,
          out: Callable[[str], None]) -> int:
    """The compare-and-swap lost: to this node's own controller, or to
    another node"""
    try:
        now = vipetcd.seen(here.local(), here.mesh_id(),
                           here.err).get(vip)
    except EtcdError as e:
        out(f"etcd did not answer: {e}")
        return exits.APPLY_FAILED
    if now is None or now.epoch is None or \
            not same_key(now.epoch.holder, own):
        out("another claim came first: nothing was claimed here; keel vip"
            " status says who holds it")
        return exits.MESH_REFUSED
    out(f"this node holds {vip} at epoch {now.epoch.epoch}, claimed by its"
        " controller")
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

