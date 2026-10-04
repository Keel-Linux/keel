# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh etcd form: etcd on a mesh that never saw a third join

A mesh that already has three or more nodes (built with keel 0.18, or
by hand and adopted) never sees the third join that forms etcd, so the
operator forms it with one command (0048, third round, point 3), on the
node that holds the mesh's root CA: only that node forms the cluster,
and once (keel.mesh.etcdca). It is built to be safe on such a mesh,
which has no CA yet:

1. it asks every peer first, over the members' channel (`probe`, which
   changes nothing on them): whether it can run etcd, which root it
   holds and whether it holds the root's key, whether it is in a
   cluster. It refuses while a network change waits here, when members
   hold two different roots, when another node holds the root, or when
   this node cannot run etcd; with `--dry-run` it stops there and prints
   what it would do;
2. when no member holds a root it makes the mesh's root CA here, so the
   operator runs it on a trust root; it enrolls every ready member that
   holds no intermediate (`enroll`: its request, signed with the root).
   Any failure here stops it before anything is started anywhere;
3. at three ready members or more it picks them, signs the formation
   record with the root, reserves the formation, sends each the cluster
   with its record (`cluster`), and starts its own; with fewer, the
   members keep their intermediates and etcd forms later.

On a cluster that exists it brings in what is missing: a ready member
that is not in etcd is added as a learner and sent the cluster
(`existing`, the same record), and a member of the first cluster that
never started is sent it again. So a run that stopped part way is run
again, and the fallback's join, whose line carries no request, comes in
the same way (keel.mesh.inviting). Every message is signed with this
node's key (keel.mesh.etcdmsg).
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from keel import exits
from keel.mesh import etcd, etcdca, etcdmsg, etcdstate, identity
from keel.mesh.etcd import QUORUM_AT, Etcd
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdmsg import Probe
from keel.mesh.etcdstate import Cluster, Grant, Member, StateError
from keel.mesh.memberlink import LinkError
from keel.mesh.node import NodeError
from keel.mesh.protocol import Peer, ProtocolError
from keel.mesh.signing import SigningError

PARALLEL = 8


class Refused(Exception):
    """The form is refused, and why"""


said = etcd.said


def send_cluster(etcd_: Etcd, member: Member, cluster: Cluster | None,
                 grant: Grant | None = None) -> str | None:
    """The cluster (and a grant) sent to `member`; None, or why not"""
    body = {"grant": etcdmsg.grant_data(grant),
            "cluster": etcdmsg.cluster_data(cluster),
            "ready": etcd.known_ready(etcd_)}
    try:
        said(etcd_, etcdmsg.CLUSTER, member.address, body)
    except (LinkError, SigningError, ValueError) as e:
        return str(e)
    return None


def probed(etcd_: Etcd, peers: tuple[Peer, ...]) -> dict[str, Probe | str]:
    """Each peer's probe, asked at once, or why it gave none"""
    def one(peer: Peer) -> Probe | str:
        try:
            found = etcdmsg.probe_answer(said(etcd_, etcdmsg.PROBE,
                                              peer.address, {}))
        except (LinkError, ProtocolError, SigningError, ValueError) as e:
            return str(e)
        if found.address != peer.address:
            return f"it answers as {found.address}"
        return found
    if not peers:
        return {}
    with ThreadPoolExecutor(min(PARALLEL, len(peers))) as pool:
        return dict(zip((one.public_key for one in peers),
                        pool.map(one, peers)))


def enrolled(etcd_: Etcd, peer: Peer) -> Grant:
    """`peer`'s intermediate, from its request; raises Refused"""
    try:
        csr = etcdmsg.enroll_answer(said(etcd_, etcdmsg.ENROLL,
                                         peer.address, {}))
        return etcdstate.grant_for(etcd_.root, csr, peer.address,
                                   peer.public_key)
    except (LinkError, ProtocolError, SigningError, StateError,
            ValueError) as e:
        raise Refused(f"member {peer.address} was not enrolled: {e};"
                      " nothing was started") from None


def form(etcd_: Etcd, dry_run: bool, out: Callable[[str], None]) -> int:
    """`keel mesh etcd form`"""
    try:
        return formed(etcd_, dry_run, out)
    except Refused as e:
        etcd_.err(str(e))
        return exits.MESH_REFUSED
    except (StateError, NodeError, SigningError, EtcdError) as e:
        etcd_.err(f"etcd: {e}")
        return exits.APPLY_FAILED


def formed(etcd_: Etcd, dry_run: bool, out: Callable[[str], None]) -> int:
    node = etcd_.node
    if not etcd.ready(node.document()):
        raise Refused("this node does not run etcd: it needs"
                      " installation.mode cloud_advanced and the etcd"
                      " overlay in its appliance")
    try:
        mesh = identity.read(etcd_.root)
    except ValueError as e:
        raise Refused(str(e)) from None
    if mesh is None:
        raise Refused("this node holds no mesh identity: keel mesh create"
                      " --adopt on one node of a mesh built by hand, keel"
                      " mesh sync --adopt on the others")
    if node.waiting():
        raise Refused("a network change waits for its confirmation on this"
                      " node: confirm or revert it, then form")
    own = etcd.own_key(etcd_)
    peers = node.peers(own or "")
    probes = probed(etcd_, peers)
    answered, ready = [], []
    for peer in peers:
        found = probes[peer.public_key]
        if isinstance(found, str):
            etcd_.err(f"member {peer.address} did not answer ({found}); it"
                      " is left out, and a later form brings it in")
            continue
        answered.append((peer, found))
        if found.ready:
            ready.append((peer, found))
        else:
            etcd_.err(f"member {peer.address} does not run etcd (not cloud"
                      " advanced)")
    roots = {found.root for _, found in answered if found.root}
    held = etcdstate.root_fingerprint(etcd_.root)
    if held:
        roots.add(held)
    if len(roots) > 1:
        raise Refused("the members hold different etcd roots: one mesh has"
                      " one; nothing was changed")
    if roots and not etcdstate.holds_root(etcd_.root):
        holders = [peer.address for peer, found in answered if found.holder]
        at = holders[0] if holders else (etcdstate.holder(etcd_.root)
                                         or "the node that made it")
        raise Refused(f"only the node that holds the mesh's root CA forms"
                      f" etcd: run keel mesh etcd form on {at}")
    if etcdstate.cluster(etcd_.root) is not None:
        return extend(etcd_, ready, dry_run, out)
    others = [peer.address for peer, found in answered if found.formed]
    if others:
        raise Refused(f"members are in a cluster this node has no record"
                      f" of ({', '.join(others)}); nothing was changed")
    return new(etcd_, mesh.hex(), ready, not roots, dry_run, out)


def new(etcd_: Etcd, mesh: str, ready: list[tuple[Peer, Probe]],
        make_root: bool, dry_run: bool, out: Callable[[str], None]) -> int:
    count = len(ready) + 1
    lacking = [peer for peer, found in ready if not found.root]
    plan = []
    if make_root:
        plan.append("make the mesh's root CA on this node (run it on a"
                    " trust root: the root's key stays where it is made)")
    plan += [f"enroll {peer.address}" for peer in lacking]
    if count > etcd.MAX_FORMED:
        raise Refused(f"{count} ready members: a cluster starts with at most"
                      f" {etcd.MAX_FORMED}")
    if count >= QUORUM_AT:
        plan.append(f"form a cluster of {count}: this node and "
                    + ", ".join(peer.address for peer, _ in ready))
    else:
        plan.append(f"not form: {count} of {QUORUM_AT} ready members")
    if dry_run:
        for line in plan:
            out(f"would {line}")
        out("dry run: nothing was changed on any member")
        return exits.OK
    address = etcd.own_address(etcd_.node)
    if make_root:
        etcdstate.make_root(etcd_.root, mesh, address)
        etcd_.err("etcd: this node now holds the mesh's root CA")
    grants = {peer.public_key: enrolled(etcd_, peer) for peer in lacking}
    members = {**etcd.known_ready(etcd_),
               **{peer.public_key: peer.address for peer, _ in ready}}
    etcdstate.add_ready(etcd_.root, members)
    cluster = None
    if count >= QUORUM_AT:
        chosen = [address] + [peer.address for peer, _ in ready]
        cluster = etcdca.record(etcd_.root, tuple(
            Member(key, at) for key, at in members.items() if at in chosen),
            mesh, etcd_.clock())
        if not etcdca.reserve(etcd_.root, cluster):
            raise Refused("a formation is under way on this node already (a"
                          " join forming the cluster); run it again once"
                          " that join is done")
    missed = []
    for peer, _ in ready:
        problem = send_cluster(etcd_, Member(peer.public_key, peer.address),
                               cluster, grants.get(peer.public_key))
        if problem:
            missed.append(f"{peer.address} ({problem})")
    if cluster is None:
        out(f"etcd: {count} of {QUORUM_AT} ready members hold their CA;"
            " etcd forms at the third")
        return finished(etcd_, missed)
    etcdstate.save_cluster(etcd_.root, cluster)
    started = etcd.start(etcd_)
    out(f"etcd: a cluster of {count} formed from this node"
        f"{'' if started else ', which did not start here'}; keel mesh"
        " status shows its leader once a majority runs")
    return finished(etcd_, missed)


def finished(etcd_: Etcd, missed: list[str]) -> int:
    if missed:
        etcd_.err(f"etcd: not reached: {'; '.join(missed)}; run keel mesh"
                  " etcd form again once they answer")
        return exits.MESH_REFUSED
    return exits.OK


def extend(etcd_: Etcd, ready: list[tuple[Peer, Probe]], dry_run: bool,
           out: Callable[[str], None]) -> int:
    """On the root's holder, in a cluster: the ready members it lacks"""
    client = etcd_.local()
    listed = {one.address: one for one in client.members()}
    held = etcdstate.cluster(etcd_.root)
    late = [peer for peer, _ in ready if peer.address in listed
            and not listed[peer.address].started and held.state == "new"
            and peer.address in held.addresses()]
    missing = [(peer, found) for peer, found in ready
               if peer.address not in listed]
    if not late and not missing:
        out("etcd: every ready member is in the cluster")
        return exits.OK
    if dry_run:
        for peer in late:
            out(f"would send the first cluster again to {peer.address}")
        for peer, _ in missing:
            out(f"would add {peer.address} as a learner")
        out("dry run: nothing was changed on any member")
        return exits.OK
    missed = []
    again = held
    if late and etcdca.expired(held, etcd_.clock()):
        # a member that never received the first record: the same
        # members, signed again, at a newer epoch
        again = etcdca.record(etcd_.root, held.members, held.token,
                              etcd_.clock())
    for peer in late:
        problem = send_cluster(etcd_, Member(peer.public_key, peer.address),
                               again)
        if problem:
            missed.append(f"{peer.address} ({problem})")
    for peer, found in missing:
        grant = None if found.root else enrolled(etcd_, peer)
        etcdstate.add_ready(etcd_.root, {peer.public_key: peer.address})
        cluster, _ = etcd.holder_adds(etcd_, peer.address, peer.public_key,
                                      held)
        problem = send_cluster(etcd_, Member(peer.public_key, peer.address),
                               cluster, grant)
        if problem:
            missed.append(f"{peer.address} ({problem})")
    out("etcd: the cluster brought in what it lacked; keel-mesh-etcd.timer"
        " promotes each learner once it is in sync")
    return finished(etcd_, missed)
