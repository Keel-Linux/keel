# Copyright (c) 2026 KeelLinux maintainers
"""The answer to `POST /v1/etcd` on the members' channel (0048)

What a member says to this node about etcd (keel.mesh.etcdmsg), on the
root side of the members' channel (keel.mesh.memberd), which has
already refused any source that is not a peer and names the peer by its
WireGuard key. A message is taken only when it names that same key as
its sender, is fresh, is for this node's mesh, and is signed by the
signing key this node's trust store holds for that member
(keel.mesh.trust): what WireGuard says is who speaks, and a message
that acts needs the member's own signature too (0048's amendment).

- `probe` changes nothing: ready for etcd, the root held, in a cluster,
  the overlay address, the PKI, an intermediate still held;
- `enroll` makes this node's key once and answers the request for its
  certificate, with the proof it is this node's (keel.mesh.etcdproof);
- `cluster` keeps the certificate a grant brings, only from this
  node's inviter or a trust root (never in place of one this node
  holds, never under another root), notes the members ready that are
  this node's peers at those addresses, and with a cluster of this mesh
  that names this node, and no other cluster held, keeps it and starts
  etcd (keel.mesh.etcd.start), as a join's new node does; never while a
  network change waits;
- `reissue` keeps a certificate the root signed for this node's own
  key, name and address in place of the one it holds, when it lasts
  longer or the held one is an intermediate's, and drops the
  intermediate (keel mesh etcd reissue); etcd reads it at its next
  handshake, with no restart;
- `crl` keeps the root's CRL when the root signed it and it is newer;
- on the root's holder: `issue`, which signs only a request shown to be
  the member's own, asked by that member or relayed by its inviter with
  the evidence of its admission (keel.mesh.etcdproof); `issue` with
  `kind: database`, the member's database leaf (keel.system.dbtls),
  signed for the address the holder's own spec gives the sender's key
  and no other; `revoke`; and `pair` (keel.mesh.etcdauth).
"""

import ipaddress
import json

from keel.mesh import (
    etcd,
    etcdauth,
    etcdca,
    etcdproof,
    protocol,
    etcdmsg,
    etcdpki,
    etcdstate,
    identity,
    trust,
)
from keel.mesh.etcd import Etcd
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, StateError
from keel.mesh.memberlink import Answer, refused
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.network.wireguard import is_key, same_key


class Refusal(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def trusted(root: str, key: str) -> trust.Member | None:
    """The member `key` as this node's trust store holds it"""
    try:
        store = trust.load(root)
    except ValueError:
        return None
    found = store.find(key)
    return None if found is None else store.members[found]


def sign_key(root: str, key: str) -> str | None:
    """The signing key this node trusts for the member `key`"""
    found = trusted(root, key)
    return None if found is None else found.sign_key


def same(held: Cluster, cluster: Cluster) -> bool:
    """The same cluster: the same formation record, for the same token"""
    return (held.token, held.record, held.signature) == (
        cluster.token, cluster.record, cluster.signature)


def checked(member: Etcd, body: bytes, key: str) -> etcdmsg.Message:
    """The message, if `key` sent it and signed it; raises Refusal"""
    try:
        message = etcdmsg.loads(body)
    except ProtocolError as e:
        raise Refusal(400, f"malformed etcd message: {e}") from None
    if not same_key(message.sender, key):
        raise Refusal(403, "the message is not the sender's")
    if not message.fresh(member.clock()):
        raise Refusal(403, "the message is stale")
    try:
        own = identity.read(member.root)
    except ValueError:
        own = None
    if own is None or message.mesh_id != own.hex():
        raise Refusal(403, "the message is for another mesh")
    signer = sign_key(member.root, key)
    if signer is None or not message.verified(signer):
        raise Refusal(403, "the message is not signed by a key this node"
                      " trusts for its sender (keel mesh sync on this node"
                      " learns its trust roots' keys)")
    return message


def answer(member: Etcd, body: bytes, key: str) -> Answer:
    """The answer to one etcd message from the peer `key`; never raises"""
    try:
        message = checked(member, body, key)
        doc = member.node.document()
        if message.kind == etcdmsg.PROBE:
            return Answer(200, etcdmsg.probe_dumps(
                etcd.ready(doc), etcdstate.root_fingerprint(member.root),
                etcdstate.cluster(member.root) is not None,
                etcd.own_address(member.node),
                etcdstate.holds_root(member.root),
                etcdstate.legacy(member.root)))
        if message.kind in (etcdmsg.ISSUE, etcdmsg.REVOKE):
            return holder(member, message)
        if message.kind == etcdmsg.PAIR:
            return paired(member, message)
        if not etcd.ready(doc):
            raise Refusal(409, "this node does not run etcd (cloud advanced"
                          " members only)")
        if message.kind == etcdmsg.ENROLL:
            csr = etcdstate.member_request(member.root)
            return Answer(200, json.dumps({
                "csr": csr, "proof": etcdproof.sign(member.root, csr)}
            ).encode())
        if message.kind == etcdmsg.REISSUE:
            return reissued(member, message)
        if message.kind == etcdmsg.CRL_KIND:
            return crl_taken(member, message)
        return taken(member, message)
    except Refusal as e:
        member.err(f"etcd: refused a message from {key}: {e.reason}")
        return refused(e.status, e.reason)
    except (StateError, NodeError, PkiError, OSError) as e:
        member.err(f"etcd: cannot answer {key}: {e}")
        return refused(503, f"this node cannot answer now: {e}")


def taken(member: Etcd, message: etcdmsg.Message) -> Answer:
    """A `cluster` message: the grant, the members ready, the cluster"""
    try:
        grant = etcdmsg.grant(message.body.get("grant"))
        cluster = etcdmsg.cluster(message.body.get("cluster"))
        members = etcdmsg.ready(message.body.get("ready"))
    except ProtocolError as e:
        raise Refusal(400, f"malformed cluster: {e}") from None
    own = etcd.own_address(member.node)
    if cluster is not None and (own not in cluster.addresses()
                                or cluster.token != message.mesh_id):
        raise Refusal(409, "the cluster does not name this node, or is"
                      " another mesh's")
    held = etcdstate.cluster(member.root)
    if cluster is not None and held is not None:
        if same(held, cluster):
            # the record this node took: started again, when it never
            # started (keel mesh etcd form sends it again)
            started = etcd.start(member)
            return Answer(200, json.dumps({"taken": True,
                                           "started": started}).encode())
        raise Refusal(409, "this node is in a cluster already: a cluster"
                      " is never replaced by a message")
    if cluster is not None and member.node.waiting():
        raise Refusal(409, "a network change waits for its confirmation"
                      " on this node; send it again once it is kept")
    if grant is not None and not etcdstate.credentials(member.root):
        sender = trusted(member.root, message.sender)
        if sender is None or not sender.root:
            raise Refusal(403, "an etcd certificate is taken only from this"
                          " node's inviter or a trust root")
        etcdstate.take_grant(member.root, grant,
                             etcd.own_address(member.node))
    elif grant is not None and etcdstate.root_fingerprint(member.root) != \
            etcdpki.fingerprint(grant.root):
        raise Refusal(409, "this node holds another root")
    if not etcdstate.credentials(member.root):
        raise Refusal(409, "this node holds no etcd certificate, and the"
                      " message brings none")
    problem = None if cluster is None else etcdca.problem(
        member.root, cluster, member.clock())
    if problem:
        raise Refusal(403, problem)
    etcdstate.add_ready(member.root, etcd.vetted(member, members))
    if cluster is None:
        return Answer(200, b'{"taken": true, "started": false}')
    etcdstate.save_cluster(member.root, cluster)
    etcdca.taken(member.root, cluster)
    started = etcd.start(member)
    member.err(f"etcd: a cluster of {len(cluster.members)} from"
               f" {message.sender}; {'started' if started else 'not started'}")
    return Answer(200, json.dumps({"taken": True,
                                   "started": started}).encode())


def reissued(member: Etcd, message: etcdmsg.Message) -> Answer:
    """A `reissue` message: this node's certificate, signed by the root,
    in place of the one it holds"""
    try:
        grant = etcdmsg.grant(message.body.get("grant"))
    except ProtocolError as e:
        raise Refusal(400, f"malformed reissue: {e}") from None
    if grant is None:
        raise Refusal(400, "the message brings no certificate")
    if not etcdstate.credentials(member.root):
        raise Refusal(409, "this node holds no etcd certificate to replace:"
                      " it joins etcd with keel mesh etcd form")
    try:
        lasts = etcdpki.not_after(grant.certificate)
    except PkiError as e:
        raise Refusal(400, str(e)) from None
    held = etcdstate.expires(member.root)
    if not etcdstate.legacy(member.root) and held is not None and \
            lasts <= held:
        raise Refusal(409, "the certificate lasts no longer than the one"
                      " this node holds")
    problem = etcdstate.checked(member.root, grant,
                                etcd.own_address(member.node))
    if problem:
        raise Refusal(403, problem)
    etcdstate.take_grant(member.root, grant, etcd.own_address(member.node))
    started = etcdstate.cluster(member.root) is not None and \
        etcd.start(member)
    member.err(f"etcd: this node's certificate signed by the root, from"
               f" {message.sender}; no intermediate held any more")
    return Answer(200, json.dumps({"taken": True,
                                   "started": started}).encode())


def crl_taken(member: Etcd, message: etcdmsg.Message) -> Answer:
    """A `crl` message: the root's CRL, kept when the root signed it and
    it is newer, and written for etcd"""
    try:
        found = etcdmsg.crl(message.body.get("crl"))
    except ProtocolError as e:
        raise Refusal(400, str(e)) from None
    kept = etcdstate.take_crl(member.root, found)
    if kept and etcdstate.cluster(member.root) is not None:
        etcd.start(member)
    return Answer(200, json.dumps({"taken": kept}).encode())


def paired(member: Etcd, message: etcdmsg.Message) -> Answer:
    """On the root's holder: a VIP's pair record from one of its
    members, and the pair's role in etcd"""
    if not etcdstate.holds_root(member.root):
        raise Refusal(409, "this node does not hold the mesh's root CA")
    try:
        roles = etcdauth.pair_roles(member, message.body.get("pair"),
                                    message.sender)
    except StateError as e:
        raise Refusal(403, str(e)) from None
    except EtcdError as e:
        raise Refusal(503, f"etcd did not take the pair's role: {e}") \
            from None
    member.err(f"etcd: the pair's role {', '.join(roles)}, asked by"
               f" {message.sender}")
    return Answer(200, json.dumps({"roles": roles}).encode())


def database_issued(member: Etcd, message: etcdmsg.Message, address: str,
                    key: str) -> Answer:
    """On the root's holder: a member's database leaf, for the address
    the holder's spec gives the sender's own key alone (its own address
    when the holder asks itself), with the VIP asked as a second SAN"""
    try:
        csr = etcdmsg.csr(message.body.get("csr"))
        vip = message.body.get("vip")
        if vip is not None:
            vip = etcdmsg.address(vip)
    except ProtocolError as e:
        raise Refusal(400, str(e)) from None
    if csr is None:
        raise Refusal(400, "no request to sign")
    if not same_key(key, message.sender):
        raise Refusal(403, "a database certificate is asked by the member"
                      " it is for, and no other")
    known = claimed(member, address)
    if known is None or not same_key(known, message.sender):
        raise Refusal(403, f"{address} is not the address this node knows"
                      f" {message.sender} by")
    if vip is not None:
        pair_bound(member, message, vip, key)
    try:
        found = etcdstate.database_grant(member.root, csr, address, vip, key)
    except StateError as e:
        raise Refusal(403, str(e)) from None
    member.err(f"etcd: a database certificate for {address} signed with"
               f" the root, asked by {message.sender}")
    return Answer(200, json.dumps({
        "grant": etcdmsg.grant_data(found)}).encode())


def pair_bound(member: Etcd, message: etcdmsg.Message, vip: str,
               key: str) -> None:
    """A VIP goes into a database certificate's SANs only on the signed
    pair record of that VIP, naming the asker, every signature by a key
    this node trusts (keel.mesh.vippair); raises Refusal"""
    from keel.mesh import signing, vippair
    found = message.body.get("pair")
    if found is None:
        raise Refusal(403, f"a certificate for the VIP {vip} needs the"
                      " pair's signed record")
    try:
        pair = vippair.loads(found)
    except ProtocolError as e:
        raise Refusal(400, f"malformed pair record: {e}") from None
    if pair.vip != vip or not pair.has(key):
        raise Refusal(403, f"the pair record is not {key}'s for {vip}")
    own = etcd.own_key(member)

    def signer_of(member_key: str) -> str | None:
        if own and same_key(member_key, own):
            return signing.public(member.root)
        return sign_key(member.root, member_key)
    try:
        store = trust.load(member.root)
        roots = {one for one, entry in store.members.items() if entry.root}
    except ValueError:
        roots = set()
    problem = vippair.problem(pair, signer_of, roots)
    if problem:
        raise Refusal(403, problem)


def holder(member: Etcd, message: etcdmsg.Message) -> Answer:
    """On the root's holder: a certificate signed by the root for a
    request shown to be the member's own (`issue`), or a removed node's
    certificates revoked, its etcd member and user removed (`revoke`)"""
    if not etcdstate.holds_root(member.root):
        raise Refusal(409, "this node does not hold the mesh's root CA")
    body = message.body
    try:
        address = etcdmsg.address(body.get("address"))
    except ProtocolError as e:
        raise Refusal(400, str(e)) from None
    own = etcd.own_address(member.node)
    if ipaddress.IPv6Address(address) not in ipaddress.IPv6Network(
            etcdstate.prefix_of(own)):
        raise Refusal(403, f"{address} is not in this mesh's prefix")
    removed = body.get("public_key")
    if not isinstance(removed, str) or not is_key(removed):
        raise Refusal(400, "no WireGuard key for the member")
    if message.kind == etcdmsg.ISSUE and body.get("kind") == "database":
        return database_issued(member, message, address, removed)
    if message.kind == etcdmsg.ISSUE:
        try:
            csr = etcdmsg.csr(body.get("csr"))
            if csr is None:
                raise Refusal(400, "no request to sign")
            request = etcdproof.Request(csr, etcdproof.proof(
                body.get("proof")))
            evidence = None if body.get("admission") is None else \
                protocol.admission(body.get("admission"))
        except ProtocolError as e:
            raise Refusal(400, str(e)) from None
        # who asks, and whether the request is the member's own
        # (keel.mesh.etcdproof): refused with why, before anything is
        # signed
        try:
            found = etcd.sign_here(member, request, address, removed,
                                   message.sender, evidence,
                                   sign_key(member.root, message.sender))
        except StateError as e:
            if "cannot be signed" in str(e) or "only the node" in str(e):
                raise
            raise Refusal(403, str(e)) from None
        member.err(f"etcd: a certificate for {address} signed with the"
                   f" root, asked by {message.sender}")
        return Answer(200, json.dumps({
            "grant": etcdmsg.grant_data(found.grant),
            "cluster": etcdmsg.cluster_data(found.cluster),
            "learner": found.learner}).encode())
    if not may_revoke(member.root, message.sender, removed):
        raise Refusal(403, "the sender may not remove that node: neither"
                      " its admitter, nor a trust root, nor the node")
    try:
        found = etcdca.revoke(member.root, address, removed, member.clock())
    except StateError as e:
        raise Refusal(404, str(e)) from None
    member.err(f"etcd: the certificates of {address} revoked, asked by"
               f" {message.sender}")
    if etcdstate.cluster(member.root) is not None:
        removed_from_etcd(member, address)
        etcd.start(member)
    return Answer(200, json.dumps({"crl": found}).encode())


def removed_from_etcd(member: Etcd, address: str) -> None:
    """On the root's holder: the removed node's etcd member and user
    gone, which etcd lets only its root user do once auth is on"""
    try:
        client = member.admin()
        for one in client.members():
            if one.address == address:
                client.remove(one.id)
                member.err(f"etcd: the member at {address} removed")
        if etcdauth.enabled(member, client) and \
                etcdstate.name(address) in client.users():
            client.user_delete(etcdstate.name(address))
            member.err(f"etcd: the user of {address} deleted")
    except EtcdError as e:
        member.err(f"etcd: the member at {address} was not removed from"
                   f" etcd ({e})")


def claimed(member: Etcd, address: str) -> str | None:
    """The WireGuard key `address` belongs to, as this node knows it:
    its own, a peer's of its spec, or the key a certificate was signed
    for at that address; None for an address nobody holds yet (a node
    an inviter is admitting)"""
    if address == etcd.own_address(member.node):
        return etcd.own_key(member)
    for one in member.node.peers(""):
        if one.address == address:
            return one.public_key
    try:
        issued = json.loads(etcdstate.read(member.root, etcdstate.ISSUED)
                            or "{}")
    except ValueError:
        issued = {}
    for one in issued.get(address, []) if isinstance(issued, dict) else []:
        if isinstance(one, list) and len(one) >= 3 and one[2]:
            return one[2]
    return None


def may_revoke(root: str, sender: str, removed: str) -> bool:
    """The amendment's rule, as this node knows it: the node itself, a
    trust root, the member whose key signed the node's admission, or the
    member that relayed the node's request to this holder (its inviter,
    giving back a join that was not confirmed)"""
    if same_key(sender, removed):
        return True
    member = trusted(root, sender)
    if member is None:
        return False
    if member.root:
        return True
    admitted = trusted(root, removed)
    if admitted is not None and admitted.admission is not None and \
            admitted.admission.by == member.sign_key:
        return True
    return any(len(one) >= 6 and one[2] == removed and one[5] is not None
               and same_key(one[5], sender)
               for entries in etcdstate.issued(root).values()
               for one in entries)
