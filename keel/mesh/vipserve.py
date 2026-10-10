# Copyright (c) 2026 KeelLinux maintainers
"""The answer to `POST /v1/vip` on the members' channel (decision 0049)

On the root side of the members' channel (keel.mesh.memberd), which
has already refused any source that is not a peer and names the peer
by its WireGuard key. A message is taken only when it names that same
key as its sender, is for this node's mesh, and is signed by the
signing key this node's trust store holds for that member, as an etcd
message is (keel.mesh.etcdserve); then:

- `epoch` answers the newest claim this node took of the VIP, which
  the asker checks itself; it changes nothing;
- `claim` is taken when it is newer (keel.mesh.vipnode.take), from
  the holder's own overlay address; a stale one is refused with 409
  and the epoch this node knows;
- `release` is taken only by a node whose own spec declares that VIP,
  from the other member its pair record names, fresh, for an epoch
  newer than any this node knows: it turns its database read only
  when it declares one (the commits in flight end first, keel#138),
  drops the address, then answers;
- `pair` is the other member's pair record (keel.mesh.vippair), signed
  here too when this node's spec declares that VIP, and kept;
- `secret` is answered with a secret the pair shares, only to the other
  member of the pair record, fresh (keel.system.dbsecret); 404 while
  this node holds none, and the asker tries again later.

Nothing here applies a change under 0018's window, and nothing waits
but a release on a database: each answer is the time of an `ip` or a
`wg set`, and a release also waits for SET GLOBAL read_only = ON (up to
dbreadonly.QUIESCE_TIMEOUT).
"""

import json

from keel.mesh import etcdserve, signing, vipmsg, vipnode, vippair
from keel.mesh import vip as vipstate
from keel.mesh.memberlink import Answer, refused
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError
from keel.mesh.vipnode import Here, VipError
from keel.network.wireguard import same_key

Refusal = etcdserve.Refusal


def checked(here: Here, body: bytes, key: str) -> vipmsg.Message:
    """The message, if `key` sent it and signed it; raises Refusal"""
    try:
        message = vipmsg.loads(body)
    except ProtocolError as e:
        raise Refusal(400, f"malformed VIP message: {e}") from None
    if not same_key(message.sender, key):
        raise Refusal(403, "the message is not the sender's")
    try:
        mesh = here.mesh_id()
    except VipError:
        mesh = None
    if message.mesh_id != mesh:
        raise Refusal(403, "the message is for another mesh")
    signer = etcdserve.sign_key(here.root, key)
    if signer is None or not message.verified(signer):
        raise Refusal(403, "the message is not signed by a key this node"
                      " trusts for its sender")
    return message


def answer(here: Here, body: bytes, key: str) -> Answer:
    """The answer to one VIP message from the peer `key`; never raises"""
    try:
        message = checked(here, body, key)
        if message.kind == vipmsg.EPOCH:
            held = vipnode.current(here, message.vip())
            return Answer(200, vipmsg.epoch_answer(held.claim))
        if message.kind == vipmsg.CLAIM:
            return claimed(here, body)
        if message.kind == vipmsg.PAIR:
            return countersigned(here, message)
        if message.kind == vipmsg.SECRET:
            return shared(here, message)
        return released(here, message)
    except ProtocolError as e:
        here.err(f"vip: refused a message from {key}: {e}")
        return refused(400, str(e))
    except Refusal as e:
        here.err(f"vip: refused a message from {key}: {e.reason}")
        return refused(e.status, e.reason)
    except (VipError, NodeError, OSError) as e:
        here.err(f"vip: cannot answer {key}: {e}")
        return refused(503, f"this node cannot answer now: {e}")


def claimed(here: Here, body: bytes) -> Answer:
    claim = vipmsg.claim_of(body)
    problem = vipnode.verified(here, claim)
    if problem:
        raise Refusal(403, problem)
    if vipnode.take(here, claim):
        return Answer(200, json.dumps({"applied": True,
                                       "epoch": claim.epoch}).encode())
    held = vipnode.current(here, claim.vip)
    if held.claim is not None and held.claim.raw == claim.raw:
        return Answer(200, json.dumps({"applied": False,
                                       "epoch": held.epoch}).encode())
    raise Refusal(409, f"stale claim: epoch {claim.epoch}, and this node"
                  f" knows epoch {held.epoch} held by {held.holder}")


def countersigned(here: Here, message: vipmsg.Message) -> Answer:
    """The pair record from the other member: signed here too when this
    node's spec declares that VIP and the record names both, and kept"""
    if not message.fresh(here.clock()):
        raise Refusal(403, "the message is stale")
    pair = vippair.loads(message.body.get("pair"))
    own = here.own_key()
    try:
        declared = vipstate.declared(here.node.document())
    except ValueError:
        declared = None
    if declared != pair.vip or not pair.has(own) or \
            not pair.has(message.sender):
        raise Refusal(403, f"this node's appliance.vip is {declared}, and"
                      " a pair record is signed only for that VIP, by the"
                      " two nodes it names")
    sender = vipnode.signer_of(here)(message.sender)
    theirs = next((sig for key, sig in pair.signatures
                   if same_key(key, message.sender)), None)
    if not sender or theirs is None or not signing.verified(
            sender, pair.message(), theirs):
        raise Refusal(403, "the pair record is not signed by its sender")
    problem = vipnode.new_pair_problem(here, pair) or reserved(here, pair)
    if problem:
        raise Refusal(409, problem)
    try:
        both = vippair.sign(here.root, pair, own)
    except SigningError as e:
        raise Refusal(503, str(e)) from None
    problem = vipnode.record_problem(here, both)
    if problem:
        raise Refusal(409, problem)
    vippair.write(here.root, both)
    here.err(f"vip {pair.vip}: paired with {message.sender}")
    return Answer(200, json.dumps({"pair": both.dumps()}).encode())


def reserved(here: Here, pair: vippair.Pair) -> str | None:
    """With etcd, why the pair's VIP is not reserved for it there, or
    None (keel.mesh.vipreserve); None before etcd"""
    from keel.mesh import vipetcd, vippromote, vipreserve
    from keel.mesh.etcdclient import EtcdError
    if not vippromote.with_etcd(here):
        return None
    try:
        client = vipetcd.local(here)
    except EtcdError as e:
        return f"etcd cannot be asked ({e})"
    return vipreserve.held_for(client, pair, vipnode.signer_of(here))


def of_the_pair(here: Here, message: vipmsg.Message, what: str) -> str:
    """The VIP of a fresh message from the other member of this node's
    pair; raises Refusal for anything else"""
    vip = message.vip()
    if not message.fresh(here.clock()):
        raise Refusal(403, "the message is stale")
    try:
        own = vipstate.declared(here.node.document())
    except ValueError:
        own = None
    if own != vip:
        raise Refusal(403, f"{vip} is not this node's appliance.vip: only"
                      f" the nodes of the pair {what}")
    pair = vipnode.kept(here, vip)
    if not pair.has(here.own_key()) or not pair.has(message.sender):
        raise Refusal(403, f"{message.sender} is not the other member of"
                      f" the pair of {vip}: only the pair's nodes {what}")
    return vip


def shared(here: Here, message: vipmsg.Message) -> Answer:
    """A secret the pair shares, to the other member alone"""
    from keel.system import dbsecret
    vip = of_the_pair(here, message, "ask a shared secret")
    name = message.body.get("name")
    if name not in vipmsg.SECRET_NAMES:
        raise Refusal(400, f"no shared secret is named {name!r}")
    value = dbsecret.read(here.root)
    if value is None:
        raise Refusal(404, f"this node holds no {name} secret yet: the"
                      " pair's primary makes it at its first apply")
    here.err(f"vip {vip}: the {name} secret given to {message.sender}")
    return Answer(200, json.dumps({"value": value}).encode())


def released(here: Here, message: vipmsg.Message) -> Answer:
    vip = of_the_pair(here, message, "release it")
    epoch = message.epoch()
    held = vipnode.current(here, vip)
    if epoch <= held.epoch:
        raise Refusal(409, f"stale release: epoch {epoch}, and this node"
                      f" knows epoch {held.epoch}")

    def revoke(lease: str) -> None:
        here.local().revoke(lease)
    quiesced(here, vip)
    vipnode.release(here, vip, revoke)
    return Answer(200, b'{"released": true}')


def quiesced(here: Here, vip: str) -> None:
    """The database of a node that declares one made read only before
    the VIP goes (keel#138): the commits in flight end first, their
    clients get the answer while the address is still here, and no new
    write is taken. A failure is logged and the release goes on: the
    database follows the VIP's state after, as before"""
    try:
        doc = here.node.document()
    except NodeError:
        return
    if not (doc.get("database") or {}).get("server"):
        return
    from keel.system import dbreadonly
    problem = dbreadonly.quiesce()
    if problem:
        here.err(f"vip {vip}: the database could not be made read only"
                 f" first ({problem}); the release goes on")
        return
    here.err(f"vip {vip}: the database is read only before the release")
