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
  from the other node of the pair, fresh, for an epoch newer than any
  this node knows: it drops the address, then answers.

Nothing here applies a change under 0018's window, and nothing waits:
each answer is the time of an `ip` or a `wg set`.
"""

import json

from keel.mesh import etcdserve, vipmsg, vipnode
from keel.mesh import vip as vipstate
from keel.mesh.memberlink import Answer, refused
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
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


def released(here: Here, message: vipmsg.Message) -> Answer:
    vip = message.vip()
    epoch = message.epoch()
    if not message.fresh(here.clock()):
        raise Refusal(403, "the message is stale")
    try:
        own = vipstate.declared(here.node.document())
    except ValueError:
        own = None
    if own != vip:
        raise Refusal(403, f"{vip} is not this node's appliance.vip: only"
                      " the nodes of the pair release it")
    held = vipnode.current(here, vip)
    if epoch <= held.epoch:
        raise Refusal(409, f"stale release: epoch {epoch}, and this node"
                      f" knows epoch {held.epoch}")

    def revoke(lease: str) -> None:
        here.local().revoke(lease)
    vipnode.release(here, vip, revoke)
    return Answer(200, b'{"released": true}')
