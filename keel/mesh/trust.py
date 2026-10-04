# Copyright (c) 2026 KeelLinux maintainers
"""Who may vouch for a member: admission evidence and the trust store

0048 lets only an admitted join add a peer. A node that a member
admits gets a long-term signing key (keel.mesh.signing), and the member
signs evidence of the admission (protocol.Admission): the mesh's
identity, the invite, the node's WireGuard and signing keys, its
overlay address and endpoint, and the time. The new node learns the
inviter's signing key and its own admission in the join's answer,
which the invite's HMAC authenticates.

A roster entry is taken (keel.mesh.sync) only when its admission was
signed by a key this node already trusts: its own, the inviter it
joined through, a member admitted the same way, or a trust root. The
signer of an entry it takes is trusted in turn, so evidence chains from
member to member; an entry without valid evidence is left out. A mesh
built by hand before `keel mesh` has no evidence: `keel mesh create
--adopt` and `keel mesh sync --adopt`, explicit acts of the operator,
make the peers the spec lists trust roots. A root's signing key is
learned from the root itself, in a roster this node fetched from the
root's own overlay address, which WireGuard authenticates; never from
an announcement. Evidence always names an invite: no member, root or
not, vouches for a node it did not admit.

A removed key leaves a tombstone (protocol.Removal), signed by the
remover's key. A node takes a tombstone only from a key that may remove
that node: the admitting member's, a trust root's, or the node's own;
it then drops the key from its spec (keel.mesh.sync) and never takes it
again. Tombstones are kept for good, at most MAX_REMOVED of them and
MAX_REMOVED_PER_SIGNER from one signer, and every roster carries them
all.

State, under /var/lib/keel/mesh/trust.json, 0600, as the invites are.
"""

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime

from keel.mesh import DIR, invites, protocol, signing
from keel.mesh.protocol import Admission, Peer, ProtocolError, Removal
from keel.network.marker import path, write_private
from keel.network.wireguard import same_key

TRUST = f"{DIR}/trust.json"
# tombstones are kept for good (a removed key never comes back), and
# every roster carries them all: the cap bounds both, per signer too
MAX_REMOVED = 1024
MAX_REMOVED_PER_SIGNER = 64


@dataclass
class Member:
    """A member this node trusts: its signing key once known, whether
    the operator made it a root, and the evidence it was admitted by"""

    sign_key: str | None
    root: bool = False
    admission: Admission | None = None


@dataclass
class Store:
    members: dict[str, Member] = field(default_factory=dict)
    removed: dict[str, Removal] = field(default_factory=dict)

    def find(self, key: str) -> str | None:
        """The store's spelling of `key`, None when it has none"""
        return next((one for one in self.members if same_key(one, key)),
                    None)

    def gone(self, key: str) -> bool:
        return any(same_key(one, key) for one in self.removed)

    def signers(self, own: str) -> set[str]:
        return {own} | {one.sign_key for one in self.members.values()
                        if one.sign_key}

    def evidence(self, key: str) -> Admission | None:
        found = self.find(key)
        return None if found is None else self.members[found].admission


def load(root: str) -> Store:
    """The store; empty when there is none, ValueError when damaged"""
    try:
        with open(path(root, TRUST)) as fob:
            data = json.load(fob)
        members = {
            str(key): Member(
                one["sign_key"], bool(one["root"]),
                None if one["admission"] is None
                else protocol.admission(one["admission"]))
            for key, one in data["members"].items()}
        removed = {str(key): protocol.removal(one)
                   for key, one in data["removed"].items()}
    except FileNotFoundError:
        return Store()
    except (ValueError, KeyError, TypeError, AttributeError,
            ProtocolError):
        raise ValueError(f"/{TRUST} is damaged: keel does not guess whom"
                         " this node trusts; keel mesh sync --adopt makes"
                         " its peers trust roots again") from None
    return Store(members, removed)


def save(root: str, store: Store) -> None:
    invites.ensure(root)
    data = {"members": {key: {"sign_key": one.sign_key, "root": one.root,
                              "admission": None if one.admission is None
                              else asdict(one.admission)}
                        for key, one in store.members.items()},
            "removed": {key: asdict(one)
                        for key, one in store.removed.items()}}
    write_private(root, TRUST, json.dumps(data, sort_keys=True) + "\n")


def admit(root: str, mesh_id: bytes, invite_id: str, public_key: str,
          sign_key: str, address: str, endpoint: str | None,
          now: datetime) -> Admission:
    """Evidence, signed with this node's key, that it admitted the node;
    raises signing.SigningError"""
    draft = Admission(mesh_id.hex(), invite_id, public_key, sign_key,
                      address, endpoint, int(now.timestamp()),
                      signing.public(root), "")
    return Admission(**{**asdict(draft),
                        "signature": signing.sign(root, draft.message())})


def removal(root: str, mesh_id: bytes, public_key: str,
            now: datetime) -> Removal:
    """A tombstone for `public_key`, signed with this node's key"""
    draft = Removal(mesh_id.hex(), public_key, int(now.timestamp()),
                    signing.public(root), "")
    return Removal(**{**asdict(draft),
                      "signature": signing.sign(root, draft.message())})


def matches(entry: Peer, mesh_id: bytes) -> bool:
    found = entry.admission
    return (same_key(found.public_key, entry.public_key)
            and found.address == entry.address
            and found.mesh_id == mesh_id.hex())


def accepted(store: Store, own: str, mesh_id: bytes,
             entries: Iterable[Peer]) -> tuple[Peer, ...]:
    """The entries whose evidence chains to a key this node trusts, as
    their admissions name them; each is recorded in `store`, and its
    signing key trusted in turn. An entry without evidence, with
    evidence of no invite, for another key, address or mesh, by a key
    not trusted, or whose key has a tombstone, is left out."""
    waiting = [one for one in entries
               if one.admission is not None and one.admission.invite_id
               and matches(one, mesh_id) and not store.gone(one.public_key)]
    trusted = store.signers(own)
    taken: list[Peer] = []
    progress = True
    while progress:
        progress = False
        for entry in list(waiting):
            found = entry.admission
            if found.by not in trusted:
                continue
            waiting.remove(entry)
            if not signing.verified(found.by, found.message(),
                                    found.signature):
                continue
            taken.append(Peer(found.public_key, found.endpoint,
                              found.address, found))
            if recorded(store, found):
                trusted.add(found.sign_key)
                progress = True
    return tuple(taken)


def recorded(store: Store, found: Admission) -> bool:
    """`found` recorded for its node; whether its signing key is the one
    the store holds for the node: a node keeps the first key it was
    known by, and evidence naming another one does not make it trusted"""
    known = store.find(found.public_key)
    if known is None:
        store.members[found.public_key] = Member(found.sign_key, False,
                                                 found)
        return True
    member = store.members[known]
    if member.sign_key is None:
        member.sign_key = found.sign_key
    if member.sign_key != found.sign_key:
        return False
    if member.admission is None:
        member.admission = found
    return True


def may_remove(store: Store, own: str, found: Removal) -> bool:
    """Whether `found` was signed by a key that may remove its node: this
    node's own, a trust root's, the node's own (it leaves), or the key
    of the member that admitted it, as the evidence this node keeps
    says. Any other member, trusted or not, removes it only from its
    own spec."""
    roots = {one.sign_key for one in store.members.values()
             if one.root and one.sign_key}
    if found.by == own or found.by in roots:
        return True
    known = store.find(found.public_key)
    if known is None:
        return False
    member = store.members[known]
    return found.by == member.sign_key or (
        member.admission is not None and found.by == member.admission.by)


def may_remove_everywhere(store: Store, own: str, key: str) -> bool:
    """Whether this node, signing with `own`, may remove `key` from the
    whole mesh, which etcd's `member remove` does (0048, third round,
    point 4): it admitted that node (the evidence it keeps for it is
    signed with `own`), or that node is one of its trust roots. Roots
    are made by the operator's act on a mesh built by hand, which makes
    the members each other's roots (keel.mesh.adopt): a node this node
    holds as a root holds this node as one too, and takes its
    tombstones (`may_remove`). The node itself leaving is the third
    case of the rule, and is not `keel mesh remove`'s."""
    known = store.find(key)
    if known is None:
        return False
    member = store.members[known]
    return member.root or (member.admission is not None
                           and member.admission.by == own)


def room_for(store: Store, signer: str) -> bool:
    """Whether the store takes another tombstone signed by `signer`"""
    return len(store.removed) < MAX_REMOVED and sum(
        1 for one in store.removed.values()
        if one.by == signer) < MAX_REMOVED_PER_SIGNER


def removals(store: Store, own: str, mesh_id: bytes,
             found: Iterable[Removal]) -> tuple[str, ...]:
    """The tombstones signed by a key that may remove their node
    (`may_remove`), within the caps (`room_for`), recorded: the key is
    trusted no more, and never taken again. The keys newly removed"""
    taken = []
    for one in found:
        if store.gone(one.public_key) or one.mesh_id != mesh_id.hex() or \
                not may_remove(store, own, one) or \
                not room_for(store, one.by) or \
                not signing.verified(one.by, one.message(), one.signature):
            continue
        record_removal(store, one)
        taken.append(one.public_key)
    return tuple(taken)


def record_removal(store: Store, found: Removal) -> None:
    store.removed[found.public_key] = found
    key = store.find(found.public_key)
    if key is not None:
        del store.members[key]


def make_roots(store: Store, keys: Iterable[str]) -> None:
    """The operator's act: these members are trusted as roots"""
    for key in keys:
        known = store.find(key)
        if known is None:
            store.members[key] = Member(None, True)
        else:
            store.members[known].root = True


def bind_root(store: Store, key: str, sign_key: str) -> bool:
    """A root's signing key, as the root itself gave it over the overlay;
    whether it was bound now (a root bound before keeps its key)"""
    known = store.find(key)
    if known is None or not store.members[known].root or \
            store.members[known].sign_key is not None:
        return False
    store.members[known].sign_key = sign_key
    return True
