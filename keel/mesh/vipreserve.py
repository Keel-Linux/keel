# Copyright (c) 2026 KeelLinux maintainers
"""A VIP reserved in etcd when its pair is made (decision 0051, keel#97)

VIPs live in one range of the overlay outside every region
(keel.mesh.vip, `<prefix>::ffff:n`), so no inviter allocates them and
no region's allocator keeps two pairs apart. With etcd, `keel vip pair`
reserves the VIP before it asks the other member to sign: one key per
VIP under the mesh's prefix, written only when it does not exist yet
(a compare-and-swap on its version):

    /keel/<mesh id>/vips/<vip>/pair
    {"reservation": {"mesh_id", "vip", "members": [key, key], "by"},
     "signature": Ed25519 signature}

The value is signed by the member that reserves (`by`), with its node
signing key (decision 0048), over `keel vip reserve 1\\n` and the
reservation's canonical JSON. Every reader checks that signature with
the signing key its trust store holds for `by`, and that `by` is a
member the reservation names (`judged`):

- signed, and naming the same two members: this pair's, however many
  times `keel vip pair` runs;
- signed, and naming others: another pair's; the VIP is refused;
- unsigned, or signed by a key this node does not trust for `by`: an
  alert. The VIP is blocked as if another pair held it, and keel never
  overwrites or deletes the key. An operator finds who wrote it.

The key is under a prefix every member may write (keel.mesh.etcdauth),
since the pair's own role exists only once the pair does, so etcd
cannot keep one member off another pair's reservation; the signature
makes a forged one visible, and a reservation is never a claim: claims
rest on the signed pair record, which every node checks
(keel.mesh.vippair).

A reservation is written with a lease of TTL (24 h). Once both members
signed the pair record, `kept` takes the key off its lease, so it stays
as long as the pair does; a pair the other member never signed lets its
VIP go when the lease ends. `keel vip unpair VIP` (`release`) deletes
this pair's reservation, only at the revision it read, and never
another pair's or an unverified one.

The member asked to sign checks the reservation first (`held_for`): it
signs only a pair whose VIP etcd holds for that pair, so an initiator
that skips the reservation gets no signature.

Before etcd, or on a node whose etcd is not formed, nothing is reserved:
the two signatures on the record are then what binds the VIP.
"""

import base64
import binascii
import json
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass

from keel.mesh import signing
from keel.mesh.etcdauth import vips_prefix
from keel.mesh.etcdclient import Client, EtcdError, Value, absent, modified
from keel.mesh.etcdmsg import canonical
from keel.mesh.vippair import Pair
from keel.network.wireguard import is_key, same_key

LABEL = b"keel vip reserve 1\n"
SUFFIX = "/pair"
# a reservation whose pair record the other member never signed ends
TTL = 24 * 60 * 60
Signer = Callable[[bytes], str]
SignerOf = Callable[[str], str | None]


@dataclass(frozen=True)
class Reservation:
    mesh_id: str
    vip: str
    members: tuple[str, ...]
    by: str
    signature: str = ""

    def record(self) -> dict:
        return {"mesh_id": self.mesh_id, "vip": self.vip,
                "members": list(self.members), "by": self.by}

    def message(self) -> bytes:
        return LABEL + canonical(self.record())

    def dumps(self) -> bytes:
        return canonical({"reservation": self.record(),
                          "signature": self.signature})

    def has(self, key: str) -> bool:
        return any(same_key(one, key) for one in self.members)

    def names(self, pair: Pair) -> bool:
        """Whether it holds `pair`'s VIP for `pair`'s two members"""
        return self.mesh_id == pair.mesh_id and self.vip == pair.vip and \
            len(self.members) == len(pair.members) and \
            all(self.has(one) for one in pair.members)


def key_of(mesh_id: str, vip: str) -> str:
    return f"{vips_prefix(mesh_id)}{vip}{SUFFIX}"


def made(pair: Pair, by: str, sign: Signer) -> Reservation:
    """`pair`'s reservation, signed by `by`; raises SigningError"""
    found = Reservation(pair.mesh_id, pair.vip, pair.members, by)
    return Reservation(found.mesh_id, found.vip, found.members, by,
                       sign(found.message()))


def loads(raw: bytes) -> Reservation | None:
    """The reservation a value holds; None for one keel did not write"""
    try:
        found = json.loads(raw.decode())
        record, signature = found["reservation"], found["signature"]
        members, by = record["members"], record["by"]
        mesh_id, vip = record["mesh_id"], record["vip"]
        base64.b64decode(signature, validate=True)
    except (ValueError, KeyError, TypeError, AttributeError,
            binascii.Error):
        return None
    if not isinstance(members, list) or not all(
            isinstance(one, str) and is_key(one) for one in members) or \
            not all(isinstance(one, str) for one in (by, mesh_id, vip,
                                                     signature)):
        return None
    return Reservation(mesh_id, vip, tuple(members), by, signature)


def read(client: Client, mesh_id: str, vip: str) -> Value | None:
    """The VIP's reservation as etcd holds it, or None; raises EtcdError"""
    key = key_of(mesh_id, vip)
    return next((one for one in client.prefix(key) if one.key == key),
                None)


def blocked(key: str, vip: str) -> str:
    return (f"ALERT: the reservation of {vip} in etcd ({key}) is not"
            " signed by a member it names, with a key this node trusts."
            f" keel never overwrites or deletes it, and {vip} stays"
            " blocked. Find who wrote it. Remove it as etcd's root user"
            f" (etcdctl del {key}) only when no pair uses {vip}")


def judged(value: Value, mesh_id: str, vip: str,
           signer_of: SignerOf) -> tuple[Reservation | None, str | None]:
    """The reservation `value` holds when its signature is good, else
    None and the alert"""
    found = loads(value.value)
    if found is None or found.mesh_id != mesh_id or found.vip != vip or \
            not found.has(found.by):
        return None, blocked(value.key, vip)
    key = signer_of(found.by)
    if not key or not signing.verified(key, found.message(),
                                       found.signature):
        return None, blocked(value.key, vip)
    return found, None


def foreign(found: Reservation) -> str:
    return (f"{found.vip} is reserved in etcd by another pair"
            f" ({', '.join(found.members)}): a VIP belongs to one pair")


def whose(value: Value, pair: Pair, signer_of: SignerOf) -> str | None:
    """None when `value` is `pair`'s reservation, else why not"""
    found, alert = judged(value, pair.mesh_id, pair.vip, signer_of)
    if alert:
        return alert
    return None if found.names(pair) else foreign(found)


def reserve(client: Client, pair: Pair, by: str, sign: Signer,
            signer_of: SignerOf) -> str | None:
    """`pair.vip` reserved for `pair`'s members, signed by `by`, on a
    lease of TTL; or why it cannot be: another pair holds it, an
    unverified reservation blocks it, or etcd did not answer. Raises
    SigningError"""
    key = key_of(pair.mesh_id, pair.vip)
    try:
        value = read(client, pair.mesh_id, pair.vip)
        if value is None:
            mine = made(pair, by, sign)
            lease = client.grant(TTL)
            if client.swap([absent(key)], [(key, mine.dumps(), lease)]):
                return None
            with suppress(EtcdError):
                client.revoke(lease)
            # written between the read and the swap: whose is it now?
            value = read(client, pair.mesh_id, pair.vip)
    except EtcdError as e:
        return (f"{pair.vip} could not be reserved in etcd ({e}): with"
                " etcd, a pair is made only once its VIP is reserved")
    if value is None:
        return (f"the reservation of {pair.vip} changed while it was"
                " made: run keel vip pair again")
    return whose(value, pair, signer_of)


def held_for(client: Client, pair: Pair,
             signer_of: SignerOf) -> str | None:
    """None when etcd holds `pair`'s reservation, signed; else why not:
    what the member asked to sign checks first"""
    try:
        value = read(client, pair.mesh_id, pair.vip)
    except EtcdError as e:
        return (f"etcd did not answer ({e}): with etcd, a pair is signed"
                " only once its VIP is reserved")
    if value is None:
        return (f"{pair.vip} is not reserved in etcd for this pair: keel"
                " vip pair reserves it before it asks for a signature")
    return whose(value, pair, signer_of)


def kept(client: Client, pair: Pair, by: str, sign: Signer,
         signer_of: SignerOf) -> str | None:
    """The reservation of a pair both members signed, taken off its
    lease so it never ends; or why not. Raises SigningError"""
    key = key_of(pair.mesh_id, pair.vip)
    try:
        value = read(client, pair.mesh_id, pair.vip)
        if value is None:
            # the lease ended before the pair was made: reserved again
            done = client.swap([absent(key)], [(
                key, made(pair, by, sign).dumps(), None)])
        else:
            why = whose(value, pair, signer_of)
            if why:
                return why
            done = value.lease is None or client.swap(
                [modified(key, value.mod_revision)],
                [(key, value.value, None)])
    except EtcdError as e:
        return f"etcd did not answer ({e})"
    return None if done else (f"the reservation of {pair.vip} changed"
                              " while it was kept")


def release(client: Client, mesh_id: str, vip: str, own: str,
            signer_of: SignerOf) -> str | None:
    """This pair's reservation of `vip` deleted at the revision it was
    read at; why not, when it is another pair's or unverified. Nothing
    reserved is nothing to release. Raises EtcdError"""
    value = read(client, mesh_id, vip)
    if value is None:
        return None
    found, alert = judged(value, mesh_id, vip, signer_of)
    if alert:
        return alert
    if not found.has(own):
        return f"{foreign(found)}; only its members release it"
    if client.swap([modified(value.key, value.mod_revision)], [],
                   (value.key,)):
        return None
    return (f"the reservation of {vip} changed while it was released:"
            " run keel vip unpair again")
