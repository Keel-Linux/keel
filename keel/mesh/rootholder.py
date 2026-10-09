# Copyright (c) 2026 KeelLinux maintainers
"""Where the mesh's root CA is, for every member (keel#105, 0051)

The root's holder signs the database certificates of a pair (and every
etcd certificate). An etcd member learns the holder's address with its
own certificate (keel.mesh.etcdstate.take_grant). A member that is no
etcd member, such as both nodes of a cloud simple pair, did not: on a
real mesh whose root was held by a cloud advanced node outside the
pair, each pair member asked the other one, which refused, and the
database certificate could not be made (keel#105).

So the holder's address travels in every roster (keel.mesh.members), as
0051 says it is kept: "a short notice signed by that root's key alone
(`holder`: region, overlay address, time), so a region can move its
holder without a vote". The notice is the mesh's identity, the region
(absent: the first region, the only one until 0051's bundle exists),
the holder's overlay address and the time, signed with the root's key
over LABEL.
Any roster may carry it, the holder's own or one relayed by any member,
since only the root's key makes one: a member that does not hold that
key cannot send requests to another address. A notice is taken when
it is for this mesh and the first region, verifies with the root
certificate this node holds, is newer than the one it keeps, and is
not more than FUTURE ahead of this node's clock. A time and not a
sequence number: 0051 names the time, and a counter would have to move
with the root's key when the holder moves. Without the bound, one
notice dated far ahead would make every later notice "older" and pin
the holder's address for good.

The anchor is the root certificate: the one an etcd member holds
(`etcdstate.ROOT_CERT`), else the one this node learned (`ANCHOR`). A
node that holds none takes the root certificate only from a roster it
fetched from a trust root's own overlay address (keel mesh sync, or
the fetch below), which WireGuard authenticates as that root's, as a
trust root's signing key is learned (docs/mesh.md); never from an
announcement. It must be a CA, self signed, and named for this mesh.
Once a node holds one, it never takes another: a new root is 0051's
trust bundle, by a majority of the roots. The database leaf is then
taken only under that root (keel.system.dbtls).
"""

import base64
import ipaddress
import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from keel.mesh import etcdpki, etcdstate, memberlink, trust
from keel.mesh.etcdpki import PkiError
from keel.mesh.memberlink import LinkError
from keel.network.marker import path
from keel.network.wireguard import same_key

LABEL = b"keel mesh root holder 1\n"
NOTICE = f"{etcdstate.DIR}/holder.notice"
ANCHOR = f"{etcdstate.DIR}/root-anchor.crt"
FIELDS = ("address", "mesh_id", "time", "signature")
REGION = "region"
MAX_REGION = 64
# how far ahead of this node's clock a notice's time may be
FUTURE = timedelta(minutes=5)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_SIGNATURE = 256


def body(found: dict) -> bytes:
    """What the root's key signs: every field of the notice but the
    signature; a region only when the notice names one"""
    return LABEL + json.dumps({one: found[one] for one in found
                               if one != "signature"},
                              sort_keys=True).encode()


def signed(key: str, mesh_id: str, address: str, when: datetime,
           region: str | None = None) -> dict:
    """A notice that the holder of the root key at `key` is at
    `address`; raises PkiError"""
    found = {"address": str(ipaddress.IPv6Address(address)),
             "mesh_id": mesh_id,
             "time": when.astimezone(timezone.utc).strftime(TIME_FORMAT)}
    if region is not None:
        found[REGION] = region
    return {**found, "signature": etcdpki.sign(key, body(found))}


def when(found: dict) -> datetime:
    return datetime.strptime(found["time"], TIME_FORMAT).replace(
        tzinfo=timezone.utc)


def notice(value: object) -> dict | None:
    """A notice as a roster carries it, or None when it is not one"""
    if not isinstance(value, dict) or \
            set(value) - {REGION} != set(FIELDS) or \
            not all(isinstance(value[one], str) for one in value) or \
            len(value["signature"]) > MAX_SIGNATURE or \
            len(value.get(REGION, "")) > MAX_REGION:
        return None
    try:
        at = str(ipaddress.IPv6Address(value["address"]))
        datetime.strptime(value["time"], TIME_FORMAT)
        base64.b64decode(value["signature"], validate=True)
        bytes.fromhex(value["mesh_id"])
    except ValueError:
        return None
    if at != value["address"]:
        return None
    return dict(value)


def certificate(value: object) -> str | None:
    """A root certificate as a roster carries it, or None"""
    if not isinstance(value, str) or len(value) > 16384:
        return None
    found = etcdpki.blocks(value)
    return value if len(found) == 1 and found[0] == value and \
        "BEGIN CERTIFICATE-----" in value else None


def anchor(root: str) -> str | None:
    """The root certificate this node verifies against: an etcd
    member's, else the one it learned"""
    return etcdstate.read(root, etcdstate.ROOT_CERT) or \
        etcdstate.read(root, ANCHOR)


def kept(root: str) -> dict | None:
    """The notice this node took, or None"""
    try:
        return notice(json.loads(etcdstate.read(root, NOTICE) or "null"))
    except ValueError:
        return None


def offered(root: str, mesh_id: str | None, address: str,
            now: datetime) -> tuple[str | None, dict | None]:
    """What this node's roster carries: the root certificate it holds,
    and the holder's notice; on the holder, its own, signed once and
    kept"""
    found = kept(root)
    if not etcdstate.holds_root(root) or mesh_id is None:
        return anchor(root), found
    if found is None or found["address"] != address or \
            found["mesh_id"] != mesh_id:
        try:
            found = signed(path(root, etcdstate.ROOT_KEY), mesh_id, address,
                           now)
        except PkiError:
            return anchor(root), None
        etcdstate.write(root, NOTICE, json.dumps(found, sort_keys=True))
    return anchor(root), found


def is_root_of(cert: str, mesh_id: str) -> bool:
    """Whether `cert` is a self-signed CA named for this mesh's root"""
    try:
        return etcdpki.is_ca(cert) and etcdpki.verified(cert, [], cert) and \
            etcdpki.subject(cert) == f"keel mesh {mesh_id[:16]} etcd root"
    except PkiError:
        return False


def learn(root: str, mesh_id: str, cert: str | None, found: dict | None,
          vouched: bool, now: datetime) -> str | None:
    """Take what a roster says of the root: its certificate when this
    node holds none and the roster was fetched from a trust root
    (`vouched`), and the holder's notice when it verifies and is not
    dated more than FUTURE after `now`; what was learned, or None"""
    if etcdstate.holds_root(root):
        return None
    with etcdstate.locked(root):
        held = anchor(root)
        if held is None and cert and vouched and is_root_of(cert, mesh_id):
            etcdstate.write(root, ANCHOR, cert)
            held = cert
        if held is None or found is None or found["mesh_id"] != mesh_id \
                or REGION in found or when(found) > now + FUTURE:
            return None
        before = kept(root)
        if before is not None and found["time"] <= before["time"]:
            return None
        if not etcdpki.verified_by(held, body(found), found["signature"]):
            return None
        etcdstate.write(root, NOTICE, json.dumps(found, sort_keys=True))
        etcdstate.write(root, etcdstate.HOLDER, found["address"] + "\n")
    return (f"the root CA's holder is at {found['address']} (a notice"
            " signed by the root)")


def trusted_root(store: trust.Store, key: str) -> bool:
    found = store.find(key)
    return found is not None and store.members[found].root


def taken_from(root: str, mesh_id: str, rosters: list, store: trust.Store,
               fetched: bool, say: Callable[[str], None],
               now: datetime) -> None:
    """What `rosters` of this mesh say of the root, taken"""
    for one in rosters:
        if one.identity is None or one.identity.hex() != mesh_id:
            continue
        line = learn(root, mesh_id, one.root, one.holder,
                     fetched and trusted_root(store, one.public_key), now)
        if line:
            say(line)


def asked(node, own_key: str, mesh_id: str, say: Callable[[str], None],
          now: datetime, fetch: Callable | None = None) -> None:
    """The rosters of this node's peers fetched now and taken: what a
    node that knows no holder does before it asks for a certificate"""
    from keel.network import wireguard
    fetch = fetch or memberlink.fetch
    store = trust.load(node.root)
    iface = wireguard.interface(node.overlay())
    rosters = []
    for peer in node.peers(own_key):
        try:
            found = fetch(peer.address, iface)
        except LinkError as e:
            say(f"member {peer.address} did not answer: {e}")
            continue
        if same_key(found.public_key, peer.public_key) and \
                found.address == peer.address:
            rosters.append(found)
    taken_from(node.root, mesh_id, rosters, store, True, say, now)
