# Copyright (c) 2026 KeelLinux maintainers
"""A member's etcd credentials and cluster: state, not the spec

The spec says only `overlays.etcd: enabled`; the member list, the
certificates and the cluster are state (0048, third round, point 2),
under /var/lib/keel/etcd, root's, the directory 0700 and every file
0600, written through a temporary file and a rename as the mesh's state
is (keel.network.marker.write_private):

| File | What it holds |
| --- | --- |
| `root.key` | the mesh's root CA key, on the root's holder alone |
| `root.crt` | the mesh's root CA, which every member trusts |
| `member.key`, `member.crt` | this member's certificate, the root's |
| `admin.key`, `admin.crt` | on the root's holder: etcd's root user |
| `cluster.json` | the cluster, its members, token and signed record |
| `holder` | the overlay address of the member that holds the root CA |
| `crl.pem` | the CRL the root signed, the newest this member has seen |
| `issued.json` | on the root's holder: the certificates it signed |
| `revoked.json` | on the root's holder: what it revoked (etcdca) |
| `formation.json` | on the root's holder: the formation it reserved |
| `auth.json` | on the root's holder: whether etcd's auth is on |
| `pairs.json` | on the root's holder: the VIP pairs it gave a role |
| `ready.json` | the members known to be ready for etcd: key to address |
| `learners.json` | when each learner was first seen, for `tend` |

The database's leaf (keel.system.dbtls) is the root's too, kind
`database` (keel.mesh.etcdpki): CN `<member name> mariadb`, no etcd
user, its IP SANs the member's address and its pair's VIP, so a client
verifying the VIP works later. It lives under /etc/mysql/keel-tls,
where the mysql user reads it, never here.

A member's certificate is its peer, server and client certificate
alike; the holder's admin certificate is CN `root`, etcd's root user
(keel.mesh.etcdauth). The root signs every member's certificate itself
(keel#83): the request
goes to the root's holder, relayed by the inviter at a join, sent by the
member itself at a renewal, and the holder names the certificate after
the member's address and its key, whatever the request asks
(`grant_for`); the member checks it is for its own key, name and
address, and chains to the root (`take_grant`). A member is named after
its overlay address, which every member computes alike (`name`), and
that name is its etcd user.

Before keel#83 every member held an intermediate CA (`ca.key`,
`ca.crt`, `chain.pem`) and issued its own leaves (`client.key`,
`client.crt` beside `member.*`): `LEGACY`. A member that takes a
certificate the root signed removes them, and keel mesh etcd reissue
moves a running cluster over (keel.mesh.etcdreissue).
"""

import fcntl
import ipaddress
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta

from keel.mesh import DIR_MODE, FILE_MODE, etcdpki
from keel.mesh.etcdpki import PkiError
from keel.network.marker import path, write_private

DIR = "var/lib/keel/etcd"
LOCK = f"{DIR}/lock"
ROOT_KEY = f"{DIR}/root.key"
ROOT_CERT = f"{DIR}/root.crt"
MEMBER_KEY = f"{DIR}/member.key"
MEMBER_CERT = f"{DIR}/member.crt"
ADMIN_KEY = f"{DIR}/admin.key"
ADMIN_CERT = f"{DIR}/admin.crt"
# the layout before keel#83: an intermediate per member, which issued
# the member's leaves
CA_KEY = f"{DIR}/ca.key"
CA_CERT = f"{DIR}/ca.crt"
CHAIN = f"{DIR}/chain.pem"
CLIENT_KEY = f"{DIR}/client.key"
CLIENT_CERT = f"{DIR}/client.crt"
LEGACY = (CA_KEY, CA_CERT, CHAIN, CLIENT_KEY, CLIENT_CERT)
CLUSTER = f"{DIR}/cluster.json"
READY = f"{DIR}/ready.json"
LEARNERS = f"{DIR}/learners.json"
PENDING = f"{DIR}/pending.json"
RENEWAL = f"{DIR}/renewal.json"
HOLDER = f"{DIR}/holder"
ISSUED = f"{DIR}/issued.json"
# written once keel started etcd here for this mesh's cluster
STARTED = f"{DIR}/started"
CRL = f"{DIR}/crl.pem"
PEER_PORT = 2380
CLIENT_PORT = 2379
STATES = ("new", "existing")
LOOPBACK = "::1"
# etcd's root user: the CN of the holder's admin certificate alone; a
# member's name always starts with keel-, so no member is ever it
ROOT_USER = "root"
LEAF, INTERMEDIATE, DATABASE_LEAF = "leaf", "intermediate", "database"


class StateError(Exception):
    """The credentials or the cluster cannot be used, and why"""


@dataclass(frozen=True)
class Grant:
    """A member's certificate, signed by the root; `chain`, always
    empty since keel#83 (a leaf is one below the root), kept in the
    message's format; the mesh's root, and, when the issuer has them,
    the root's CRL and the root holder's overlay address"""

    certificate: str
    chain: tuple[str, ...]
    root: str
    crl: str | None = None
    holder: str | None = None


@dataclass(frozen=True)
class Member:
    """A member by its overlay address, and its WireGuard key when
    known: etcd lists members by their peer URLs alone"""

    public_key: str | None
    address: str


@dataclass(frozen=True)
class Cluster:
    """`new` (formed at its first start) or `existing` (joined), its
    members, and its token: the mesh's identity"""

    state: str
    members: tuple[Member, ...]
    token: str
    # the formation record (canonical JSON) and the root's signature of
    # it (keel.mesh.etcdca): what makes a cluster this mesh's
    record: str | None = None
    signature: str | None = None

    def addresses(self) -> tuple[str, ...]:
        return tuple(one.address for one in self.members)

    def dumps(self) -> dict:
        return {"state": self.state, "token": self.token,
                "members": [{"public_key": one.public_key,
                             "address": one.address}
                            for one in self.members],
                "record": self.record, "signature": self.signature}

    @staticmethod
    def loads(data: object) -> "Cluster":
        """Raises StateError for anything but a cluster"""
        try:
            if data["state"] not in STATES or \
                    not isinstance(data["members"], list):
                raise ValueError("not a cluster")
            members = tuple(
                Member(None if one["public_key"] is None
                       else str(one["public_key"]),
                       str(ipaddress.IPv6Address(one["address"])))
                for one in data["members"])
            record, signature = data.get("record"), data.get("signature")
            if not all(one is None or isinstance(one, str)
                       for one in (record, signature)):
                raise ValueError("a record is text")
            return Cluster(data["state"], members, str(data["token"]),
                           record, signature)
        except (KeyError, TypeError, ValueError) as e:
            raise StateError(f"not a cluster: {e}") from None


def ensure(root: str) -> None:
    directory = path(root, DIR)
    os.makedirs(directory, mode=DIR_MODE, exist_ok=True)
    os.chmod(directory, DIR_MODE)


@contextmanager
def locked(root: str) -> Iterator[None]:
    ensure(root)
    fd = os.open(path(root, LOCK), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read(root: str, relative: str) -> str | None:
    try:
        with open(path(root, relative)) as fob:
            return fob.read()
    except FileNotFoundError:
        return None


def write(root: str, relative: str, text: str) -> None:
    ensure(root)
    write_private(root, relative, text)


def name(address: str) -> str:
    """The etcd member name of the member at `address`"""
    return "keel-" + str(ipaddress.IPv6Address(address)).replace(":", "-")


def peer_url(address: str) -> str:
    return f"https://[{ipaddress.IPv6Address(address)}]:{PEER_PORT}"


def client_url(address: str) -> str:
    return f"https://[{ipaddress.IPv6Address(address)}]:{CLIENT_PORT}"


def credentials(root: str) -> bool:
    """Whether this member holds its certificate, its key and the root"""
    return all(os.path.exists(path(root, one))
               for one in (MEMBER_KEY, MEMBER_CERT, ROOT_CERT))


def legacy(root: str) -> bool:
    """Whether this member still holds an intermediate CA, or leaves
    one issued (the layout before keel#83)"""
    return any(os.path.exists(path(root, one)) for one in LEGACY)


def holds_root(root: str) -> bool:
    return os.path.exists(path(root, ROOT_KEY))


def root_fingerprint(root: str) -> str | None:
    """The fingerprint of the root held; raises StateError for a file
    that holds no certificate"""
    found = read(root, ROOT_CERT)
    try:
        return etcdpki.fingerprint(found) if found else None
    except PkiError as e:
        raise StateError(f"/{ROOT_CERT}: {e}") from None


def key(root: str, relative: str) -> str:
    """The key file at `relative`, made when there is none; its path"""
    if not os.path.exists(path(root, relative)):
        write(root, relative, etcdpki.new_key())
    return path(root, relative)


def make_root(root: str, mesh_id: str, address: str) -> bool:
    """The mesh's root CA, this node's certificate and its admin
    certificate signed by it, and the root's first CRL, empty, when this
    node holds no credentials; whether they were made now. `address` is
    this node's overlay address"""
    with locked(root):
        if credentials(root) or os.path.exists(path(root, ROOT_KEY)):
            return False
        try:
            made = etcdpki.root(key(root, ROOT_KEY), mesh_id)
            own = etcdpki.issue(etcdpki.MEMBER, path(root, ROOT_KEY), made,
                                etcdpki.request(key(root, MEMBER_KEY)),
                                name(address), (address, LOOPBACK))
            admin = etcdpki.issue(etcdpki.CLIENT, path(root, ROOT_KEY),
                                  made, etcdpki.request(key(root, ADMIN_KEY)),
                                  ROOT_USER)
            first = etcdpki.crl(path(root, ROOT_KEY), made, {}, 1)
        except PkiError as e:
            raise StateError(str(e)) from None
        write(root, ROOT_CERT, made)
        write(root, MEMBER_CERT, own)
        write(root, ADMIN_CERT, admin)
        write(root, CRL, first)
        write(root, HOLDER, str(ipaddress.IPv6Address(address)) + "\n")
    return True


def prefix_of(address: str) -> str:
    """The overlay prefix of a member's address: the mesh's /64"""
    return str(ipaddress.IPv6Network(f"{address}/64", strict=False))


def holder(root: str) -> str | None:
    """The overlay address of the member that holds the root CA"""
    found = (read(root, HOLDER) or "").strip()
    return found or None


def member_request(root: str) -> str:
    """The request for this node's certificate: its key made once"""
    with locked(root):
        try:
            return etcdpki.request(key(root, MEMBER_KEY))
        except PkiError as e:
            raise StateError(str(e)) from None


def database_grant(root: str, csr: str, address: str, vip: str | None,
                   public_key: str | None = None) -> Grant:
    """On the root's holder: the database leaf of the member at
    `address`, kind database, named after the member with ` mariadb`,
    its SANs the address and `vip`; recorded for revocation with the
    member's. Raises StateError off the holder"""
    if not holds_root(root):
        raise StateError("only the node that holds the mesh's root CA signs"
                         " a database certificate")
    issuer = read(root, ROOT_CERT)
    at = str(ipaddress.IPv6Address(address))
    sans = (at,) + ((str(ipaddress.IPv6Address(vip)),) if vip else ())
    try:
        made = etcdpki.issue(etcdpki.DATABASE, path(root, ROOT_KEY), issuer,
                             csr, database_name(at), sans)
        record_issued(root, at, made, public_key, DATABASE_LEAF)
    except PkiError as e:
        raise StateError(f"the request cannot be signed: {e}") from None
    return Grant(made, (), issuer, read(root, CRL), holder(root))


def database_name(address: str) -> str:
    """The CN of a member's database leaf: never an etcd user"""
    return name(address) + " mariadb"


def grant_for(root: str, csr: str, address: str,
              public_key: str | None = None, sign_key: str | None = None,
              relay: str | None = None) -> Grant:
    """The certificate of the member at `address` (WireGuard key
    `public_key`) for the key of `csr`, signed with the root: named
    after the address, which it carries with ::1 as its SANs, whatever
    the request says; recorded for revocation. Raises StateError off the
    root's holder"""
    if not holds_root(root):
        raise StateError("only the node that holds the mesh's root CA signs"
                         " a member's certificate")
    issuer = read(root, ROOT_CERT)
    at = str(ipaddress.IPv6Address(address))
    try:
        made = etcdpki.issue(etcdpki.MEMBER, path(root, ROOT_KEY), issuer,
                             csr, name(at), (at, LOOPBACK))
        record_issued(root, at, made, public_key, LEAF, sign_key, relay)
    except PkiError as e:
        raise StateError(f"the request cannot be signed: {e}") from None
    return Grant(made, (), issuer, read(root, CRL), holder(root))


def admin(root: str, now: datetime) -> bool:
    """On the root's holder: its admin certificate (CN root), issued
    when missing or with a third of its life left; whether it was"""
    if not holds_root(root):
        raise StateError("only the root's holder is etcd's root user")
    with locked(root):
        found = read(root, ADMIN_CERT)
        if found and etcdpki.not_after(found) - now >= timedelta(
                days=etcdpki.LEAF_DAYS // 3):
            return False
        try:
            made = etcdpki.issue(etcdpki.CLIENT, path(root, ROOT_KEY),
                                 read(root, ROOT_CERT),
                                 etcdpki.request(key(root, ADMIN_KEY)),
                                 ROOT_USER)
        except PkiError as e:
            raise StateError(str(e)) from None
        write(root, ADMIN_CERT, made)
    return True


def record_issued(root: str, address: str, certificate: str,
                  public_key: str | None = None, kind: str = LEAF,
                  sign_key: str | None = None,
                  relay: str | None = None) -> None:
    """On the root's holder: a certificate it signed, by its member's
    address, with the member's WireGuard key, so a removal revokes it
    and only it (keel.mesh.etcdca); the signing key the request's proof
    verified with and the member that relayed it (keel.mesh.etcdproof),
    so a certificate issued under a key the trust store disowns is
    revoked, and the relay may give back a join that failed. An entry is
    [serial, expiry, key, kind, sign key, relay]; the entries of the
    layout before keel#83 have no kind, and are intermediates"""
    try:
        data = json.loads(read(root, ISSUED) or "{}")
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    entry = [etcdpki.serial(certificate),
             etcdpki.stamp(etcdpki.not_after(certificate)), public_key, kind,
             sign_key, relay]
    data.setdefault(str(ipaddress.IPv6Address(address)), []).append(entry)
    write(root, ISSUED, json.dumps(data, sort_keys=True) + "\n")


def issued(root: str) -> dict[str, list[list]]:
    """On the root's holder: what it signed, by address"""
    try:
        data = json.loads(read(root, ISSUED) or "{}")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): [one for one in v if isinstance(one, list)
                     and len(one) >= 3]
            for k, v in data.items() if isinstance(v, list)}


def checked(root: str, grant: Grant, address: str) -> str | None:
    """Why `grant` is not this member's certificate, or None: it
    certifies this member's own key, is no CA, names this member's
    address in its CN and its first SAN, and chains to the root it came
    with, which is the one this member holds, if any"""
    at = str(ipaddress.IPv6Address(address))
    try:
        mine = etcdpki.key_public(key(root, MEMBER_KEY))
        certified = etcdpki.public(grant.certificate)
        held = read(root, ROOT_CERT)
        if held and etcdpki.fingerprint(held) != etcdpki.fingerprint(
                grant.root):
            return ("the certificate is under another root than the one"
                    " this node holds")
        if mine != certified:
            return "the certificate certifies another key, not this node's"
        if grant.chain or etcdpki.is_ca(grant.certificate) or \
                not etcdpki.verified(grant.certificate, [], grant.root):
            return "the certificate is not one the root signed for a member"
        if etcdpki.subject(grant.certificate) != name(at) or \
                etcdpki.addresses(grant.certificate)[:1] != (at,):
            return f"the certificate does not name this node ({at})"
    except PkiError as e:
        return str(e)
    return None


def take_grant(root: str, grant: Grant, address: str) -> None:
    """Keep `grant` as this node's certificate, once checked (`checked`),
    and drop the intermediate and the leaves of the layout before
    keel#83. Raises StateError"""
    with locked(root):
        problem = checked(root, grant, address)
        if problem:
            raise StateError(problem)
        # the root first: a crash between leaves no certificate that
        # chains to a root this node does not hold
        write(root, ROOT_CERT, grant.root)
        write(root, MEMBER_CERT, grant.certificate)
        if grant.holder:
            write(root, HOLDER, str(ipaddress.IPv6Address(grant.holder))
                  + "\n")
        for one in LEGACY:
            try:
                os.remove(path(root, one))
            except FileNotFoundError:
                pass
    if grant.crl:
        take_crl(root, grant.crl)


def take_crl(root: str, found: str) -> bool:
    """Keep `found` as this member's CRL when the root signed it and it
    is newer than the one held; whether it was kept"""
    anchor = read(root, ROOT_CERT)
    if not anchor or not etcdpki.crl_verified(found, anchor):
        return False
    held = read(root, CRL)
    try:
        if held and etcdpki.crl_number(held) >= etcdpki.crl_number(found):
            return False
    except PkiError:
        pass
    write(root, CRL, found)
    return True


def expires(root: str) -> datetime | None:
    """When this member's certificate expires, None without one"""
    found = read(root, MEMBER_CERT)
    if not found:
        return None
    return etcdpki.not_after(etcdpki.blocks(found)[0])


def stale(root: str, address: str, now: datetime) -> bool:
    """Whether this member's certificate is to be renewed: missing, for
    another address, or with a third of its life left. One an
    intermediate issued (before keel#83) is not due for that alone: keel
    mesh etcd reissue moves the cluster one member at a time; until it
    runs, a renewal at the end of its life asks the root as any does"""
    found = read(root, MEMBER_CERT)
    if not found or not read(root, ROOT_CERT):
        return True
    leaf = etcdpki.blocks(found)[0]
    left = etcdpki.not_after(leaf) - now
    return left < timedelta(days=etcdpki.LEAF_DAYS // 3) or \
        etcdpki.addresses(leaf)[:1] != (str(ipaddress.IPv6Address(address)),)


def keep_own_intermediate(root: str, address: str,
                          public_key: str | None) -> None:
    """On the root's holder of the layout before keel#83: its own
    intermediate recorded, before taking a certificate drops it, so the
    revocation of the intermediates finds it (keel.mesh.etcdca)"""
    own = read(root, CA_CERT)
    if own and holds_root(root):
        record_issued(root, address, own, public_key, INTERMEDIATE)


def cluster(root: str) -> Cluster | None:
    """The cluster this member is in, None before it is in one"""
    found = read(root, CLUSTER)
    if found is None:
        return None
    try:
        return Cluster.loads(json.loads(found))
    except (ValueError, StateError):
        raise StateError(f"/{CLUSTER} is damaged: keel does not guess"
                         " the cluster") from None


def save_cluster(root: str, found: Cluster) -> None:
    write(root, CLUSTER, json.dumps(found.dumps(), sort_keys=True) + "\n")


def ready(root: str) -> dict[str, str]:
    """The members known to be ready for etcd, key to overlay address"""
    try:
        data = json.loads(read(root, READY) or "{}")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def add_ready(root: str, entries: dict[str, str]) -> None:
    with locked(root):
        write(root, READY, json.dumps({**ready(root), **entries},
                                      sort_keys=True) + "\n")


def drop_ready(root: str, public_key: str) -> None:
    with locked(root):
        write(root, READY, json.dumps(
            {k: v for k, v in ready(root).items() if k != public_key},
            sort_keys=True) + "\n")


def pending(root: str) -> list[dict]:
    """The requests that wait for the root CA's holder: an inviter could
    not reach it when it admitted the node, and the timer asks again"""
    try:
        data = json.loads(read(root, PENDING) or "[]")
    except ValueError:
        return []
    return [one for one in data if isinstance(one, dict)] \
        if isinstance(data, list) else []


def queue(root: str, address: str, public_key: str, csr: str, proof: str,
          evidence: dict | None) -> None:
    """A request that waits for the holder: the node's request and its
    proof, and the evidence of its admission (keel.mesh.etcdproof)"""
    with locked(root):
        kept = [one for one in pending(root) if one.get("address") != address]
        write(root, PENDING, json.dumps(kept + [{
            "address": address, "public_key": public_key, "csr": csr,
            "proof": proof, "admission": evidence}],
            sort_keys=True) + "\n")


def unqueue(root: str, address: str) -> None:
    with locked(root):
        write(root, PENDING, json.dumps(
            [one for one in pending(root) if one.get("address") != address],
            sort_keys=True) + "\n")


def learners(root: str, ids: list[str], now: datetime) -> dict[str, datetime]:
    """When each learner of `ids` was first seen; those gone forgotten"""
    try:
        kept = json.loads(read(root, LEARNERS) or "{}")
    except ValueError:
        kept = {}
    found = {}
    for one in ids:
        seen = kept.get(one) if isinstance(kept, dict) else None
        found[one] = (datetime.fromtimestamp(seen, now.tzinfo)
                      if isinstance(seen, int) else now)
    write(root, LEARNERS, json.dumps(
        {k: int(v.timestamp()) for k, v in found.items()},
        sort_keys=True) + "\n")
    return found
