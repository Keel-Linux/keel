# Copyright (c) 2026 KeelLinux maintainers
"""A member's etcd credentials and cluster: state, not the spec

The spec says only `overlays.etcd: enabled`; the member list, the
certificates and the cluster are state (0048, third round, point 2),
under /var/lib/keel/etcd, root's, the directory 0700 and every file
0600, written through a temporary file and a rename as the mesh's state
is (keel.network.marker.write_private):

| File | What it holds |
| --- | --- |
| `root.key` | the mesh's root CA key, on the first node alone |
| `root.crt` | the mesh's root CA, which every member trusts |
| `ca.key`, `ca.crt` | this member's intermediate CA |
| `chain.pem` | the intermediates above it, its issuer's first, not the root |
| `member.key`, `member.crt` | its member certificate, with its chain |
| `client.key`, `client.crt` | keel's client certificate, with its chain |
| `cluster.json` | the cluster, its members, token and signed record |
| `holder` | the overlay address of the member that holds the root CA |
| `crl.pem` | the CRL the root signed, the newest this member has seen |
| `issued.json` | on the root's holder: the intermediates it signed |
| `revoked.json` | on the root's holder: what it revoked (etcdca) |
| `formation.json` | on the root's holder: the formation it reserved |
| `ready.json` | the members known to be ready for etcd: key to address |
| `learners.json` | when each learner was first seen, for `tend` |

A member's intermediate is signed by its inviter (`grant_for`), whose
own chain goes with it; the member checks it is for its own key and
chains to the root (`take_grant`), and issues its own leaves with it
(`leaves`). A member is named after its overlay address, which every
member computes alike (`name`).
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
CA_KEY = f"{DIR}/ca.key"
CA_CERT = f"{DIR}/ca.crt"
CHAIN = f"{DIR}/chain.pem"
MEMBER_KEY = f"{DIR}/member.key"
MEMBER_CERT = f"{DIR}/member.crt"
CLIENT_KEY = f"{DIR}/client.key"
CLIENT_CERT = f"{DIR}/client.crt"
CLUSTER = f"{DIR}/cluster.json"
READY = f"{DIR}/ready.json"
LEARNERS = f"{DIR}/learners.json"
HOLDER = f"{DIR}/holder"
ISSUED = f"{DIR}/issued.json"
# written once keel started etcd here for this mesh's cluster
STARTED = f"{DIR}/started"
CRL = f"{DIR}/crl.pem"
PEER_PORT = 2380
CLIENT_PORT = 2379
STATES = ("new", "existing")
LOOPBACK = "::1"


class StateError(Exception):
    """The credentials or the cluster cannot be used, and why"""


@dataclass(frozen=True)
class Grant:
    """A member's intermediate CA, the chain above it (its issuer's
    first, the root left out), the mesh's root, and, when the issuer
    has them, the root's CRL and the root holder's overlay address"""

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
    """Whether this member holds its intermediate and the root"""
    return all(os.path.exists(path(root, one))
               for one in (CA_KEY, CA_CERT, ROOT_CERT))


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
    """The mesh's root CA and this node's intermediate under it, when
    this node holds no credentials, and the root's first CRL, empty;
    whether they were made now. `address` is this node's overlay
    address, whose prefix constrains every intermediate"""
    with locked(root):
        if credentials(root):
            return False
        try:
            made = etcdpki.root(key(root, ROOT_KEY), mesh_id)
            own = etcdpki.issue(etcdpki.CA, path(root, ROOT_KEY), made,
                                etcdpki.request(key(root, CA_KEY)),
                                name(address), prefix=prefix_of(address))
            first = etcdpki.crl(path(root, ROOT_KEY), made, {}, 1)
        except PkiError as e:
            raise StateError(str(e)) from None
        write(root, ROOT_CERT, made)
        write(root, CHAIN, "")
        write(root, CA_CERT, own)
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


def ca_request(root: str) -> str:
    """The request for this node's intermediate: its key made once"""
    with locked(root):
        try:
            return etcdpki.request(key(root, CA_KEY))
        except PkiError as e:
            raise StateError(str(e)) from None


def grant_for(root: str, csr: str, address: str) -> Grant:
    """An intermediate CA for the key of `csr`, for the member at
    `address`: signed with the root on the root's holder, which keeps
    every chain one deep, else with this member's own intermediate (the
    root's holder cannot be reached, keel.mesh.etcd); the intermediate
    is constrained to the mesh's prefix. Raises StateError"""
    if not credentials(root):
        raise StateError("this node holds no etcd CA to issue with")
    rooted = holds_root(root)
    issuer = read(root, ROOT_CERT) if rooted else read(root, CA_CERT)
    try:
        made = etcdpki.issue(
            etcdpki.CA, path(root, ROOT_KEY if rooted else CA_KEY), issuer,
            csr, name(address), prefix=prefix_of(address))
        if rooted:
            record_issued(root, address, made)
    except PkiError as e:
        raise StateError(f"the request cannot be signed: {e}") from None
    chain = () if rooted else (issuer, *etcdpki.blocks(read(root, CHAIN)
                                                       or ""))
    return Grant(made, chain, read(root, ROOT_CERT), read(root, CRL),
                 holder(root))


def record_issued(root: str, address: str, certificate: str) -> None:
    """On the root's holder: an intermediate it signed, by its member's
    address, so a removal can revoke it (keel.mesh.etcdca)"""
    try:
        data = json.loads(read(root, ISSUED) or "{}")
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    entry = [etcdpki.serial(certificate),
             etcdpki.stamp(etcdpki.not_after(certificate))]
    data.setdefault(str(ipaddress.IPv6Address(address)), []).append(entry)
    write(root, ISSUED, json.dumps(data, sort_keys=True) + "\n")


def take_grant(root: str, grant: Grant) -> None:
    """Keep `grant` as this node's intermediate, once checked: it
    certifies this node's own key, chains to its root, and that root is
    the one this node holds, if any. Raises StateError"""
    with locked(root):
        try:
            mine = etcdpki.key_public(key(root, CA_KEY))
            certified = etcdpki.public(grant.certificate)
        except PkiError as e:
            raise StateError(str(e)) from None
        if mine != certified:
            raise StateError("the intermediate certifies another key, not"
                             " this node's")
        if not etcdpki.is_ca(grant.certificate) or not etcdpki.verified(
                grant.certificate, list(grant.chain), grant.root):
            raise StateError("the intermediate does not chain to the root"
                             " it came with")
        held = read(root, ROOT_CERT)
        if held and etcdpki.fingerprint(held) != etcdpki.fingerprint(
                grant.root):
            raise StateError("the grant is under another root than the one"
                             " this node holds")
        # the root first: a crash between leaves no intermediate that
        # chains to a root this node does not hold
        write(root, ROOT_CERT, grant.root)
        write(root, CHAIN, "".join(grant.chain))
        write(root, CA_CERT, grant.certificate)
        if grant.holder:
            write(root, HOLDER, str(ipaddress.IPv6Address(grant.holder))
                  + "\n")
    if grant.crl:
        take_crl(root, grant.crl)


def take_crl(root: str, found: str) -> bool:
    """Keep `found` as this member's CRL when the root signed it and it
    is newer than the one held; whether it was kept"""
    trusted = read(root, ROOT_CERT)
    if not trusted or not etcdpki.crl_verified(found, trusted):
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
    found = read(root, MEMBER_CERT)
    if not found or not os.path.exists(path(root, CLIENT_CERT)):
        return True
    leaf = etcdpki.blocks(found)[0]
    left = etcdpki.not_after(leaf) - now
    return left < timedelta(days=etcdpki.LEAF_DAYS // 3) or \
        etcdpki.addresses(leaf)[:1] != (str(ipaddress.IPv6Address(address)),)


def leaves(root: str, address: str, now: datetime) -> bool:
    """This member's certificate and keel's client certificate, issued
    with its own intermediate when missing, for another address, or
    with a third of their life left; whether they were issued now"""
    if not credentials(root):
        raise StateError("this node holds no etcd credentials yet")
    with locked(root):
        if not stale(root, address, now):
            return False
        issuer, own = path(root, CA_KEY), read(root, CA_CERT)
        chain = own + (read(root, CHAIN) or "")
        try:
            member = etcdpki.issue(
                etcdpki.MEMBER, issuer, own,
                etcdpki.request(key(root, MEMBER_KEY)), name(address),
                (address, LOOPBACK))
            client = etcdpki.issue(
                etcdpki.CLIENT, issuer, own,
                etcdpki.request(key(root, CLIENT_KEY)),
                f"keel client {name(address)}")
        except PkiError as e:
            raise StateError(str(e)) from None
        write(root, MEMBER_CERT, member + chain)
        write(root, CLIENT_CERT, client + chain)
    return True


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
