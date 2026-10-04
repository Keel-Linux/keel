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
| `cluster.json` | the cluster: `new` or `existing`, its members, its token |
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
PEER_PORT = 2380
CLIENT_PORT = 2379
STATES = ("new", "existing")
LOOPBACK = "::1"


class StateError(Exception):
    """The credentials or the cluster cannot be used, and why"""


@dataclass(frozen=True)
class Grant:
    """A member's intermediate CA, the chain above it (its issuer's
    first, the root left out), and the mesh's root"""

    certificate: str
    chain: tuple[str, ...]
    root: str


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

    def addresses(self) -> tuple[str, ...]:
        return tuple(one.address for one in self.members)

    def dumps(self) -> dict:
        return {"state": self.state, "token": self.token,
                "members": [{"public_key": one.public_key,
                             "address": one.address}
                            for one in self.members]}

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
            return Cluster(data["state"], members, str(data["token"]))
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
    found = read(root, ROOT_CERT)
    return etcdpki.fingerprint(found) if found else None


def key(root: str, relative: str) -> str:
    """The key file at `relative`, made when there is none; its path"""
    if not os.path.exists(path(root, relative)):
        write(root, relative, etcdpki.new_key())
    return path(root, relative)


def make_root(root: str, mesh_id: str) -> bool:
    """The mesh's root CA and this node's intermediate under it, when
    this node holds no credentials; whether they were made now"""
    with locked(root):
        if credentials(root):
            return False
        try:
            made = etcdpki.root(key(root, ROOT_KEY), mesh_id)
            own = etcdpki.issue(etcdpki.CA, path(root, ROOT_KEY), made,
                                etcdpki.request(key(root, CA_KEY)),
                                f"keel mesh {mesh_id[:16]} first member")
        except PkiError as e:
            raise StateError(str(e)) from None
        write(root, CHAIN, "")
        write(root, CA_CERT, own)
        write(root, ROOT_CERT, made)
    return True


def ca_request(root: str) -> str:
    """The request for this node's intermediate: its key made once"""
    with locked(root):
        try:
            return etcdpki.request(key(root, CA_KEY))
        except PkiError as e:
            raise StateError(str(e)) from None


def grant_for(root: str, csr: str, who: str) -> Grant:
    """An intermediate CA for the key of `csr`, named `who`, signed with
    this member's own intermediate; raises StateError"""
    if not credentials(root):
        raise StateError("this node holds no etcd CA to issue with")
    own = read(root, CA_CERT)
    try:
        made = etcdpki.issue(etcdpki.CA, path(root, CA_KEY), own, csr, who)
    except PkiError as e:
        raise StateError(f"the request cannot be signed: {e}") from None
    return Grant(made, (own, *etcdpki.blocks(read(root, CHAIN) or "")),
                 read(root, ROOT_CERT))


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
        write(root, CHAIN, "".join(grant.chain))
        write(root, CA_CERT, grant.certificate)
        write(root, ROOT_CERT, grant.root)


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
