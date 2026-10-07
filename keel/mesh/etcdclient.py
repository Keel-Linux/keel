# Copyright (c) 2026 KeelLinux maintainers
"""etcd, asked over its v3 JSON gateway with keel's client certificate

etcd serves its gRPC API as JSON on its client port too (`/v3/...`),
the same calls etcdctl makes: the member list, `member add --learner`,
`member promote` and `member remove`, a member's status (its leader and
term) and `/health`. keel asks it with Python's TLS and the client
certificate this member issued itself (keel.mesh.etcdstate), trusting
the mesh's root alone, so keel needs no etcdctl and nothing it asks
can be answered by a server the mesh did not certify.

An etcd member ID is a 64-bit number, which the gateway writes as a
string; it is kept a string here.
"""

import base64
import http.client
import ipaddress
import json
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from keel.mesh import etcdstate
from keel.network.marker import path

# one member's answer; on a poor link a round trip is 250 ms or more
TIMEOUT = 10
MAX_ANSWER = 1048576


class EtcdError(Exception):
    """etcd did not answer, or refused, and why"""


@dataclass(frozen=True)
class Member:
    """One member as etcd lists it; `started` once it ran and named
    itself, which a learner added for a join that never came has not"""

    id: str
    name: str
    peer_urls: tuple[str, ...]
    client_urls: tuple[str, ...]
    learner: bool

    @property
    def started(self) -> bool:
        return bool(self.name)

    @property
    def address(self) -> str | None:
        """The overlay address of its first peer URL"""
        for url in self.peer_urls:
            try:
                return str(ipaddress.IPv6Address(urlsplit(url).hostname))
            except ValueError:
                continue
        return None


@dataclass(frozen=True)
class Status:
    member_id: str
    leader: str
    raft_term: int
    learner: bool


@dataclass(frozen=True)
class Value:
    """One key as a range gives it; `lease` the lease it is attached to"""

    key: str
    value: bytes
    mod_revision: int
    lease: str | None


def context(root: str) -> ssl.SSLContext:
    """TLS trusting the mesh's root alone, with keel's client
    certificate; raises EtcdError without one"""
    try:
        found = ssl.create_default_context(
            cafile=path(root, etcdstate.ROOT_CERT))
        found.load_cert_chain(path(root, etcdstate.CLIENT_CERT),
                              path(root, etcdstate.CLIENT_KEY))
    except (OSError, ssl.SSLError):
        raise EtcdError("this node holds no client certificate for etcd"
                        " yet") from None
    found.minimum_version = ssl.TLSVersion.TLSv1_3
    return found


def member(data: dict) -> Member:
    return Member(str(data["ID"]), str(data.get("name") or ""),
                  tuple(data.get("peerURLs") or ()),
                  tuple(data.get("clientURLs") or ()),
                  bool(data.get("isLearner")))


class Client:
    def __init__(self, endpoints: tuple[str, ...], tls: ssl.SSLContext,
                 timeout: float = TIMEOUT):
        self.endpoints = endpoints
        self.tls = tls
        self.timeout = timeout

    def call(self, endpoint: str, method: str, where: str,
             body: dict | None) -> tuple[int, bytes]:
        url = urlsplit(endpoint)
        connection = http.client.HTTPSConnection(
            url.hostname, url.port, context=self.tls, timeout=self.timeout)
        try:
            connection.request(method, where, None if body is None
                               else json.dumps(body),
                               {"Content-Type": "application/json"})
            answer = connection.getresponse()
            return answer.status, answer.read(MAX_ANSWER)
        finally:
            connection.close()

    def ask(self, where: str, body: dict) -> dict:
        """etcd's answer to one call, from the first member that gives
        one; raises EtcdError"""
        problems = []
        for endpoint in self.endpoints:
            try:
                status, data = self.call(endpoint, "POST", where, body)
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                problems.append(f"{endpoint}: {e}")
                continue
            return answered(status, data)
        raise EtcdError(f"no member answered: {'; '.join(problems)}")

    def cluster_id(self) -> str:
        """etcd's ID of the cluster, as its member list's header says"""
        found = self.ask("/v3/cluster/member/list", {})
        return str((found.get("header") or {}).get("cluster_id") or "")

    def members(self) -> list[Member]:
        found = self.ask("/v3/cluster/member/list", {})
        try:
            return [member(one) for one in found.get("members") or []]
        except (KeyError, TypeError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def add_learner(self, url: str) -> Member:
        found = self.ask("/v3/cluster/member/add",
                         {"peerURLs": [url], "isLearner": True})
        return member(found["member"])

    def promote(self, member_id: str) -> None:
        self.ask("/v3/cluster/member/promote", {"ID": member_id})

    def remove(self, member_id: str) -> None:
        self.ask("/v3/cluster/member/remove", {"ID": member_id})

    def put(self, key: str, value: str) -> int:
        found = self.ask("/v3/kv/put", {
            "key": base64.b64encode(key.encode()).decode(),
            "value": base64.b64encode(value.encode()).decode()})
        return int(found["header"]["revision"])

    def grant(self, ttl: int) -> str:
        """A lease of `ttl` seconds; its ID"""
        found = self.ask("/v3/lease/grant", {"TTL": ttl})
        try:
            return str(found["ID"])
        except KeyError:
            raise EtcdError("an answer that is not etcd's") from None

    def keepalive(self, lease: str) -> int:
        """The lease renewed once; the TTL etcd gives it again, 0 when the
        lease is gone (expired or revoked)"""
        found = self.ask("/v3/lease/keepalive", {"ID": lease})
        result = found.get("result")
        if not isinstance(result, dict):
            raise EtcdError(str((found.get("error") or {}).get("message")
                                or "an answer that is not etcd's"))
        return int(result.get("TTL") or 0)

    def time_to_live(self, lease: str) -> int:
        """The seconds a lease has left; -1 once it expired or was
        revoked, which is for good: a lease never comes back"""
        found = self.ask("/v3/lease/timetolive", {"ID": lease})
        try:
            return int(found.get("TTL", -1))
        except (TypeError, ValueError):
            raise EtcdError("an answer that is not etcd's") from None

    def revoke(self, lease: str) -> None:
        """The lease revoked, and every key attached to it deleted"""
        self.ask("/v3/lease/revoke", {"ID": lease})

    def prefix(self, key: str) -> list[Value]:
        """Every key under `key`, linearizable: a member cut off from the
        majority answers nothing"""
        found = self.ask("/v3/kv/range", {
            "key": encoded(key), "range_end": encoded(range_end(key))})
        try:
            return [Value(base64.b64decode(one["key"]).decode(),
                          base64.b64decode(one.get("value") or ""),
                          int(one.get("mod_revision") or 0),
                          str(one.get("lease") or "") or None)
                    for one in found.get("kvs") or []]
        except (KeyError, TypeError, ValueError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def swap(self, compare: list[dict], puts: list[tuple[str, bytes,
                                                         str | None]]) -> bool:
        """A transaction: every put, with its lease, only when every
        comparison holds; whether it did"""
        found = self.ask("/v3/kv/txn", {
            "compare": compare,
            "success": [{"request_put": {
                "key": encoded(key), "value": base64.b64encode(
                    value).decode(), **({"lease": lease} if lease else {})}}
                for key, value, lease in puts]})
        return found.get("succeeded") is True

    def status(self, endpoint: str) -> Status:
        """One member's own status, asked of it alone"""
        found = Client((endpoint,), self.tls, self.timeout).ask(
            "/v3/maintenance/status", {})
        return Status(str(found["header"]["member_id"]),
                      str(found.get("leader") or ""),
                      int(found.get("raftTerm") or 0),
                      bool(found.get("isLearner")))

    def health(self, endpoint: str) -> tuple[bool, str]:
        """Whether the member at `endpoint` says it is healthy, and why
        not"""
        try:
            status, data = self.call(endpoint, "GET", "/health", None)
            found = json.loads(data.decode())
        except (OSError, ssl.SSLError, http.client.HTTPException,
                ValueError) as e:
            return False, str(e)
        return (status == 200 and found.get("health") == "true",
                str(found.get("reason") or ""))


def encoded(key: str) -> str:
    return base64.b64encode(key.encode()).decode()


def range_end(key: str) -> str:
    """The end of the range of keys under `key`: its last byte plus one"""
    return key[:-1] + chr(ord(key[-1]) + 1)


def modified(key: str, revision: int) -> dict:
    """A comparison: `key` last modified at `revision` (0: absent)"""
    return {"key": encoded(key), "target": "MOD", "result": "EQUAL",
            "mod_revision": str(revision)}


def absent(key: str) -> dict:
    """A comparison: `key` does not exist"""
    return {"key": encoded(key), "target": "VERSION", "result": "EQUAL",
            "version": "0"}


def answered(status: int, data: bytes) -> dict:
    try:
        found = json.loads(data.decode())
    except (UnicodeDecodeError, ValueError):
        found = None
    if status != 200:
        said = found.get("message") if isinstance(found, dict) else None
        raise EtcdError(said or f"etcd answered {status}")
    if not isinstance(found, dict):
        raise EtcdError("an answer that is not etcd's")
    return found


def local(root: str) -> Client:
    """This member's etcd, on ::1"""
    return Client((etcdstate.client_url(etcdstate.LOOPBACK),), context(root))
