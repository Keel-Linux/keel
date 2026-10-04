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
