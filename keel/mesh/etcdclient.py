# Copyright (c) 2026 KeelLinux maintainers
"""etcd, asked over gRPC with etcdctl and this member's certificate

etcd takes the CN of a client certificate as its user only over gRPC:
its JSON gateway calls etcd with the member's own certificate, and
refuses any client certificate that carries a CN once auth is enabled
(etcd's docs, "Using TLS Common Name"). keel#83 makes the CN the user,
so keel asks etcd with `etcdctl` (etcd-client, the same source as
etcd-server, a dependency of keel-overlay-etcd), and keel renders
etcd's configuration with the gateway off (keel.mesh.etcdconf).

Every call is one `etcdctl ... -w json` process: an argument list,
never a shell; the certificates by their paths (on the controller of
the VIP, /proc/self/fd paths of memfds the child inherits, so its key
is never in a file); no secret in the arguments (a VIP's claim, the
one value keel writes, is signed and public); an environment of PATH
and GOMAXPROCS alone, so no ETCDCTL_* variable of the caller is taken
and the Go runtime's threads stay within the VIP controller's
TasksMax (keel.mesh.bridge); etcd's own
timeouts and the process's, which is longer by SPAWN. A call that
exits non-zero, does not finish in time, or prints anything but the
JSON it should, raises EtcdError: it never counts as done, and a
lease's keep-alive that raises is no renewal (keel.mesh.vipetcd).

etcd's IDs (members, leases) are 64-bit numbers; JSON gives them as
numbers, which Python reads exactly, and keel keeps them as decimal
strings, as the gateway gave them; etcdctl takes them in hex.
"""

import base64
import ipaddress
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from keel.mesh import etcdstate
from keel.network.marker import path

ETCDCTL = "etcdctl"
# one member's answer; on a poor link a round trip is 250 ms or more
TIMEOUT = 10
# what the process may take beyond etcd's own timeout: starting it,
# its TLS handshake, printing (about 35 ms measured, keel#83); the
# process is killed then, whatever etcdctl's own timeouts did, so a
# call never holds the VIP's controller much past its CALL_TIMEOUT
SPAWN = 0.5
MAX_ANSWER = 1048576
DEFAULT_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# etcdctl's own threads: a few, under the controller's TasksMax
GOMAXPROCS = "2"
# etcd's words for a lease that is gone (expired or revoked)
LEASE_GONE = "requested lease not found"
PERMISSIONS = {"read": 0, "write": 1, "readwrite": 2}


class EtcdError(Exception):
    """etcd did not answer, or refused, and why"""


@dataclass(frozen=True)
class Tls:
    """The files a call presents: the mesh's root alone trusted, this
    member's certificate and key; `fds`, descriptors those paths name
    (/proc/self/fd/N), which the child keeps"""

    ca: str
    certificate: str
    key: str
    fds: tuple[int, ...] = ()


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


Runner = Callable[..., subprocess.CompletedProcess]


def hex_id(value: str) -> str:
    """A decimal ID, as etcdctl takes it; raises EtcdError"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise EtcdError(f"{value!r} is not an etcd ID") from None
    if not 0 <= number < 2 ** 64:
        raise EtcdError(f"{value!r} is not an etcd ID")
    return format(number, "x")


def member(data: dict) -> Member:
    return Member(str(data["ID"]), str(data.get("name") or ""),
                  tuple(data.get("peerURLs") or ()),
                  tuple(data.get("clientURLs") or ()),
                  bool(data.get("isLearner")))


def seconds(value: float) -> str:
    return f"{max(1, int(value * 1000))}ms"


def said(stderr: str) -> str:
    """etcdctl's error, without its client's log lines"""
    lines = [one.strip() for one in stderr.splitlines() if one.strip()]
    errors = [one for one in lines if one.startswith("Error:")]
    found = (errors or lines or ["no reason given"])[-1]
    return found.removeprefix("Error:").strip()[:300]


class Client:
    def __init__(self, endpoints: tuple[str, ...], tls: Tls,
                 timeout: float = TIMEOUT, run: Runner | None = None):
        self.endpoints = endpoints
        self.tls = tls
        self.timeout = timeout
        self.run = run or subprocess.run

    def argv(self, args: tuple[str, ...],
             endpoints: tuple[str, ...] | None = None) -> list[str]:
        where = ",".join(endpoints or self.endpoints)
        return [ETCDCTL, f"--endpoints={where}",
                f"--cacert={self.tls.ca}", f"--cert={self.tls.certificate}",
                f"--key={self.tls.key}",
                f"--dial-timeout={seconds(self.timeout)}",
                f"--command-timeout={seconds(self.timeout)}", "-w", "json",
                *args]

    def process(self, args: tuple[str, ...], stdin: str | None,
                endpoints: tuple[str, ...] | None
                ) -> subprocess.CompletedProcess:
        try:
            return self.run(
                self.argv(args, endpoints), input=stdin, capture_output=True,
                text=True, check=False, timeout=self.timeout + SPAWN,
                env={"PATH": os.environ.get("PATH") or DEFAULT_PATH,
                     "GOMAXPROCS": GOMAXPROCS},
                pass_fds=self.tls.fds)
        except subprocess.TimeoutExpired:
            raise EtcdError(f"etcdctl {args[0]}: no answer within"
                            f" {self.timeout + SPAWN:g} s") from None
        except (OSError, ValueError) as e:
            raise EtcdError(f"etcdctl could not be run: {e}") from None

    def ctl(self, *args: str, stdin: str | None = None,
            endpoints: tuple[str, ...] | None = None) -> object:
        """etcdctl's JSON answer to one call; raises EtcdError when it
        fails or prints anything else"""
        done = self.process(args, stdin, endpoints)
        if done.returncode != 0:
            raise EtcdError(f"etcdctl {args[0]}: {said(done.stderr or '')}")
        return parsed(done.stdout, args[0])

    def ask(self, *args: str, stdin: str | None = None) -> dict:
        found = self.ctl(*args, stdin=stdin)
        if not isinstance(found, dict):
            raise EtcdError(f"etcdctl {args[0]}: an answer that is not"
                            " etcd's")
        return found

    def cluster_id(self) -> str:
        """etcd's ID of the cluster, as its member list's header says"""
        found = self.ask("member", "list")
        return str((found.get("header") or {}).get("cluster_id") or "")

    def members(self) -> list[Member]:
        found = self.ask("member", "list")
        try:
            return [member(one) for one in found.get("members") or []]
        except (KeyError, TypeError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def add_learner(self, url: str) -> Member:
        # etcd takes no name at an add (the member names itself when it
        # starts); etcdctl wants one, for the lines it prints
        found = self.ask("member", "add", "keel-learner",
                         f"--peer-urls={url}", "--learner")
        try:
            return member(found["member"])
        except (KeyError, TypeError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def promote(self, member_id: str) -> None:
        self.ask("member", "promote", hex_id(member_id))

    def remove(self, member_id: str) -> None:
        self.ask("member", "remove", hex_id(member_id))

    def put(self, key: str, value: str) -> int:
        found = self.ask("put", "--", key, value)
        try:
            return int(found["header"]["revision"])
        except (KeyError, TypeError, ValueError):
            raise EtcdError("an answer that is not etcd's") from None

    def delete(self, key: str) -> int:
        """The key deleted; how many were"""
        found = self.ask("del", "--", key)
        return int(found.get("deleted") or 0)

    def grant(self, ttl: int) -> str:
        """A lease of `ttl` seconds; its ID"""
        found = self.ask("lease", "grant", str(int(ttl)))
        if found.get("Error") or "ID" not in found:
            raise EtcdError(str(found.get("Error")
                                or "an answer that is not etcd's"))
        return str(found["ID"])

    def keepalive(self, lease: str) -> int:
        """The lease renewed once; the TTL etcd gives it again, 0 when etcd
        says the lease is gone (expired or revoked). Anything else that
        is not a TTL raises EtcdError: no renewal"""
        done = self.process(("lease", "keep-alive", "--once",
                             hex_id(lease)), None, None)
        if done.returncode != 0:
            why = said(done.stderr or "")
            if LEASE_GONE in why:
                return 0
            raise EtcdError(f"etcdctl lease: {why}")
        found = parsed(done.stdout, "lease")
        try:
            ttl = int(found["TTL"])
        except (KeyError, TypeError, ValueError):
            raise EtcdError("an answer that is not etcd's") from None
        return max(ttl, 0)

    def time_to_live(self, lease: str) -> int:
        """The seconds a lease has left; -1 once it expired or was
        revoked, which is for good: a lease never comes back"""
        found = self.ask("lease", "timetolive", hex_id(lease))
        try:
            return int(found["ttl"])
        except (KeyError, TypeError, ValueError):
            raise EtcdError("an answer that is not etcd's") from None

    def revoke(self, lease: str) -> None:
        """The lease revoked, and every key attached to it deleted"""
        self.ask("lease", "revoke", hex_id(lease))

    def prefix(self, key: str) -> list[Value]:
        """Every key under `key`, linearizable: a member cut off from the
        majority answers nothing"""
        found = self.ask("get", "--prefix", "--", key)
        try:
            return [Value(base64.b64decode(one["key"]).decode(),
                          base64.b64decode(one.get("value") or ""),
                          int(one.get("mod_revision") or 0),
                          str(one.get("lease") or "") or None)
                    for one in found.get("kvs") or []]
        except (KeyError, TypeError, ValueError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def swap(self, compare: list[dict], puts: list[tuple[str, bytes,
                                                         str | None]],
             deletes: tuple[str, ...] = ()) -> bool:
        """A transaction: every put, with its lease (none: the key leaves
        the lease it had), and every delete, only when every comparison
        holds; whether it did"""
        lines = [condition(one) for one in compare] + [""]
        for key, value, lease in puts:
            lines.append("put " + (f"--lease={hex_id(lease)} " if lease
                                   else "")
                         + f"-- {quoted(key.encode())} {quoted(value)}")
        lines += [f"del -- {quoted(key.encode())}" for key in deletes]
        found = self.ask("txn", "--interactive=false",
                         stdin="\n".join(lines + ["", "", ""]))
        return found.get("succeeded") is True

    def status(self, endpoint: str) -> Status:
        """One member's own status, asked of it alone"""
        found = self.ctl("endpoint", "status", endpoints=(endpoint,))
        try:
            one = found[0]["Status"]
            return Status(str(one["header"]["member_id"]),
                          str(one.get("leader") or ""),
                          int(one.get("raftTerm") or 0),
                          bool(one.get("isLearner")))
        except (KeyError, TypeError, ValueError, IndexError):
            raise EtcdError("an answer that is not etcd's") from None

    def health(self, endpoint: str) -> tuple[bool, str]:
        """Whether the member at `endpoint` says it is healthy, and why
        not"""
        try:
            done = self.process(("endpoint", "health"), None, (endpoint,))
            found = parsed(done.stdout, "endpoint")[0]
        except (EtcdError, TypeError, IndexError, KeyError) as e:
            return False, str(e)
        if not isinstance(found, dict):
            return False, "an answer that is not etcd's"
        return (found.get("health") is True and done.returncode == 0,
                str(found.get("error") or ""))

    def move_leader(self, member_id: str) -> None:
        """The leader, which must be this client's endpoint, hands its
        leadership to `member_id`"""
        self.ask("move-leader", hex_id(member_id))

    # what the root's holder does, with its admin certificate (CN root):
    # etcd's users and roles (keel.mesh.etcdauth)
    def auth_enabled(self) -> bool:
        return self.ask("auth", "status").get("enabled") is True

    def plain(self, *args: str) -> None:
        """A call etcdctl answers in words whatever -w says (`auth
        enable`, `auth disable`): its exit status alone; raises
        EtcdError"""
        done = self.process(args, None, None)
        if done.returncode != 0:
            raise EtcdError(f"etcdctl {args[0]}: {said(done.stderr or '')}")

    def auth_enable(self) -> None:
        self.plain("auth", "enable")

    def auth_disable(self) -> None:
        self.plain("auth", "disable")

    def users(self) -> list[str]:
        return [str(one) for one in self.ask("user", "list").get("users")
                or []]

    def user_roles(self, user: str) -> list[str]:
        return [str(one) for one in self.ask("user", "get", "--", user).get(
            "roles") or []]

    def user_add(self, user: str) -> None:
        """A user with no password: it is known only by a certificate
        whose CN is its name, which only the root issues"""
        self.ask("user", "add", "--no-password", "--", user)

    def user_delete(self, user: str) -> None:
        self.ask("user", "delete", "--", user)

    def grant_role(self, user: str, role: str) -> None:
        self.ask("user", "grant-role", "--", user, role)

    def revoke_role(self, user: str, role: str) -> None:
        self.ask("user", "revoke-role", "--", user, role)

    def roles(self) -> list[str]:
        return [str(one) for one in self.ask("role", "list").get("roles")
                or []]

    def role_add(self, role: str) -> None:
        self.ask("role", "add", "--", role)

    def role_delete(self, role: str) -> None:
        self.ask("role", "delete", "--", role)

    def permissions(self, role: str) -> set[tuple[str, str, str]]:
        """A role's permissions: (kind, key, range end), the end empty
        for one key"""
        found = self.ask("role", "get", "--", role)
        names = {v: k for k, v in PERMISSIONS.items()}
        try:
            return {(names[int(one.get("permType") or 0)],
                     base64.b64decode(one.get("key") or "").decode(),
                     base64.b64decode(one.get("range_end") or "").decode())
                    for one in found.get("perm") or []}
        except (KeyError, TypeError, ValueError, AttributeError):
            raise EtcdError("an answer that is not etcd's") from None

    def permit(self, role: str, kind: str, key: str) -> None:
        """`kind` (read, write, readwrite) on every key under `key`"""
        if kind not in PERMISSIONS:
            raise EtcdError(f"{kind!r} is not a permission")
        self.ask("role", "grant-permission", "--prefix", "--", role, kind,
                 key)

    def unpermit(self, role: str, key: str) -> None:
        self.ask("role", "revoke-permission", "--prefix", "--", role, key)


def parsed(stdout: str, call: str) -> object:
    if len(stdout) > MAX_ANSWER:
        raise EtcdError(f"etcdctl {call}: an answer too long")
    try:
        return json.loads(stdout)
    except ValueError:
        raise EtcdError(f"etcdctl {call}: an answer that is not"
                        " JSON") from None


def quoted(raw: bytes) -> str:
    """`raw` as one double-quoted word of etcdctl's txn lines, which it
    reads with Go's strconv.Unquote: printable ASCII as itself, every
    other byte escaped, so any key or value goes through unchanged"""
    out = []
    for byte in raw:
        char = chr(byte)
        if char in '"\\':
            out.append("\\" + char)
        elif 0x20 <= byte < 0x7f:
            out.append(char)
        else:
            out.append(f"\\x{byte:02x}")
    return '"' + "".join(out) + '"'


def condition(one: dict) -> str:
    """A comparison (`modified`, `absent`) as a txn line"""
    key = quoted(base64.b64decode(one["key"]))
    if one.get("target") == "MOD":
        return f'mod({key}) = "{int(one["mod_revision"])}"'
    if one.get("target") == "VERSION":
        return f'ver({key}) = "{int(one["version"])}"'
    raise EtcdError(f"not a comparison keel makes: {one!r}")


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


def files(root: str, certificate: str = etcdstate.MEMBER_CERT,
          key: str = etcdstate.MEMBER_KEY) -> Tls:
    """This member's certificate and key and the mesh's root, by path;
    raises EtcdError without them"""
    found = Tls(path(root, etcdstate.ROOT_CERT), path(root, certificate),
                path(root, key))
    if not all(os.path.exists(one) for one in
               (found.ca, found.certificate, found.key)):
        raise EtcdError("this node holds no certificate for etcd yet")
    return found


def local(root: str) -> Client:
    """This member's etcd, on ::1, as this member"""
    return Client((etcdstate.client_url(etcdstate.LOOPBACK),), files(root))


def admin(root: str, endpoints: tuple[str, ...] | None = None) -> Client:
    """etcd as its root user, on the root's holder alone (its admin
    certificate, CN root, which the root issues to its own holder only);
    raises EtcdError elsewhere"""
    return Client(endpoints or (etcdstate.client_url(etcdstate.LOOPBACK),),
                  files(root, etcdstate.ADMIN_CERT, etcdstate.ADMIN_KEY))
