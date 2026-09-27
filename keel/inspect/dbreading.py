# Copyright (c) 2026 KeelLinux maintainers
"""What one database server says about itself, field by field

A Reading is the result of asking a server what it is. Every field carries
either a value and what answered, or nothing and why, so the caller turns
it into findings without knowing which engine produced it (the shape the
ipv6 probe settled: a value, or a reason, never a guess).

Nothing here runs a command or reads a file.
"""

import ipaddress
from dataclasses import dataclass, field

from keel.inspect.tree import File

# A role the spec has no value for. The reading says so instead of
# flattening a Galera or Redis Cluster node into primary, which is what
# lets decision 0013 add those roles later without renaming these.
NO_SPEC_ROLE = (
    "{mode} has no role in the spec yet; decision 0013 leaves room for it"
)
LOCAL_ORIGINS = ("localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1")
# `ss -lntH` prints State, Recv-Q, Send-Q, then the local address and port.
LOCAL_ADDRESS_FIELD = 3


@dataclass(frozen=True)
class Value:
    """One field of a reading: the value and its source, or the reason"""

    value: object = None
    source: str = ""
    problem: str = ""

    @property
    def known(self) -> bool:
        return self.value is not None


def found(value: object, source: str) -> Value:
    return Value(value, source=source)


def unknown(problem: str) -> Value:
    return Value(problem=problem)


@dataclass(frozen=True)
class Reading:
    """A server's own view of itself

    `role` is the observed role. `primary` is the endpoint it replicates
    from, a mapping of host and port, and is only read when the role is
    replica. `allowed_from` is the list of origins the server holds an
    authorization for, which is not the list of replicas: see docs/spec.md.
    """

    role: Value = field(default_factory=Value)
    primary: Value = field(default_factory=Value)
    allowed_from: Value = field(default_factory=Value)
    listen: Value = field(default_factory=Value)


def field_lines(output: File) -> dict[str, str]:
    """`Name: value` lines, as `SHOW ... \\G` and redis INFO print them

    Redis uses a colon with no space (`role:master`), MariaDB's vertical
    output a colon and padding; both parse the same way. The first colon
    wins, so a value that holds one survives.
    """
    values = {}
    for line in (output.text or "").splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip():
            values[name.strip()] = value.strip()
    return values


def columns(output: File, separator: str = "\t") -> list[list[str]]:
    """Rows of a batch query, split into their columns"""
    return [
        line.split(separator)
        for line in (output.text or "").splitlines()
        if line.strip()
    ]


def is_local(origin: str) -> bool:
    """Whether an origin means this machine and authorizes nobody else

    A loopback address, however it is written: `::1`, `127.0.0.1`, and the
    host prefixes `pg_hba` reports for either (`127.0.0.1/32`).
    """
    text = origin.strip().lower()
    if text in LOCAL_ORIGINS:
        return True
    try:
        return ipaddress.ip_network(text, strict=False).is_loopback
    except ValueError:
        return False


def listening_on(sockets: File, port: int) -> Value:
    """The addresses a server answers on, from the sockets it holds open

    Read from `ss`, not from the engine's own setting, because the setting
    is what the appliance was told and the socket is what it did. The
    PostgreSQL appliance shipped with `listen_addresses` reading correctly
    and one family bound (docs/traps.md), and a `listen` field taken from
    the configuration would have agreed with it.
    """
    if not sockets.readable:
        return unknown(f"{sockets.path} {sockets.problem}")
    addresses = []
    for line in sockets.lines():
        fields = line.split()
        if len(fields) < LOCAL_ADDRESS_FIELD + 1:
            continue
        address, sep, listening = fields[LOCAL_ADDRESS_FIELD].rpartition(":")
        if not sep or listening != str(port):
            continue
        addresses.append(address.strip("[]"))
    if not addresses:
        return unknown(
            f"{sockets.path} shows nothing listening on port {port}"
        )
    return found(sorted(dict.fromkeys(addresses)), sockets.path)
