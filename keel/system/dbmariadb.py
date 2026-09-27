# Copyright (c) 2026 KeelLinux maintainers
"""What configuring a MariaDB server in a declared role comes to

One table for one engine, the way keel.inspect.dbengines holds one table
per engine for reading. Everything here is a pure function of the
description and of what the server answered: the file to write, the
statements to send, and the questions whose answers the planner needs.
Nothing here writes a file, runs a command or decides whether an action
is allowed; keel.system.database decides and keel.system.effects acts.

Three things about MariaDB that shape the rest:

- `server_id`, `bind-address` and `log_bin` are not settable while the
  server runs, so they go in a configuration file and the server is
  restarted once, and only when that file changed;
- a primary holds authorizations, which in MariaDB are the `Host` part of
  an account with `REPLICATION SLAVE`, and an IPv6 prefix has exactly one
  spelling there, the host pattern (keel.spec.origins);
- `skip_name_resolve` decides whether a grant whose host is a name can
  ever match, so it is only turned on when no declared origin is a name.
"""

import hashlib
from dataclasses import dataclass

from keel.spec.origins import host_pattern

DROPIN = "etc/mysql/mariadb.conf.d/99-keel-database.cnf"
CLIENT = ("mariadb", "--batch")
QUIET_CLIENT = ("mariadb", "--batch", "--skip-column-names")
SERVICE = "mariadb"
# The account both ends of a pair name. It is a constant and not a field
# of the description on purpose: the primary grants to it and the replica
# connects as it, so a field each operator could set differently on their
# own machine is a way to end up with two machines that cannot talk, and
# decision 0013 keeps every screen to the machine it runs on.
REPLICATION_USER = "repl"
# Relative, so the binary log lands in the data directory the package
# owns, rather than in a directory this code would have to create.
BINLOG = "mariadb-bin"
SCHEMAS_QUESTION = (
    "mariadb", "--batch", "--skip-column-names", "--execute",
    "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA",
)
# The schemas the server owns. Anything else is somebody's data, and
# becoming a replica replaces it with a copy of the primary.
SYSTEM_SCHEMAS = (
    "information_schema", "performance_schema", "mysql", "sys",
)
SERVER_ID_MODULUS = 2**31 - 1
HEADER = (
    "# Written by keel spec apply from database.server of the instance\n"
    "# description. Edited by hand, it is overwritten on the next run.\n"
    "[mysqld]\n"
)
# MariaDB's own escapes inside a single quoted literal.
ESCAPES = {
    "\\": "\\\\", "'": "\\'", "\n": "\\n", "\r": "\\r", "\x1a": "\\Z",
}
CONTROL = "a credential holding a control character or a NUL byte"


@dataclass(frozen=True)
class Statements:
    """SQL to send, and what it does, for one action of a plan"""

    text: str
    summary: str


def server_id(machine_id: str) -> int | None:
    """A server id of this machine's own, or None when it has no identity

    Every node of a pair needs a different one and nothing outside the
    machine may choose it, so it is derived from `/etc/machine-id`, which
    systemd gives each machine at its first boot. A description cannot
    carry it: two appliances deployed from one description would collide,
    and replication between them would stop with a duplicate id.
    """
    text = (machine_id or "").strip()
    if not text:
        return None
    digest = hashlib.sha256(text.encode()).digest()
    return int.from_bytes(digest[:8], "big") % SERVER_ID_MODULUS + 1


def dropin_text(
    identity: int, listen: list | None, role: str, resolve_names: bool,
) -> str:
    """The configuration file the declared role needs, as it is written"""
    lines = [HEADER, f"server_id = {identity}\n"]
    if listen:
        lines.append("bind-address = " + ",".join(str(one) for one in listen))
        lines.append("\n")
    if not resolve_names:
        lines.append("skip_name_resolve = ON\n")
    if role == "primary":
        lines.append(f"log_bin = {BINLOG}\nbinlog_format = ROW\n")
    return "".join(lines)


def user_schemas(lines: list[str]) -> list[str]:
    """The schemas that are somebody's data and not the server's own"""
    return [
        name for name in (one.strip() for one in lines)
        if name and name.lower() not in SYSTEM_SCHEMAS
    ]


def as_host(origin: str) -> str | None:
    """The origin as a grant holds it, or None when it has no spelling"""
    return host_pattern(str(origin))


def grants(hosts: list[str], password: str) -> Statements | None:
    """Authorize replication from each origin, and nothing else

    Idempotent: a re-run of apply alters the account it already created
    rather than failing, which is what makes the phase safe to repeat.
    """
    text = ""
    for host in hosts:
        quoted = literal(host)
        text += (
            f"CREATE USER IF NOT EXISTS '{REPLICATION_USER}'@{quoted}"
            f" IDENTIFIED BY {literal(password)};\n"
            f"ALTER USER '{REPLICATION_USER}'@{quoted}"
            f" IDENTIFIED BY {literal(password)};\n"
            f"GRANT REPLICATION SLAVE ON *.* TO"
            f" '{REPLICATION_USER}'@{quoted};\n"
        )
    if not text:
        return None
    return Statements(
        text + "FLUSH PRIVILEGES;\n",
        "authorize replication from " + ", ".join(hosts),
    )


def revoke(hosts: list[str]) -> Statements | None:
    """Drop the replication accounts the description no longer declares

    Convergence, not tidiness: `inspect` reads the authorizations off the
    server, so an account left behind is a field that never stops
    drifting. Dropping a replication grant loses no data.
    """
    if not hosts:
        return None
    text = "".join(
        f"DROP USER IF EXISTS '{REPLICATION_USER}'@{literal(host)};\n"
        for host in hosts
    )
    return Statements(
        text + "FLUSH PRIVILEGES;\n",
        "withdraw the authorization of " + ", ".join(hosts),
    )


def replicate_from(host: str, port: int, password: str) -> Statements:
    """Make this node a replica of that endpoint, with GTID

    `gtid_slave_pos` empty means from the start of the primary's binary
    log, which is right for a database that holds nothing, and is the only
    seeding this version does: see docs/apply.md.
    """
    return Statements(
        "STOP SLAVE;\n"
        "RESET SLAVE ALL;\n"
        "SET GLOBAL gtid_slave_pos = '';\n"
        f"CHANGE MASTER TO MASTER_HOST={literal(host)}, MASTER_PORT={port},"
        f" MASTER_USER='{REPLICATION_USER}',"
        f" MASTER_PASSWORD={literal(password)},"
        " MASTER_USE_GTID=slave_pos, MASTER_CONNECT_RETRY=2;\n"
        "START SLAVE;\n",
        f"replicate from [{host}]:{port} as '{REPLICATION_USER}'",
    )


def stop_replicating() -> Statements:
    """Stop replicating and forget where from, which is half of promoting

    `RESET SLAVE ALL` and not `STOP SLAVE` alone: a node that still holds
    the coordinates of its old primary would start following it again at
    the next restart, which is the split brain promotion exists to avoid.
    """
    return Statements(
        "STOP SLAVE;\nRESET SLAVE ALL;\n",
        "stop replicating and forget the primary",
    )


def destroy(schemas: list[str]) -> Statements:
    """Drop every schema that is not the server's own

    The one step of this feature that loses data. It is only ever built
    into a plan behind an explicit confirmation (keel.system.database).
    """
    text = "".join(
        f"DROP DATABASE IF EXISTS {name(one)};\n" for one in schemas
    )
    return Statements(
        text,
        "destroy the local database: drop " + ", ".join(schemas),
    )


def literal(value: str) -> str:
    """A single quoted SQL literal, escaped the way MariaDB reads one

    A credential comes from a file whose content nobody here chose, so it
    is escaped rather than trusted or pattern matched. A NUL byte or a
    control character other than the three MariaDB spells is refused by
    the caller before it gets here (`unquotable`).
    """
    escaped = "".join(ESCAPES.get(char, char) for char in str(value))
    return f"'{escaped}'"


def unquotable(value: str) -> str:
    """Why a value cannot go into a statement at all, or an empty string"""
    for char in str(value):
        if char in ESCAPES:
            continue
        if ord(char) < 0x20 or ord(char) == 0x7F:
            return CONTROL
    return ""


def name(identifier: str) -> str:
    """A back quoted identifier, as the server spelled it back to us"""
    return "`" + str(identifier).replace("`", "``") + "`"
