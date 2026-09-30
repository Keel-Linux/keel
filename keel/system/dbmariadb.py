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
import ipaddress
from dataclasses import dataclass

from keel.spec.origins import host_pattern

DROPIN = "etc/mysql/mariadb.conf.d/99-keel-database.cnf"
CLIENT = ("mariadb", "--batch")
QUIET_CLIENT = ("mariadb", "--batch", "--skip-column-names")
# Whether the server answers at all, asked before anything else
# (keel.system.dbready).
PING = QUIET_CLIENT + ("--execute", "SELECT 1")
SERVICE = "mariadb"
# The account both ends of a pair name. It is a constant and not a field
# of the description on purpose: the primary grants to it and the replica
# connects as it, so a field each operator could set differently on their
# own machine is a way to end up with two machines that cannot talk, and
# decision 0013 keeps every screen to the machine it runs on.
REPLICATION_USER = "repl"
# What mariadb-dump --single-transaction --gtid --master-data=2 --routines
# --events --triggers needs, measured against MariaDB 11.8 on Debian 13:
# no RELOAD and no LOCK TABLES, because the server hands the dump a
# consistent binary log position without FLUSH TABLES WITH READ LOCK.
SEED_GRANTS = ("SELECT", "SHOW VIEW", "TRIGGER", "EVENT")
GRANTED = ", ".join(("REPLICATION SLAVE",) + SEED_GRANTS)
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
# A replica takes no writes but its primary's (tracker#26). The
# replication thread and accounts holding READ_ONLY ADMIN, root among
# them, write through it; an application's account holds privileges on
# its own schema only and is refused with error 1290.
READ_ONLY_LINE = "read_only = ON\n"
# Listen entries that are not addresses and name no one machine.
WILDCARDS = ("*", "localhost")
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


def server_id(
    machine_id: str, listen: list | None = None, overlay: list | tuple = (),
) -> int | None:
    """A server id of this machine's own, or None when it has nothing to
    derive one from

    Every node of a pair needs a different one and no description may
    choose it: two appliances deployed from one description would collide,
    and two nodes with the same server id stop replicating. So it is
    derived from what is this machine's own, and from two things and not
    one, because the first turned out not to be enough.

    `/etc/machine-id` is what systemd gives a machine at its first boot,
    and it is the right source. Measured on the bench: the published
    `core` layer ships a populated one, so every appliance assembled from
    it, and both live appliances on the build host, hold the same value
    and would take the same server id. That is a defect of the layer
    (docs/traps.md), and a feature that breaks silently when it is
    present is a feature that breaks. The addresses the server answers on
    are mixed in for that reason: a pair on one /64 differs there by
    construction, whatever the layer shipped.

    So two machines collide only when they hold the same machine-id and
    answer on the same addresses, which is to say when they are the same
    machine.

    Except that `listen` is `::` on every node that answers everywhere,
    and then it tells nobody apart. So on a node with a WireGuard overlay
    the seed is the machine-id, the overlay address(es) (`overlay`, one
    per family, unique to each node and stable, decision 0020) and the
    listen entries that name this machine: wildcards and loopback are
    left out. A node without an overlay keeps the seed, and the server
    id, it had: changing it restarts the server under a new identity.
    """
    text = (machine_id or "").strip()
    parts = [str(one).strip() for one in (listen or [])]
    if overlay:
        parts = [one for one in parts if not _anywhere_or_here(one)]
        parts += [str(one).strip() for one in overlay]
    if not text and not any(parts):
        return None
    seed = "\n".join([text] + sorted(parts))
    digest = hashlib.sha256(seed.encode()).digest()
    return int.from_bytes(digest[:8], "big") % SERVER_ID_MODULUS + 1


def _anywhere_or_here(entry: str) -> bool:
    """A listen entry every node shares: a wildcard or this machine only"""
    if entry.lower() in WILDCARDS:
        return True
    try:
        address = ipaddress.ip_address(entry)
    except ValueError:
        return False
    return address.is_unspecified or address.is_loopback


def overlay_addresses(doc: dict) -> list[str]:
    """This node's WireGuard overlay addresses, without their prefix

    network.overlay.wireguard.address and ipv4_address. The prefix length
    is left out: it is the network's, and changing it must not give the
    server a new identity. A value that is not an address counts as none;
    keel spec validate refuses it before apply gets here.
    """
    overlay = ((doc.get("network") or {}).get("overlay") or {})
    wireguard = overlay.get("wireguard") or {}
    found = []
    for key in ("address", "ipv4_address"):
        value = wireguard.get(key)
        if not value:
            continue
        try:
            found.append(str(ipaddress.ip_interface(str(value)).ip))
        except ValueError:
            continue
    return found


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
    if role == "replica":
        lines.append(READ_ONLY_LINE)
    return "".join(lines)


def writable(text: str) -> str:
    """The configuration file without its read_only line, for a promotion"""
    return "".join(
        line for line in text.splitlines(keepends=True)
        if line != READ_ONLY_LINE
    )


def set_read_only(on: bool) -> Statements:
    """Turn read_only on or off now, without waiting for a restart

    SET GLOBAL waits for the running write transactions to finish, and
    it needs no restart: the file carries the same value into the next.
    """
    value = "ON" if on else "OFF"
    return Statements(
        f"SET GLOBAL read_only = {value};\n",
        f"set read_only {value}: "
        + ("a replica takes no writes of its own" if on
           else "this role takes the application's writes"),
    )


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
    """Authorize replication from each origin, and the copy that seeds it

    `REPLICATION SLAVE` streams the binary log. The rest (`SEED_GRANTS`)
    is what mariadb-dump needs to copy the data the primary held before a
    replica existed (keel.system.dbseed), and SELECT on *.* is also what
    reads the primary's accounts so the replica can hold them. Nothing is
    written with them, but they let `repl` read every table, the password
    hashes of mysql.global_priv included, root's among them: docs/apply.md
    says why this is the grant and not one per schema. Idempotent: a
    re-run of apply alters the account it already
    created rather than failing, and GRANT only adds, so a primary set up
    by an older keel gains them at its next apply.
    """
    text = ""
    for host in hosts:
        quoted = literal(host)
        text += (
            f"CREATE USER IF NOT EXISTS '{REPLICATION_USER}'@{quoted}"
            f" IDENTIFIED BY {literal(password)};\n"
            f"ALTER USER '{REPLICATION_USER}'@{quoted}"
            f" IDENTIFIED BY {literal(password)};\n"
            f"GRANT {GRANTED} ON *.* TO"
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


def replicate_from(
    host: str, port: int, password: str, position: str = "",
) -> Statements:
    """Make this node a replica of that endpoint, with GTID

    `position` is the GTID position of the copy this node was just seeded
    with (keel.system.dbseed), so replication resumes exactly after the
    last transaction the copy holds. Empty means from the start of the
    primary's binary log, which is only right when the primary has never
    logged anything yet.
    """
    return Statements(
        "STOP SLAVE;\n"
        "RESET SLAVE ALL;\n"
        f"SET GLOBAL gtid_slave_pos = {literal(position)};\n"
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


def promote() -> Statements:
    """Stop replicating, forget the primary, then take writes

    In that order: read_only goes off only once nothing arrives from the
    old primary any more.
    """
    stop = stop_replicating()
    return Statements(
        stop.text + set_read_only(False).text,
        stop.summary + ", then turn read_only off",
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
