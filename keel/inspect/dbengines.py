# Copyright (c) 2026 KeelLinux maintainers
"""The three engines, and what each one says about itself

One table per engine: how to tell that its server is installed, which
questions to ask it, and how to read the answers. Every question is put to
the **server**, never to a configuration file, because a build that asserts
the setting it just wrote passes while the service does something else
(docs/traps.md, "Asserting the configuration is not asserting the
behaviour"): the PostgreSQL appliance shipped listening on IPv4 only with a
`listen_addresses` that read correctly.

Redis sets the standard here and the SQL engines are held to it rather than
the other way round. `INFO replication` answers `role:master` or
`role:slave` with the primary's host and port, and `INFO cluster` says
whether Cluster is on, in two lines with no parsing to speak of. MariaDB's
`SHOW REPLICA STATUS` and PostgreSQL's `pg_is_in_recovery()` are the same
question asked less conveniently, and each is asked here.

The one asymmetry, stated because it shows up in `keel diff`: MariaDB and
PostgreSQL keep a durable record of who may replicate, a grant and a
`pg_hba` rule, so a primary whose replicas are all down still reads as a
primary. Redis keeps none, so a master with no connected replica reads as
standalone and the report says why.
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from keel.inspect.dbreading import (
    NO_SPEC_ROLE,
    Reading,
    Value,
    columns,
    field_lines,
    found,
    is_local,
    listening_on,
    unknown,
)
from keel.inspect.tree import File

PRIMARY = "primary"
REPLICA = "replica"
STANDALONE = "standalone"

# The SQL of each question, and whether the answer needs its column names.
# `\\G` prints one `Name: value` per line and `--skip-column-names` takes the
# names away, leaving values nothing identifies: measured on the bench, where
# the primary's address arrived as a bare line and the reading found no
# primary at all on a machine that plainly had one.
MARIADB_SQL = {
    "status": ("SHOW REPLICA STATUS\\G", True),
    "replicas": ("SHOW REPLICA HOSTS", False),
    "variables": ("SHOW GLOBAL VARIABLES WHERE Variable_name IN"
                  " ('wsrep_on', 'log_bin', 'server_id', 'port',"
                  " 'read_only')", False),
    "grants": ("SELECT Host FROM mysql.user WHERE Repl_slave_priv = 'Y'",
               False),
    # Who writes through read_only. Measured on MariaDB 11.8: an account
    # with SUPER alone is refused with error 1290 and one with READ_ONLY
    # ADMIN writes, so SUPER is not asked about.
    "bypass": ("SELECT DISTINCT GRANTEE FROM"
               " information_schema.USER_PRIVILEGES"
               " WHERE PRIVILEGE_TYPE = 'READ_ONLY ADMIN'", False),
}
# The questions whose answers say what the server is. `bypass` is not one:
# a server that cannot list who writes through read_only still has a role.
MARIADB_ROLE_QUESTIONS = ("status", "replicas", "variables", "grants")
# Accounts of the server itself, which hold every privilege by design:
# root and mysql are Debian's socket accounts, mariadb.sys the definer of
# the sys views. The replication thread is not an account at all.
MARIADB_OWN_ACCOUNTS = ("root", "mysql", "mariadb.sys")
POSTGRESQL_SQL = {
    "state": "SELECT pg_is_in_recovery(),"
             " (SELECT count(*) FROM pg_stat_replication),"
             " current_setting('port')",
    "receiver": "SELECT conninfo FROM pg_stat_wal_receiver",
    "standby": "SELECT current_setting('primary_conninfo')",
    "hba": "SELECT type, address, netmask FROM pg_hba_file_rules"
           " WHERE 'replication' = ANY(database)",
}
REDIS_INFO = {
    "replication": "replication",
    "cluster": "cluster",
    "server": "server",
}
# Both spellings of the column that names the primary: MariaDB renamed the
# statement and kept the column, and a future rename should not be a defect.
PRIMARY_HOST_KEYS = ("Master_Host", "Source_Host")
PRIMARY_PORT_KEYS = ("Master_Port", "Source_Port")
NO_ORIGIN_RECORD = (
    "{engine} keeps no record of which origins may replicate: reachability"
    " is the listen addresses and the credential is {credential}, so there"
    " is no list on the machine to read"
)


@dataclass(frozen=True)
class Engine:
    """One database engine: how to find it, ask it, and read its answers"""

    name: str
    server_binaries: tuple[str, ...]
    client: str
    port: int
    questions: dict[str, tuple[str, ...]]
    read: Callable[[dict[str, File], File], Reading]

    def installed(self, matches: Callable[[str], list[str]]) -> str | None:
        """The server binary that proves this engine runs here, if any

        A pattern, because PostgreSQL keeps its server under the major
        version it belongs to and an appliance is not tied to one.
        """
        for pattern in self.server_binaries:
            found_paths = matches(pattern)
            if found_paths:
                return found_paths[0]
        return None


def mariadb_argv(sql: str, named: bool = False) -> tuple[str, ...]:
    """The client invocation for one question; `named` keeps the columns"""
    if named:
        return ("mariadb", "--batch", "--execute", sql)
    return ("mariadb", "--batch", "--skip-column-names", "--execute", sql)


def psql_argv(sql: str) -> tuple[str, ...]:
    return (
        "runuser", "-u", "postgres", "--",
        "psql", "--no-psqlrc", "-At", "-F", "\t", "-c", sql,
    )


def redis_argv(section: str) -> tuple[str, ...]:
    return ("redis-cli", "INFO", section)


def read_mariadb(answers: dict[str, File], sockets: File) -> Reading:
    """MariaDB's own view: the replica status, its replicas, its grants"""
    variables = dict(
        (row[0], row[1]) for row in columns(answers["variables"])
        if len(row) > 1
    )
    allowed = _mariadb_allowed(answers["grants"])
    status = answers["status"]
    # Any output at all is a replica row: SHOW REPLICA STATUS prints
    # nothing on a server that replicates from nowhere.
    replicating = bool(status.lines())
    role = _mariadb_role(variables, replicating, {
        name: answers[name] for name in MARIADB_ROLE_QUESTIONS
    }, allowed)
    return Reading(
        role=role,
        primary=_primary_from(field_lines(status), status,
                              PRIMARY_HOST_KEYS, PRIMARY_PORT_KEYS),
        allowed_from=allowed,
        listen=listening_on(
            sockets, _port(variables.get("port"), 3306)
        ),
        read_only=_mariadb_read_only(variables, answers["variables"]),
        bypass=_mariadb_bypass(answers["bypass"]),
    )


def _mariadb_read_only(variables: dict[str, str], answer: File) -> Value:
    """Whether the server refuses writes from ordinary accounts"""
    value = variables.get("read_only", "").upper()
    if value not in ("ON", "OFF"):
        return unknown(f"{answer.path} names no read_only")
    return found(value == "ON", answer.path)


def _mariadb_bypass(answer: File) -> Value:
    """The accounts that write through read_only, the server's own aside"""
    if not answer.readable:
        return unknown(f"{answer.path} {answer.problem}")
    accounts = [
        row[0] for row in columns(answer)
        if row and row[0].rpartition("@")[0].strip("'")
        not in MARIADB_OWN_ACCOUNTS
    ]
    return found(accounts, answer.path)


def _mariadb_role(
    variables: dict[str, str], replicating: bool,
    answers: dict[str, File], allowed: Value,
) -> Value:
    if variables.get("wsrep_on", "").upper() == "ON":
        return unknown(
            NO_SPEC_ROLE.format(mode="a Galera node (wsrep_on is ON)")
            + f", read from {answers['variables'].path}"
        )
    problem = _unreadable(answers)
    if problem:
        return unknown(problem)
    if replicating:
        return found(REPLICA, answers["status"].path)
    attached = [row for row in columns(answers["replicas"]) if row]
    if attached:
        return found(
            PRIMARY,
            f"{answers['replicas'].path} lists {len(attached)} replica(s)"
            " connected",
        )
    if allowed.known and allowed.value:
        return found(
            PRIMARY,
            f"{answers['grants'].path}: replication is granted from"
            f" {', '.join(allowed.value)}",
        )
    return found(
        STANDALONE,
        f"{answers['status'].path} is empty, no replica is connected and no"
        " replication is granted from anywhere but this machine",
    )


def _mariadb_allowed(grants: File) -> Value:
    """The Host of every account that may replicate, this machine aside"""
    if not grants.readable:
        return unknown(f"{grants.path} {grants.problem}")
    origins = [
        row[0] for row in columns(grants)
        if row and row[0] and not is_local(row[0])
    ]
    return found(list(dict.fromkeys(origins)), grants.path)


def read_postgresql(answers: dict[str, File], sockets: File) -> Reading:
    """PostgreSQL's recovery state, its walsenders, its pg_hba rules"""
    state = answers["state"]
    row = (columns(state) or [[]])[0]
    allowed = _postgresql_allowed(answers["hba"])
    role = _postgresql_role(row, state, answers, allowed)
    return Reading(
        role=role,
        primary=_postgresql_primary(answers),
        allowed_from=allowed,
        listen=listening_on(
            sockets, _port(row[2] if len(row) > 2 else None, 5432)
        ),
    )


def _postgresql_role(
    row: list[str], state: File, answers: dict[str, File], allowed: Value,
) -> Value:
    problem = _unreadable(answers)
    if problem:
        return unknown(problem)
    if not row:
        return unknown(f"{state.path} answered nothing")
    if row[0] == "t":
        return found(REPLICA, f"{state.path}: pg_is_in_recovery() is true")
    senders = row[1] if len(row) > 1 else "0"
    if senders.isdigit() and int(senders) > 0:
        return found(
            PRIMARY,
            f"{state.path}: pg_stat_replication has {senders} row(s), so a"
            " replica is streaming from here",
        )
    if allowed.known and allowed.value:
        return found(
            PRIMARY,
            f"{answers['hba'].path}: replication is allowed from"
            f" {', '.join(allowed.value)}",
        )
    return found(
        STANDALONE,
        f"{state.path}: not in recovery, nothing is streaming from here and"
        " pg_hba allows replication from this machine only",
    )


def _postgresql_primary(answers: dict[str, File]) -> Value:
    """Where a standby streams from: the walreceiver, else primary_conninfo

    `pg_stat_wal_receiver.conninfo` is the connection actually in use and
    PostgreSQL obfuscates its password, which is why it is asked first. The
    setting is the fallback for a standby that is not streaming, and only
    `host` and `port` are taken from it: the rest may hold a password and
    inspect never reads one.
    """
    for name in ("receiver", "standby"):
        answer = answers[name]
        for row in columns(answer):
            endpoint = _conninfo(row[0])
            if endpoint:
                return found(endpoint, answer.path)
    receiver = answers["receiver"]
    problem = receiver.problem or "names no host"
    return unknown(f"{receiver.path} {problem}")


def _conninfo(text: str) -> dict | None:
    """The host and port of a libpq connection string, and nothing else"""
    endpoint: dict = {}
    for word in text.split():
        key, sep, value = word.partition("=")
        if sep and key == "host" and value:
            endpoint["host"] = value
        elif sep and key == "port" and value.isdigit():
            endpoint["port"] = int(value)
    return endpoint or None


def _postgresql_allowed(hba: File) -> Value:
    """Every pg_hba rule for the replication pseudo database, as a prefix

    Read through `pg_hba_file_rules`, which is the server's own parse of
    the file and not the file. A `local` rule authorizes this machine's
    unix socket and names no origin.
    """
    if not hba.readable:
        return unknown(f"{hba.path} {hba.problem}")
    origins = []
    for row in columns(hba):
        if not row or row[0] == "local":
            continue
        address = row[1] if len(row) > 1 else ""
        netmask = row[2] if len(row) > 2 else ""
        origin = _prefix(address, netmask)
        if origin and not is_local(origin):
            origins.append(origin)
    return found(list(dict.fromkeys(origins)), hba.path)


def _prefix(address: str, netmask: str) -> str:
    """An address and a netmask as one prefix, or the address as written

    `pg_hba_file_rules` reports the prefix length as a netmask in its own
    family. Python's ipaddress takes a dotted IPv4 netmask and refuses an
    IPv6 one, so an IPv6 mask is counted here. Keywords such as `all` and
    `samenet`, and a host name, carry no netmask at all.
    """
    if not address:
        return ""
    if not netmask:
        return address
    length = _prefix_length(netmask)
    try:
        return str(
            ipaddress.ip_network(f"{address}/{length}", strict=False)
        )
    except ValueError:
        return address


def _prefix_length(netmask: str) -> str:
    """An IPv6 netmask as a prefix length; anything else is passed through"""
    try:
        bits = f"{int(ipaddress.IPv6Address(netmask)):0128b}"
    except ValueError:
        return netmask
    return str(len(bits) - len(bits.lstrip("1")))


def read_redis(answers: dict[str, File], sockets: File) -> Reading:
    """Redis's own view, the cleanest of the three: two INFO sections"""
    replication = field_lines(answers["replication"])
    cluster = field_lines(answers["cluster"])
    server = field_lines(answers["server"])
    return Reading(
        role=_redis_role(replication, cluster, answers),
        primary=_primary_from(
            replication, answers["replication"],
            ("master_host",), ("master_port",),
        ),
        allowed_from=unknown(
            NO_ORIGIN_RECORD.format(
                engine="Redis",
                credential="requirepass or an ACL user",
            )
        ),
        listen=listening_on(
            sockets, _port(server.get("tcp_port"), 6379)
        ),
    )


def _redis_role(
    replication: dict[str, str], cluster: dict[str, str],
    answers: dict[str, File],
) -> Value:
    if cluster.get("cluster_enabled") == "1":
        return unknown(
            NO_SPEC_ROLE.format(mode="a Redis Cluster node")
            + f", read from {answers['cluster'].path}"
        )
    problem = _unreadable(answers)
    if problem:
        return unknown(problem)
    role = replication.get("role")
    path = answers["replication"].path
    if role == "slave":
        return found(REPLICA, f"{path}: role:slave")
    if role != "master":
        return unknown(f"{path} reports no role")
    attached = replication.get("connected_slaves", "0")
    if attached.isdigit() and int(attached) > 0:
        return found(
            PRIMARY, f"{path}: role:master with connected_slaves:{attached}"
        )
    return found(
        STANDALONE,
        f"{path}: role:master with connected_slaves:0. Redis keeps no"
        " record of an authorization, so a primary whose replicas are all"
        " disconnected reads as standalone",
    )


def _primary_from(
    values: dict[str, str], output: File,
    host_keys: tuple[str, ...], port_keys: tuple[str, ...],
) -> Value:
    """The endpoint a replica replicates from, as the server names it"""
    source = output.path
    if not output.readable:
        return unknown(f"{source} {output.problem}")
    host = _first(values, host_keys)
    if not host:
        return unknown(f"{source} names no primary")
    endpoint: dict = {"host": host}
    port = _first(values, port_keys)
    if port and port.isdigit():
        endpoint["port"] = int(port)
    return found(endpoint, source)


def _first(values: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = values.get(key)
        if value:
            return value
    return ""


def _port(value: object, default: int) -> int:
    text = str(value or "")
    return int(text) if text.isdigit() else default


def _unreadable(answers: dict[str, File]) -> str:
    """The first answer that did not come back, and why"""
    for answer in answers.values():
        if not answer.readable:
            return f"{answer.path} {answer.problem}"
    return ""


ENGINES = (
    Engine(
        name="mariadb",
        server_binaries=("usr/sbin/mariadbd", "usr/sbin/mysqld"),
        client="mariadb",
        port=3306,
        questions={
            name: mariadb_argv(sql, named)
            for name, (sql, named) in MARIADB_SQL.items()
        },
        read=read_mariadb,
    ),
    Engine(
        name="postgresql",
        server_binaries=(
            "usr/lib/postgresql/*/bin/postgres",
            "usr/lib/postgresql/*/bin/pg_ctl",
        ),
        client="psql",
        port=5432,
        questions={
            name: psql_argv(sql) for name, sql in POSTGRESQL_SQL.items()
        },
        read=read_postgresql,
    ),
    Engine(
        name="redis",
        server_binaries=("usr/bin/redis-server", "usr/sbin/redis-server"),
        client="redis-cli",
        port=6379,
        questions={
            name: redis_argv(section)
            for name, section in REDIS_INFO.items()
        },
        read=read_redis,
    ),
)
