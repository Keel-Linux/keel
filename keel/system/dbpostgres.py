# Copyright (c) 2026 KeelLinux maintainers
"""What configuring a PostgreSQL server in a declared role comes to

The twin of keel.system.dbmariadb, one table for one engine, the way
keel.inspect.dbengines holds one table per engine for reading
(handbook decision 0054). Everything here is a pure function of the
description and of what the server answered: the file to write, the
statements to send, and the questions whose answers the planner needs.
Nothing here writes a file, runs a command or decides whether an action
is allowed; keel.system.database decides and keel.system.effects acts.

Three things about PostgreSQL that shape the rest, and how they differ
from the MariaDB twin:

- a standby refuses writes while it is in recovery, so there is no
  read_only line, no role drop-in and no account lock: the enforcement
  MariaDB builds from a privilege is here a property of the role
  itself (0054). The one thing a promoted standby must not do, take
  writes while it still follows the old primary, is what
  `pg_promote()` refuses by itself;
- the configuration it cannot change while it runs (`listen_addresses`,
  `wal_level`, the TLS file names) goes in one drop-in under the
  cluster's conf.d, and the server is restarted once, and only when
  that file changed. Debian's cluster directories are versioned
  (/etc/postgresql/17/main), so the paths are resolved from what is
  installed and not spelled out here;
- the authorization surface is pg_hba.conf, and this module writes the
  whole of it through the hba_file setting: the base rules Debian
  ships, plus one line per declared origin for the replication
  pseudo-database. A password goes into the line, so the password
  authentication method is scram-sha-256 and the line is only ever
  written for an origin the description declares.
"""

import glob
import os
from dataclasses import dataclass

# The cluster's configuration directory carries the version Debian
# installed (17 on Debian 13), so the paths are resolved from the root,
# never spelled out: cluster_paths() is the resolver, and the
# appliance ships exactly one cluster.
CONF_GLOB = "etc/postgresql/*/main"
DROPIN_NAME = "99-keel-database.conf"
FOLLOW_DROPIN_NAME = "99-keel-follow.conf"
HBA_DROPIN_NAME = "99-keel-pg_hba.conf"
DATADIR_GLOB = "var/lib/postgresql/*/main"
# The drop-in that points the server at keel's hba file and carries the
# listen addresses lives in conf.d; Debian's postgresql.conf already
# includes conf.d, measured on the published layer.
DROPIN_HEADER = (
    "# Written by keel spec apply from database.server of the instance\n"
    "# description. Edited by hand, it is overwritten on the next run.\n"
)
HBA_HEADER = (
    "# Written by keel spec apply: the whole authorization surface of\n"
    "# this server (0054), pointed at by hba_file in the drop-in beside\n"
    "# this file. Edited by hand, it is overwritten on the next run.\n"
    "# TYPE  DATABASE        USER            ADDRESS                 METHOD\n"
)
# What Debian ships for the local machine, kept so the postgres OS user
# and loopback clients keep their access when hba_file moves the rules
# to this file.
HBA_BASE = (
    "local   all             all                                     peer\n"
    "host    all             all             127.0.0.1/32            scram-sha-256\n"
    "host    all             all             ::1/128                 scram-sha-256\n"
)
# keel's own statements go through the unix socket as the postgres OS
# user, the way keel.inspect.dbengines' psql_argv does. runuser keeps
# the environment, so the tests point PGHOST at a socket of the node's
# own.
AS_POSTGRES = ("runuser", "-u", "postgres", "--")
CLIENT = AS_POSTGRES + ("psql", "--no-psqlrc", "--batch", "--tuples-only")
QUIET_CLIENT = CLIENT
# Whether the server answers at all, asked before anything else
# (keel.system.dbready): no credential, only the socket.
PING = ("pg_isready",)
SERVICE_DEFAULT = "postgresql"
# the unit's name: postgresql, or what KEEL_POSTGRES_SERVICE says (the
# tests run a cluster per node in one container, each its own unit)
SERVICE_ENV = "KEEL_POSTGRES_SERVICE"
# The role both ends of a pair name, a constant for the reason
# keel.system.dbmariadb gives (0013: every screen stays on its own
# machine; a field each operator could set differently is how two
# machines stop being able to talk).
REPLICATION_USER = "repl"
# A standby follows its primary through primary_conninfo and the empty
# file standby.signal in the data directory; signal and connection live
# apart so a promotion is one SQL statement and no file change.
STANDBY_SIGNAL = "standby.signal"
# The databases the server owns. Anything else is somebody's data, and
# becoming a replica replaces it with a copy of the primary (0013).
SYSTEM_DATABASES = ("template0", "template1", "postgres")
# How a primary takes a replica later without a restart when the
# operator asks for it (wal_level and max_wal_senders are not settable
# while it runs, so the role is chosen before the server is configured
# for the first time, the way 0013's console flow has it).
PRIMARY_LINES = (
    "wal_level = replica\n"
    "max_wal_senders = 10\n"
    "max_replication_slots = 10\n"
)
# PostgreSQL with standard_conforming_strings on (the default since
# 9.1) reads a single quoted literal with only the quote doubled.
CONTROL = "a credential holding a control character or a NUL byte"


@dataclass(frozen=True)
class Statements:
    """SQL to send, and what it does, for one action of a plan"""

    text: str
    summary: str


def service() -> str:
    """The server's unit"""
    return os.environ.get(SERVICE_ENV) or SERVICE_DEFAULT


def cluster_paths(root: str) -> tuple[str, str, str, str]:
    """The cluster's version and its paths, relative to the root

    (version, conf.d drop-in directory, data directory, the hba file
    keel writes). Debian versions both directories by the server
    version, so they are found, not spelled out. The appliance ships
    exactly one cluster; where more than one version directory exists,
    the highest version is taken, which is what apt's default cluster
    is. None installed is a programming error here: the planner only
    asks for paths after the observation said the engine is installed.
    """
    confs = sorted(glob.glob(os.path.join(root, CONF_GLOB)))
    if not confs:
        raise FileNotFoundError("no PostgreSQL cluster under " + CONF_GLOB)
    conf = confs[-1]
    version = conf.rsplit("/main", 1)[0].rsplit("/", 1)[-1]
    dropdir = os.path.join(conf, "conf.d")
    datadirs = sorted(glob.glob(os.path.join(root, DATADIR_GLOB)))
    datadir = datadirs[-1] if datadirs else os.path.join(
        root, "var/lib/postgresql", version, "main")
    hba = os.path.join(dropdir, HBA_DROPIN_NAME)
    return version, dropdir, datadir, hba


def rel(path: str, root: str) -> str:
    """A path as the plan's actions carry it, relative to the root"""
    return os.path.relpath(path, root)


def dropin_text(listen: list | None, role: str, hba: str) -> str:
    """The configuration file the declared role needs, as it is written

    The whole hba surface moves with hba_file (module docstring), the
    listen addresses are what the description declared, and a primary
    carries the lines a future replica asks of it. A replica adds
    nothing: hot standby is the default of wal_level replica, and its
    read-only-ness needs no line (module docstring).
    """
    lines = [DROPIN_HEADER, f"hba_file = '{hba}'\n"]
    if listen:
        lines.append("listen_addresses = '"
                     + ",".join(str(one) for one in listen) + "'\n")
    if role == "primary":
        lines.append(PRIMARY_LINES)
    return "".join(lines)


def hba_text(hosts: list[str], password: str) -> str:
    """The whole hba file: Debian's base rules and, per origin, one
    line that authorizes replication

    0013's "Several replicas": a primary holds who may replicate, as
    pg_hba lines for the replication pseudo-database. scram-sha-256
    never puts the password on the wire. The file is rewritten whole on
    each apply, so a withdrawn origin disappears with the line.
    """
    lines = [HBA_HEADER, HBA_BASE]
    for host in hosts:
        lines.append(
            "hostssl replication "
            + REPLICATION_USER + " " + str(host)
            + " scram-sha-256\n"
        )
    return "".join(lines)


def follow_dropin_text(
    host: str, port: int, password: str, tls: str = "",
) -> str:
    """The drop-in that makes this server a replica of that endpoint

    primary_conninfo is a GUC, so following is a file and a restart, no
    SQL; the empty standby.signal in the data directory is what turns
    the start into recovery (keel.system.dbseed writes both after the
    base backup). The password goes through two parsers: libpq's
    keyword/value syntax wants its quotes backslashed, and the
    configuration file wants backslashes and quotes escaped for its own
    string literal, so one escaping is not enough and the order is
    fixed: libpq first, the file second.
    """
    conninfo = (
        f"host={conninfo_value(host)} port={int(port)}"
        f" user={REPLICATION_USER}"
        f" password={conninfo_value(password)}"
        f" application_name=keel{tls}"
    )
    return (DROPIN_HEADER
            + f"primary_conninfo = '{file_value(conninfo)}'\n")


def promote() -> Statements:
    """Take writes: the one SQL step of a promotion

    pg_promote() ends recovery and opens the server for writes in one
    transaction-safe step; it refuses while the standby has not finished
    recovery, so there is no stop-forgetting step the way MariaDB's
    RESET SLAVE ALL is one.
    """
    return Statements(
        "SELECT pg_promote();\n",
        "end recovery and take writes",
    )


def literal(value: str) -> str:
    """A single quoted SQL literal, escaped the way PostgreSQL reads one

    A credential comes from a file whose content nobody here chose, so
    it is escaped rather than trusted or pattern matched. A NUL byte or
    a control character is refused by the caller before it gets here
    (`unquotable`).
    """
    return "'" + str(value).replace("'", "''") + "'"


def unquotable(value: str) -> str:
    """Why a value cannot go into a statement at all, or an empty string"""
    for char in str(value):
        if char in ("'", "\n", "\r"):
            continue
        if ord(char) < 0x20 or ord(char) == 0x7F:
            return CONTROL
    return ""


def conninfo_value(value: str) -> str:
    """A value as libpq's keyword/value syntax reads it

    Backslash and quote are the only special characters there, so they
    are the only ones escaped; a caller that embeds the result in a
    configuration file escapes it again for that parser (`file_value`).
    """
    return (str(value).replace("\\", "\\\\").replace("'", "\\'"))


def file_value(value: str) -> str:
    """A value as postgresql.conf's string literal reads it

    The file processes backslash escapes inside quoted strings, so a
    literal backslash is written doubled and a literal quote either
    backslashed or doubled; the quote is doubled, which reads the same
    and keeps the two escape characters apart.
    """
    return value.replace("\\", "\\\\").replace("'", "''")


def user_databases(lines: list[str]) -> list[str]:
    """The databases that are somebody's data and not the server's own"""
    return [
        name for name in (one.strip() for one in lines)
        if name and name.lower() not in SYSTEM_DATABASES
    ]


def schemas_question() -> tuple[str, ...]:
    """The question whose answer lists the databases (keel.system.dbstate)"""
    return QUIET_CLIENT + (
        "--command", "SELECT datname FROM pg_database",
    )
