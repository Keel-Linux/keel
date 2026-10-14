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
  ships, plus two lines per declared origin: one for the replication
  pseudo-database and one that lets the replication role ask the
  server's own postgres database (the reach and seed probes), never
  user data. A password line's method is scram-sha-256, so the
  password never goes on the wire and the line is only ever written
  for an origin the description declares; the pair's replication line
  is the cert method instead, the certificate pins the peer (map= is
  refused with a password method).
"""

import glob
import ipaddress
import os
from dataclasses import dataclass

# The cluster's configuration directory carries the version Debian
# installed (17 on Debian 13), so the paths are resolved from the root,
# never spelled out: cluster_paths() is the resolver, and the
# appliance ships exactly one cluster.
CONF_GLOB = "etc/postgresql/*/main"
DROPIN_NAME = "99-keel-database.conf"
FOLLOW_DROPIN_NAME = "99-keel-follow.conf"
# The pair's hba and ident files are NOT drop-ins: conf.d is swept as
# GUC (Debian's postgresql.conf includes it, measured on the published
# layer), their formats are not GUC, and the server dies reading them
# (found by the pair's network-namespace test of this release). They
# live in the cluster's configuration directory, the way Debian keeps
# pg_hba.conf beside postgresql.conf; only the GUC drop-ins stay in
# conf.d. The pair drop-in (a GUC file) and the user name map it points
# at (keel.system.dbtls' certificates verify-full against the map,
# 0054) are found by cluster_paths().
HBA_NAME = "keel-pg_hba.conf"
PAIR_DROPIN_NAME = "98-keel-pair.conf"
IDENT_NAME = "keel-pg_ident.conf"
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
# own. The answers are unaligned with a tab between the columns, the
# way keel.inspect.dbengines' psql_argv asks them: keel's readers split
# a row on the tab, and psql's aligned default pads the columns with
# spaces and a bar, so no row split into its columns (found when the
# pair's cases (b) to (e) were built: every promote read "not in
# recovery"). ON_ERROR_STOP makes a failed statement on standard input
# fail the client: without it psql goes on to the next statement and
# exits 0, so a refused pg_promote() or role statement read as done.
AS_POSTGRES = ("runuser", "-u", "postgres", "--")
CLIENT = AS_POSTGRES + ("psql", "--no-psqlrc", "--tuples-only",
                        "--no-align", "--field-separator=\t",
                        "--set=ON_ERROR_STOP=1")
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
# The pair's lines, on both nodes whatever the role (0054): the
# primary confirms a commit only after the standby of application_name
# `keel` received and flushed it, with no timeout — while the replica
# is away the primary stops committing; wal_log_hints is the revisit
# path for pg_rewind, not used in this version.
SLOT = "keel"
SYNC_LINE = f"synchronous_standby_names = 'FIRST 1 ({SLOT})'\n"
PAIR_LINES = (
    SYNC_LINE
    + "synchronous_commit = on\n"
    "wal_log_hints = on\n"
)
# The one exception to the rule above (0054, amended 2026-10-14): when
# the operator promotes with --old-primary-gone, the new primary has no
# standby, and with the line above every commit would wait until the
# old primary is reseeded. The operator's flag says the old primary is
# gone, so the new primary commits alone: the line is replaced by this
# one and the server reloads (no restart). keel writes the line back
# once a standby streams again (keel.system.dbpgfollow.synchronous_again).
ALONE_LINES = (
    "# keel database promote --old-primary-gone: this primary commits\n"
    "# alone until a standby streams again; keel then writes the pair's\n"
    "# synchronous line back (0054)\n"
    "synchronous_standby_names = ''\n"
)


def alone_text(text: str) -> str:
    """The pair drop-in's text with the primary committing alone"""
    return text.replace(SYNC_LINE, ALONE_LINES)


def synchronous_text(text: str) -> str:
    """The pair drop-in's text with the pair's synchronous line back"""
    return text.replace(ALONE_LINES, SYNC_LINE)


def commits_alone(text: str) -> bool:
    return ALONE_LINES in text
# The user name map of pg_ident.conf: a replication connection's
# certificate CN is `<member> postgresql`, never the database user
# `repl`, so the cert method needs this map, the twin of MariaDB's
# REQUIRE SUBJECT (0054).
IDENT_MAP = "keel"
IDENT_HEADER = (
    "# Written by keel spec apply: the map of the replication\n"
    "# authorizations' cert method (0054). Edited by hand,\n"
    "# it is overwritten on the next run.\n"
    "# MAPNAME       SYSTEM-USERNAME         PG-USERNAME\n"
)
# the sysctl drop-in and its key, the twin of keel.system.dbmariadb's
# (a pair's both nodes bind the VIP); engine neutral, spelt out here
# so this module is the pair's whole PostgreSQL surface
SYSCTL = "etc/sysctl.d/90-keel-database.conf"
NONLOCAL_BIND = "net.ipv6.ip_nonlocal_bind"
NONLOCAL_BIND_LIVE = "proc/sys/net/ipv6/ip_nonlocal_bind"
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
    """The cluster's version and its directories, relative to the root

    (version, configuration directory, conf.d drop-in directory, data
    directory). Debian versions both directories by the server version,
    so they are found, not spelled out. The appliance ships exactly one
    cluster; where more than one version directory exists, the highest
    version is taken, which is what apt's default cluster is. None
    installed is a programming error here: the planner only asks for
    paths after the observation said the engine is installed. The hba
    and ident files are not here: they belong to the configuration
    directory, not the swept conf.d (the constants above).
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
    return version, conf, dropdir, datadir


def rel(path: str, root: str) -> str:
    """A path as the plan's actions carry it, relative to the root"""
    return os.path.relpath(path, root)


def overlay_addresses(doc: dict) -> list[str]:
    """This node's WireGuard overlay addresses, without their prefix

    The twin of keel.system.dbmariadb.overlay_addresses, which see: the
    value is network, not engine, and lives here so the pair's planner
    reads one engine's module alone.
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


def hba_text(hosts: list[str], password: str, verify: bool = False) -> str:
    """The whole hba file: Debian's base rules and, per origin, the two
    lines the replication role needs

    0013's "Several replicas": a primary holds who may replicate, as
    pg_hba lines for the replication pseudo-database, and the role is
    also how a would-be replica asks the primary what it is before a
    copy (keel.system.dbpgseed: does it answer, does the role
    authenticate, is it a standby) — that probe connects to the
    server's own postgres database, so each origin carries a second
    line for that database; user data is never reachable, least power
    for a credential both nodes hold. scram-sha-256 never puts the
    password on the wire, and it is the postgres-database line's method
    in both modes: the probe authenticates with the pair's password and
    presents no certificate. `verify` is the pair's TLS: the
    replication line is the cert method instead (pg refuses map= with
    a password method, and the server dies loading the file), which
    pins the other member's certificate through the `keel` map of
    ident_text (0054), the twin of MariaDB's REQUIRE SUBJECT:
    clientcert=verify-full is deliberately not there — it asks the
    client host's name of a DNS the mesh has not (0054), and the map is
    the pinning. The file is rewritten whole on each apply, so a
    withdrawn origin disappears with the lines. An origin that is an IP
    address takes the host mask of its length: pg_hba.conf reads a bare
    token as a hostname, and a host line with no IP mask stops the
    server at hba load.
    """
    lines = [HBA_HEADER, HBA_BASE]
    method = "scram-sha-256"
    if verify:
        method = f"cert map={IDENT_MAP}"
    for host in hosts:
        origin = _hba_host(str(host))
        lines.append(
            "hostssl replication "
            + REPLICATION_USER + " " + origin + " " + method + "\n"
        )
        lines.append(
            "hostssl postgres " + REPLICATION_USER + " " + origin
            + " scram-sha-256\n"
        )
    return "".join(lines)


def _hba_host(host: str) -> str:
    """An origin as pg_hba.conf spells its address field: an IP without
    a mask takes the host's own (/32 or /128); a network and a name
    pass through (a name pins no certificate, NAME_NOTE)"""
    try:
        return str(ipaddress.ip_interface(host))
    except ValueError:
        return host


def ident_text(cns: list[str]) -> str:
    """The pg_ident.conf for the pair: each authorized member's
    certificate CN maps to the replication role, so the cert method
    accepts it (module docstring of hba_text)

    A CN comes from the mesh PKI's member naming (keel.mesh.etcdstate
    .database_name) and holds no quote; the doubling keeps the file
    honest if that ever changes.
    """
    lines = [IDENT_HEADER]
    for cn in cns:
        quoted = str(cn).replace('"', '""')
        lines.append(f"{IDENT_MAP} \"{quoted}\" {REPLICATION_USER}\n")
    return "".join(lines)


def pair_dropin_text(ident: str = "") -> str:
    """The pair drop-in, on both nodes whatever the role: the
    synchronous commit policy and wal_log_hints (0054). `ident` is the
    ident file's path, set only by the pair (hba_text's verify lines
    consult the map it holds), as a GUC beside the others"""
    return (DROPIN_HEADER + PAIR_LINES
            + (f"ident_file = '{ident}'\n" if ident else ""))


def slot_statements() -> Statements:
    """The statements that make the replication slot true, as declared

    One idempotent statement: the slot a standby connects to, named
    for the pair (module constant SLOT, 0054), so the primary keeps
    the WAL of an away replica. The guards refuse on a standby, where
    slots cannot be made, and when the slot exists. The SET comes
    first because the slot is WAL-logged (PG 17) and the pair's
    synchronous commit has no timeout (0054): without it the
    statement's commit would wait for the standby that does not exist
    yet — this statement is what lets it exist (found by the pair's
    network-namespace test of this release).
    """
    return Statements(
        "SET synchronous_commit = local;\n"
        f"SELECT pg_create_physical_replication_slot('{SLOT}') WHERE NOT"
        " pg_is_in_recovery() AND NOT EXISTS (SELECT 1 FROM"
        f" pg_replication_slots WHERE slot_name = '{SLOT}');\n",
        "ensure the replication slot of the pair exists on the primary",
    )


def sysctl_text() -> str:
    """The sysctl drop-in letting both nodes bind the VIP; the twin of
    keel.system.dbmariadb.sysctl_text (0049)"""
    return ("# Written by keel spec apply for a database pair (decision"
            " 0049):\n# both nodes bind the pair's VIP, and the primary"
            " answers on it the\n# moment it carries the address, with no"
            " restart.\n"
            f"{NONLOCAL_BIND} = 1\n")


def follow_dropin_text(
    host: str, port: int, password: str, tls: str = "", slot: str = "",
) -> str:
    """The drop-in that makes this server a replica of that endpoint

    primary_conninfo is a GUC, so following is a file and a restart, no
    SQL; the empty standby.signal in the data directory is what turns
    the start into recovery (keel.system.dbseed writes both after the
    base backup). The password goes through two parsers: libpq's
    keyword/value syntax wants its quotes backslashed, and the
    configuration file wants backslashes and quotes escaped for its own
    string literal, so one escaping is not enough and the order is
    fixed: libpq first, the file second. `slot` is the pair's
    replication slot (constant SLOT, 0054): a pair's standby streams
    from it, so the primary keeps its WAL while the replica is away.
    """
    # dbtls.options_lines is one option per line; a configuration value
    # ends at the newline, so the block is flattened before it lands in
    # this file's single-quoted string
    flat_tls = " ".join(tls.split())
    conninfo = (
        f"host={conninfo_value(host)} port={int(port)}"
        f" user={REPLICATION_USER}"
        f" password={conninfo_value(password)}"
        f" application_name=keel"
        + (f" {flat_tls}" if flat_tls else "")
    )
    lines = [DROPIN_HEADER,
             f"primary_conninfo = '{file_value(conninfo)}'\n"]
    if slot:
        lines.append(f"primary_slot_name = '{file_value(str(slot))}'\n")
    return "".join(lines)


def role_statements(password: str) -> Statements:
    """The statements that make the replication role true, as declared

    One idempotent block: the role a replica logs in as, created when it
    is not there, given the pair's password when it is. `password` is
    escaped as a literal, and control characters are refused by the
    credential gate before the planner builds on this (keel.system
    .dbstate.credential), so a value from a secret file is safe here.
    The SET comes first for the reason slot_statements gives: the
    block commits WAL, and the pair's synchronous commit must not
    wait for the standby this role lets connect. On a standby the
    block does nothing: the role arrives with the primary's copy, and
    a standby refuses ALTER ROLE in its read-only transaction (an
    apply on a standby failed once the client stopped at an error).
    """
    quoted = literal(password)
    return Statements(
        "SET synchronous_commit = local;\n"
        "DO $keel$\n"
        "BEGIN\n"
        "   IF pg_is_in_recovery() THEN\n"
        "      RETURN;\n"
        "   END IF;\n"
        "   IF NOT EXISTS (SELECT FROM pg_roles"
        f" WHERE rolname = '{REPLICATION_USER}') THEN\n"
        f"      CREATE ROLE {REPLICATION_USER}"
        " WITH LOGIN REPLICATION PASSWORD " + quoted + ";\n"
        "   ELSE\n"
        f"      ALTER ROLE {REPLICATION_USER}"
        " WITH LOGIN REPLICATION PASSWORD " + quoted + ";\n"
        "   END IF;\n"
        "END\n"
        "$keel$;\n",
        "ensure the replication role holds the pair's password",
    )


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
