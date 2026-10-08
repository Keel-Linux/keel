# Copyright (c) 2026 KeelLinux maintainers
"""Seed a new replica with a copy of its primary, then replicate

A replica that starts from an empty `gtid_slave_pos` receives only what
the primary logs from then on. The data the primary held before, a
WordPress site installed at first boot, never arrives, and the first
UPDATE of one of those rows stops the replica's SQL thread. So a replica
is built the way MariaDB documents: a consistent copy of the primary, and
replication from the GTID position that copy was taken at.

The copy is `mariadb-dump --single-transaction --gtid --master-data=2`,
pulled over the network by the replica as the replication account, and
not `mariadb-backup` streamed: it is in `mariadb-client`, which every
appliance with a server has, where mariadb-backup is a package the
images do not ship; it needs nothing started on the primary and no port
but the one replication already uses; and a WordPress database is small
enough that a logical copy costs seconds. docs/apply.md says where it
stops being the right tool.

The order is what makes it safe to run against a machine holding data:

1. ask the primary, as the replication account, which privileges it
   holds, which proves it answers and that the copy can read everything;
2. read its accounts (keel.system.dbaccounts), refusing roles;
3. dump it to a file of mode 0600 in a directory of mode 0700 under
   /var/tmp, on disk and not in a tmpfs;
4. read the GTID position the dump was taken at from its last lines,
   check the room for the load, read the accounts again and refuse if
   they changed, and read the replica's own;
5. only then stop replication, forget the old primary and drop the
   local databases the operator confirmed;
6. load the copy, align the accounts, set `gtid_slave_pos` to that
   position and start.

A failure in steps 1 to 4 leaves the machine as it was. The password
reaches the clients in an options file (`--defaults-extra-file`) of mode
0600, created exclusively and removed with its directory whatever
happens, never in an argument vector, and no message here quotes it.
keel.system.effects is the only caller of `seed`, and
keel.system.dbstate the only caller of `reach`.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from contextlib import contextmanager

from keel.system import dbaccounts
from keel.system import dbmariadb as mariadb

SPOOL = "var/tmp"
PREFIX = "keel-seed-"
OPTIONS = "client.cnf"
DUMP = "primary.sql"
OPTIONS_MODE = 0o600
CONNECT_TIMEOUT = "--connect-timeout=10"
# The dump reads only its last lines for the position, which mariadb-dump
# writes after the data; this much holds them with room to spare.
TAIL_BYTES = 65536
DUMP_OPTIONS = (
    "--single-transaction", "--gtid", "--master-data=2",
    "--routines", "--events", "--triggers",
    "--all-databases", "--ignore-database=mysql", "--ignore-database=sys",
)
# The account's own global privileges. Filtered on CURRENT_USER() because
# SELECT on *.* shows every account's rows, not only its own.
PRIVILEGES_SQL = (
    "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES"
    " WHERE GRANTEE = CONCAT(\"'\", SUBSTRING_INDEX(CURRENT_USER(), '@', 1),"
    " \"'@'\", SUBSTRING_INDEX(CURRENT_USER(), '@', -1), \"'\")"
)
POSITION_LINE = re.compile(
    r"^-- SET GLOBAL gtid_slave_pos='([^']*)';\s*$", re.MULTILINE
)
POSITION_VALUE = re.compile(r"^(\d+-\d+-\d+(,\d+-\d+-\d+)*)?$")
# MariaDB's escapes inside a quoted value of an options file.
OPTION_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r",
                  "\t": "\\t"}
# the local statements and the load, as the server's mysql account
# (keel.system.dbmariadb): on a paired node root cannot write through
# read_only, and the load must not enter this node's binary log, which a
# pair has on both nodes (its GTIDs are the primary's, not this node's)
LOCAL_CLIENT = mariadb.CLIENT
LOAD_CLIENT = LOCAL_CLIENT + ("--init-command=SET SESSION sql_log_bin=0",)
REMOTE = ("mariadb",)
# --raw so a value is printed as it is and not with batch escapes, which
# would change a statement copied from one server to the other.
READ = ("--batch", "--raw", "--skip-column-names")
DATADIR = "var/lib/mysql"
# Loading SQL builds tables and indexes about as large as its text; twice
# the dump leaves the server room to work while it does.
DISK_MARGIN = 2

KEPT = "nothing was dropped and replication was not started"
UNREACHABLE = (
    "the primary [{host}]:{port} did not answer as '{user}' ({detail})"
)
NOT_GRANTED = (
    "the primary [{host}]:{port} lets '{user}' replicate but not copy what"
    " it holds: it lacks {missing}. Run `keel spec apply --system-only`"
    " on the primary with keel 0.11.3 or later, which grants them"
)
DUMP_FAILED = "mariadb-dump of [{host}]:{port} failed ({detail})"
NO_POSITION = (
    "the dump of [{host}]:{port} names no GTID position to replicate from,"
    " so the copy cannot be joined to the binary log"
)
STOP_FAILED = "stopping replication and dropping {drop} failed ({detail})"
LOAD_FAILED = (
    "loading the copy of [{host}]:{port} failed ({detail}). The local copy"
    " is incomplete and replication was not started: run the same command"
    " again with --destroy-local-database to start over"
)
NO_ROOM = (
    "{datadir} has {free} bytes free and loading the copy needs about"
    " {need}"
)
ACCOUNTS_UNREADABLE = "the accounts of {where} could not be read ({detail})"
CHANGED = (
    "the primary's accounts changed while it was copied, so the copy"
    " cannot be matched to them; run the same command again"
)
ACCOUNTS_FAILED = (
    "the copy of [{host}]:{port} is loaded and creating the primary's"
    " accounts failed ({detail}). Replication was not started: run the"
    " same command again with --destroy-local-database to start over"
)
START_FAILED = (
    "the copy of [{host}]:{port} is loaded and replication did not start"
    " ({detail})"
)


def seed(root: str, action, runner=subprocess.run) -> str | None:
    """Carry out a SeedReplica; None on success, else what went wrong"""
    try:
        with spool(root) as directory:
            options = write_options(
                directory, action.host, action.port, action.password,
                action.options
            )
            return _seed(directory, os.path.join(root, DATADIR), options,
                         action, runner)
    except OSError as e:
        # Not KEPT: the error may come after the drop, reading the copy.
        return f"cannot seed from [{action.host}]:{action.port}:" \
            f" {e.strerror or e}"


def reach(
    root: str, host: str, port: int, password: str, runner=subprocess.run,
    tls: str = "",
) -> "Reach":
    """Why the primary cannot be copied from, and the accounts both hold

    Asked before the plan is made, so a replica that cannot be seeded is
    refused before its configuration is rewritten or anything dropped,
    and the plan can name the accounts that keep this server's password.
    `tls` is the clients' TLS, as keel.system.dbtls.options_lines writes
    it, on a pair.
    """
    try:
        with spool(root) as directory:
            options = write_options(directory, host, port, password, tls)
            problem = _privileges(options, host, port, runner)
            if problem:
                return Reach(problem)
            primary, problem = _primary_accounts(options, runner)
            if problem:
                return Reach(problem)
            held, problem = _held(primary, runner)
            return Reach(problem, tuple(one.sql() for one in held))
    except OSError as e:
        return Reach(f"cannot ask [{host}]:{port}: {e.strerror or e}")


@dataclass(frozen=True)
class Reach:
    """What the replica learnt from the primary before planning"""

    problem: str = ""
    # The primary's accounts this server holds too, as it spells them.
    shared: tuple[str, ...] = ()


def _seed(
    directory: str, datadir: str, options: str, action, runner,
) -> str | None:
    where = {"host": action.host, "port": action.port}
    problem = _privileges(options, action.host, action.port, runner)
    if problem:
        return f"{problem}; {KEPT}"
    before, problem = _primary_accounts(options, runner)
    if problem:
        return f"{problem}; {KEPT}"
    dump = os.path.join(directory, DUMP)
    problem = _dump(options, dump, runner)
    if problem:
        return DUMP_FAILED.format(detail=problem, **where) + f"; {KEPT}"
    position = gtid_position(_tail(dump))
    if position is None:
        return NO_POSITION.format(**where) + f"; {KEPT}"
    problem = _room(datadir, dump)
    if problem:
        return f"{problem}; {KEPT}"
    after, problem = _primary_accounts(options, runner)
    if problem:
        return f"{problem}; {KEPT}"
    if after != before:
        return f"{CHANGED}; {KEPT}"
    copy, problem = _alignment(before, runner)
    if problem:
        return f"{problem}; {KEPT}"

    stop = mariadb.stop_replicating().text
    if action.drop:
        stop += mariadb.destroy(list(action.drop)).text
    problem = _run(runner, LOCAL_CLIENT, text=stop)
    if problem:
        return STOP_FAILED.format(
            drop=", ".join(action.drop) or "nothing", detail=problem
        )
    with open(dump, "rb") as fob:
        problem = _run(runner, LOAD_CLIENT, stdin=fob)
    if problem:
        return LOAD_FAILED.format(detail=problem, **where)
    if copy:
        problem = _run(runner, LOCAL_CLIENT, text=copy)
        if problem:
            return ACCOUNTS_FAILED.format(detail=problem, **where)
    start = mariadb.replicate_from(
        action.host, action.port, action.password, position, action.tls
    )
    problem = _run(runner, LOCAL_CLIENT, text=start.text)
    if problem:
        return START_FAILED.format(detail=problem, **where)
    return None


def _privileges(options: str, host: str, port: int, runner) -> str:
    """Ask the primary what the account may do; the reason it cannot copy"""
    argv = ("mariadb", f"--defaults-extra-file={options}", CONNECT_TIMEOUT,
            "--batch", "--skip-column-names", "--execute", PRIVILEGES_SQL)
    out = {}
    problem = _run(runner, argv, output=out)
    where = {"host": host, "port": port, "user": mariadb.REPLICATION_USER}
    if problem:
        return UNREACHABLE.format(detail=problem, **where)
    missing = missing_privileges(out["stdout"])
    if missing:
        return NOT_GRANTED.format(missing=", ".join(missing), **where)
    return ""


def _room(datadir: str, dump: str) -> str:
    """Why the copy may not fit where the server keeps its data, if so

    Checked with the copy on disk and nothing dropped yet: loading it
    takes about as much room again as its text, and a server that runs
    out of disk half way has lost the old data and not got the new.
    """
    try:
        found = os.statvfs(datadir)
    except OSError as e:
        return f"cannot measure the free space of {datadir}: {e.strerror}"
    free = found.f_bavail * found.f_frsize
    need = os.path.getsize(dump) * DISK_MARGIN
    if free < need:
        return NO_ROOM.format(datadir=datadir, free=free, need=need)
    return ""


def _primary_accounts(options: str, runner) -> tuple[dict, str]:
    """The primary's accounts, each as it would create it; or why not

    Read once before the dump, which is the reading the replica gets, and
    once after it: equal readings mean no account changed while the dump
    was taken, so the copy and the accounts agree. Read only after, a
    CREATE USER in between was applied twice and stopped the replica;
    read only before, it was never applied at all. A primary with roles
    or grants to PUBLIC is refused (keel.system.dbaccounts).
    """
    remote = REMOTE + (f"--defaults-extra-file={options}", CONNECT_TIMEOUT)
    listed = {}
    problem = _run(runner, remote + READ + ("--execute", dbaccounts.LIST_SQL),
                   output=listed)
    if problem:
        return {}, ACCOUNTS_UNREADABLE.format(where="the primary",
                                              detail=problem)
    accounts, roles = dbaccounts.listing(listed["stdout"])
    if roles:
        return {}, dbaccounts.ROLES.format(roles=", ".join(roles))
    answer = {}
    problem = _run(runner, remote + READ,
                   text=dbaccounts.primary_questions(accounts),
                   output=answer)
    if problem:
        return {}, ACCOUNTS_UNREADABLE.format(where="the primary",
                                              detail=problem)
    return dbaccounts.primary_definitions(answer["stdout"], accounts)


def _held(primary: dict, runner) -> tuple[list, str]:
    """The primary's accounts this server holds too, as it spells them"""
    listed = {}
    problem = _run(runner, REMOTE + READ + ("--execute", dbaccounts.LIST_SQL),
                   output=listed)
    if problem:
        return [], ACCOUNTS_UNREADABLE.format(where="this server",
                                              detail=problem)
    mine, _ = dbaccounts.listing(listed["stdout"])
    wanted = {account.key() for account in primary}
    return [account for account in mine if account.key() in wanted], ""


def _alignment(primary: dict, runner) -> tuple[str, str]:
    """The statements that give this server the primary's accounts"""
    held, problem = _held(primary, runner)
    if problem:
        return "", problem
    local = {}
    if held:
        answer = {}
        problem = _run(runner, REMOTE + READ,
                       text=dbaccounts.local_questions(held), output=answer)
        if problem:
            return "", ACCOUNTS_UNREADABLE.format(where="this server",
                                                  detail=problem)
        local, problem = dbaccounts.local_grants(answer["stdout"], held)
        if problem:
            return "", problem
    return dbaccounts.alignment(
        primary, {account.key() for account in held}, local
    ), ""


def _dump(options: str, path: str, runner) -> str:
    """The copy, written to `path`; the probe before it has a timeout

    mariadb-dump 11.8 has no --connect-timeout and refuses the whole run
    over it (measured on the bench), and the primary answered the probe
    an instant earlier, so none is given.
    """
    argv = ("mariadb-dump", f"--defaults-extra-file={options}"
            ) + DUMP_OPTIONS
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, OPTIONS_MODE)
    with os.fdopen(fd, "wb") as fob:
        return _run(runner, argv, stdout=fob)


def _run(runner, argv, text=None, stdin=None, stdout=None, output=None):
    """Run one client; an empty string, or why it failed

    Bytes throughout: a dump is not guaranteed to be text in any one
    encoding. What failed is taken from standard error, which the clients
    fill with the server's message and never with a statement fed to
    them or the options file's content.
    """
    kwargs = {"stdout": stdout if stdout is not None else subprocess.PIPE,
              "stderr": subprocess.PIPE, "check": False}
    if text is not None:
        kwargs["input"] = text.encode()
    elif stdin is not None:
        kwargs["stdin"] = stdin
    try:
        out = runner(list(argv), **kwargs)
    except OSError as e:
        return f"cannot run {argv[0]}: {e.strerror}"
    if output is not None:
        output["stdout"] = (out.stdout or b"").decode(errors="replace")
    if out.returncode != 0:
        detail = (out.stderr or b"").decode(errors="replace").strip()
        return detail or f"{argv[0]} exited {out.returncode}"
    return ""


def _tail(path: str) -> str:
    with open(path, "rb") as fob:
        fob.seek(0, os.SEEK_END)
        fob.seek(max(0, fob.tell() - TAIL_BYTES))
        return fob.read().decode(errors="replace")


@contextmanager
def spool(root: str):
    """A directory of mode 0700 for the options file and the dump

    Under /var/tmp, which is on disk: /tmp is a tmpfs on Debian 13 and a
    dump held in memory is a dump that runs a small machine out of it.
    Removed with everything in it on the way out, whatever happened.
    """
    directory = tempfile.mkdtemp(prefix=PREFIX, dir=os.path.join(root, SPOOL))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def write_options(directory: str, host: str, port: int, password: str,
                  more: str = "") -> str:
    """The options file, created exclusively at mode 0600; its path"""
    path = os.path.join(directory, OPTIONS)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 OPTIONS_MODE)
    with os.fdopen(fd, "w") as fob:
        fob.write(options_text(host, port, password, more))
    return path


def options_text(host: str, port: int, password: str,
                 more: str = "") -> str:
    """What the clients read instead of a password on their command
    line; `more` is the TLS of a pair (keel.system.dbtls.options_lines)"""
    return (
        "[client]\n"
        f"user={mariadb.REPLICATION_USER}\n"
        f"password={option_value(password)}\n"
        f"host={option_value(host)}\n"
        f"port={int(port)}\n"
        f"{more}"
    )


def option_value(value: str) -> str:
    """A double quoted value, escaped the way MariaDB reads an options file

    Quoted, because a `#` or a trailing blank would otherwise be read as a
    comment or trimmed away.
    """
    escaped = "".join(OPTION_ESCAPES.get(char, char) for char in str(value))
    return f'"{escaped}"'


def gtid_position(text: str) -> str | None:
    """The GTID position a dump was taken at, or None when it names none

    mariadb-dump --gtid --master-data=2 writes it as a comment after the
    data. The last such line counts, and a value that is not a list of
    domain-server-sequence triples is no position: it goes into a
    statement, so it is checked rather than trusted.
    """
    found = POSITION_LINE.findall(text or "")
    if not found or not POSITION_VALUE.match(found[-1]):
        return None
    return found[-1]


def missing_privileges(answer: str) -> list[str]:
    """What the copy and the replication need that the account lacks"""
    held = {line.strip().upper() for line in (answer or "").splitlines()}
    wanted = ("REPLICATION SLAVE",) + mariadb.SEED_GRANTS
    return [one for one in wanted if one not in held]
