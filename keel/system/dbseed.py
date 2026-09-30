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
2. dump it to a file of mode 0600 in a directory of mode 0700 under
   /var/tmp, on disk and not in a tmpfs;
3. read the GTID position the dump was taken at from its last lines;
4. only then stop replication, forget the old primary and drop the
   local databases the operator confirmed;
5. load the copy, set `gtid_slave_pos` to that position and start.

A failure in steps 1 to 3 leaves the machine as it was. The password
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
from contextlib import contextmanager

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
LOCAL_CLIENT = ("mariadb", "--batch")
REMOTE = ("mariadb",)
# --raw so a value is printed as it is and not with batch escapes, which
# would change a statement copied from one server to the other.
READ = ("--batch", "--raw", "--skip-column-names")
DATADIR = "var/lib/mysql"
# Loading SQL builds tables and indexes about as large as its text; twice
# the dump leaves the server room to work while it does.
DISK_MARGIN = 2
ACCOUNTS_SQL = "SELECT User, Host FROM mysql.user WHERE is_role = 'N'"
# The server's own accounts and keel's: Debian's socket accounts, the
# definer of the sys views, the old maintenance account, and the
# replication account each node already holds with its own grant.
EXCLUDED_USERS = frozenset(
    ("root", "mysql", "mariadb.sys", "debian-sys-maint",
     mariadb.REPLICATION_USER)
)
# What SHOW GRANTS prints about roles, which are not copied.
SKIPPED = ("SET DEFAULT ROLE ",)

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
UNEXPECTED = (
    "the primary answered a question about an account with a statement"
    " that is not one ({line})"
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
                directory, action.host, action.port, action.password
            )
            return _seed(directory, os.path.join(root, DATADIR), options,
                         action, runner)
    except OSError as e:
        # Not KEPT: the error may come after the drop, reading the copy.
        return f"cannot seed from [{action.host}]:{action.port}:" \
            f" {e.strerror or e}"


def reach(
    root: str, host: str, port: int, password: str, runner=subprocess.run,
) -> str:
    """Why the primary cannot be copied from, or an empty string

    Asked before the plan is made, so a replica that cannot be seeded is
    refused before its configuration is rewritten or anything dropped.
    """
    try:
        with spool(root) as directory:
            options = write_options(directory, host, port, password)
            return _privileges(options, host, port, runner)
    except OSError as e:
        return f"cannot ask [{host}]:{port}: {e.strerror or e}"


def _seed(
    directory: str, datadir: str, options: str, action, runner,
) -> str | None:
    where = {"host": action.host, "port": action.port}
    problem = _privileges(options, action.host, action.port, runner)
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
    copy, problem = _account_copy(options, runner)
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
        problem = _run(runner, LOCAL_CLIENT, stdin=fob)
    if problem:
        return LOAD_FAILED.format(detail=problem, **where)
    if copy:
        problem = _run(runner, LOCAL_CLIENT, text=copy)
        if problem:
            return ACCOUNTS_FAILED.format(detail=problem, **where)
    start = mariadb.replicate_from(
        action.host, action.port, action.password, position
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


def _account_copy(options: str, runner) -> tuple[str, str]:
    """The statements that give the replica the accounts it lacks

    Read from the primary right after the dump and before anything is
    dropped. Only accounts that are nobody's but the application's are
    copied (not EXCLUDED_USERS, not the anonymous one, not roles), and
    only those the replica does not hold: an account on both keeps the
    replica's own password until the primary changes it through the
    binary log. Returns the statements, or an empty string and why not.
    """
    primary = {}
    problem = _run(runner, REMOTE + (f"--defaults-extra-file={options}",
                                     CONNECT_TIMEOUT) + READ
                   + ("--execute", ACCOUNTS_SQL), output=primary)
    if problem:
        return "", ACCOUNTS_UNREADABLE.format(where="the primary",
                                              detail=problem)
    local = {}
    problem = _run(runner, REMOTE + READ + ("--execute", ACCOUNTS_SQL),
                   output=local)
    if problem:
        return "", ACCOUNTS_UNREADABLE.format(where="this server",
                                              detail=problem)
    held = {(user, host.lower()) for user, host in accounts(local["stdout"])}
    missing = [
        (user, host) for user, host in accounts(primary["stdout"])
        if user and user not in EXCLUDED_USERS
        and (user, host.lower()) not in held
    ]
    if not missing:
        return "", ""
    show = "".join(
        f"SHOW CREATE USER {mariadb.literal(user)}@{mariadb.literal(host)};\n"
        f"SHOW GRANTS FOR {mariadb.literal(user)}@{mariadb.literal(host)};\n"
        for user, host in missing
    )
    answer = {}
    problem = _run(runner, REMOTE + (f"--defaults-extra-file={options}",
                                     CONNECT_TIMEOUT) + READ,
                   text=show, output=answer)
    if problem:
        return "", ACCOUNTS_UNREADABLE.format(where="the primary",
                                              detail=problem)
    kept = []
    for line in (one.strip() for one in answer["stdout"].splitlines()):
        if not line or line.startswith(SKIPPED) or (
            line.startswith("GRANT ") and " ON " not in line
        ):
            continue
        if not line.startswith(("CREATE USER ", "GRANT ")):
            return "", UNEXPECTED.format(line=line)
        kept.append(line + ";\n")
    return "SET SESSION sql_log_bin = 0;\n" + "".join(kept), ""


def accounts(text: str) -> list[tuple[str, str]]:
    """User and host pairs from a batch answer, one per line"""
    pairs = []
    for line in (text or "").splitlines():
        user, sep, host = line.partition("\t")
        if sep:
            pairs.append((user, host))
    return pairs


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


def write_options(directory: str, host: str, port: int, password: str) -> str:
    """The options file, created exclusively at mode 0600; its path"""
    path = os.path.join(directory, OPTIONS)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 OPTIONS_MODE)
    with os.fdopen(fd, "w") as fob:
        fob.write(options_text(host, port, password))
    return path


def options_text(host: str, port: int, password: str) -> str:
    """What the clients read instead of a password on their command line"""
    return (
        "[client]\n"
        f"user={mariadb.REPLICATION_USER}\n"
        f"password={option_value(password)}\n"
        f"host={option_value(host)}\n"
        f"port={int(port)}\n"
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
