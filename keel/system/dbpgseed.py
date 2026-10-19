# Copyright (c) 2026 KeelLinux maintainers
"""Seed a new PostgreSQL standby with a base backup of its primary

The PostgreSQL twin of keel.system.dbseed (handbook decision 0054). Where
MariaDB seeds from a logical dump and aligns the accounts after it, a
PostgreSQL standby is a physical copy: pg_basebackup streams the primary's
whole data directory with the replication protocol, roles included, so
there is no account step at all and the copy is consistent on its own
(the backup's WAL is replayed on the first start).

The order is what makes it safe to run against a machine holding data:

1. ask the primary, as the replication role, what it is, which proves it
   answers and that the copy can be taken (a standby refuses: one copies
   only from a primary);
2. measure the room for the copy where the server keeps its data;
3. take the base backup into a sibling of the data directory, on the same
   file system, while this server keeps running;
4. only then stop this server's own cluster unit, wait until its
   postmaster is gone, write standby.signal into the copy, move the data
   directory aside, move the copy in and write the follow drop-in, so
   the copy can never start as a writable primary: the signal is what
   makes it a standby, and it is in the copy before the copy moves;
5. remove the old copy, start the server, and wait for the walreceiver to
   stream.

The stop names the cluster's unit, postgresql@17-main, never the umbrella
postgresql: the umbrella's stop returns before the cluster stops, and the
old server's shutdown then wrote its pg_control into the copy (keel#153).
A returned systemctl stop is not proof either, so the postmaster of the
data directory's postmaster.pid must be gone before anything moves.

A failure before step 4 leaves the machine as it was, the server still
running, and removes the copy: a copy left behind made the next
pg_basebackup fail. A failure in step 4 puts the old data directory back
and starts the server: the undo runs before the step's problem is
returned. The
password reaches the clients in a pgpass file of mode 0600, created
exclusively and removed with its directory whatever happens, never in an
argument vector (the libpq passfile keyword points the clients at it),
and no message here quotes it. keel.system.effects is the only caller of
`seed`, and keel.system.dbstate the only caller of `reach`.
"""

import os
import pwd
import shutil
import subprocess
import time
from contextlib import contextmanager

from keel.system import dbpgkeep, dbpostgres
from keel.system.dbseed import DISK_MARGIN, KEPT, Reach, _run, spool

# pg_database_size() needs CONNECT on the database (or the role
# pg_read_all_stats), and an application may revoke CONNECT from PUBLIC:
# the size counts only the databases repl may connect to, and the last
# column counts the others, which the free space check leaves out
# (keel#183)
PROBE_SQL = (
    "SELECT pg_is_in_recovery(), count(*),"
    " COALESCE(sum(pg_database_size(oid))"
    " FILTER (WHERE has_database_privilege(oid, 'CONNECT')), 0),"
    " count(*) FILTER (WHERE NOT has_database_privilege(oid, 'CONNECT'))"
    " FROM pg_database"
    " WHERE datname NOT IN ('template0', 'template1')"
)
STREAMING_QUESTION = "SELECT status FROM pg_stat_wal_receiver"
CONNECT_TIMEOUT = "connect_timeout=10"
# the name of keel's own replication connections (the copy, the
# probes): never the standby's application_name, which the pair's
# synchronous_standby_names counts (keel.system.dbpostgres.SLOT)
SEED_NAME = "keel-seed"
# the base backup compressed on the primary, unpacked here (PG 15+)
COMPRESSION = "server-zstd"
PGPASS = "pgpass"
ASIDE_SUFFIX = ".keel-aside"
FRESH_SUFFIX = ".keel-fresh"
# how long a freshly seeded standby may take to connect to its primary
STREAMING_TIMEOUT = 60
POLL_SECONDS = 1.0
# how long the old server's postmaster may live after systemctl stop of
# its unit returned, before the seed gives up and moves nothing
STOP_TIMEOUT = 60
PIDFILE = "postmaster.pid"
STILL_RUNS = (
    "the server of {datadir} still runs (postmaster {pid}) {timeout} s"
    " after systemctl stop {unit}"
)
UNREACHABLE = (
    "cannot ask [{host}]:{port} as {user}: {detail}"
)
IS_STANDBY = (
    "[{host}]:{port} is itself a standby: a copy is taken from a primary"
)
NO_ROOM = (
    "the copy of [{host}]:{port} needs {need} bytes free where {datadir}"
    " keeps its data, and {free} are"
)
LEFT_OUT = (
    " (the need leaves out {count} database(s) that the role {user} has"
    " no CONNECT on, so the copy needs more)"
)
BASEBACKUP_FAILED = "pg_basebackup of [{host}]:{port} failed: {detail}"
START_FAILED = (
    "the copy of [{host}]:{port} is in place and the server did not start"
    " ({detail})"
)
NOT_STREAMING = (
    "the copy of [{host}]:{port} is in place and its walreceiver does not"
    " stream after {timeout} s"
)


def reach(
    root: str, host: str, port: int, password: str, runner=subprocess.run,
) -> Reach:
    """Why the primary cannot be copied from; the accounts are not asked

    The twin of keel.system.dbseed.reach. A base backup copies the whole
    cluster, roles included, so there is nothing to align and `shared` is
    always empty: only the primary is asked, and only that it answers,
    authenticates the pair's role, and is not itself a standby.
    """
    try:
        with spool(root) as directory:
            pgpass = write_pgpass(directory, host, port, password)
            _, problem = _probe(pgpass, host, port, runner)
            return Reach(problem)
    except OSError as e:
        return Reach(f"cannot ask [{host}]:{port}: {e.strerror or e}")


def seed(root: str, action, runner=subprocess.run,
         clock=time.monotonic, sleep=time.sleep,
         alive=None) -> str | None:
    """Carry out a SeedReplica of engine postgresql; None, or why not

    `alive` says whether a process id still runs (the tests' seam)."""
    try:
        with spool(root) as directory:
            pgpass = write_pgpass(directory, action.host, action.port,
                                  action.password)
            return _seed(root, pgpass, action, runner, clock, sleep,
                         alive or _alive)
    except OSError as e:
        # not KEPT: the error may come after the data directory moved
        return f"cannot seed from [{action.host}]:{action.port}:" \
            f" {e.strerror or e}"


class PairAction:
    """The attributes write_follow reads: the holder, the pair's
    password and TLS, and the slot the standby streams from"""

    def __init__(self, host: str, port: int, password: str, tls: str):
        self.host = host
        self.port = port
        self.password = password
        self.tls = tls
        self.slot = dbpostgres.SLOT
        # keep the old data directory when there is room (decision 0054,
        # second amendment of 2026-10-18); `kept` is where it went
        self.keep = False
        self.kept = ""


def write_pgpass(directory: str, host: str, port: int, password: str) -> str:
    """The pgpass file, created exclusively at mode 0600; its path

    libpq ignores a pgpass file any easier to read, so the mode is what
    makes it usable, not only what makes it safe. The clients run as
    the server user (dbpostgres.CLIENT and AS_POSTGRES), so the file
    and its spool directory are handed to that user: left root-owned,
    libpq cannot read them and answers the server's password challenge
    with nothing (found by the pair's network-namespace test of this
    release). Best effort: a dev host without the user keeps root
    ownership, the way _as_postgres has it
    """
    path = os.path.join(directory, PGPASS)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "w") as fob:
        fob.write(pgpass_line(host, port, password))
    try:
        uid = pwd.getpwnam("postgres").pw_uid
        os.chown(directory, uid, -1)
        os.chown(path, uid, -1)
    except (KeyError, OSError):
        pass
    return path


def pgpass_line(host: str, port: int, password: str) -> str:
    """One pgpass line for the replication role against the primary

    The file's fields are colon separated, so every colon and backslash
    in a field is backslash-escaped; a password holding a newline never
    gets here, the credential gate refuses it before the plan is built
    (keel.system.dbstate.credential).
    """
    return (f"{pgpass_value(host)}:{port}:postgres:"
            f"{dbpostgres.REPLICATION_USER}:{pgpass_value(password)}\n")


def pgpass_value(value: str) -> str:
    """One field of a pgpass line, with the two characters it escapes"""
    return str(value).replace("\\", "\\\\").replace(":", "\\:")


def conninfo(host: str, port: int, pgpass: str, tls: str = "") -> str:
    """The connection string the clients take, the password by file only

    `tls` is the pair's client side (keel.system.dbtls.options_lines,
    engine postgresql): without it a replication-protocol connection
    reaches the primary with no certificate, and the pair's cert method
    refuses it — pg_basebackup answers "connection requires a valid
    client certificate", falls back to no TLS, and finds no line at all
    (found by the pair's network-namespace test of this release)

    The application name is SEED_NAME, not the standby's `keel`: the
    WAL stream of pg_basebackup reports what it flushed, so under the
    name `keel` the primary took the half-made copy for the pair's
    synchronous standby and acknowledged commits that only the copy
    held (found by the pair's network-namespace test, case (d): writes
    on the new primary were acknowledged during the reseed, before the
    old primary streamed)
    """
    return (
        f"host={dbpostgres.conninfo_value(host)} port={int(port)}"
        f" user={dbpostgres.REPLICATION_USER} dbname=postgres"
        f" passfile={dbpostgres.conninfo_value(pgpass)}"
        f" application_name={SEED_NAME} {CONNECT_TIMEOUT}"
        + (f" {tls.strip()}" if tls else "")
    )


def _seed(
    root: str, pgpass: str, action, runner, clock, sleep, alive,
) -> str | None:
    where = {"host": action.host, "port": action.port}
    found, problem = _probe(pgpass, action.host, action.port, runner,
                            getattr(action, "tls", ""))
    if problem:
        return f"{problem}; {KEPT}"
    _, _, dropdir, datadir = dbpostgres.cluster_paths(root)
    problem = _room(datadir, found["size"], action, found["left_out"])
    if problem:
        return f"{problem}; {KEPT}"
    aside = datadir + ASIDE_SUFFIX
    fresh = datadir + FRESH_SUFFIX
    # a copy that an earlier run left behind: pg_basebackup refuses a
    # target that is not empty
    shutil.rmtree(fresh, ignore_errors=True)
    problem = _basebackup(fresh, pgpass, action, runner)
    if problem:
        shutil.rmtree(fresh, ignore_errors=True)
        return BASEBACKUP_FAILED.format(detail=problem, **where) \
            + f"; {KEPT}"
    unit = dbpostgres.service(root)
    problem = _stopped(runner, unit, datadir, clock, sleep, alive)
    if not problem:
        problem = _signal(fresh)
    if problem:
        shutil.rmtree(fresh, ignore_errors=True)
        return f"{problem}; {KEPT}"
    keep = bool(getattr(action, "keep", False)) \
        and dbpgkeep.can_keep(datadir, found["size"])
    problem = _swap(dropdir, datadir, aside, fresh, action, runner, unit,
                    keep)
    if problem:
        return problem
    problem = _run(runner, ("systemctl", "start", unit))
    if problem:
        return START_FAILED.format(detail=problem, **where)
    problem = _streaming(runner, clock, sleep)
    if problem:
        return NOT_STREAMING.format(timeout=STREAMING_TIMEOUT, **where)
    return None


def _stopped(runner, unit: str, datadir: str, clock, sleep,
             alive) -> str:
    """The cluster's unit stopped and its postmaster gone; why not

    The pid is the first line of the data directory's postmaster.pid,
    which the postmaster removes when it exits. The server holds the
    data directory until then, and its last write is pg_control."""
    problem = _run(runner, ("systemctl", "stop", unit))
    if problem:
        return f"cannot stop {unit}: {problem}"
    deadline = clock() + STOP_TIMEOUT
    while True:
        pid = _postmaster(datadir)
        if pid is None or not alive(pid):
            return ""
        if clock() >= deadline:
            return STILL_RUNS.format(datadir=datadir, pid=pid,
                                     timeout=STOP_TIMEOUT, unit=unit)
        sleep(POLL_SECONDS)


def _postmaster(datadir: str) -> int | None:
    """The postmaster's pid from postmaster.pid, or None without one"""
    try:
        with open(os.path.join(datadir, PIDFILE)) as fob:
            first = fob.readline().strip()
    except OSError:
        return None
    return int(first) if first.isdigit() else None


def _alive(pid: int) -> bool:
    """Whether the process runs and is a PostgreSQL server: a pid that
    a stale postmaster.pid names may be another process's by now"""
    try:
        with open(f"/proc/{pid}/comm") as fob:
            return fob.read().strip().startswith("postgres")
    except OSError:
        return False


def _signal(fresh: str) -> str:
    """standby.signal in the copy before the copy moves; why not

    A server started between the move and the signal would take
    writes on the copy (keel#153: a start that takes no lock ran in the
    middle of a reseed)."""
    try:
        signal = os.path.join(fresh, dbpostgres.STANDBY_SIGNAL)
        fd = os.open(signal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
        _as_postgres(signal)
    except OSError as e:
        return f"cannot write standby.signal into the copy:" \
            f" {e.strerror or e}"
    return ""


def _probe(pgpass: str, host: str, port: int, runner,
           tls: str = "") -> tuple[dict, str]:
    """Ask the primary what it is; the reason it cannot be copied"""
    out = {}
    argv = dbpostgres.CLIENT + (conninfo(host, port, pgpass, tls),
                                "--command", PROBE_SQL)
    problem = _run(runner, argv, output=out)
    where = {"host": host, "port": port,
             "user": dbpostgres.REPLICATION_USER}
    if problem:
        return {}, UNREACHABLE.format(detail=problem, **where)
    columns = (out["stdout"].strip().split("\t") + ["", "0", "0"])[:4]
    if columns[0] == "t":
        return {}, IS_STANDBY.format(**where)
    return {"size": _count(columns[2]), "left_out": _count(columns[3])}, ""


def _count(column: str) -> int:
    try:
        return int(column or 0)
    except ValueError:
        return 0


def _room(datadir: str, size: int, action, left_out: int = 0) -> str:
    """Why the copy may not fit where the server keeps its data, if so

    Checked before anything is stopped: the peak is the old directory
    and the copy beside it at once, about twice the primary's size.
    """
    try:
        found = os.statvfs(datadir)
    except OSError as e:
        return f"cannot measure the free space of {datadir}: {e.strerror}"
    free = found.f_bavail * found.f_frsize
    need = size * DISK_MARGIN
    if free < need:
        return NO_ROOM.format(datadir=datadir, free=free, need=need,
                              host=action.host, port=action.port) + (
            LEFT_OUT.format(count=left_out,
                            user=dbpostgres.REPLICATION_USER)
            if left_out else "")
    return ""


def _basebackup(fresh: str, pgpass: str, action, runner) -> str:
    """The copy, streamed into a sibling of the data directory

    Compressed by the primary (zstd, which the plain format unpacks on
    this side): a data directory is mostly empty pages, and the design
    case's link (250 ms, 2 % loss, decision 0050) carries about 50 kB/s
    of one TCP stream. A fresh cluster with one small database is about
    40 MB raw and under 3 MB compressed (measured on PostgreSQL 17),
    so the copy takes seconds instead of minutes (found by the pair's
    network-namespace test: in case (a), B's apply and its seed took
    about 12 minutes)."""
    argv = dbpostgres.AS_POSTGRES + (
        "pg_basebackup", f"--pgdata={fresh}", "--format=plain",
        "--wal-method=stream", "--checkpoint=fast",
        f"--compress={COMPRESSION}",
        "--dbname", conninfo(action.host, action.port, pgpass,
                             getattr(action, "tls", "")),
    )
    return _run(runner, argv)


def _swap(dropdir: str, datadir: str, aside: str, fresh: str,
          action, runner, unit: str, keep: bool = False) -> str:
    """Move the copy in; undo every failure before the old copy goes"""
    os.rename(datadir, aside)
    problem = _standby_in_place(dropdir, datadir, fresh, action)
    if problem:
        return _undo(runner, datadir, aside, problem, unit)
    if keep:
        kept = dbpgkeep.kept_name(datadir)
        try:
            os.rename(aside, kept)
            action.kept = kept
            return ""
        except OSError:
            pass
    shutil.rmtree(aside)
    return ""


def _standby_in_place(dropdir: str, datadir: str, fresh: str,
                      action) -> str:
    """The copy where the data directory was, with the follow drop-in;
    the reason

    The copy holds standby.signal before it moves (_signal), so a start
    at any point after the move is a recovery: the copy cannot take
    writes. The follow drop-in comes next, and gives the standby its
    primary.
    """
    os.rename(fresh, datadir)
    return write_follow(dropdir, action)


def write_follow(dropdir: str, action) -> str:
    """The follow drop-in of the standby; the reason it failed, if so"""
    try:
        os.makedirs(dropdir, exist_ok=True)
        follow = os.path.join(dropdir, dbpostgres.FOLLOW_DROPIN_NAME)
        # 0600 while it holds the password: the chown to postgres below
        # is what opens it to the server, never the other way round
        fd = os.open(follow, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                     | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fob:
            fob.write(dbpostgres.follow_dropin_text(
                action.host, action.port, action.password, action.tls,
                slot=str(getattr(action, "slot", "") or "")))
        _as_postgres(follow)
    except OSError as e:
        return f"cannot write the standby files: {e.strerror or e}"
    return ""


def _undo(runner, datadir: str, aside: str, problem: str,
          unit: str) -> str:
    """Put the old data directory back and start the server; the error"""
    shutil.rmtree(datadir, ignore_errors=True)
    try:
        os.rename(aside, datadir)
    except OSError:
        problem += f"; the old data directory is at {aside}"
    _run(runner, ("systemctl", "start", unit))
    return problem + "; the server is as it was"


def _as_postgres(path: str) -> None:
    """The file owned by the server user; a dev host without the user
    keeps a root-owned file, which the server reads all the same"""
    try:
        uid = pwd.getpwnam("postgres").pw_uid
        os.chown(path, uid, -1)
    except (KeyError, OSError):
        pass


def _streaming(runner, clock, sleep) -> str:
    """Why the walreceiver is not streaming yet, or an empty string

    The server was just started: the socket may refuse the first asks,
    and the connection to the primary takes a moment on a poor network
    (250 ms RTT is the design case, decision 0050), so the answer is
    polled until STREAMING_TIMEOUT.
    """
    deadline = clock() + STREAMING_TIMEOUT
    while True:
        out = {}
        problem = _run(runner, dbpostgres.CLIENT
                       + ("--command", STREAMING_QUESTION), output=out)
        if not problem and out["stdout"].strip() == "streaming":
            return ""
        if clock() >= deadline:
            return problem or "the walreceiver names no status"
        sleep(POLL_SECONDS)
