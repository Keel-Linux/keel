# Copyright (c) 2026 KeelLinux maintainers
"""Keep a replica read only, and promote one without losing a row

A replica's drop-in says `read_only = ON` (keel.system.dbmariadb), and
on MariaDB 11.8 an account holding READ_ONLY ADMIN writes through it.
The appliances ship two: the image's `admin` and Adminer's `adminer`,
both with ALL PRIVILEGES ON *.*, so Adminer on port 12322 could write to
a replica. `lock` takes the privilege from every account but the
server's own socket accounts, and records which, so that `unlock` gives
it back to those and no others once the node is no longer a replica.
Both run with `sql_log_bin` off: a privilege a replica takes or gives
back is its own business and never goes into a binary log.

**root loses it too** (0049, second round, point 1): MariaDB 11.8 has
no setting that stops an account holding the privilege, so the privilege
is taken from every account but `'mysql'@'localhost'`, which only the
system's mysql user reaches by the unix socket, and `mariadb.sys`. keel
runs its own replica statements as that user (keel.system.dbmariadb's
CLIENT), root through Webmin or at a shell gets error 1290 like the
application, and root cannot grant itself the privilege back: GRANT
gives only what the granter holds. docs/apply.md says so.

`promote` drains before it forgets: STOP SLAVE followed by RESET SLAVE
ALL discards the relay log, and with it every transaction the I/O thread
received and the SQL thread had not applied yet. So the I/O thread stops
first, the SQL thread applies what it holds for a bounded time, and only
then does the node stop replicating, forget its primary and take writes.
A SQL thread that stopped on an error is refused, since what it did not
apply would be lost.

keel.system.effects is the only caller.
"""

import contextlib
import fcntl
import io
import os
import subprocess
import time
from collections.abc import Iterator

from keel.inspect.dbengines import grantee, own_account
from keel.inspect.dbreading import field_lines
from keel.inspect.tree import File
from keel.system import dbmariadb as mariadb
from keel.system.actions import READ_ONLY_RECORD as RECORD

QUIET = mariadb.QUIET_CLIENT + ("--execute",)
BYPASS_QUESTION = QUIET + (
    "SELECT DISTINCT GRANTEE FROM information_schema.USER_PRIVILEGES"
    " WHERE PRIVILEGE_TYPE = 'READ_ONLY ADMIN'",
)
ACCOUNTS_QUESTION = QUIET + ("SELECT User, Host FROM mysql.user",)
STATUS_QUESTION = mariadb.CLIENT + ("--execute", "SHOW REPLICA STATUS\\G")
NO_BINLOG = "SET SESSION sql_log_bin = 0;\n"
POLL_SECONDS = 1.0
# how long the old primary waits for read_only before it releases the
# VIP: the semi-synchronous timeout (10 s) and room
QUIESCE_TIMEOUT = 15
# the lock follow and spec apply take around the replication's statements
REPLICATION_LOCK = "var/lib/keel/database/follow.lock"
IO_STOP = "STOP SLAVE IO_THREAD"
# subprocess.run as the module found it: a runner that is anything else
# (a test's) runs the stop to its end itself
REAL_RUN = subprocess.run
# the stop running in the server: its own statement, exactly
STOPPING_QUESTION = QUIET + (
    "SELECT STATE FROM information_schema.PROCESSLIST"
    " WHERE INFO = 'STOP SLAVE IO_THREAD'",
)
# the stop's STATE while it kills the thread (sql/slave.cc stop_slave)
KILLING = "Killing slave"
# how long the stop may take to show in the server, and how often it is
# looked for; how long it may take to end (slave_net_timeout and the
# 5 s of the semi-synchronous kill, with room)
SHOWN_WAIT = 5.0
SHOWN_POLL = 0.1
STOP_WAIT = 60

NOT_REPLICATING = (
    "this server replicates from nowhere, so there is nothing to promote."
    " Nothing was changed"
)
STOPPED = (
    "the SQL thread stopped ({error}), and promoting would discard what it"
    " received and did not apply. Fix what stopped it and START SLAVE"
    " until Seconds_Behind_Master is 0, then promote; or, while the old"
    " primary is there, rebuild this replica from it with `keel spec"
    " apply --system-only --destroy-local-database`. Nothing was changed"
)
STOPPED_DRAINING = (
    "the SQL thread stopped while applying what it had received ({error})."
    " Nothing was promoted: fix what stopped it, START SLAVE, and promote"
    " once it has caught up"
)
SLOW = (
    "the SQL thread did not apply everything it had received within"
    " {timeout} s. Nothing was promoted; run keel database promote again"
    " once Seconds_Behind_Master is 0"
)
RESUMED = ". The I/O thread was started again"
RESUME_FAILED = (
    ". Starting the I/O thread again failed ({problem}), so this replica"
    " receives nothing from its primary: run START SLAVE IO_THREAD"
)


def lock(root: str, runner=subprocess.run) -> str | None:
    """Take READ_ONLY ADMIN from the accounts that hold it; None or why not

    What is taken is recorded before it is taken, so a failure half way
    still gives back everything a later `unlock` finds missing.
    """
    out, problem = _ask(runner, BYPASS_QUESTION)
    if problem:
        return f"cannot list the accounts that write through read_only:" \
            f" {problem}"
    taken = []
    for line in out.splitlines():
        pair = grantee(line)
        if pair is not None and not own_account(*pair):
            taken.append(pair)
    if not taken:
        return None
    _write_record(root, _merge(_read_record(root), taken))
    text = NO_BINLOG + "".join(
        f"REVOKE READ_ONLY ADMIN ON *.* FROM {_account(*pair)};\n"
        for pair in taken
    )
    return _send(runner, text) or None


def unlock(root: str, runner=subprocess.run) -> str | None:
    """Give READ_ONLY ADMIN back to the recorded accounts that still exist

    An account dropped since is not created again by the GRANT. The
    record goes only once the grant went through.
    """
    recorded = _read_record(root)
    if recorded is None:
        return None
    out, problem = _ask(runner, ACCOUNTS_QUESTION)
    if problem:
        return f"cannot list the accounts of this server: {problem}"
    existing = {tuple(line.split("\t", 1)) for line in out.splitlines()
                if "\t" in line}
    back = [pair for pair in recorded if pair in existing]
    if back:
        problem = _send(runner, NO_BINLOG + "".join(
            f"GRANT READ_ONLY ADMIN ON *.* TO {_account(*pair)};\n"
            for pair in back
        ))
        if problem:
            return problem
    os.remove(os.path.join(root, RECORD))
    return None


def promote(
    root: str, action, runner=subprocess.run, clock=time.monotonic,
    sleep=time.sleep, spawn=None,
) -> str | None:
    """Stop receiving, drain, then take writes; None on success, else
    why not

    STOP SLAVE IO_THREAD can take seconds when the primary is dead
    (keel#118). Measured on 11.8: a thread that tries to connect ends
    only when the try times out (slave_net_timeout, 10 s); a connected
    thread with semi-synchronous replication tries to connect to the
    primary to end its dump thread (5 s). So the stop runs in a client
    of its own, and read_only goes off before it ends only when all of
    this holds:

    - the stop is in the server's killing phase (its process list STATE
      is "Killing slave"), or it ended without an error, both before
      the drain and again after it: the server marks the I/O thread
      killed in that phase, and a killed thread receives no more events
      (it leaves its read loop, and one that connects ends before it
      asks for the binary log);
    - the SQL thread applied everything received (the drain);
    - the received position read after the drain is the drained one.

    Otherwise the old order applies: the stop waited for, the drain
    again, then the promotion. The guarantee is the old order's: read_only
    goes off only once the I/O thread receives nothing and the SQL thread
    applied all it received. The SQL thread is not stopped first: it has
    nothing more to apply, and STOP SLAVE SQL_THREAD waits behind the I/O
    thread's stop (4.7 s measured). The I/O thread is waited for and the
    primary forgotten after. A planned promote takes the same path; its
    stop ends at once, since the primary answers.
    """
    values, problem = _status(runner)
    if problem:
        return f"cannot read the replica status: {problem}. Nothing was" \
            " changed"
    if not values:
        return NOT_REPLICATING
    if values.get("Slave_SQL_Running", "").lower() != "yes":
        return STOPPED.format(error=_error(values))
    stopping, problem = _stop_io(runner, spawn)
    if problem:
        return f"stopping the I/O thread failed ({problem}). Nothing was" \
            " changed"
    if not _stop_shown(runner, stopping, clock, sleep):
        problem = _waited(stopping)
        if problem:
            # the server may have taken the statement before the client
            # died: the I/O thread is started again either way
            return f"stopping the I/O thread failed ({problem}). Nothing" \
                " was promoted" + _resume(runner)
    problem, drained = _drain(runner, action.timeout, clock, sleep)
    if problem:
        _waited(stopping)
        return problem + _resume(runner)
    # the SQL thread is left running: it has nothing more to apply, and
    # STOP SLAVE SQL_THREAD would wait behind the I/O thread's stop
    after, problem = _status(runner)
    if problem or _received(drained, after) or \
            not _killing(runner, stopping):
        return _promote_in_order(runner, stopping, action.timeout, clock,
                                 sleep)
    writable = mariadb.set_read_only(False)
    problem = _send(runner, writable.text)
    if problem:
        _waited(stopping)
        return f"{writable.summary} failed: {problem}"
    forget = mariadb.stop_replicating()
    problem = _send(runner, forget.text)
    _waited(stopping)
    if problem:
        return (f"the server takes writes, but {forget.summary} failed:"
                f" {problem}. Run STOP SLAVE; RESET SLAVE ALL before its"
                " next restart")
    return None


def quiesce(runner=subprocess.run) -> str | None:
    """read_only on, before the old primary lets the VIP go (keel#138);
    None, or why not

    SET GLOBAL read_only = ON returns once the commits in flight ended,
    and a commit with semi-synchronous replication ends when the
    replica, still connected then, acknowledged it. So a client whose
    write was in flight gets its answer before the address goes, and no
    new write is taken. Bounded by QUIESCE_TIMEOUT: a replica that does
    not acknowledge costs rpl_semi_sync_master_timeout (10 s) at most."""
    statements = mariadb.set_read_only(True)
    try:
        done = runner(list(mariadb.CLIENT), input=statements.text,
                      capture_output=True, text=True, check=False,
                      timeout=QUIESCE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"the server did not turn read only within" \
            f" {QUIESCE_TIMEOUT} s"
    except OSError as e:
        return f"cannot run {mariadb.CLIENT[0]}: {e.strerror}"
    if done.returncode != 0:
        return (done.stderr or "").strip() or f"exited {done.returncode}"
    return None


@contextlib.contextmanager
def replication_locked(root: str) -> Iterator[None]:
    """One writer of the replication's statements at a time: keel
    database follow, keel database watch's follow and spec apply's
    replication actions (keel#118)"""
    path = os.path.join(root, REPLICATION_LOCK)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class _Ran:
    """A client that already ran to its end, as a process looks"""

    def __init__(self, done):
        self.returncode = done.returncode
        self.stderr = io.StringIO(done.stderr or "")

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout=None) -> int:
        return self.returncode


def _stop_io(runner, spawn):
    """STOP SLAVE IO_THREAD in a client of its own, `spawn` (Popen when
    the runner is subprocess.run); with another runner, run to its end
    by it. (the process, why it could not start)"""
    argv = list(QUIET) + [IO_STOP]
    try:
        if spawn is None and runner is not REAL_RUN:
            return _Ran(runner(argv, capture_output=True, text=True,
                               check=False)), ""
        return (spawn or subprocess.Popen)(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True), ""
    except OSError as e:
        return None, f"cannot run {mariadb.CLIENT[0]}: {e.strerror}"


def _stop_shown(runner, stopping, clock, sleep) -> bool:
    """Whether the stop reached the server's killing phase, waited for
    up to SHOWN_WAIT"""
    deadline = clock() + SHOWN_WAIT
    while True:
        if _killing(runner, stopping):
            return True
        if stopping.poll() is not None or clock() >= deadline:
            return False
        sleep(SHOWN_POLL)


def _killing(runner, stopping) -> bool:
    """Whether the stop ended without an error, or is in the server's
    killing phase: its process list STATE is KILLING (the statement's
    INFO is set when it is dispatched, before the stop takes its lock,
    so INFO alone says nothing)"""
    done = stopping.poll()
    if done is not None:
        return done == 0
    out, problem = _ask(runner, STOPPING_QUESTION)
    return not problem and KILLING in out.splitlines()


def _waited(stopping) -> str:
    """The stop waited for; an empty string, or why it failed"""
    try:
        stopping.wait(STOP_WAIT)
    except subprocess.TimeoutExpired:
        return f"it did not end within {STOP_WAIT} s"
    if stopping.returncode != 0:
        said = stopping.stderr.read() if stopping.stderr else ""
        return (said or "").strip() or f"exited {stopping.returncode}"
    return ""


def _received(drained: dict[str, str], after: dict[str, str]) -> bool:
    """Whether the I/O thread received anything after the drain"""
    return any(drained.get(one) != after.get(one)
               for one in ("Master_Log_File", "Read_Master_Log_Pos"))


def _promote_in_order(runner, stopping, timeout: int, clock,
                      sleep) -> str | None:
    """The old order: the stop waited for, the SQL thread started and
    drained again, then STOP SLAVE, RESET SLAVE ALL, read_only off"""
    problem = _waited(stopping)
    if problem:
        return f"stopping the I/O thread failed ({problem}). Nothing was" \
            " promoted" + _resume(runner)
    problem, _ = _drain(runner, timeout, clock, sleep)
    if problem:
        return problem + _resume(runner)
    statements = mariadb.promote()
    problem = _send(runner, statements.text)
    if problem:
        return f"{statements.summary} failed: {problem}"
    return None


def _resume(runner) -> str:
    """Start the I/O thread again after a drain that promoted nothing,
    and say whether it did"""
    problem = _send(runner, "START SLAVE IO_THREAD;\n")
    if problem:
        return RESUME_FAILED.format(problem=problem)
    return RESUMED


def _drain(runner, timeout: int, clock,
           sleep) -> tuple[str, dict[str, str]]:
    """Wait until the SQL thread applied everything received; ("", the
    status then), or (why not, {})"""
    deadline = clock() + timeout
    while True:
        values, problem = _status(runner)
        if problem:
            return f"the replica status could not be read while draining" \
                f" ({problem}); nothing was promoted", {}
        if values.get("Slave_SQL_Running", "").lower() != "yes":
            return STOPPED_DRAINING.format(error=_error(values)), {}
        if _drained(values):
            return "", values
        if clock() >= deadline:
            return SLOW.format(timeout=timeout), {}
        sleep(POLL_SECONDS)


def _drained(values: dict[str, str]) -> bool:
    """Whether the SQL thread has executed up to what the I/O thread read"""
    return (
        values.get("Relay_Master_Log_File") == values.get("Master_Log_File")
        and values.get("Exec_Master_Log_Pos")
        == values.get("Read_Master_Log_Pos")
    )


def _error(values: dict[str, str]) -> str:
    return values.get("Last_SQL_Error") or "no error was recorded"


def _status(runner) -> tuple[dict[str, str], str]:
    out, problem = _ask(runner, STATUS_QUESTION)
    if problem:
        return {}, problem
    return _fields(out), ""


def _fields(text: str) -> dict[str, str]:
    return field_lines(File("SHOW REPLICA STATUS", text))


def _account(user: str, host: str) -> str:
    return f"{mariadb.literal(user)}@{mariadb.literal(host)}"


def _merge(recorded, taken) -> list[tuple[str, str]]:
    merged = list(recorded or [])
    merged += [pair for pair in taken if pair not in merged]
    return merged


def _read_record(root: str) -> list[tuple[str, str]] | None:
    path = os.path.join(root, RECORD)
    if not os.path.exists(path):
        return None
    with open(path) as fob:
        return [tuple(line.split("\t", 1)) for line in fob.read().splitlines()
                if "\t" in line]


def _write_record(root: str, pairs: list[tuple[str, str]]) -> None:
    path = os.path.join(root, RECORD)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fob:
        fob.write("".join(f"{user}\t{host}\n" for user, host in pairs))


def _ask(runner, argv) -> tuple[str, str]:
    """Run one question; its output, or an empty one and why it failed"""
    return _run(runner, argv, None)


def _send(runner, text: str) -> str:
    """Send statements on standard input; an empty string, or why not"""
    return _run(runner, mariadb.CLIENT, text)[1]


def _run(runner, argv, text) -> tuple[str, str]:
    try:
        out = runner(list(argv), input=text, capture_output=True,
                     text=True, check=False)
    except OSError as e:
        return "", f"cannot run {argv[0]}: {e.strerror}"
    if out.returncode != 0:
        detail = (out.stderr or "").strip()
        return "", detail or f"{argv[0]} exited {out.returncode}"
    return out.stdout or "", ""
