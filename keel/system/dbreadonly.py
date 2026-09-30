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

root keeps it. MariaDB 11.8 has no setting that stops root, which holds
every privilege and can grant itself any it lacks; so can Webmin's MySQL
module, which connects as root. docs/apply.md says so.

`promote` drains before it forgets: STOP SLAVE followed by RESET SLAVE
ALL discards the relay log, and with it every transaction the I/O thread
received and the SQL thread had not applied yet. So the I/O thread stops
first, the SQL thread applies what it holds for a bounded time, and only
then does the node stop replicating, forget its primary and take writes.
A SQL thread that stopped on an error is refused, since what it did not
apply would be lost.

keel.system.effects is the only caller.
"""

import os
import subprocess
import time

from keel.inspect.dbengines import grantee, own_account
from keel.inspect.dbreading import field_lines
from keel.inspect.tree import File
from keel.system import dbmariadb as mariadb
from keel.system.actions import READ_ONLY_RECORD as RECORD

QUIET = ("mariadb", "--batch", "--skip-column-names", "--execute")
BYPASS_QUESTION = QUIET + (
    "SELECT DISTINCT GRANTEE FROM information_schema.USER_PRIVILEGES"
    " WHERE PRIVILEGE_TYPE = 'READ_ONLY ADMIN'",
)
ACCOUNTS_QUESTION = QUIET + ("SELECT User, Host FROM mysql.user",)
STATUS_QUESTION = ("mariadb", "--batch", "--execute",
                   "SHOW REPLICA STATUS\\G")
NO_BINLOG = "SET SESSION sql_log_bin = 0;\n"
POLL_SECONDS = 1.0

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
    sleep=time.sleep,
) -> str | None:
    """Drain the SQL thread, then promote; None on success, else why not"""
    values, problem = _status(runner)
    if problem:
        return f"cannot read the replica status: {problem}. Nothing was" \
            " changed"
    if not values:
        return NOT_REPLICATING
    if values.get("Slave_SQL_Running", "").lower() != "yes":
        return STOPPED.format(error=_error(values))
    problem = _send(runner, "STOP SLAVE IO_THREAD;\n")
    if problem:
        return f"stopping the I/O thread failed ({problem}). Nothing was" \
            " changed"
    problem = _drain(runner, action.timeout, clock, sleep)
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


def _drain(runner, timeout: int, clock, sleep) -> str:
    """Wait until the SQL thread applied everything received; or why not"""
    deadline = clock() + timeout
    while True:
        values, problem = _status(runner)
        if problem:
            return f"the replica status could not be read while draining" \
                f" ({problem}); nothing was promoted"
        if values.get("Slave_SQL_Running", "").lower() != "yes":
            return STOPPED_DRAINING.format(error=_error(values))
        if _drained(values):
            return ""
        if clock() >= deadline:
            return SLOW.format(timeout=timeout)
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
