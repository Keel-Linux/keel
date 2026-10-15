# Copyright (c) 2026 KeelLinux maintainers
"""Promote a PostgreSQL standby: drain, then take writes

The PostgreSQL twin of keel.system.dbreadonly's promote (handbook
decision 0054). A standby refuses writes while it is in recovery, so
there is no read_only to turn off and no replication setting to forget:
a promotion ends recovery, and `pg_promote()` is the one statement that
does it, refusing by itself while the standby has not finished recovery.

What remains is the drain. `pg_promote()` ends recovery where replay
stands, and a standby that promotes with received WAL not yet replayed
loses it: the guarantee is that the replayed position reached the
received one. Positions are compared as numbers, not text: an LSN is
two hexadecimal parts and the text form does not zero-pad them, so
"0/A" sorts after "0/1000" and only the parsed pair compares right.

A standby that receives nothing cannot be drained: the walreceiver is
not connected, the primary is unreachable, and replay may stand behind
what the primary once had. That is refused, not promoted: taking writes
on a copy behind the old primary is the split-brain the pair exists to
prevent.
"""

import subprocess
import time

from keel.system import dbpostgres
from keel.system.dbseed import _run

POSITIONS = (
    "SELECT pg_is_in_recovery(), pg_last_wal_replay_lsn(),"
    " pg_last_wal_receive_lsn()"
)
POLL_SECONDS = 1.0
NOT_STANDBY = (
    "the server is not in recovery: only a standby is promoted"
)
NOT_RECEIVING = (
    "the standby receives nothing from its primary, so it cannot be"
    " drained: the primary is unreachable. Nothing was changed"
)
DRAIN_TIMEOUT = (
    "the standby did not replay everything it received within {timeout}"
    " s; it still follows the old primary and refuses writes"
)


def promote(
    root: str, action, runner=subprocess.run, clock=time.monotonic,
    sleep=time.sleep, drain: bool = True,
) -> str | None:
    """Carry out a PromoteReplica of engine postgresql; None, or why not

    The drain is polled until the replayed position reaches the received
    one, for at most `action.timeout` seconds, and only then does
    pg_promote() run. A failure leaves the standby as it was: still in
    recovery, still following the old primary.

    Without `drain`, a standby that follows nobody (a fenced one,
    keel#152) is promoted where its replay stands: it receives nothing,
    so there is nothing to drain. keel.system.dbpgfollow decides when
    that loses nothing of the pair.
    """
    deadline = clock() + action.timeout
    while True:
        in_recovery, replayed, received, problem = positions(runner)
        if problem:
            return f"cannot read the standby's positions: {problem}." \
                " Nothing was changed"
        if not in_recovery:
            return NOT_STANDBY
        if not drain:
            break
        if received is None:
            return NOT_RECEIVING
        if replayed is not None and replayed >= received:
            break
        if clock() >= deadline:
            return DRAIN_TIMEOUT.format(timeout=action.timeout)
        sleep(POLL_SECONDS)
    problem = _run(runner, dbpostgres.CLIENT,
                   text=dbpostgres.promote().text)
    if problem:
        return f"pg_promote() failed: {problem}"
    return None


def lsn(value: str):
    """A WAL position as a comparable pair of numbers, or None

    "0/3A0F1C" is (0, 0x3A0F1C). Text comparison is wrong for these:
    the hexadecimal parts are not zero-padded, so the pair, not the
    string, orders them.
    """
    high, sep, low = str(value).strip().partition("/")
    if not sep:
        return None
    try:
        return int(high, 16), int(low, 16)
    except ValueError:
        return None


def positions(runner):
    """What recovery replayed and what the walreceiver received; the
    reason they could not be read"""
    out = {}
    problem = _run(runner, dbpostgres.CLIENT
                   + ("--command", POSITIONS), output=out)
    if problem:
        return False, None, None, problem
    columns = (out["stdout"].strip().split("\t") + ["", "", ""])[:3]
    return (columns[0] == "t", lsn(columns[1]), lsn(columns[2]), "")
