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

A stream that a cut ends inside a record leaves bytes that replay cannot
apply (keel#215): the walreceiver flushes what arrived, replay stands at
the end of the last whole record, and the two positions never meet. The
drain ends then too, when neither position has moved for STALL_SECONDS:
nothing more arrives, and pg_promote() replays every whole record that
is in pg_wal before it ends recovery, so only the bytes of the unfinished
record are left behind, which no standby can apply.
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
STALL_SECONDS = 5.0
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


INCOMPLETE_RECORD = (
    "{gap} bytes after the last record that replay applied were received"
    " and cannot be applied: an incomplete record, because the stream"
    " ended inside it. Neither position moved for {seconds:g} s, so the"
    " drain is over; pg_promote() replays every whole record that is in"
    " pg_wal first"
)


def promote(
    root: str, action, runner=subprocess.run, clock=time.monotonic,
    sleep=time.sleep, drain: bool = True, say=None,
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

    The drain also ends when neither position has moved for
    STALL_SECONDS (keel#215); `say` is told why, with the size of the gap.
    """
    deadline = clock() + action.timeout
    seen, moved_at = None, clock()
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
        if (replayed, received) != seen:
            seen, moved_at = (replayed, received), clock()
        elif replayed is not None and clock() - moved_at >= STALL_SECONDS:
            if say is not None:
                say(INCOMPLETE_RECORD.format(
                    gap=_distance(replayed, received),
                    seconds=STALL_SECONDS))
            break
        if clock() >= deadline:
            return DRAIN_TIMEOUT.format(timeout=action.timeout)
        sleep(POLL_SECONDS)
    problem = _run(runner, dbpostgres.CLIENT,
                   text=dbpostgres.promote().text)
    if problem:
        return f"pg_promote() failed: {problem}"
    return None


def _distance(low, high) -> int:
    """The bytes from one position to a later one"""
    return ((high[0] - low[0]) << 32) + high[1] - low[1]


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
