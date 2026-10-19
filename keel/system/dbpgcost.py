# Copyright (c) 2026 KeelLinux maintainers
"""What the rejoin of an old primary costs: pg_rewind or a reseed

Handbook decision 0054, second amendment of 2026-10-18. pg_rewind copies
every WAL file of the holder from the segment of the fork on, in full,
through SQL. On the design case's link (250 ms, 1.5 % loss) that is 47
kB/s, and the reseed, which compresses the copy on the holder, was 8
times faster for a small cluster. So keel estimates both before the
rejoin and takes the cheaper one:

- the rewind copies the WAL files of the holder from the segment of the
  fork (the holder's timeline history file names the fork), plus the WAL
  that the old primary wrote after the fork, as a measure of the changed
  files;
- the reseed copies the databases of the holder, compressed (COMPRESSION);
- the speed is timed by a read of PROBE_BYTES of the holder's WAL.

A rewind that is expected to take CHEAP_S or less is taken at once: it
keeps the data, and the cost is small. When keel cannot make the estimate
(an older holder lacks the grants), it rewinds, as before.
"""

import re
import subprocess
import time
from typing import NamedTuple

from keel.system import dbpgseed, dbpostgres
from keel.system.dbseed import _run, spool

COMPRESSION = 0.3
CHEAP_S = 120
PROBE_BYTES = 262144
WAL_NAME = re.compile(r"^[0-9A-F]{24}$")
HISTORY_SQL = (
    "SELECT convert_from(pg_read_binary_file('pg_wal/{name}.history'),"
    " 'UTF8')"
)
WAL_SQL = (
    "SELECT f || E'\\t' || (pg_stat_file('pg_wal/' || f, true)).size"
    " FROM pg_ls_dir('pg_wal', true, false) AS f"
    " WHERE f ~ '^[0-9A-F]{24}$'"
)
SPEED_SQL = (
    "SELECT length(pg_read_binary_file('pg_wal/{name}', 0, {size}, true))"
)
REPLAY_SQL = "SELECT pg_last_wal_replay_lsn()"


class Estimate(NamedTuple):
    rewind: int
    reseed: int
    speed: float | None
    wal: int
    changed: int
    databases: int = 0


def _clock() -> float:
    return time.monotonic()


def fork_lsn(history: str, own: int) -> int | None:
    """Where the holder's history leaves the timeline `own`, or None"""
    for line in history.splitlines():
        columns = line.split("\t")
        if len(columns) >= 2 and columns[0].strip() == str(own):
            return lsn_value(columns[1])
    return None


def lsn_value(text: str) -> int | None:
    high, sep, low = str(text).strip().partition("/")
    if not sep:
        return None
    try:
        return (int(high, 16) << 32) | int(low, 16)
    except ValueError:
        return None


def parse_wal(text: str) -> list[tuple[str, int]]:
    found = []
    for line in text.splitlines():
        name, _, size = line.partition("\t")
        if WAL_NAME.match(name) and size.strip().isdigit():
            found.append((name, int(size)))
    return found


def wal_bytes(files: list[tuple[str, int]], fork: int) -> int:
    """The size of the WAL files from the segment of the fork on"""
    if not files:
        return 0
    segsize = max(size for _, size in files)
    total = 0
    for name, size in files:
        position = (int(name[8:16], 16) << 32) \
            + int(name[16:24], 16) * segsize
        if position + segsize > fork:
            total += size
    return total


def reseed_bytes(databases: int) -> int:
    return int(databases * COMPRESSION)


def choose(rewind: int, reseed: int, speed: float | None) -> str:
    """"rewind" or "reseed": the quick rewind, else the smaller"""
    if not speed:
        return "rewind"
    if rewind / speed <= CHEAP_S:
        return "rewind"
    return "reseed" if reseed < rewind else "rewind"


def measure(root: str, host: str, port: int, password: str, tls: str,
            own: int, theirs: str, runner=subprocess.run
            ) -> Estimate | None:
    """The estimate, asked of the holder as the replication role; None
    when it cannot be made"""
    try:
        with spool(root) as directory:
            pgpass = dbpgseed.write_pgpass(directory, host, port, password)
            conn = dbpgseed.conninfo(host, port, pgpass, tls)
            return _measure(conn, own, theirs, runner, pgpass, host, port,
                            tls)
    except (OSError, ValueError):
        return None


def _ask(conn: str, sql: str, runner) -> str | None:
    out: dict = {}
    if _run(runner, dbpostgres.CLIENT + (conn, "--command", sql),
            output=out):
        return None
    return out.get("stdout") or ""


def _measure(conn, own, theirs, runner, pgpass, host, port, tls):
    history = _ask(conn, HISTORY_SQL.format(
        name="%08X" % int(theirs)), runner)
    listing = _ask(conn, WAL_SQL, runner)
    if history is None or listing is None:
        return None
    fork = fork_lsn(history, own)
    files = parse_wal(listing)
    if fork is None or not files:
        return None
    found, problem = dbpgseed._probe(pgpass, host, port, runner, tls)
    if problem:
        return None
    wal = wal_bytes(files, fork)
    replay = _ask_local(runner)
    changed = max(0, replay - fork) if replay is not None else 0
    name = max(files)[0]
    began = _clock()
    got = _ask(conn, SPEED_SQL.format(name=name, size=PROBE_BYTES), runner)
    seconds = _clock() - began
    speed = None
    if got is not None and got.strip().isdigit() and int(got) > 0 \
            and seconds > 0:
        speed = int(got) / seconds
    return Estimate(wal + changed, reseed_bytes(found["size"]), speed, wal,
                    changed, found["size"])


def _ask_local(runner) -> int | None:
    out: dict = {}
    if _run(runner, dbpostgres.CLIENT + ("--command", REPLAY_SQL),
            output=out):
        return None
    return lsn_value(out.get("stdout") or "")
