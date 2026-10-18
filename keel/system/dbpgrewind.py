# Copyright (c) 2026 KeelLinux maintainers
"""An old PostgreSQL primary rejoins with pg_rewind when it can

Handbook decision 0054, amendment of 2026-10-18. The follow of
keel.system.dbpgfollow fences an old primary: a standby that follows
nobody, with a dump of what it holds kept. Before the divergence is
recorded and the reseed waits for its confirmation, this module tries
the cheaper path, in this order:

1. ask the running server for the settings pg_rewind needs
   (wal_log_hints or data checksums, and full_page_writes), and ask the
   holder what it is: a node that cannot be rewound is not stopped;
2. stop the server and wait until its postmaster is gone: a clean
   shutdown, which pg_rewind needs;
3. run pg_rewind with --progress. It only changes this node: it reads
   the holder and never writes to it, so what the holder acknowledged
   stays. What this node wrote after the fork point is discarded; the
   dump that the caller kept first holds it. A run that fails before it
   says "need to copy" changed nothing: the server starts again as the
   fenced standby it was, and the caller records the divergence. There
   is no dry run, because a dry run reads as much as the run does, and
   on the design case's link (250 ms, 1.5 % loss) that is 20 minutes
   spent twice;
5. write the follow drop-in and standby.signal, start the server, and
   wait for the walreceiver to stream from the holder on the new
   timeline.

A run that fails after it said "need to copy" leaves the data directory
half copied. The mark FAILED then says that this copy is unusable:
nothing runs pg_rewind on it again and only the confirmed reseed
replaces it (the manual says to take a new copy).

The password reaches pg_rewind in a pgpass file of mode 0600 that
keel.system.dbpgseed writes, never in an argument vector.
"""

import os
import subprocess
import time
from typing import NamedTuple

from keel.system import dbpgseed, dbpostgres
from keel.system.dbseed import _run, spool

FAILED = "var/lib/keel/database/rewind-failed"
# pg_rewind --progress prints this line when the copy begins
COPY_BEGINS = "need to copy"
# the dump taken before the rewind: the rewind writes no divergence
# record, and a run after a half copy or a standby that did not stream
# must not dump the half copied cluster again
DUMP = "var/lib/keel/database/rewind-dump"
# the last run that failed before the copy, with the reason: its time is
# the time of the refusal. The server is stopped for each run, so a node
# that cannot be rewound asks again only after RETRY_S, not at each
# follow
REFUSED = "var/lib/keel/database/rewind-refused"
RETRY_S = 600
# what pg_rewind needs of this node: either data checksums or
# wal_log_hints on, and full page writes
SETTINGS_SQL = (
    "SELECT current_setting('wal_log_hints'),"
    " current_setting('data_checksums'),"
    " current_setting('full_page_writes')"
)
TAIL = 300
UNUSABLE = (
    "pg_rewind failed halfway, so the copy of this node is unusable and"
    " is not rewound again ({detail}). It stays read only and is not"
    " connected; keel spec apply --system-only --destroy-local-database"
    " reseeds it from the holder, the dump kept first"
)


class Outcome(NamedTuple):
    """What the caller does next: `rejoined` ends the follow, `halt`
    ends it with a problem, and neither goes on to the divergence"""

    rejoined: bool = False
    halt: bool = False


REJOINED = Outcome(rejoined=True)
HALT = Outcome(halt=True)
FALLBACK = Outcome()
# the holder is a standby that is not promoted yet: nothing is recorded
WAIT = Outcome(halt=True)


def broken(root: str) -> bool:
    """Whether an earlier run failed halfway on this copy"""
    return os.path.exists(os.path.join(root, FAILED))


def _now() -> float:
    return time.time()


def forget(root: str) -> None:
    for relative in (FAILED, DUMP, REFUSED):
        try:
            os.remove(os.path.join(root, relative))
        except FileNotFoundError:
            pass


def keep(root: str, dump: str) -> None:
    """Record the dump this node took before the rewind"""
    _write(root, DUMP, dump)


def _write(root: str, relative: str, text: str) -> None:
    """A mark under the state directory; best effort, since a mark that
    cannot be written only costs a second dump or a second run"""
    path = os.path.join(root, relative)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text + "\n")
        os.chmod(path, 0o600)
    except OSError:
        pass


def _refused_ago(root: str) -> float | None:
    """Seconds since the last refusal when it is younger than RETRY_S"""
    try:
        age = _now() - os.path.getmtime(os.path.join(root, REFUSED))
    except OSError:
        return None
    return age if 0 <= age < RETRY_S else None


def kept(root: str) -> str | None:
    """The dump recorded before the rewind, when it is still there"""
    try:
        with open(os.path.join(root, DUMP)) as fob:
            path = fob.read().strip()
    except OSError:
        return None
    return path if os.path.isfile(path) else None


def unusable(root: str) -> str:
    """The text of the problem while the copy is unusable"""
    try:
        with open(os.path.join(root, FAILED)) as fob:
            detail = fob.read().strip()
    except OSError:
        detail = "no detail"
    return UNUSABLE.format(detail=detail)


def unfit(answer: str) -> str:
    """Why the settings of the running server forbid pg_rewind, or an
    empty string"""
    columns = answer.strip().split("\t")
    if len(columns) < 3:
        return "the server did not say its wal_log_hints, data_checksums" \
            " and full_page_writes"
    hints, checksums, pages = (one.strip() for one in columns[:3])
    if hints != "on" and checksums != "on":
        return "wal_log_hints and data checksums are both off, and" \
            " pg_rewind needs one of them"
    if pages != "on":
        return "full_page_writes is off, and pg_rewind needs it on"
    return ""


def rejoin(root: str, host: str, port: int, password: str, tls: str,
           found, runner=subprocess.run, clock=time.monotonic,
           sleep=time.sleep, alive=None) -> Outcome:
    """Rewind this fenced node against the holder; what comes next

    Every reason not to rewind is said on `found` and falls back: the
    divergence path, with the reseed that the operator confirms."""
    waiting = _refused_ago(root)
    if waiting is not None:
        found.say(f"no pg_rewind: the last run refused {waiting:.0f} s ago"
                  f" and the next one is {RETRY_S - waiting:.0f} s away")
        return FALLBACK
    why = _cannot(root, runner)
    if why:
        found.say(f"no pg_rewind: {why}")
        return FALLBACK
    version, conf, dropdir, datadir = dbpostgres.cluster_paths(root)
    tool = os.path.join(root, "usr/lib/postgresql", version, "bin",
                        "pg_rewind")
    if not os.path.isfile(tool):
        found.say("no pg_rewind: pg_rewind is not installed")
        return FALLBACK
    unit = dbpostgres.service(root)
    try:
        with spool(root) as directory:
            pgpass = dbpgseed.write_pgpass(directory, host, port, password)
            _, problem = dbpgseed._probe(pgpass, host, port, runner, tls)
            if problem and "is itself a standby" in problem:
                found.say(f"{problem}: the holder is not promoted yet,"
                          " and the next run asks again")
                return WAIT
            if problem:
                found.say(f"no pg_rewind: {problem}")
                return FALLBACK
            argv = dbpostgres.AS_POSTGRES + (
                tool, f"--target-pgdata={datadir}",
                "--source-server=" + dbpgseed.conninfo(
                    host, port, pgpass, tls),
                "--config-file=" + os.path.join(conf, "postgresql.conf"))
            return _rewind(root, argv, dropdir, datadir, unit,
                           (host, port, password, tls), found, runner,
                           clock, sleep, alive or dbpgseed._alive)
    except OSError as e:
        found.say(f"no pg_rewind: {e.strerror or e}")
        return FALLBACK


def _cannot(root: str, runner) -> str:
    """Why this node cannot be rewound, asked of the running server"""
    out: dict = {}
    problem = _run(runner, dbpostgres.CLIENT + ("--command", SETTINGS_SQL),
                   output=out)
    if problem:
        return f"the server did not say its settings: {problem}"
    return unfit(out.get("stdout") or "")


def _rewind(root, argv, dropdir, datadir, unit, source, found, runner,
            clock, sleep, alive) -> Outcome:
    began = clock()
    problem = dbpgseed._stopped(runner, unit, datadir, clock, sleep, alive)
    if problem:
        found.fail(f"{problem}; nothing else was changed")
        return HALT
    failed = _run(runner, argv + ("--progress",))
    if failed and COPY_BEGINS not in failed:
        found.say("no pg_rewind: pg_rewind cannot rewind this node"
                  f" ({_tail(failed)}); nothing was changed")
        _write(root, REFUSED, _tail(failed))
        return _started(unit, found, runner)
    if failed:
        return _failed(root, unit, failed, found, runner)
    host, port, password, tls = source
    action = dbpgseed.PairAction(host, port, password, tls)
    problem = _standby(dropdir, datadir, action)
    if not problem:
        problem = _run(runner, ("systemctl", "start", unit))
    if problem:
        found.fail(f"this node is rewound and could not start as a"
                   f" standby of [{host}]:{port}: {problem}")
        return HALT
    problem = dbpgseed._streaming(runner, clock, sleep)
    if problem:
        return _not_streaming(dropdir, unit, host, port, found, runner)
    forget(root)
    found.say(f"rewound against [{host}]:{port} in"
              f" {clock() - began:.1f} s: what this node wrote after the"
              " fork point is discarded (the dump kept holds it), and it"
              " follows the holder's timeline with no reseed")
    return REJOINED


def _standby(dropdir: str, datadir: str, action) -> str:
    """standby.signal, and the follow drop-in that names the holder"""
    try:
        signal = os.path.join(datadir, dbpostgres.STANDBY_SIGNAL)
        fd = os.open(signal, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW,
                     0o644)
        os.close(fd)
        dbpgseed._as_postgres(signal)
    except OSError as e:
        return f"cannot write standby.signal: {e.strerror or e}"
    return dbpgseed.write_follow(dropdir, action)


def _started(unit: str, found, runner) -> Outcome:
    """The fenced standby started again after a run that refused"""
    problem = _run(runner, ("systemctl", "start", unit))
    if problem:
        found.fail(f"the server could not be started again: {problem}")
        return HALT
    return FALLBACK


def _failed(root: str, unit: str, detail: str, found, runner) -> Outcome:
    """The run failed after the copy began: the mark, and the server
    started again if it can, as the standby that follows nobody"""
    detail = _tail(detail)
    _write(root, FAILED, detail)
    _run(runner, ("systemctl", "start", unit))
    found.fail(UNUSABLE.format(detail=detail))
    return HALT


def _not_streaming(dropdir: str, unit: str, host: str, port: int, found,
                   runner) -> Outcome:
    """Rewound, and the walreceiver does not stream (the holder may not
    have made its checkpoint after the promotion yet): back to the
    fenced standby that follows nobody, so a later run asks again"""
    try:
        os.remove(os.path.join(dropdir, dbpostgres.FOLLOW_DROPIN_NAME))
    except OSError:
        pass
    _run(runner, ("systemctl", "restart", unit))
    found.fail(f"pg_rewind finished and the standby does not stream from"
               f" [{host}]:{port} after {dbpgseed.STREAMING_TIMEOUT} s;"
               " it follows nobody again and the next run asks again")
    return HALT


def _tail(text: str) -> str:
    text = " ".join(text.split())
    return text[-TAIL:]
