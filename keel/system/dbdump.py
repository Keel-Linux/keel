# Copyright (c) 2026 KeelLinux maintainers
"""keel database dump: the dump on the standby (docs/replication.md)

keel-database-dump.timer ticks each hour on a node of a pair, and this
module decides from `database.server.dump` in the spec. The dump runs
only while the node is the replica: the primary serves the writes, and
a standby that serves nothing has the room and the idle time.

What keeps a dump from filling the disk:

- before the dump, the room is what is free above `min_free_percent`.
  With no room, or less room than the last dump's size, there is no dump;
- during the dump, the kernel stops the pack at that room
  (RLIMIT_FSIZE), and the partial file is removed;
- after a good dump, only the newest `keep` dumps stay. A `rejoin-*`
  file is never removed here: it can be the only copy of a diverged
  node's writes.

No credential is on a command line or in a file here: root reaches
MariaDB by its socket and the postgres user reaches PostgreSQL by peer.
The file has mode 0600 from its first byte, and has its name only when
both processes exited 0, so a partial file never counts as a backup.

A failed dump cannot be trusted to report itself, and a dead timer reports
nothing. So keel database watch, each 30 s, reads the state this module
writes and the age of the newest dump, and alerts through the monitor's
channels once per kind of problem and once at the recovery.
"""

import contextlib
import fcntl
import json
import os
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from keel import exits
from keel.inspect import constants as paths
from keel.inspect.collect import database_servers
from keel.inspect.tree import Tree
from keel.mesh.node import Node, NodeError
from keel.monitor import alerting
from keel.spec.constants import (
    DUMP_ENGINES,
    DUMP_EVERY_HOURS,
    DUMP_KEEP,
    DUMP_MIN_FREE_PERCENT,
)
from keel.system import dbfollow, dbpair
from keel.system.dbpostgres import AS_POSTGRES

BACKUPS = {"mariadb": "var/backups/keel/mariadb",
           "postgresql": "var/backups/keel/postgresql"}
STATE = "var/lib/keel/database/dump"
ALERT_STATE = "var/lib/keel/database/dump-alert"
LOCK = "var/lib/keel/database/dump.lock"
NAME = re.compile(r"^dump-\d{8}T\d{6}Z\.sql\.zst$")
PARTIAL = re.compile(r"^\.dump-\d{8}T\d{6}Z\.partial$")
COMMANDS = {
    # --master-data=2 writes the GTID position as a comment (--gtid alone
    # writes none). --dump-slave is not used: it stops the SQL thread for
    # the whole dump.
    "mariadb": ("mariadb-dump", "--single-transaction", "--gtid",
                "--master-data=2", "--routines", "--events", "--triggers",
                "--all-databases"),
    "postgresql": AS_POSTGRES + ("pg_dumpall",),
}
REAL_PACK = ("zstd", "-q", "-c", "-T1")
PACK = REAL_PACK
HOUR = 3600
# the hourly tick must not push a daily dump to 25 hours
DUE_SLACK = 1800
# the interval twice, and the tick that was to take the third
STALE_INTERVALS = 2
STALE_TICKS_HOURS = 1
# a rejoin's dump protects data and is not repeated, so it may take
# more of the disk than a dump that can wait for the next tick
REJOIN_MIN_FREE_PERCENT = 5
TAIL = 200
CHECK = "database-dump"
FAILED_TITLE = "the database dump failed"
FAILED_TEXT = ("{host}, the replica of {vip}: {problem}. This node has no"
               " new backup. keel database status says what it holds.")
STALE_TITLE = "the database dump is stale"
STALE_TEXT = ("{host}, the replica of {vip}: {what}; the spec asks for one"
              " each {every} h. Look at keel-database-dump.timer and at"
              " journalctl -u keel-database-dump.")
BACK_TITLE = "the database dump is good again"
BACK_TEXT = "{host}, the node of {vip}: no problem with the dump now."
FAILED, STALE = "failed", "stale"


@dataclass(frozen=True)
class Settings:
    enabled: bool = True
    every_hours: int = DUMP_EVERY_HOURS
    keep: int = DUMP_KEEP
    min_free_percent: int = DUMP_MIN_FREE_PERCENT


class DumpFailed(Exception):
    """Why there is no new dump"""


def settings(doc: dict) -> Settings:
    declared = _server(doc).get("dump") or {}
    return Settings(**{key: declared[key] for key in
                       ("enabled", "every_hours", "keep",
                        "min_free_percent") if key in declared})


def _server(doc: dict) -> dict:
    return (doc.get("database") or {}).get("server") or {}


def _document(root: str, spec: str) -> dict:
    return Node(root, spec).document()


def room(directory: str, min_free_percent: int,
         statvfs: Callable = os.statvfs) -> int:
    """The bytes free above the floor; zero or less is no room"""
    found = statvfs(directory)
    floor = found.f_frsize * found.f_blocks * min_free_percent // 100
    return found.f_frsize * found.f_bavail - floor


def file_size_limit(limit: int) -> Callable[[], None]:
    """For preexec_fn: the kernel stops the process at `limit` bytes"""
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    return apply


def rejoin_guard(directory: str, statvfs: Callable = os.statvfs
                 ) -> tuple[str, Callable[[], None] | None]:
    """What a rejoin's dump may take: why not, or the preexec_fn. The
    plain file and its compressed copy are on the disk together, so the
    plain file has half the room."""
    free = room(directory, REJOIN_MIN_FREE_PERCENT, statvfs)
    if free <= 0:
        return (f"no room: less than {REJOIN_MIN_FREE_PERCENT}% of the disk"
                f" is free at {directory}"), None
    return "", file_size_limit(free // 2)


def dumps(directory: str) -> list[str]:
    """The names of the scheduled dumps, the oldest first (the stamp
    sorts as time)"""
    try:
        return sorted(one for one in os.listdir(directory)
                      if NAME.match(one))
    except OSError:
        return []


def _newest(directory: str) -> tuple[str, float, int] | None:
    """The newest dump's name, its time and its size"""
    for name in reversed(dumps(directory)):
        try:
            found = os.stat(os.path.join(directory, name))
        except OSError:
            continue
        return name, found.st_mtime, found.st_size
    return None


def take(engine: str, directory: str, limit: int,
         now: float) -> str:
    """Dump into a file of mode 0600 and give it its name when the dump
    and the pack both exited 0; the path. A failure removes the file."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    partial = os.path.join(directory, f".dump-{stamp}.partial")
    final = os.path.join(directory, f"dump-{stamp}.sql.zst")
    try:
        _pipe(COMMANDS[engine], partial, limit)
        if os.path.getsize(partial) == 0:
            raise DumpFailed(f"{COMMANDS[engine][0]} wrote an empty dump")
        os.replace(partial, final)
    except OSError as e:
        _discard(partial)
        raise DumpFailed(f"the dump could not be written: {e.strerror or e}"
                         ) from e
    except DumpFailed:
        _discard(partial)
        raise
    return final


def _pipe(argv: tuple[str, ...], target: str, limit: int) -> None:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output, tempfile.TemporaryFile() as dump_err, \
            tempfile.TemporaryFile() as pack_err:
        try:
            dump = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=dump_err, cwd="/")
        except OSError as e:
            raise DumpFailed(f"cannot run {argv[0]}: {e.strerror}") from e
        try:
            pack = subprocess.Popen(
                PACK, stdin=dump.stdout, stdout=output, stderr=pack_err,
                cwd="/", preexec_fn=file_size_limit(limit))
        except (OSError, subprocess.SubprocessError) as e:
            dump.kill()
            dump.wait()
            raise DumpFailed(f"cannot run {PACK[0]}: {e}") from e
        finally:
            dump.stdout.close()
        packed = pack.wait()
        dumped = dump.wait()
        if packed == -signal.SIGXFSZ:
            raise DumpFailed(f"stopped at the free-space limit of {limit}"
                             " bytes: the dump is larger than the room on"
                             " the disk")
        # a pack that ends breaks the dump's pipe, and the dump dies of
        # it too (EPIPE, or SIGPIPE): the pack is the cause and is named
        # first, the dump's own words after it
        if packed != 0:
            also = f"; {argv[0]} exited {dumped}: {_tail(dump_err)}" \
                if dumped != 0 else ""
            raise DumpFailed(f"{PACK[0]} exited {packed}:"
                             f" {_tail(pack_err)}{also}")
        if dumped != 0:
            raise DumpFailed(f"{argv[0]} exited {dumped}: {_tail(dump_err)}")
        output.flush()
        os.fsync(output.fileno())


def _tail(fob) -> str:
    fob.seek(0, os.SEEK_END)
    fob.seek(max(0, fob.tell() - TAIL))
    return fob.read().decode(errors="replace").strip()


def _discard(path: str) -> None:
    with contextlib.suppress(OSError):
        os.remove(path)


def _prune(directory: str, keep: int, err: Callable[[str], None]) -> None:
    names = dumps(directory)
    for name in names[:-keep]:
        try:
            os.remove(os.path.join(directory, name))
        except OSError as e:
            err(f"database dump: {name} was not removed: {e.strerror}")


def _prepare(directory: str) -> None:
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    for name in os.listdir(directory):
        if PARTIAL.match(name):
            _discard(os.path.join(directory, name))


@contextlib.contextmanager
def locked(root: str) -> Iterator[bool]:
    """Whether this run holds the lock; a run that does not leaves the
    other run's partial file alone"""
    path = os.path.join(root, LOCK)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def _replicating(root: str, engine: str) -> bool:
    """Whether the server here is a replica: an empty server that was
    never seeded would push the good dumps out of the retention"""
    for one in database_servers(Tree(root)):
        if one.engine.name == engine:
            return one.reading().role.value == dbpair.REPLICA
    return False


# a replica whose server does not replicate yet is asked again for this
# long, every REPLICATION_POLL s, before the run fails: right after a
# failback the claim says replica some seconds before the server follows
# the new primary (release A, laravel cloud_simple, 2026-11-09: the hourly
# run fell in that window on both nodes and left the unit failed). A fault
# that lasts still fails the run, with its alert
REPLICATION_WAIT = 300.0
REPLICATION_POLL = 10.0
# what the wait sleeps and reads the time with; the tests replace them
_sleep = time.sleep
_clock = time.monotonic


class NoLongerReplica(Exception):
    """The claim stopped saying replica while the run waited"""


def _wait_for_replication(root: str, engine: str,
                          still_replica: Callable[[], bool],
                          out: Callable[[str], None]) -> bool:
    """Whether the server here replicates, asked again every
    REPLICATION_POLL s for up to REPLICATION_WAIT s; raises
    NoLongerReplica when the claim stops saying replica meanwhile"""
    if _replicating(root, engine):
        return True
    out(f"database dump: the claim says replica, and the server does not"
        f" replicate yet; the dump waits for the server to replicate, up to"
        f" {REPLICATION_WAIT:g} s")
    end = _clock() + REPLICATION_WAIT
    while _clock() < end:
        _sleep(min(REPLICATION_POLL, max(0.0, end - _clock())))
        if not still_replica():
            raise NoLongerReplica()
        if _replicating(root, engine):
            return True
    return False


def _dump_once(root: str, engine: str, chosen: Settings, due_only: bool,
               now: float, statvfs: Callable, out: Callable[[str], None],
               err: Callable[[str], None],
               still_replica: Callable[[], bool] = lambda: True) -> None:
    directory = os.path.join(root, BACKUPS[engine])
    newest = _newest(directory)
    if due_only and newest is not None and \
            now - newest[1] < chosen.every_hours * HOUR - DUE_SLACK:
        out(f"database dump: not due; {newest[0]} is recent")
        return
    if dbfollow.diverged(root) is not None:
        raise DumpFailed("this node diverged, so its data is not the pair's;"
                         " there is no dump until it is reseeded")
    if not _wait_for_replication(root, engine, still_replica, out):
        raise DumpFailed("the server here does not replicate, so there is"
                         " no dump of it")
    _prepare(directory)
    free = room(directory, chosen.min_free_percent, statvfs)
    needed = newest[2] if newest else 0
    if free <= 0 or free < needed:
        raise DumpFailed(
            f"no room: {max(free, 0)} bytes free above the"
            f" {chosen.min_free_percent}% floor at {directory}, and the last"
            f" dump was {needed} bytes")
    path = take(engine, directory, free, now)
    out(f"database dump: {path}")
    _prune(directory, chosen.keep, err)


def run(root: str, spec: str, out: Callable[[str], None],
        err: Callable[[str], None], due_only: bool = False,
        now: float | None = None,
        statvfs: Callable = os.statvfs) -> int:
    """keel database dump"""
    now = time.time() if now is None else now
    try:
        doc = _document(root, spec)
    except (NodeError, ValueError) as e:
        err(f"database dump: {e}")
        return exits.APPLY_FAILED
    pair = dbpair.observe_pair(root, doc)
    if pair is None:
        out("database dump: this node declares no appliance.vip; nothing"
            " to dump")
        return exits.OK
    engine = _server(doc).get("engine")
    if engine not in DUMP_ENGINES:
        out(f"database dump: no dump for {engine or 'none'}")
        return exits.OK
    chosen = settings(doc)
    if not chosen.enabled:
        out("database dump: the spec says enabled: false")
        return exits.OK
    try:
        with locked(root) as held:
            if not held:
                out("database dump: another dump already runs")
                return exits.OK
            return _locked_run(
                root, engine, chosen, pair, due_only, now, statvfs, out, err,
                lambda: _still_replica(root, doc))
    except OSError as e:
        err(f"database dump: {e.strerror or e}")
        return exits.APPLY_FAILED


def _still_replica(root: str, doc: dict) -> bool:
    found = dbpair.observe_pair(root, doc)
    return found is not None and found.role == dbpair.REPLICA


def _locked_run(root: str, engine: str, chosen: Settings,
                pair: dbpair.PairState, due_only: bool, now: float,
                statvfs: Callable, out: Callable[[str], None],
                err: Callable[[str], None],
                still_replica: Callable[[], bool] = lambda: True) -> int:
    if pair.role != dbpair.REPLICA:
        out("database dump: a dump runs only while this node is the"
            " replica; nothing to do")
        _record(root, err, problem="", not_replica_at=now)
        return exits.OK
    try:
        _dump_once(root, engine, chosen, due_only, now, statvfs, out, err,
                   still_replica)
    except NoLongerReplica:
        out("database dump: this node is no longer the replica; nothing to"
            " do")
        _record(root, err, problem="", not_replica_at=now)
        return exits.OK
    except DumpFailed as e:
        err(f"database dump: {e}")
        _record(root, err, problem=str(e))
        return exits.APPLY_FAILED
    _record(root, err, problem="")
    return exits.OK


def read_state(root: str) -> dict:
    return _load(os.path.join(root, STATE))


def _load(path: str) -> dict:
    try:
        with open(path) as fob:
            found = json.load(fob)
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def _save(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    temporary = f"{path}.new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fob:
        json.dump(state, fob)
        fob.write("\n")
    os.replace(temporary, path)


def _save_state(root: str, state: dict) -> None:
    _save(os.path.join(root, STATE), state)


def _record(root: str, err: Callable[[str], None], **changes) -> None:
    """A full disk must not hide the dump's own result: the watch then
    sees the age of the newest dump"""
    try:
        _save_state(root, {**read_state(root), **changes})
    except OSError as e:
        err(f"database dump: the state was not kept: {e.strerror or e}")


def _problem(root: str, engine: str, chosen: Settings, pair: dbpair.PairState,
             first_seen: float, now: float) -> tuple[str, str]:
    """The kind of problem and what to say, on a replica"""
    if pair.role != dbpair.REPLICA:
        return "", ""
    state = read_state(root)
    if state.get("problem"):
        return FAILED, FAILED_TEXT.format(
            host=os.uname().nodename, vip=pair.vip, problem=state["problem"])
    newest = _newest(os.path.join(root, BACKUPS[engine]))
    since = max(newest[1] if newest else first_seen,
                state.get("not_replica_at") or 0)
    limit = (STALE_INTERVALS * chosen.every_hours + STALE_TICKS_HOURS) * HOUR
    if now - since <= limit:
        return "", ""
    what = (f"the newest dump is {(now - newest[1]) / HOUR:.0f} h old"
            if newest else
            f"there is no dump after {(now - since) / HOUR:.0f} h")
    return STALE, STALE_TEXT.format(host=os.uname().nodename, vip=pair.vip,
                                    what=what, every=chosen.every_hours)


def watch(root: str, doc: dict, pair: dbpair.PairState,
          err: Callable[[str], None], now: float | None = None) -> None:
    """The failed or stale dump, alerted once per kind; kept only after
    a channel took it, so an alert no channel took is sent again"""
    engine = _server(doc).get("engine")
    if engine not in DUMP_ENGINES:
        return
    now = time.time() if now is None else now
    path = os.path.join(root, ALERT_STATE)
    before = _load(path)
    first_seen = before.get("first_seen") or now
    alerted = before.get("alerted") or ""
    chosen = settings(doc)
    kind, text = ("", "") if not chosen.enabled else _problem(
        root, engine, chosen, pair, first_seen, now)
    taken = True
    if kind and kind != alerted:
        taken = alerting.alert(root, err, FAILED_TITLE if kind == FAILED
                               else STALE_TITLE, text, CHECK)
    elif not kind and alerted and chosen.enabled:
        taken = alerting.alert(root, err, BACK_TITLE, BACK_TEXT.format(
            host=os.uname().nodename, vip=pair.vip), CHECK, "recovery")
    wanted = {"first_seen": first_seen,
              "alerted": kind if taken else alerted}
    if wanted == before:
        return
    try:
        _save(path, wanted)
    except OSError as e:
        err(f"database dump: the alert's state was not kept:"
            f" {e.strerror or e}")


def status_lines(root: str, doc: dict, now: float | None = None) -> list[str]:
    """What keel database status says of the dump"""
    engine = _server(doc).get("engine")
    if engine not in DUMP_ENGINES:
        return []
    chosen = settings(doc)
    if not chosen.enabled:
        return ["  dump: off (database.server.dump.enabled: false)"]
    now = time.time() if now is None else now
    newest = _newest(os.path.join(root, BACKUPS[engine]))
    found = [f"  dump: newest {newest[0]}, {(now - newest[1]) / HOUR:.1f} h"
             " old" if newest else "  dump: none yet"]
    problem = read_state(root).get("problem")
    if problem:
        found.append(f"  dump problem: {problem}")
    return found


def main(args) -> int:
    root = os.path.abspath(getattr(args, "root", paths.ROOT_DEFAULT))
    return run(root, args.spec, print,
               lambda line: print(line, file=sys.stderr),
               due_only=args.if_due)
