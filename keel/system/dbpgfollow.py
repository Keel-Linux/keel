# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL database follows the VIP: the engine's rows of
keel.system.dbfollow's table (0020, 0031, 0049, 0054)

A standby refuses writes while it is in recovery, so what the MariaDB
twin builds from read_only, a role drop-in, the root lock and
READ_ONLY ADMIN is here a property of the server: a pg replica row is
the follow drop-in, a seed, or a confirmed reseed and nothing else.
The other rows:

| the VIP here | what is done |
| --- | --- |
| held, by this node's newest claim, and on wg0 | a standby drained and promoted (keel.system.dbpgpromote); a primary left alone |
| held by this node's newest claim, not on wg0 | a primary is stopped: pg cannot be made read only while it runs, and a stopped server takes no writes; a standby refuses them already |
| held by the other member | a standby of the holder left alone; anything else seeded from the holder, or reseeded once confirmed |

The rejoin (0054, "rejoin after promotion = confirmed reseed", no
pg_rewind this version): timelines answer whether the copy on disk is
the holder's history or one this node's own writes forked from — the
holder's is asked with the replication protocol (IDENTIFY_SYSTEM, the
replication privilege is enough for the pair's role) over TLS, this
node's from its current WAL file's name. A node holding no user
database is seeded without the confirmation: there is nothing of its
own to lose. A node holding data is dumped first (pg_dumpall, the
twin of the MariaDB twin's), and reseeds only on
--destroy-local-database; until then the divergence is recorded, the
way dbfollow's GTID errancy is, under the same path, so inspect and
diff read either engine's record.
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone

from keel.monitor import alerting
from keel.spec.constants import DEFAULT_PORTS
from keel.spec.origins import canonical
from keel.system import dbpair, dbpgpromote, dbpgseed, dbpostgres, dbtls
from keel.system.actions import PromoteReplica
from keel.system.database import DRAIN_TIMEOUT, REPLICA
from keel.system.dbfollow import DIVERGED
from keel.system.dbseed import _run, spool
from keel.system.dbstate import DatabaseState

DIVERGED_TITLE = "the old primary diverged and stays read only"
DIVERGED_TEXT = (
    "{host}: this node was the primary of {vip} and came back with a"
    " history the new primary at {holder} is past (timeline {own}"
    " against {theirs}). It stays read only and is not connected."
    " Reseed it from the holder with `keel spec apply --system-only"
    " --destroy-local-database` (a dump of what it holds is kept under"
    " /{backups} first), or reconcile by hand and run `keel database"
    " follow`."
)
BACKUPS = "var/backups/keel/postgresql"
CHECK = "database-rejoin"
TIMELINE_SQL = "SELECT pg_walfile_name(pg_current_wal_lsn())"
IDENTIFY_SYSTEM = "IDENTIFY_SYSTEM"


class PairSeed:
    """The attributes dbpgseed reads, with the pair's slot

    keel.system.actions is engine neutral on purpose (0054): SeedReplica
    has no slot field, so the follow flow hands dbpgseed.seed a plain
    object with the slot the pair streams from (the standby's
    primary_slot_name, constant SLOT of keel.system.dbpostgres)
    """

    def __init__(self, host: str, port: int, password: str, tls: str):
        self.host = host
        self.port = port
        self.password = password
        self.tls = tls
        self.slot = dbpostgres.SLOT


def follow(root: str, state: DatabaseState, server: dict, role: str,
           confirmed: bool, found, runner, proven) -> bool:
    """The PostgreSQL rows; `proven` is the caller's wait for this
    node's own claim to carry, and the ROLE_FILE write stays with it
    (keel.system.dbfollow). Returns whether the ROLE_FILE may record
    the role: an unproven claim never does (keel#104), the way a
    MariaDB primary that is read only on a stale claim records nothing"""
    if role == dbpair.PRIMARY and not proven():
        _unproven(root, state, found, runner)
        return False
    if role == dbpair.PRIMARY:
        _primary(root, state, found, runner)
    elif role == REPLICA:
        _replica(root, server, state, confirmed, found, runner)
    else:
        found.fail(f"no role to follow: the VIP has no claim and the spec"
                   f" declares {role or 'none'}")
    return True


def _unproven(root: str, state: DatabaseState, found, runner) -> None:
    """This node's own claim, not proven: a primary is stopped (a
    stopped server takes no writes), a standby refuses them already,
    until the VIP is on wg0 (keel#104)"""
    if state.reading.role.value == REPLICA:
        found.say("in recovery: this node takes no writes until"
                  f" {state.pair.vip} is proven on wg0")
        return
    problem = _run(runner, ("systemctl", "stop", dbpostgres.service()))
    if problem:
        found.fail(f"this node's claim of {state.pair.vip} is not proven"
                   f" (the VIP is not on wg0) and the server could not be"
                   f" stopped: {problem}")
        return
    found.say(f"stopped: this node's claim of {state.pair.vip} is not"
              " proven (the VIP is not on wg0), and a server that is not"
              " a standby can only be kept from writes by stopping it;"
              " it is seeded from the holder once the VIP decides")


def _primary(root: str, state: DatabaseState, found, runner) -> None:
    """The holder: recovery ended, replicating from nobody"""
    if state.reading.role.value == REPLICA:
        action = PromoteReplica(DRAIN_TIMEOUT, engine="postgresql")
        problem = dbpgpromote.promote(root, action, runner)
        if problem:
            found.fail(problem)
            return
        found.say("drained and promoted: this node replicates from nobody"
                  " and takes writes")
    else:
        found.say("unchanged (the primary, writable)")
    _ensure_slot(found, runner)
    _forget_divergence(root)


def _ensure_slot(found, runner) -> None:
    """The pair's slot on the holder, made when it is not there

    A base backup copies no replication slot (pg_basebackup leaves
    pg_replslot out), so a standby promoted to the holder has none, and
    the reseed of the old primary, whose follow drop-in names the slot,
    would never stream (found when the pair's cases (b) to (e) were
    built, on PostgreSQL 17). The statement is idempotent and commits without the
    standby (keel.system.dbpostgres.slot_statements)."""
    statements = dbpostgres.slot_statements()
    problem = _run(runner, dbpostgres.CLIENT, text=statements.text)
    if problem:
        found.fail(f"{statements.summary} failed: {problem}")


def _replica(root: str, server: dict, state: DatabaseState,
             confirmed: bool, found, runner) -> None:
    """The other node: a standby of the holder, seeded or reseeded"""
    pair = state.pair
    host = dbpair.primary_host(pair, server)
    port = int(((server.get("replication") or {}).get("primary") or {})
               .get("port") or DEFAULT_PORTS["postgresql"])
    if host is None:
        found.fail("the holder's address is not known")
        return
    if _following(state, host, port):
        found.say(f"unchanged (a standby of [{host}]:{port})")
        _forget_divergence(root)
        return
    if not state.credential.known:
        found.fail(state.credential.problem)
        return
    if not state.tls_ready:
        found.fail("the database certificate is not in place yet"
                   " (database.server.tls)")
        return
    held = dbpostgres.user_databases((state.schemas.text or "").splitlines())
    if not held:
        _seed(root, host, port, state, found, runner)
        return
    own = _own_timeline(root, runner)
    theirs = _holder_timeline(root, host, port, state, runner)
    if theirs is None:
        found.fail(f"the holder at [{host}]:{port} did not answer its"
                   " timeline over TLS; nothing was changed")
        return
    kept = _dump(root, runner)
    if kept.startswith("not kept"):
        found.fail(f"a dump of what this node holds was {kept}; nothing"
                   " was changed")
        return
    found.say(f"a dump of what this node holds is kept at {kept}")
    if not confirmed:
        _diverged(root, state, host, own, theirs, found)
        return
    found.say("confirmed with --destroy-local-database: what this node"
              f" holds is discarded (timeline {own or 'unknown'} against"
              f" the holder's {theirs})")
    _seed(root, host, port, state, found, runner)


def _following(state: DatabaseState, host: str, port: int) -> bool:
    """Whether this node is already the holder's standby: in recovery,
    and its walreceiver's connection names the holder (a walreceiver
    that fails retries forever, so a standby is left to retry on its
    own — the way MariaDB's stopped SQL thread is not one row here)"""
    if state.reading.role.value != REPLICA:
        return False
    current = state.reading.primary.value or {}
    was_host = str(current.get("host") or "")
    was_port = int(current.get("port") or 0)
    return canonical(was_host) == canonical(host) and was_port == port


def _seed(root: str, host: str, port: int, state: DatabaseState, found,
          runner) -> None:
    action = PairSeed(host, port, state.credential.value,
                      dbtls.options_lines(root, "postgresql"))
    problem = dbpgseed.seed(root, action, runner)
    if problem:
        found.fail(problem)
        return
    found.say(f"seeded from [{host}]:{port} and streaming from it over"
              " TLS (the pair's slot keeps the primary's WAL while this"
              " node is away)")
    _forget_divergence(root)


def _own_timeline(root: str, runner) -> str | None:
    """This node's timeline, from its current WAL file's name, or None
    when the server did not answer"""
    out: dict = {}
    problem = _run(runner, dbpostgres.CLIENT
                   + ("--command", TIMELINE_SQL), output=out)
    if problem:
        return None
    name = (out.get("stdout") or "").strip()
    return name[:8] or None


def _holder_timeline(root: str, host: str, port: int,
                     state: DatabaseState, runner) -> str | None:
    """The holder's timeline, asked as the replication role over TLS
    with the replication protocol; None when it did not answer"""
    try:
        with spool(root) as directory:
            pgpass = dbpgseed.write_pgpass(directory, host, port,
                                           state.credential.value)
            out: dict = {}
            problem = _run(runner, dbpostgres.CLIENT + (
                dbpgseed.conninfo(host, port, pgpass,
                                  dbtls.options_lines(root, "postgresql"))
                + " replication=database",
                "--command", IDENTIFY_SYSTEM), output=out)
    except OSError:
        return None
    if problem:
        return None
    columns = (out.get("stdout") or "").strip().split("\t")
    return columns[1] if len(columns) > 1 else None


def _diverged(root: str, state: DatabaseState, holder: str, own: str | None,
              theirs: str, found) -> None:
    first = not os.path.exists(os.path.join(root, DIVERGED))
    _write(root, DIVERGED, json.dumps({
        "own_timeline": own, "holder_timeline": theirs, "holder": holder,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        sort_keys=True) + "\n", 0o600)
    found.fail(
        f"diverged: this node holds transactions the holder at {holder}"
        f" lacks (timeline {own or 'unknown'} against the holder's"
        f" {theirs}). It stays read only and is not connected; keel spec"
        " apply --system-only --destroy-local-database reseeds it from"
        " the holder, the dump above kept")
    if first:
        alerting.alert(root, lambda line: found.say(line), DIVERGED_TITLE,
                       DIVERGED_TEXT.format(
                           host=os.uname().nodename, vip=state.pair.vip,
                           holder=holder, own=own or "unknown",
                           theirs=theirs, backups=BACKUPS), CHECK)


def _forget_divergence(root: str) -> None:
    try:
        os.remove(os.path.join(root, DIVERGED))
    except FileNotFoundError:
        pass


def _dump(root: str, runner) -> str:
    """A dump of everything this node holds, compressed, under BACKUPS;
    where it is, or `not kept (why)`"""
    directory = os.path.join(root, BACKUPS)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as e:
        return f"not kept ({e.strerror})"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    plain = os.path.join(directory, f"rejoin-{stamp}.sql")
    try:
        fd = os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fob:
            done = runner(dbpostgres.AS_POSTGRES + ("pg_dumpall",),
                          stdout=fob, stderr=subprocess.PIPE, check=False)
        if done.returncode != 0:
            os.remove(plain)
            return "not kept (pg_dumpall exited" \
                f" {done.returncode}: {(done.stderr or b'').decode()[-200:]})"
        packed = runner(["zstd", "-q", "--rm", plain], capture_output=True,
                        check=False)
        if packed.returncode != 0:
            return plain
    except OSError as e:
        return f"not kept ({e.strerror or e})"
    return plain + ".zst"


def _write(root: str, relative: str, text: str, mode: int) -> None:
    target = os.path.join(root, relative)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fob:
        fob.write(text)
    os.chmod(target, mode)
