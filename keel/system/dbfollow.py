# Copyright (c) 2026 KeelLinux maintainers
"""The database follows the VIP: keel database follow (0020, 0031, 0049)

Everything that depends on the role follows the elected role (0020), and
on a pair the role is the VIP's (0049): the holder is the primary. This
is the one place that acts on it, run by apply's FollowVip action, by
keel database promote once the VIP moved, and by
keel-database-follow.service when the VIP's state changes or at boot:

| the VIP here | what is done |
| --- | --- |
| held, by this node's newest claim | the server made writable: a replica drained and promoted (keel.system.dbreadonly), read_only off, READ_ONLY ADMIN back |
| held by the other member; released or fenced here | read_only on at once, the root lock, then replication from the holder: a fresh server seeded, one already following it left alone, an old primary rejoined by GTID when it holds nothing the holder lacks, else left read only, reported and alerted |
| no claim yet | the declared role, the installation's (0020) |

The rejoin (0049, "The old primary coming back", MariaDB): the node's
`@@gtid_binlog_state` against the holder's, read over the overlay as the
replication account under TLS (keel.system.dbgtid). None errant: a dump
of what the node holds is kept first (0020), `gtid_slave_pos` is set to
its own `gtid_binlog_pos`, and it follows the holder. Some: it stays
read only, unconnected; the errant GTIDs are recorded for inspect, diff
and status, and alerted once; the operator reseeds with
`--destroy-local-database` (the dump kept first) or reconciles by hand
and runs follow again.

keel's statements go through the server's `mysql` account
(keel.system.dbmariadb.CLIENT): root has no READ_ONLY ADMIN on a replica.
"""

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone

from keel.inspect.dbreading import field_lines
from keel.inspect.tree import File
from keel.mesh.node import Node, NodeError
from keel.monitor import alerting
from keel.spec.constants import DEFAULT_PORTS
from keel.system import dbgtid, dbpair, dbreadonly, dbseed, dbtls
from keel.system import dbmariadb as mariadb
from keel.system.actions import PromoteReplica, SeedReplica
from keel.system.database import DRAIN_TIMEOUT, PRIMARY, REPLICA
from keel.system.dbstate import (
    DatabaseState,
    declared_server,
    observe_database,
    replicates_from,
    sql_stopped,
)

DIVERGED = "var/lib/keel/database/diverged"
BACKUPS = "var/backups/keel/mariadb"
DROPIN_MODE = 0o644
GTID_QUESTION = mariadb.QUIET_CLIENT + (
    "--execute", "SELECT @@gtid_binlog_state, @@gtid_binlog_pos")
HOLDER_GTID_SQL = "SELECT @@gtid_binlog_state, @@gtid_slave_pos"
CHECK = "database-rejoin"
NO_PAIR = ("this node declares no appliance.vip: there is no VIP for the"
           " database to follow (keel spec apply converges a declared role)")
DIVERGED_TITLE = "the old primary diverged and stays read only"
DIVERGED_TEXT = (
    "{host}: this node was the primary of {vip} and came back holding"
    " transactions the new primary at {holder} lacks: {errant}. It stays"
    " read only and is not connected. Reseed it from the holder with"
    " `keel spec apply --system-only --destroy-local-database` (a dump of"
    " what it holds is kept under /{backups} first), or reconcile by hand"
    " and run `keel database follow`."
)


class Followed:
    """What one run said, and whether it failed"""

    def __init__(self, out: Callable[[str], None] | None = None):
        self.lines: list[str] = []
        self.out = out
        self.problem: str | None = None

    def say(self, line: str) -> None:
        self.lines.append(line)
        if self.out:
            self.out(line)

    def fail(self, problem: str) -> None:
        self.problem = self.problem or problem
        self.say(f"refused: {problem}")


def followed(root: str, spec: str, confirmed: bool = False,
             out: Callable[[str], None] | None = None) -> str | None:
    """Carry out a FollowVip; None on success, else what went wrong"""
    found = Followed(out or (lambda line: print(
        f"database.server.role: {line}", file=sys.stderr)))
    follow(root, spec, confirmed, found)
    return found.problem


def follow(root: str, spec: str, confirmed: bool, found: Followed,
           runner=subprocess.run) -> None:
    try:
        doc = Node(root, spec).document()
    except (NodeError, ValueError) as e:
        found.fail(str(e))
        return
    state = observe_database(root, doc, start=True, spec=spec)
    if state is None or state.pair is None:
        found.fail(NO_PAIR)
        return
    pair = state.pair
    if state.down:
        found.fail(f"the server is not answering ({state.down})")
        return
    if not state.reading.role.known:
        found.fail(f"the server could not be asked what it is"
                   f" ({state.reading.role.problem})")
        return
    if pair.problem or pair.peer_address is None:
        found.fail(pair.problem or "the other member of the pair is not"
                   " known (keel vip pair)")
        return
    server = declared_server(doc)
    role = dbpair.role_of(pair, str(server.get("role") or ""))
    if role == PRIMARY:
        _primary(root, state, found, runner)
    elif role == REPLICA:
        _replica(root, doc, server, state, confirmed, found, runner)
    else:
        found.fail(f"no role to follow: the VIP has no claim and the spec"
                   f" declares {role or 'none'}")
        return
    if found.problem is None:
        _write(root, dbpair.ROLE_FILE, dbpair.role_text(role, pair.vip),
               0o644)


def _primary(root: str, state: DatabaseState, found: Followed,
             runner) -> None:
    """The holder: writable, replicating from nobody"""
    replicating = bool(state.status.lines())
    if replicating:
        problem = dbreadonly.promote(root, PromoteReplica(DRAIN_TIMEOUT),
                                     runner)
        if problem:
            found.fail(problem)
            return
        found.say("drained and promoted: this node replicates from nobody"
                  " and takes writes")
    elif state.reading.read_only.value is True:
        statements = mariadb.set_read_only(False)
        problem = _send(runner, statements.text)
        if problem:
            found.fail(f"{statements.summary} failed: {problem}")
            return
        found.say(statements.summary)
    else:
        found.say("unchanged (the primary, writable)")
    # read only at the next boot too: follow lifts it on the holder
    _write(root, mariadb.ROLE_DROPIN, mariadb.role_dropin_text(),
           DROPIN_MODE)
    if state.revoked.readable:
        problem = dbreadonly.unlock(root, runner)
        if problem:
            found.fail(problem)
            return
        found.say("READ_ONLY ADMIN given back to the accounts the replica"
                  " took it from")
    _forget_divergence(root)


def _replica(root: str, doc: dict, server: dict, state: DatabaseState,
             confirmed: bool, found: Followed, runner) -> None:
    """The other node: read only, locked, following the holder"""
    pair = state.pair
    if state.reading.read_only.value is not True:
        statements = mariadb.set_read_only(True)
        problem = _send(runner, statements.text)
        if problem:
            found.fail(f"{statements.summary} failed: {problem}")
            return
        found.say(statements.summary)
    _write(root, mariadb.ROLE_DROPIN, mariadb.role_dropin_text(),
           DROPIN_MODE)
    problem = dbreadonly.lock(root, runner)
    if problem:
        found.fail(problem)
        return
    host = dbpair.primary_host(pair, server)
    port = int(((server.get("replication") or {}).get("primary") or {})
               .get("port") or DEFAULT_PORTS["mariadb"])
    if host is None:
        found.fail("the holder's address is not known")
        return
    if replicates_from(state.status, host, port):
        error = sql_stopped(state.status)
        if error is None:
            found.say(f"unchanged (a replica of [{host}]:{port})")
            _forget_divergence(root)
            return
        if not confirmed:
            found.fail(f"this node replicates from [{host}]:{port} and its"
                       f" SQL thread stopped ({error}); run keel spec apply"
                       " --system-only --destroy-local-database to rebuild"
                       " it from a fresh copy")
            return
    if not state.credential.known:
        found.fail(state.credential.problem)
        return
    if not state.tls_ready:
        found.fail("the database certificate is not in place yet"
                   " (database.server.tls)")
        return
    held = mariadb.user_schemas((state.schemas.text or "").splitlines())
    if not held and not state.status.lines():
        _seed(root, host, port, state, (), found, runner)
        return
    _rejoin(root, host, port, state, held, confirmed, found, runner)


def _seed(root: str, host: str, port: int, state: DatabaseState,
          drop: tuple[str, ...], found: Followed, runner) -> None:
    action = SeedReplica(host, port, state.credential.value, drop,
                         dbtls.options_lines(root), dbtls.master_options(root))
    problem = dbseed.seed(root, action, runner)
    if problem:
        found.fail(problem)
        return
    found.say(f"seeded from [{host}]:{port} and replicating from it over"
              " TLS")
    _forget_divergence(root)


def _rejoin(root: str, host: str, port: int, state: DatabaseState,
            held: list[str], confirmed: bool, found: Followed,
            runner) -> None:
    """An old primary, or a replica of another node: by GTID"""
    own = _ask(runner, GTID_QUESTION)
    if own is None:
        found.fail("this node's GTID state could not be read")
        return
    own_state, _, own_pos = own.strip().partition("\t")
    theirs = _holder_gtid(root, host, port, state, runner)
    if theirs is None:
        found.fail(f"the holder at [{host}]:{port} did not answer its GTID"
                   " state over TLS; nothing was changed")
        return
    their_state, _, their_pos = theirs.strip().partition("\t")
    try:
        errant = dbgtid.errant(own_state, their_state, their_pos)
    except ValueError as e:
        found.fail(f"a GTID state could not be read: {e}")
        return
    kept = _dump(root, runner)
    if kept.startswith("not kept"):
        found.fail(f"a dump of what this node holds was {kept}; nothing was"
                   " changed")
        return
    found.say(f"a dump of what this node holds is kept at {kept}")
    if errant and not confirmed:
        _diverged(root, state, host, errant, found)
        return
    if errant:
        found.say(f"confirmed with --destroy-local-database: {len(errant)}"
                  f" errant GTID(s) discarded ({dbgtid.describe(errant)})")
        _seed(root, host, port, state, tuple(held), found, runner)
        return
    statements = mariadb.replicate_from(
        host, port, state.credential.value, own_pos,
        dbtls.master_options(root))
    problem = _send(runner, statements.text)
    if problem:
        found.fail(f"{statements.summary} failed: {problem}")
        return
    found.say(f"rejoined: no errant GTID, replicating from [{host}]:{port}"
              f" over TLS from {own_pos or 'the start'}")
    _forget_divergence(root)


def _diverged(root: str, state: DatabaseState, holder: str,
              errant: list[str], found: Followed) -> None:
    first = not os.path.exists(os.path.join(root, DIVERGED))
    _write(root, DIVERGED, json.dumps({
        "errant": errant, "holder": holder,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        sort_keys=True) + "\n", 0o600)
    described = dbgtid.describe(errant)
    found.fail(f"diverged: this node holds {len(errant)} transaction(s) the"
               f" holder at {holder} lacks ({described}). It stays read"
               " only and is not connected; keel spec apply --system-only"
               " --destroy-local-database reseeds it from the holder, the"
               " dump above kept")
    if first:
        alerting.alert(root, lambda line: found.say(line), DIVERGED_TITLE,
                       DIVERGED_TEXT.format(
                           host=os.uname().nodename, vip=state.pair.vip,
                           holder=holder, errant=described, backups=BACKUPS),
                       CHECK)


def _forget_divergence(root: str) -> None:
    try:
        os.remove(os.path.join(root, DIVERGED))
    except FileNotFoundError:
        pass


def diverged(root: str) -> dict | None:
    """What the last rejoin recorded of a divergence, or None"""
    try:
        with open(os.path.join(root, DIVERGED)) as fob:
            found = json.load(fob)
    except (OSError, ValueError):
        return None
    return found if isinstance(found, dict) else None


def _holder_gtid(root: str, host: str, port: int, state: DatabaseState,
                 runner) -> str | None:
    """The holder's binlog state and slave position, as `repl` over TLS"""
    try:
        with dbseed.spool(root) as directory:
            options = dbseed.write_options(
                directory, host, port, state.credential.value,
                dbtls.options_lines(root))
            return _ask(runner, (
                "mariadb", f"--defaults-extra-file={options}",
                dbseed.CONNECT_TIMEOUT, "--batch", "--skip-column-names",
                "--execute", HOLDER_GTID_SQL))
    except OSError:
        return None


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
            done = runner(["mariadb-dump", "--all-databases",
                           "--single-transaction", "--gtid", "--routines",
                           "--events", "--triggers"], stdout=fob,
                          stderr=subprocess.PIPE, check=False)
        if done.returncode != 0:
            os.remove(plain)
            return "not kept (mariadb-dump exited" \
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


def _ask(runner, argv) -> str | None:
    try:
        out = runner(list(argv), capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def _send(runner, text: str) -> str:
    try:
        out = runner(list(mariadb.CLIENT), input=text, capture_output=True,
                     text=True, check=False)
    except OSError as e:
        return f"cannot run {mariadb.CLIENT[0]}: {e.strerror}"
    if out.returncode != 0:
        return (out.stderr or "").strip() or f"exited {out.returncode}"
    return ""


def status_fields(status: File) -> dict[str, str]:
    return field_lines(status)
