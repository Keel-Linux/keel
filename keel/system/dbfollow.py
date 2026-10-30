# Copyright (c) 2026 KeelLinux maintainers
"""The database follows the VIP: keel database follow (0020, 0031, 0049)

Everything that depends on the role follows the elected role (0020), and
on a pair the role is the VIP's (0049): the holder is the primary. This
is the one place that acts on it, run by apply's FollowVip action, by
keel database promote once the VIP moved, and by
keel-database-follow.service when the VIP's state changes or at boot.
The rows below are MariaDB's; a PostgreSQL standby refuses writes in
recovery on its own, so the engine's rows are keel.system.dbpgfollow's
(0054) and read_only, the role drop-in, the root lock and GTID errancy
have no twin there:

| the VIP here | what is done |
| --- | --- |
| held, by this node's newest claim, and on wg0 | the server made writable: a replica drained and promoted (keel.system.dbreadonly), read_only off, READ_ONLY ADMIN back; a server that replicates from nobody and is read only (restarted, or fenced) first waits up to REPLICA_WAIT for its replica (keel#242) |
| held, by this node's newest claim, and not on wg0 | read_only on, the root lock; nothing else (keel#104) |
| no claim, on a paired node | the same: read only until a claim is proven (keel#104) |
| held by the other member; released or fenced here | read_only on at once, the root lock, then replication from the holder: a fresh server seeded, one already following it left alone, an old primary rejoined by GTID when it holds nothing the holder lacks, else left read only, reported and alerted |
| no claim yet, declared replica | the replica's row above, from the other member (0020) |

A claim of this node's own is not a proof that it holds the VIP now: a
node that crashed and booted keeps its last claim in its file, while the
other member was promoted at a newer epoch (keel#104: writable 31 s on a
real pair, until keel vip check learned the newer epoch). The proof is
the VIP on wg0. keel puts it there only after a proof: keel vip promote
after its fresh claim, keel vip check once a peer answered and none
knows a newer claim, and with etcd the controller only after a renewal
of its lease the majority confirmed, for what is left of the release
time (the kernel's valid_lft removes it then). A boot removes it. So
the server is read only from its first second (the role's drop-in) and
read_only goes off only when the address is on wg0. Follow waits up to
PROOF_WAIT for it, since a promote records its claim before it carries
the VIP; keel.mesh.vipnode.carry_held writes the VIP's state again when
it carries the address, so follow runs again then.

Without etcd, nothing else ran keel vip check: keel-vip-check.timer is
part of keel-vip.service, which needs etcd (keel#154: a returned old
primary never learned the newer claim). So follow asks the other members
first, the way keel vip check does, when this node's newest claim is
its own and the VIP is not on wg0: a newer claim is taken, and the node
follows the holder in the same run. When a peer answers and none knows
a newer claim, the holder carries the VIP again. With etcd, the
controller tells, and follow asks nobody. A PostgreSQL server of a claim
that stays unproven is not started: follow would stop it again (a
primary takes writes until the stop).

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
from keel.mesh import vip as vipstate
from keel.mesh import vipnet
from keel.mesh.node import Node, NodeError
from keel.monitor import alerting
from keel.network import live, wireguard
from keel.spec.constants import DEFAULT_PORTS
from keel.system import dbgtid, dbpair, dbpgrewind, dbreadonly, dbseed, dbtls
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
FOLLOW_LOCK = dbreadonly.REPLICATION_LOCK
BACKUPS = "var/backups/keel/mariadb"
DROPIN_MODE = 0o644
GTID_QUESTION = mariadb.QUIET_CLIENT + (
    "--execute", "SELECT @@gtid_binlog_state, @@gtid_binlog_pos")
LOG_BIN_QUESTION = mariadb.QUIET_CLIENT + ("--execute", "SELECT @@log_bin")
WAITS_FOR_BINARY_LOG = (
    "this server writes no binary log yet, so the copy of the holder waits:"
    " keel spec apply writes the pair's configuration and then copies it"
)
HOLDER_GTID_SQL = "SELECT @@gtid_binlog_state, @@gtid_slave_pos"
# what this replica applied: its binary log (log_slave_updates) and its
# slave position, which a reseed sets from the dump (keel#192)
APPLIED_QUESTION = mariadb.QUIET_CLIENT + (
    "--execute", "SELECT @@gtid_binlog_state, @@gtid_slave_pos")
UNFENCED_SAID = (
    "the VIP fence is cleared: this replica applied everything the holder"
    " logged, so it may take the VIP again when the lease of the holder"
    " expires (keel#192)"
)
CHECK = "database-rejoin"
# how long follow waits for this node's own claim to be proven, the VIP
# on wg0, before it leaves the server read only: keel vip promote's own
# wait for the controller to carry it (keel.mesh.vippromote.CARRY_WAIT)
PROOF_WAIT = 15.0
# how often follow looks for the VIP on wg0 while it waits (keel#118)
PROOF_POLL = 0.2
# how long a holder that is read only and replicates from nobody (its
# server restarted, or fenced) waits for its replica before it takes
# writes (keel#242): with wait_no_slave OFF a commit with no replica
# connected is acknowledged with no copy. The semi-synchronous timeout,
# so a restarted primary does that no sooner than a running one does
REPLICA_WAIT = mariadb.SEMI_SYNC_TIMEOUT_MS / 1000
REPLICA_POLL = 0.5
SEMI_SYNC_QUESTION = mariadb.QUIET_CLIENT + (
    "--execute", "SHOW GLOBAL STATUS WHERE Variable_name IN"
    " ('Rpl_semi_sync_master_status', 'Rpl_semi_sync_master_clients')")
NO_REPLICA = (
    "the replica did not connect within {wait:g} s, so this node takes"
    " writes without it: until it connects, a commit is acknowledged with"
    " no copy on the replica (Rpl_semi_sync_master_status OFF)"
)
NO_PAIR = ("this node declares no appliance.vip: there is no VIP for the"
           " database to follow (keel spec apply converges a declared role)")
NO_SERVER = ("this node declares no database.server: there is no server to"
             " follow the VIP")
UNDECLARED_MARKER = "var/lib/keel/database/filesync-undeclared"
UNDECLARED_TITLE = "file replication is off for this pair"
UNDECLARED_TEXT = (
    "{host}: the database role changed, but the files are not replicated:"
    " {problem}. Fix the spec and run `keel spec apply --system-only`.")
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
        # keel database follow, run by keel-database-follow.service, sets
        # this: a node with no appliance.vip, the witness of a pair, has
        # nothing to follow, and that is no failure (keel#211). A spec apply
        # that declares a role leaves it off, and still refuses.
        self.nothing_without_vip = False

    def say(self, line: str) -> None:
        self.lines.append(line)
        if self.out:
            self.out(line)

    def fail(self, problem: str) -> None:
        self.problem = self.problem or problem
        self.say(f"refused: {problem}")


def followed(root: str, spec: str, confirmed: bool = False,
             out: Callable[[str], None] | None = None,
             alone: bool = False) -> str | None:
    """Carry out a FollowVip; None on success, else what went wrong.
    `alone` is keel database promote --old-primary-gone (PostgreSQL)"""
    found = Followed(out or (lambda line: print(
        f"database.server.role: {line}", file=sys.stderr)))
    follow(root, spec, confirmed, found, alone=alone)
    return found.problem


def follow(root: str, spec: str, confirmed: bool, found: Followed,
           runner=subprocess.run, output=live.output,
           wait: float = PROOF_WAIT, sleep=time.sleep,
           alone: bool = False) -> None:
    """One run at a time: keel-database-follow.service and keel database
    watch never interleave between the proof and SET read_only OFF"""
    with dbreadonly.replication_locked(root):
        _follow(root, spec, confirmed, found, runner, output, wait, sleep,
                alone)


class Flip:
    """What the file folders need from a follow, whichever way it ends:
    the document and the pair once they are known, and the role once the
    database proved it. A follow that proved no role pauses the folders
    (0050's amendment, point 5), in one place, at every exit"""

    def __init__(self):
        self.doc: dict | None = None
        self.pair = None
        self.role: str | None = None


def _follow(root: str, spec: str, confirmed: bool, found: Followed,
            runner, output, wait: float, sleep,
            alone: bool = False) -> None:
    flip = Flip()
    try:
        _follow_proof(root, spec, confirmed, found, runner, output, wait,
                      sleep, alone, flip)
    finally:
        if flip.doc is not None:
            _filesync_flip(root, flip.doc, flip.pair, flip.role, found,
                           runner, spec)


def _follow_proof(root: str, spec: str, confirmed: bool, found: Followed,
                  runner, output, wait: float, sleep, alone: bool,
                  flip: Flip) -> None:
    try:
        doc = Node(root, spec).document()
    except (NodeError, ValueError) as e:
        found.fail(str(e))
        return
    _warn_undeclared(root, doc, found)
    flip.doc = doc
    _learn(root, spec, doc, found, output)
    proof = _early_proof(root, doc, output, wait, sleep)
    state = observe_database(root, doc, start=proof is not False,
                             spec=spec)
    if state is None:
        declared = (doc.get("appliance") or {}).get("vip")
        if not declared and found.nothing_without_vip:
            found.say(f"nothing to follow: {NO_PAIR}")
            return
        found.fail(NO_SERVER if declared else NO_PAIR)
        return
    if state.pair is None:
        if found.nothing_without_vip:
            found.say(f"nothing to follow: {NO_PAIR}")
            return
        found.fail(NO_PAIR)
        return
    pair = state.pair
    flip.pair = pair
    if state.down and proof is False:
        found.say(f"not started: this node's claim of {pair.vip} is not"
                  " proven (the VIP is not on wg0), so its server stays"
                  " stopped until the VIP decides")
        return
    # a copy that pg_rewind half copied may not start: only the confirmed
    # reseed replaces it, and it needs no answer from the server
    reseed_down = bool(state.down) and confirmed and \
        state.engine == "postgresql" and dbpgrewind.broken(root)
    if state.down and not reseed_down:
        found.fail(f"the server is not answering ({state.down})")
        return
    if not reseed_down and not state.reading.role.known:
        found.fail(f"the server could not be asked what it is"
                   f" ({state.reading.role.problem})")
        return
    if pair.problem or pair.peer_address is None:
        found.fail(pair.problem or "the other member of the pair is not"
                   " known (keel vip pair)")
        return
    server = declared_server(doc)
    role = dbpair.role_of(pair, str(server.get("role") or ""))
    record_role = True
    if reseed_down:
        from keel.system import dbpgfollow
        state = dbpgfollow.for_reseed(root, state, server, spec)
    if state.engine == "postgresql":
        # the engine's rows (0054): read_only, the role drop-in, the
        # root lock and GTID errancy are MariaDB's; a standby's
        # read-only-ness is recovery-inherent for PostgreSQL
        from keel.system import dbpgfollow
        record_role = dbpgfollow.follow(
            root, state, server, role, confirmed, found, runner,
            proven=lambda: proof if proof is not None else _proven(
                root, doc, output, wait, sleep),
            alone=alone)
    elif role == PRIMARY and vipstate.unconfirmed(root, pair.vip):
        # the holder's doubt (keel#195): read only and fenced until a
        # renewal of its lease is confirmed; the role file is left
        _in_doubt(root, state, pair.vip, found, runner)
        return
    elif role == PRIMARY and not _proven(root, doc, output, wait, sleep):
        # a paired node (it has a pair record: the other member is known)
        # with no claim at all is not proven either: its state file may have
        # been removed (keel#104)
        _unproven(root, state, found, runner)
        return
    elif role == PRIMARY:
        if not _primary(root, state, found, runner, sleep,
                        lambda: _proven(root, doc, output, 0, sleep)):
            _unproven(root, state, found, runner)
            return
    elif role == REPLICA:
        _replica(root, doc, server, state, confirmed, found, runner)
    else:
        found.fail(f"no role to follow: the VIP has no claim and the spec"
                   f" declares {role or 'none'}")
        return
    if record_role and found.problem is None:
        from keel.system import filesync
        _write(root, dbpair.ROLE_FILE, dbpair.role_text(
            role, pair.vip, files=filesync.replicates_files(root, doc)),
            0o644)
        flip.role = role
    # else PostgreSQL unproven, or the engine's follow failed: flip.role
    # stays None and the folders pause until a flip is proven, as the
    # database does (0050's amendment, point 5)


def _warn_undeclared(root: str, doc: dict, found: Followed) -> None:
    """The spec does not write overlays.syncthing out (keel#224): the
    pair has its files not replicated. The database role change is never
    blocked for it; it is said at each follow, and alerted once while
    the condition lasts"""
    from keel.system import filesync
    marker = os.path.join(root, UNDECLARED_MARKER)
    problem = filesync.undeclared_problem(root, doc)
    if problem is None:
        if os.path.exists(marker):
            os.unlink(marker)
        return
    found.say(f"WARNING: file replication is off for this pair: {problem}")
    if os.path.exists(marker):
        return
    _write(root, UNDECLARED_MARKER, "", 0o600)
    alerting.alert(root, lambda line: found.say(line), UNDECLARED_TITLE,
                   UNDECLARED_TEXT.format(host=os.uname().nodename,
                                          problem=problem), CHECK)


def _filesync_flip(root: str, doc: dict, pair, role: str | None, found,
                   runner, spec: str) -> None:
    """The file folders' direction with the database role's, in the same
    operation (0050's amendment, point 5); `role` None pauses them, of
    a node in doubt or not proven. A failure is said, never raised: the
    database flip this rides on is never undone"""
    from keel.system import filesync
    filesync.follow_flip(root, doc, pair, role, found, runner,
                         here=_here(root, spec))


def _here(root: str, spec: str):
    """This node on the members' channel (keel.mesh.vipnode.Here)"""
    from keel.mesh.vipnode import Here
    return Here(Node(root, spec), lambda: datetime.now(timezone.utc),
                lambda line: print(line, file=sys.stderr))


def _learn(root: str, spec: str, doc: dict, found: Followed,
           output) -> None:
    """keel vip check for the pair's VIP, without etcd, when this node's
    newest claim is its own and the VIP is not on wg0 (keel#154)

    Each peer that does not answer costs the channel's timeout, so the
    other members are asked only then: a holder that carries the VIP,
    and a node that knows another node's claim, ask nobody."""
    pair = dbpair.observe_pair(root, doc)
    if pair is None or pair.role != PRIMARY:
        return
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    if vipnet.carried(wireguard.interface(overlay), pair.vip,
                      output) is not False:
        return
    from keel.mesh import vippromote
    from keel.mesh.vipnode import VipError
    try:
        here = _here(root, spec)
        if vippromote.with_etcd(here):
            return
        vippromote.checked(here, pair.vip, False, found.say)
    except (VipError, NodeError, ValueError, OSError) as e:
        found.say(f"the other members could not be asked for a newer"
                  f" claim of {pair.vip}: {e}")


def _early_proof(root: str, doc: dict, output, wait: float,
                 sleep) -> bool | None:
    """For a PostgreSQL primary, whether its claim is proven, asked
    before the server is started; None for every other node

    A PostgreSQL server cannot be read only while it runs, so the follow
    of an unproven claim stops it. A start before that stop let it take
    writes for the time between (keel#154: each watch run did it)."""
    server = declared_server(doc)
    if str(server.get("engine") or "") != "postgresql":
        return None
    pair = dbpair.observe_pair(root, doc)
    if pair is None or \
            dbpair.role_of(pair, str(server.get("role") or "")) != PRIMARY:
        return None
    return _proven(root, doc, output, wait, sleep)


def _proven(root: str, doc: dict, output, wait: float, sleep) -> bool:
    """Whether this node holds the VIP now: its newest claim its own,
    neither fenced nor released, and the VIP on wg0, waited for up to
    `wait` seconds"""
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    iface = wireguard.interface(overlay)
    for turn in range(int(wait / PROOF_POLL) + 1):
        if turn:
            sleep(PROOF_POLL)
        pair = dbpair.observe_pair(root, doc)
        # no claim, or another node's: nothing to wait for
        if pair is None or pair.role != PRIMARY:
            return False
        if vipnet.carried(iface, pair.vip, output):
            return True
    return False


def _in_doubt(root: str, state: DatabaseState, vip: str, found: Followed,
              runner) -> None:
    """The holder's lease has had no renewal the majority confirmed for
    keel.mesh.vipetcd.DOUBT s: read only, every client connection ended
    (the fence of keel#186), until one is confirmed. A write that waits
    for a cut replica would otherwise return OK when the dump thread to
    it ends, about 12.6 s after the cut, before the release (keel#195)"""
    if not _read_only(root, state, found, runner):
        return
    found.say(f"read only: the lease of {vip} has had no renewal the"
              " majority confirmed, so this node may be cut off; it takes"
              " writes again once a renewal is confirmed (keel#195)")


def _unproven(root: str, state: DatabaseState, found: Followed,
              runner) -> None:
    """This node's own claim, not proven: read only and locked, and
    nothing else, until the VIP is on wg0 (keel#104)"""
    if not _read_only(root, state, found, runner):
        return
    what = "this node's claim of" if state.pair.claimed else \
        "this node holds no claim of"
    found.say(f"read only: {what} {state.pair.vip}, not proven (the VIP is"
              " not on wg0). It takes writes once keel vip check, keel vip"
              " promote or, with etcd, the controller carries the VIP; a"
              " newer claim makes it a replica")


FENCED = (
    "; every client connection was ended, so no write that waited for"
    " the replica is acknowledged after this (keel#186)"
)


def _read_only(root: str, state: DatabaseState, found: Followed,
               runner) -> bool:
    """read_only on, the drop-in, the root lock; whether all went"""
    if state.reading.read_only.value is not True:
        # the fence (keel#186): read_only while the client connections
        # are killed, so a write that waits for the ACK gets no OK
        statements = mariadb.set_read_only(True)
        problem = dbreadonly.fence(runner)
        if problem:
            found.fail(f"{statements.summary} failed: {problem}")
            return False
        found.say(statements.summary + FENCED)
    _write(root, mariadb.ROLE_DROPIN, mariadb.role_dropin_text(),
           DROPIN_MODE)
    problem = dbreadonly.lock(root, runner)
    if problem:
        found.fail(problem)
        return False
    return True


def _primary(root: str, state: DatabaseState, found: Followed,
             runner, sleep=time.sleep, proven=lambda: True) -> bool:
    """The holder: writable, replicating from nobody. False when the VIP
    was no longer proven after the wait for the replica"""
    replicating = bool(state.status.lines())
    if replicating:
        problem = dbreadonly.promote(root, PromoteReplica(DRAIN_TIMEOUT),
                                     runner)
        if problem:
            found.fail(problem)
            return True
        found.say("drained and promoted: this node replicates from nobody"
                  " and takes writes")
    elif state.reading.read_only.value is True:
        if not _replica_back(runner, sleep):
            found.say(NO_REPLICA.format(wait=REPLICA_WAIT))
        if not proven():
            return False
        statements = mariadb.set_read_only(False)
        problem = _send(runner, statements.text)
        if problem:
            found.fail(f"{statements.summary} failed: {problem}")
            return True
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
            return True
        found.say("READ_ONLY ADMIN given back to the accounts the replica"
                  " took it from")
    _forget_divergence(root)
    return True


def _replica_back(runner, sleep) -> bool:
    """Whether a replica is connected and the primary's commits wait for
    it (keel#242), waited for up to REPLICA_WAIT. The server is read only
    meanwhile, so a write gets an error, not an OK with no copy"""
    for turn in range(int(REPLICA_WAIT / REPLICA_POLL) + 1):
        if turn:
            sleep(REPLICA_POLL)
        out = _ask(runner, SEMI_SYNC_QUESTION) or ""
        values = dict(line.split("\t", 1) for line in out.splitlines()
                      if "\t" in line)
        clients = values.get("Rpl_semi_sync_master_clients", "0").strip()
        if values.get("Rpl_semi_sync_master_status", "").strip() == "ON" \
                and clients.isdigit() and int(clients) >= 1:
            return True
    return False


def _replica(root: str, doc: dict, server: dict, state: DatabaseState,
             confirmed: bool, found: Followed, runner) -> None:
    """The other node: read only, locked, following the holder"""
    pair = state.pair
    if not _read_only(root, state, found, runner):
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
            _unfence(root, host, port, state, found, runner)
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


def _unfence(root: str, host: str, port: int, state: DatabaseState,
             found: Followed, runner) -> None:
    """The VIP fence of this node's old loss cleared once it replicates
    from the holder and applied everything the holder logged (keel#192,
    the twin of keel#166 for PostgreSQL). The fence keeps an old primary
    from claiming by itself (0049); a rejoined or reseeded replica holds
    nothing the holder lacks. Caught up, per GTID domain: the newest
    sequence the holder logged is at or below what this node applied,
    in its binary log or its slave position (gtid_strict_mode keeps the
    sequences of a domain in order on both nodes)"""
    pair = state.pair
    if pair is None or not pair.fenced:
        return
    theirs = _holder_gtid(root, host, port, state, runner)
    mine = _ask(runner, APPLIED_QUESTION)
    if theirs is None or mine is None:
        return
    try:
        holder = dbgtid.newest(theirs.strip().partition("\t")[0])
        applied = dbgtid.newest(",".join(
            part for part in mine.strip().split("\t") if part))
    except ValueError:
        return
    if any(applied.get(domain, 0) < sequence
           for domain, sequence in holder.items()):
        return
    if vipstate.unfenced(root, pair.vip, pair.own_key):
        found.say(UNFENCED_SAID)


def _seed(root: str, host: str, port: int, state: DatabaseState,
          drop: tuple[str, ...], found: Followed, runner) -> None:
    # The copy must carry the primary's binary log history, or the old
    # primary comes back as diverged by the GTIDs of its first boot
    # (keel#202), and a server can take that history only while it writes
    # a binary log. The follow that the VIP's promotion starts on a new
    # replica runs before keel spec apply has written the pair's
    # configuration: the apply seeds it, after the restart that turns the
    # log on.
    logged = _ask(runner, LOG_BIN_QUESTION)
    if logged is not None and logged.strip() == "0":
        found.say(WAITS_FOR_BINARY_LOG)
        return
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


def described(record: dict) -> str:
    """What a recorded divergence holds, either engine's record: the
    errant GTIDs of MariaDB, or the two timelines of PostgreSQL (0054),
    which has no transaction ids to list"""
    errant = ", ".join(str(one) for one in record.get("errant") or [])
    if errant:
        return errant
    if record.get("holder_timeline") is not None:
        return (f"timeline {record.get('own_timeline') or 'unknown'}"
                f" against the holder's {record.get('holder_timeline')}")
    return "unknown"


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
