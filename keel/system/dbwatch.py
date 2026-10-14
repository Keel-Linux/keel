# Copyright (c) 2026 KeelLinux maintainers
"""keel database watch: what a pair reports between applies (0031, 0049)

Run by keel-database-watch.timer every 30 s on a node that declares
appliance.vip:

- **the fallback to asynchronous replication**, on the primary: when
  `Rpl_semi_sync_master_status` turns OFF the replica stopped
  acknowledging within the 10 s, commits go on without it, and a failover
  now loses what it has not received. Alerted once through the monitor's
  channels (keel.monitor.alerting), and once more when it is back ON;
  the state between runs is /var/lib/keel/database/semi-sync, so a
  lasting fallback is one alert, not one every 30 s. keel diff reports
  the same as drift (docs/diff.md);
- **the synchronous commit's wait, and the primary that commits
  alone**, on a PostgreSQL primary (0054). After keel database promote
  --old-primary-gone the primary commits alone; the watch alerts at
  each run while it does, and writes the pair's synchronous line back
  once a standby streams again. Otherwise:
  the pair's synchronous commit has no timeout and no fallback, so when
  no standby streams from the primary, or a commit waited for it longer
  than SYNC_WAIT_ALERT_S, writes do not finish. Alerted once, and once
  more when the standby acknowledges again; the state between runs is
  the same file, its key `sync_commit`;
- **the database certificate**, renewed with a third of its life left
  (keel.system.dbtls), through the members' channel; a renewal that
  cannot be had is alerted;
- **the role**, followed again when the server does not match the VIP's:
  a node whose VIP says replica and that replicates from nobody, with no
  divergence recorded (an old primary that came back while the holder
  could not be asked), or whose role file disagrees. keel database
  follow runs on each VIP move and at boot; this is what picks up a run
  that could not finish then.

The divergence of an old primary is alerted by keel database follow
when it finds it (keel.system.dbfollow); watch repeats nothing.
"""

import json
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from keel import exits
from keel.inspect import constants as paths
from keel.inspect.collect import database_servers
from keel.inspect.tree import Tree
from keel.mesh import etcd, vipnet
from keel.mesh.etcdstate import StateError
from keel.mesh.node import Node, NodeError
from keel.monitor import alerting
from keel.network import live, wireguard
from keel.system import dbpair, dbtls
from keel.system import dbmariadb as mariadb
from keel.system import dbpostgres

STATE = "var/lib/keel/database/semi-sync"
CHECK = "database-semi-sync"
FELL_BACK = "semi-synchronous replication fell back to asynchronous"
BACK = "semi-synchronous replication is back"
FELL_BACK_TEXT = (
    "{host}, the primary of {vip}: the replica did not acknowledge a commit"
    " within {timeout} s, so the primary commits without it"
    " (Rpl_semi_sync_master_status OFF). Writes go on; a failover now"
    " loses the commits the replica has not received. It turns"
    " semi-synchronous again by itself once the replica is back and caught"
    " up. keel database status on both nodes says what the replica does."
)
BACK_TEXT = ("{host}, the primary of {vip}: the replica acknowledges again;"
             " commits wait for it (Rpl_semi_sync_master_status ON).")
TLS_TITLE = "the database certificate could not be renewed"
SYNC_CHECK = "database-sync-commit"
# a commit waits one round trip for the standby (0.3 s at the design
# case's 250 ms); a wait this long is the standby away, not the link:
# the twin of MariaDB's 10 s semi-synchronous timeout
SYNC_WAIT_ALERT_S = 10
# one constant text, nothing spliced in: the standby's name is
# dbpostgres.SLOT and the wait SYNC_WAIT_ALERT_S (a unit test keeps
# them in step)
SYNC_SQL = (
    "SELECT (SELECT count(*) FROM pg_stat_replication"
    " WHERE application_name = 'keel'"
    " AND sync_state IN ('sync', 'quorum')),"
    " (SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'SyncRep'"
    " AND now() - query_start > interval '10 seconds'),"
    " (SELECT count(*) FROM pg_settings WHERE name ="
    " 'synchronous_standby_names' AND setting = ''),"
    " (SELECT count(*) FROM pg_stat_replication"
    " WHERE application_name = 'keel' AND state = 'streaming')"
)
SYNC_WAITS = "the primary's commits wait for the standby"
SYNC_BACK = "the standby acknowledges the primary's commits again"
SYNC_ALONE = "the primary commits alone, with no standby"
SYNC_ALONE_TEXT = (
    "{host}, the primary of {vip}: it commits alone. keel database promote"
    " --old-primary-gone said the old primary is gone, so this primary"
    " takes commits with no standby (decision 0054's one exception to its"
    " no-fallback rule): a commit is on this node only until a standby"
    " streams again. Reseed the other node with `keel spec apply"
    " --system-only --destroy-local-database` there; keel then makes each"
    " commit wait for it again. This alert repeats at each watch while"
    " the primary commits alone."
)
SYNC_WAITS_TEXT = (
    "{host}, the primary of {vip}: {why}. The pair's synchronous commit"
    " has no timeout and no fallback (decision 0054): a commit finishes"
    " only once the standby received and flushed it, so writes wait."
    " They finish by themselves once the standby streams again: heal its"
    " link, or reseed the other node with `keel spec apply --system-only"
    " --destroy-local-database` there. keel database status on both"
    " nodes says what the standby does."
)
SYNC_BACK_TEXT = ("{host}, the primary of {vip}: the standby acknowledges"
                  " again; commits finish.")


def watch(root: str, spec: str, out: Callable[[str], None],
          err: Callable[[str], None]) -> int:
    try:
        doc = Node(root, spec).document()
    except (NodeError, ValueError) as e:
        err(f"database watch: {e}")
        return exits.APPLY_FAILED
    pair = dbpair.observe_pair(root, doc)
    if pair is None:
        out("database watch: this node declares no appliance.vip; nothing"
            " to watch")
        return exits.OK
    code = exits.OK
    reading = semi_sync(root, pair, out, err)
    if not certificate(root, doc, spec, pair, out, err):
        code = exits.APPLY_FAILED
    if reading is not None and needs_follow(root, pair, reading, doc):
        from keel.system import dbfollow
        out("database watch: the server does not match the VIP's role;"
            " keel database follow")
        found = dbfollow.Followed(lambda line: out(f"  {line}"))
        dbfollow.follow(root, spec, False, found)
        if found.problem:
            code = exits.APPLY_FAILED
    return code


def needs_follow(root: str, pair: dbpair.PairState, reading,
                 doc: dict, output=live.output) -> bool:
    """Whether the server disagrees with the VIP's role. A paired server
    takes writes only while this node holds the VIP and carries it on
    wg0 (keel#104): writable with no claim, or with the VIP gone from
    wg0 (its valid_lft ran out), it is followed again"""
    role = pair.role
    if role is None:
        return pair.peer_key is not None and \
            reading.read_only.value is False
    try:
        with open(os.path.join(root, dbpair.ROLE_FILE)) as fob:
            recorded = fob.read()
    except OSError:
        recorded = ""
    if f"role={role}\n" not in recorded:
        return True
    if role == dbpair.REPLICA:
        from keel.system import dbfollow
        replicating = reading.role.value == "replica"
        return not replicating and dbfollow.diverged(root) is None
    if reading.read_only.value is True:
        return True
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    return vipnet.carried(wireguard.interface(overlay), pair.vip,
                          output) is False


def semi_sync(root: str, pair: dbpair.PairState, out, err,
              runner=subprocess.run):
    """The fallback alerted on its change, on the primary; the server's
    reading, or None

    PostgreSQL has no semi-synchronous fallback (its pair's synchronous
    commit waits, docs/replication-postgresql.md), so its reading is
    returned without the semi-sync asks and watch follows a mismatched
    server the same way it does for mariadb (found by the pair's
    network-namespace test of this release: a mariadb-only read called a
    healthy postgresql node "no server" and needs_follow never ran)"""
    tree = Tree(root)
    readings = {one.engine.name: one.reading()
                for one in database_servers(tree)}
    reading = readings.get("mariadb") or readings.get("postgresql")
    if reading is None:
        out("database watch: no database server; nothing to watch")
        return None
    if reading.semi_sync.known:
        return _semi_sync_mariadb(root, pair, reading, out, err)
    if "mariadb" in readings:
        out("database watch: semi-synchronous status not readable"
            f" ({reading.semi_sync.problem})")
        return reading
    return _sync_postgresql(root, pair, reading, out, err, runner)


def _sync_postgresql(root: str, pair: dbpair.PairState, reading, out, err,
                     runner):
    """The synchronous commit's wait, alerted on its change, on the
    primary: no standby streams, or a commit waited SYNC_WAIT_ALERT_S"""
    if pair.role != dbpair.PRIMARY or reading.role.value == "replica":
        return reading
    try:
        done = runner(list(dbpostgres.CLIENT + ("--command", SYNC_SQL)),
                      capture_output=True, text=True, check=False)
    except OSError as e:
        out(f"database watch: the synchronous commit is not readable ({e})")
        return reading
    columns = (done.stdout or "").strip().split("\t")
    if done.returncode != 0 or len(columns) != 4 or \
            not all(one.isdigit() for one in columns):
        out("database watch: the synchronous commit is not readable"
            f" ({(done.stderr or '').strip()[-200:] or 'no answer'})")
        return reading
    standbys, waiting, alone, streaming = (int(one) for one in columns)
    host = os.uname().nodename
    before = _read_state(root)
    if alone and streaming:
        from keel.system import dbpgfollow
        problem, _ = dbpgfollow.synchronous_again(root, runner)
        out("database watch: a standby streams again; "
            + (f"the pair's synchronous line could not come back ({problem})"
               if problem else dbpgfollow.SYNCHRONOUS_SAID))
        alone = 1 if problem else 0
        standbys = 0 if problem else 1
    if alone:
        out("database watch: role primary, synchronous commit alone"
            f" (was {before.get('sync_commit') or 'unknown'})")
        alerting.alert(root, err, SYNC_ALONE, SYNC_ALONE_TEXT.format(
            host=host, vip=pair.vip), SYNC_CHECK)
        _write_state(root, {"sync_commit": "alone", "role": pair.role,
                            "at": datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ")})
        return reading
    if not standbys:
        why = "no standby streams from it"
    elif waiting:
        why = (f"{waiting} commit(s) waited more than {SYNC_WAIT_ALERT_S} s"
               " for the standby")
    else:
        why = ""
    now = "waiting" if why else "flowing"
    out(f"database watch: role primary, synchronous commit {now}"
        f" (was {before.get('sync_commit') or 'unknown'})"
        + (f": {why}" if why else ""))
    if now != before.get("sync_commit"):
        if now == "waiting":
            alerting.alert(root, err, SYNC_WAITS, SYNC_WAITS_TEXT.format(
                host=host, vip=pair.vip, why=why), SYNC_CHECK)
        elif before.get("sync_commit") in ("waiting", "alone"):
            alerting.alert(root, err, SYNC_BACK, SYNC_BACK_TEXT.format(
                host=host, vip=pair.vip), SYNC_CHECK, "recovery")
    _write_state(root, {"sync_commit": now, "role": pair.role,
                        "at": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")})
    return reading


def _semi_sync_mariadb(root: str, pair: dbpair.PairState, reading,
                       out, err):
    """The fallback to asynchronous replication, on the primary"""
    master = str(reading.semi_sync.value.get("master", "")).lower()
    now = "on" if master == "on" else "off"
    before = _read_state(root)
    role = pair.role
    out(f"database watch: role {role or 'unclaimed'}, semi-synchronous"
        f" {now} (was {before.get('semi_sync') or 'unknown'})")
    # off is alerted at its first sight too; "back" only after an off
    # that was seen, never at the pair's first watch
    if role == dbpair.PRIMARY and now != before.get("semi_sync"):
        host = os.uname().nodename
        if now == "off":
            alerting.alert(root, err, FELL_BACK, FELL_BACK_TEXT.format(
                host=host, vip=pair.vip,
                timeout=mariadb.SEMI_SYNC_TIMEOUT_MS // 1000), CHECK)
        elif before.get("semi_sync") == "off":
            alerting.alert(root, err, BACK, BACK_TEXT.format(
                host=host, vip=pair.vip), CHECK, "recovery")
    _write_state(root, {"semi_sync": now, "role": role,
                        "at": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")})
    return reading


def certificate(root: str, doc: dict, spec: str, pair: dbpair.PairState,
                out, err) -> bool:
    """The leaf renewed when due; whether it is in place"""
    from keel.mesh import vippair
    from keel.system.dbstate import declared_server
    server = declared_server(doc)
    engine = str(server.get("engine") or "mariadb")
    addresses = mariadb.overlay_addresses(doc) if engine == "mariadb" \
        else dbpostgres.overlay_addresses(doc)
    if not addresses:
        return True
    member = etcd.Etcd(Node(root, spec), lambda: datetime.now(timezone.utc),
                       err)
    try:
        key = etcd.own_key(member)
        try:
            record = vippair.read(root, pair.vip)
        except ValueError:
            record = None
        said = dbtls.ensure(member, addresses[0], pair.vip,
                            pair.peer_address, key or "", pair=record,
                            engine=engine)
    except (StateError, NodeError, ValueError) as e:
        err(f"database watch: {e}")
        until = dbtls.expires(root, engine) or "unknown"
        alerting.alert(root, err, TLS_TITLE, f"{os.uname().nodename}: {e}."
                       " Replication over TLS stops when the certificate"
                       f" expires ({until}).",
                       "database-tls")
        return False
    if said:
        out(f"database watch: {said}")
    if dbtls.refresh_crl(root, engine):
        if engine == "mariadb":
            import subprocess
            done = subprocess.run(list(mariadb.CLIENT),
                                  input="FLUSH SSL;\n",
                                  capture_output=True, text=True,
                                  check=False)
            out("database watch: the root's CRL refreshed for the server"
                + ("" if done.returncode == 0 else
                   f" (FLUSH SSL failed: {done.stderr.strip()[-120:]})"))
        else:
            out("database watch: the root's CRL refreshed for the server"
                " (a running PostgreSQL keeps its SSL files until the"
                " next restart)")
    return True


def _read_state(root: str) -> dict:
    try:
        with open(os.path.join(root, STATE)) as fob:
            found = json.load(fob)
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(root: str, state: dict) -> None:
    target = os.path.join(root, STATE)
    os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
    with open(target, "w") as fob:
        json.dump(state, fob)
        fob.write("\n")


def main(args) -> int:
    """keel database watch"""
    root = os.path.abspath(getattr(args, "root", paths.ROOT_DEFAULT))
    return watch(root, args.spec, print,
                 lambda line: print(line, file=sys.stderr))
