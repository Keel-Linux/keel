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
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from keel import exits
from keel.inspect import constants as paths
from keel.inspect.collect import database_servers
from keel.inspect.tree import Tree
from keel.mesh import etcd
from keel.mesh.etcdstate import StateError
from keel.mesh.node import Node, NodeError
from keel.monitor import alerting
from keel.system import dbpair, dbtls
from keel.system import dbmariadb as mariadb

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
                 doc: dict) -> bool:
    """Whether the server disagrees with the VIP's role"""
    role = pair.role
    if role is None:
        return False
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
    return reading.read_only.value is True


def semi_sync(root: str, pair: dbpair.PairState, out, err):
    """The fallback alerted on its change, on the primary; the server's
    reading, or None"""
    tree = Tree(root)
    reading = next((one.reading() for one in database_servers(tree)
                    if one.engine.name == "mariadb"), None)
    if reading is None or not reading.semi_sync.known:
        out("database watch: semi-synchronous status not readable"
            f" ({reading.semi_sync.problem if reading else 'no server'})")
        return reading
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
    own = mariadb.overlay_addresses(doc)
    if not own:
        return True
    member = etcd.Etcd(Node(root, spec), lambda: datetime.now(timezone.utc),
                       err)
    try:
        key = etcd.own_key(member)
        said = dbtls.ensure(member, own[0], pair.vip, pair.peer_address,
                            key or "")
    except (StateError, NodeError, ValueError) as e:
        err(f"database watch: {e}")
        alerting.alert(root, err, TLS_TITLE, f"{os.uname().nodename}: {e}."
                       " Replication over TLS stops when the certificate"
                       f" expires ({dbtls.expires(root) or 'unknown'}).",
                       "database-tls")
        return False
    if said:
        out(f"database watch: {said}")
    if dbtls.refresh_crl(root):
        import subprocess
        done = subprocess.run(list(mariadb.CLIENT), input="FLUSH SSL;\n",
                              capture_output=True, text=True, check=False)
        out("database watch: the root's CRL refreshed for the server"
            + ("" if done.returncode == 0 else
               f" (FLUSH SSL failed: {done.stderr.strip()[-120:]})"))
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
