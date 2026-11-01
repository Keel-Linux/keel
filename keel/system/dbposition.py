# Copyright (c) 2026 KeelLinux maintainers
"""What the holder of a MariaDB pair last logged, and the gate on it
(keel#271)

The drain of keel.system.dbreadonly proves that a replica applied what
it received. It does not prove that it received what the primary
acknowledged, and at a failover the primary is gone, so it cannot be
asked. `Seconds_Behind_Master` is no help: it compares the SQL thread
with what was received, and said 0 at 8000 rows behind (evidence of
2026-11-01, case G). A replica at 14614 was promoted while the primary
held 27978 (case K1).

So the holder leaves its position in etcd, and the node that claims the
VIP reads it there before it takes writes (0020: automatic failover
exists only with etcd). `keel database position`
(keel-database-position.service) writes a record each POLL seconds, only
while the server is writable:

- `position`: `gtid_binlog_pos` of DELAY turns ago. With AFTER_SYNC a
  commit is in the binary log before the replica has it, so the newest
  position is ahead of a healthy replica for one round trip, and a crash
  under load would read as a lag;
- `alone`: no replica connected, or the status OFF (keel#270). The holder
  may have acknowledged writes the record does not show yet.

A node that lags stays what it is, a read-only replica that goes on
receiving, and follow says why at each run. The old primary decides when
it answers, since what it logged is fresher than any record. Otherwise
only the operator ends it: `keel database promote --accept-lost-writes`.

What is left: a holder that acknowledges writes alone and dies within
POLL seconds of the last replica leaving, before a record says so. A cut
takes about 12.6 s to end the dump thread, and the first commit that
waits for it moves the position, so a cut does not reach this.
A member's certificate may write this key: a false record makes a
failover wait for the operator, or gives the behaviour with no record.
"""

import contextlib
import json
import os
import subprocess
import threading
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from keel.mesh.etcdauth import own_prefix
from keel.mesh.etcdclient import EtcdError
from keel.mesh.node import NodeError
from keel.mesh.vipnode import VipError
from keel.monitor import alerting
from keel.system import dbgtid
from keel.system import dbmariadb as mariadb

POLL = 2.0
# turns: the age of the published position, well over a round trip on a
# link of 250 ms with loss, well under the 12.6 s a cut takes to end the
# dump thread
DELAY = 2
SAMPLE_TIMEOUT = 5
SAMPLE_SQL = (
    "SELECT @@gtid_binlog_pos, @@read_only,"
    " (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS"
    " WHERE VARIABLE_NAME = 'RPL_SEMI_SYNC_MASTER_CLIENTS'),"
    " (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS"
    " WHERE VARIABLE_NAME = 'RPL_SEMI_SYNC_MASTER_STATUS')"
)
SAMPLE_QUESTION = mariadb.QUIET_CLIENT + ("--execute", SAMPLE_SQL)
ACCEPT_MARK = "var/lib/keel/database/accept-lost-writes"
REFUSED = "var/lib/keel/database/promotion-refused"
CHECK = "database-promotion"
TITLE = "a replica that may lack writes holds the VIP and stays read only"
ACCEPTED_SAID = (
    "the operator accepted the writes this node lacks"
    " (--accept-lost-writes): {why}"
)
THE_ACT = (
    " It stays read only and goes on receiving. To take writes without"
    " them, run `keel database promote --accept-lost-writes` here; the old"
    " primary then diverges, and keeps them in its data and its dump."
)
BEHIND = (
    "this node lacks {count} transaction(s) the old primary logged: it"
    " received up to {own}, and the old primary's record says {theirs}."
    + THE_ACT
)
ALONE = (
    "the old primary's record says that it had no replica, so it may have"
    " acknowledged writes this node lacks, and it does not answer. This"
    " node received up to {own}." + THE_ACT
)
CATCHING_UP = (
    "this node lacks {count} transaction(s) the old primary logged: it"
    " received up to {own}, and the old primary, which answers, logged"
    " {theirs}. It takes writes by itself once it catches up. To have"
    " writes sooner, run `keel database promote` on the old primary, which"
    " holds them all." + THE_ACT
)
NOT_READ = (
    "the old primary's position could not be read, and it does not answer."
    + THE_ACT
)


@dataclass(frozen=True)
class Record:
    """What the holder left: its position, whether it had no replica,
    and which member wrote it"""

    position: str
    alone: bool
    holder: str

    def text(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


UNREADABLE = Record("", True, "")


def key(mesh_id: str, vip: str) -> str:
    """Under the keys every member may write (keel.mesh.etcdauth), not
    under /vip/<vip>/: keel.mesh.vipetcd.seen takes each key there for a
    claim and says so at each tick, an older keel's too"""
    return f"{own_prefix(mesh_id)}database/{vip}"


def parsed(text: str) -> Record:
    try:
        found = json.loads(text)
        made = Record(found["position"], found["alone"], found["holder"])
        dbgtid.parse(made.position)
    except (ValueError, KeyError, TypeError, AttributeError):
        return UNREADABLE
    if not isinstance(made.alone, bool):
        return UNREADABLE
    return made


def read_record(here, vip: str) -> Record | None:
    """The record of `vip`, None when there is none, UNREADABLE when etcd
    does not answer"""
    try:
        wanted = key(here.mesh_id(), vip)
        client = here.local()
        client.timeout = SAMPLE_TIMEOUT
        values = client.prefix(wanted)
    except (EtcdError, VipError, NodeError, OSError):
        return UNREADABLE
    for value in values:
        if value.key == wanted:
            raw = value.value
            return parsed(raw.decode(errors="replace")
                          if isinstance(raw, bytes) else raw)
    return None


def with_etcd(here) -> bool:
    from keel.mesh import vippromote
    return vippromote.with_etcd(here)


def why_not(own: str, record: Record | None,
            ask_old_primary: Callable[[], str | None]) -> str | None:
    """Why a node that received up to `own` may not take writes, or None.
    The old primary is asked only when the record refuses: a dead one
    costs the connect timeout"""
    if record is None:
        return None
    try:
        if record is not UNREADABLE and not record.alone and \
                not dbgtid.behind(record.position, own):
            return None
        theirs = ask_old_primary()
        if theirs is not None:
            missing = dbgtid.behind(theirs, own)
            if not missing:
                return None
            return CATCHING_UP.format(count=sum(missing.values()), own=own,
                                      theirs=theirs)
        if record is UNREADABLE:
            return NOT_READ
        missing = dbgtid.behind(record.position, own)
    except ValueError:
        return NOT_READ
    if missing:
        return BEHIND.format(count=sum(missing.values()), own=own,
                             theirs=record.position)
    return ALONE.format(own=own)


def accepted(root: str) -> bool:
    return os.path.exists(os.path.join(root, ACCEPT_MARK))


@contextlib.contextmanager
def accepting(root: str) -> Iterator[None]:
    """The operator's act, for the follow that the command runs and for a
    follow that the claim starts meanwhile; never left for a later one"""
    path = os.path.join(root, ACCEPT_MARK)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
              "w") as fob:
        fob.write("keel database promote --accept-lost-writes\n")
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)


def refused(root: str, vip: str, why: str,
            say: Callable[[str], None]) -> None:
    """Recorded for keel database status, and alerted until a channel
    took it, once"""
    before = _read_refused(root)
    told = before.get("alerted") is True or alerting.alert(
        root, say, TITLE, f"{os.uname().nodename}, of {vip}: {why}", CHECK)
    path = os.path.join(root, REFUSED)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
              "w") as fob:
        json.dump({"why": why, "alerted": bool(told),
                   "since": before.get("since") or datetime.now(
                       timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, fob)


def forget(root: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.remove(os.path.join(root, REFUSED))


def _read_refused(root: str) -> dict:
    try:
        with open(os.path.join(root, REFUSED)) as fob:
            found = json.load(fob)
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def status_lines(root: str) -> list[str]:
    found = _read_refused(root)
    if not found:
        return []
    return [f"  PROMOTION REFUSED since {found.get('since')}:"
            f" {found.get('why')}"]


def distance_lines(here, vip: str, own: str) -> list[str]:
    """On a replica, how far it is from the holder's record, by GTID"""
    record = read_record(here, vip)
    if record is None or record is UNREADABLE:
        return []
    try:
        missing = dbgtid.behind(record.position, own)
    except ValueError:
        return []
    return [f"  behind the holder's record: {sum(missing.values())}"
            f" transaction(s) (received {own}, record {record.position})"
            + ("; the holder has no replica" if record.alone else "")]


class Publisher:
    """One turn: a sample of the server, and the record when it changed"""

    def __init__(self, runner, put: Callable[[str], None], own_key: str):
        self.runner = runner
        self.put = put
        self.own_key = own_key
        self.seen: deque[str] = deque(maxlen=DELAY + 1)
        self.last: str | None = None

    def forget(self) -> None:
        self.seen.clear()

    def turn(self) -> None:
        columns = self._sample()
        # a server that is read only logs nothing new, and a lagging
        # holder must not write its low position over the record
        if columns is None or columns[1] != "0":
            self.forget()
            return
        position, _, clients, status = columns
        self.seen.append(position)
        alone = clients == "0" or status != "ON"
        if len(self.seen) <= DELAY and not alone:
            return
        text = Record(self.seen[0], alone, self.own_key).text()
        if text != self.last:
            self.put(text)
            self.last = text

    def _sample(self) -> list[str] | None:
        try:
            done = self.runner(list(SAMPLE_QUESTION), capture_output=True,
                               text=True, check=False,
                               timeout=SAMPLE_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            return None
        columns = (done.stdout or "").rstrip("\n").split("\t")
        if done.returncode != 0 or len(columns) != 4:
            return None
        return columns


def serve(here, pair_of: Callable[[], tuple[str, bool] | None],
          stop: threading.Event, err: Callable[[str], None],
          runner=subprocess.run) -> None:
    """Until `stop`, or until this node has nothing to publish: `pair_of`
    says the VIP and whether this node holds it, None for a node that is
    no MariaDB pair under etcd. The timer starts it again. A failure is
    said once, and a record that cannot be written costs nothing here"""
    said: dict[str, str] = {}
    vip: dict[str, str] = {}

    def put(text: str) -> None:
        client = here.local()
        client.timeout = SAMPLE_TIMEOUT
        client.put(key(here.mesh_id(), vip["now"]), text)

    publisher = Publisher(runner, put, here.own_key())
    while not stop.is_set():
        try:
            found = pair_of()
            if found is None:
                return
            vip["now"] = found[0]
            if found[1]:
                publisher.turn()
            else:
                publisher.forget()
            said.clear()
        except (EtcdError, VipError, NodeError, ValueError, OSError) as e:
            publisher.last = None
            if said.get("why") != str(e):
                said["why"] = str(e)
                err(f"database position: {e}")
        stop.wait(POLL)
