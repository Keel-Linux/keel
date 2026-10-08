# Copyright (c) 2026 KeelLinux maintainers
"""etcd restarted one member at a time (decisions 0025, 0049; the
maintainer's requirement of 2026-10-10: an upgrade never breaks the
service where the VIP is active)

etcd-server's postinst restarts etcd on every upgrade, and nothing in
the package knows of the other members: apt run on two of three at once
would lose the majority for as long as both restart. keel-overlay-etcd
puts this gate around etcd.service (a drop-in):

- `keel mesh etcd gate stop`, its ExecStop, before etcd is sent SIGTERM:
  passes at once when this member does not answer (it crashed: no part of
  the majority, and its restart is the way back); otherwise waits until
  every other voter is healthy and no other member holds the restart
  lock, then takes the lock, a key written by compare-and-swap
  on a lease of LOCK_TTL seconds, so two members never pass at once. A
  stop cannot be refused for good (a shutdown, an operator who means
  it): after `wait` seconds it says so and lets the stop go on. At
  shutdown it does not wait;
- `keel mesh etcd gate started`, its ExecStartPost: waits until this
  member answers a linearizable read (it is back in the majority), then
  deletes its own lock. A member that never comes back leaves the lock
  to its lease, and the others' health to the next gate.

`keel mesh upgrade-check` reads the same, changes nothing, and says
whether this node may be upgraded now, and whether it holds a VIP
(docs/vip.md, "Upgrading a pair without downtime").

The lock is advice between keel's own gates, under the mesh's own keys
that every member may write (keel-member, keel.mesh.etcdauth), and the
health of the others, asked of each, is checked whatever the lock says.
"""

import json
import time
from collections.abc import Callable
from datetime import datetime, timezone

from keel import exits
from keel.mesh import etcdclient, etcdstate, identity
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import Client, EtcdError, absent
from keel.mesh.etcdstate import StateError

LOCK_TTL = 120
# how long the gate waits before a stop, and after a start, by default
WAIT = 300
STARTED_WAIT = 120
POLL = 2.0
CALL_TIMEOUT = 5


def lock_key(mesh_id: str) -> str:
    return f"/keel/{mesh_id}/etcd/restarting"


def client_of(root: str) -> Client:
    """etcd, this member first, then every other member of the cluster
    record: the others answer while this one is down; raises EtcdError,
    StateError"""
    urls = [etcdstate.client_url(etcdstate.LOOPBACK)]
    cluster = etcdstate.cluster(root)
    for member in cluster.members if cluster else ():
        urls.append(etcdstate.client_url(member.address))
    return Client(tuple(urls), etcdclient.files(root), CALL_TIMEOUT)


def problems(client: Client, own: str, mesh_id: str) -> list[str]:
    """Why this member, at the overlay address `own`, should not stop
    now: another voter not healthy, or another member restarting"""
    try:
        listed = client.members()
    except EtcdError as e:
        return [f"etcd does not answer: {e}"]
    found = []
    for one in listed:
        if one.learner or one.address == own:
            continue
        url = one.client_urls[0] if one.client_urls else \
            etcdstate.client_url(one.address or "::")
        healthy, why = client.health(url)
        if not healthy:
            found.append(f"etcd member {one.name or one.id} at {one.address}"
                         f" is not healthy{': ' + why if why else ''}")
    holder = locked_by(client, mesh_id)
    if holder is not None and holder.get("member") != own:
        found.append(f"etcd member at {holder.get('member')} is restarting"
                     f" (since {holder.get('at')})")
    return found


def locked_by(client: Client, mesh_id: str) -> dict | None:
    """The restart lock's value, None when nobody holds it; raises
    nothing: an unreadable lock is a problem of its own"""
    try:
        values = client.prefix(lock_key(mesh_id))
    except EtcdError as e:
        return {"member": f"(unknown: {e})", "at": "?"}
    for one in values:
        if one.key == lock_key(mesh_id):
            try:
                found = json.loads(one.value.decode())
            except (UnicodeDecodeError, ValueError):
                found = None
            return found if isinstance(found, dict) else \
                {"member": "(not keel's)", "at": "?"}
    return None


def take(client: Client, own: str, mesh_id: str,
         now: Callable[[], datetime]) -> bool:
    """The restart lock taken for this member, on a lease of LOCK_TTL;
    whether it holds it now. A lock of its own left from an earlier stop
    is taken again."""
    key = lock_key(mesh_id)
    try:
        if (locked_by(client, mesh_id) or {}).get("member") == own:
            client.delete(key)
        lease = client.grant(LOCK_TTL)
        value = json.dumps({"member": own, "at": now().isoformat(
            timespec="seconds")}).encode()
        if client.swap([absent(key)], [(key, value, lease)]):
            return True
        client.revoke(lease)
    except EtcdError:
        return False
    return False


def stopping(output: Callable[[tuple[str, ...]], str | None]) -> bool:
    """Whether the system is shutting down"""
    found = output(("systemctl", "is-system-running"))
    return (found or "").strip() == "stopping"


def before_stop(root: str, own: str, err: Callable[[str], None],
                client: Client | None = None, local: Client | None = None,
                wait: float = WAIT,
                output: Callable[[tuple[str, ...]], str | None] =
                lambda argv: None,
                monotonic: Callable[[], float] = time.monotonic,
                sleep: Callable[[float], None] = time.sleep,
                now: Callable[[], datetime] =
                lambda: datetime.now(timezone.utc)) -> int:
    """ExecStop of etcd.service: OK once the others keep the majority
    without this member and it holds the restart lock; APPLY_FAILED
    when it waited `wait` seconds in vain (the stop goes on)"""
    if etcdstate.cluster(root) is None:
        return exits.OK
    if stopping(output):
        err("etcd: the system is shutting down; this member stops now")
        return exits.OK
    local = local or etcdclient.local(root)
    local.timeout = CALL_TIMEOUT
    try:
        local.status(etcdstate.client_url(etcdstate.LOOPBACK))
    except EtcdError as e:
        # not serving (crashed, or never up): it is no part of the
        # majority now, and its stop costs nothing; its restart is the
        # way back
        err(f"etcd: this member does not answer ({e}); it stops now")
        return exits.OK
    mesh_id = identity.read(root).hex()
    client = client or client_of(root)
    deadline = monotonic() + wait
    said: list[str] = []
    while True:
        found = problems(client, own, mesh_id)
        if not found:
            if take(client, own, mesh_id, now):
                err("etcd: every other member is healthy; this member"
                    " stops, and holds the restart lock until it is back")
                return exits.OK
            found = ["another member took the restart lock first"]
        if monotonic() >= deadline:
            for line in found:
                err(f"etcd: {line}")
            err(f"etcd: waited {wait:g} s; this member stops anyway, and"
                " the cluster may lose its majority until it is back")
            return exits.APPLY_FAILED
        if found != said:
            for line in found:
                err(f"etcd: waiting before this member stops: {line}")
            said = found
        sleep(POLL)


def after_start(root: str, own: str, err: Callable[[str], None],
                local: Client | None = None, client: Client | None = None,
                wait: float = STARTED_WAIT,
                monotonic: Callable[[], float] = time.monotonic,
                sleep: Callable[[float], None] = time.sleep) -> int:
    """ExecStartPost of etcd.service: OK once this member answers a
    linearizable read and its restart lock is gone; APPLY_FAILED when it
    did not within `wait` seconds (the lock's lease ends it)"""
    if etcdstate.cluster(root) is None:
        return exits.OK
    mesh_id = identity.read(root).hex()
    local = local or etcdclient.local(root)
    local.timeout = CALL_TIMEOUT
    deadline = monotonic() + wait
    while True:
        try:
            local.prefix(lock_key(mesh_id))
            break
        except EtcdError as e:
            if monotonic() >= deadline:
                err(f"etcd: this member is not back in the majority after"
                    f" {wait:g} s ({e}); its restart lock ends with its"
                    f" lease, within {LOCK_TTL} s")
                return exits.APPLY_FAILED
        sleep(POLL)
    client = client or client_of(root)
    try:
        if (locked_by(client, mesh_id) or {}).get("member") == own:
            client.delete(lock_key(mesh_id))
    except EtcdError as e:
        err(f"etcd: the restart lock was not released ({e}); it ends with"
            f" its lease, within {LOCK_TTL} s")
        return exits.APPLY_FAILED
    err("etcd: this member is back in the majority; restart lock released")
    return exits.OK


def upgrade_check(root: str, own: str, out: Callable[[str], None],
                  client: Client | None = None) -> int:
    """`keel mesh upgrade-check`: whether this node may be upgraded now,
    one line per reason not to; OK, or MESH_REFUSED"""
    found: list[str] = []
    try:
        if etcdstate.cluster(root) is not None:
            client = client or client_of(root)
            found = problems(client, own, identity.read(root).hex())
    except (EtcdError, StateError, OSError, ValueError) as e:
        found = [f"etcd cannot be asked: {e}"]
    for line in found:
        out(f"not now: {line}")
    for held in vipstate.held_all(root):
        if held.claim is not None and held.claim.address == own and \
                not held.fenced and not held.released:
            out(f"vip {held.vip}: this node holds it; upgrade it last, or"
                " move it first with keel vip promote on the other node")
    if found:
        return exits.MESH_REFUSED
    out("upgrade: every other etcd member is healthy and none restarts;"
        " upgrade this node, then the next one")
    return exits.OK
