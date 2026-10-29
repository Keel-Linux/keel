# Copyright (c) 2026 KeelLinux maintainers
"""keel database guard: a pair's PostgreSQL server starts as a primary
only on the proven holder (keel#156)

PostgreSQL cannot be made read only while it runs, so a server that
starts as a primary takes writes until keel stops it. On real nodes that
was 3 to 4 s after a boot and after a heal, while the other member held
the VIP. A default commit waits for the standby, but a client that sets
synchronous_commit to local or off got its write acknowledged, and the
pair does not hold it (0054's exception, keel#156).

This is the ExecStartPre of the server's unit
(postgresql@.service.d/keel-guard.conf), run as root before each start:

| the VIP here | the start |
| --- | --- |
| standby.signal in the data directory | as it is: a standby takes no write |
| no claim yet (a pair in its setup) | as it is, as before |
| the newest claim is the other member's, or this node is fenced | as a standby that follows nobody: standby.signal written and the follow drop-in removed first, what keel database follow's fence leaves |
| this node's own claim, and the VIP on wg0 | as it is: the proven primary |
| this node's own claim, the VIP not on wg0 | refused; keel database follow starts it once the VIP is proven |

A node with no pair, or no PostgreSQL in its spec, starts as it is. The
guard asks nobody over the network. The spec of a pair that cannot be
read refuses the start: whether the claim is proven cannot be known.
"""

import os
from collections.abc import Callable

from keel import exits
from keel.mesh import vipnet
from keel.mesh.node import Node, NodeError
from keel.network import live, wireguard
from keel.system import dbpair, dbpgseed, dbpostgres

NOT_PROVEN = (
    "refused: this node's claim of {vip} is not proven (the VIP is not on"
    " {iface}), and a primary takes writes from its first second; keel"
    " database follow starts the server once the VIP is proven (keel#156)"
)
FENCED_START = (
    "starts as a standby that follows nobody: the newest claim of {vip}"
    " is the other member's, so this server takes no write (standby.signal"
    " written, the follow drop-in removed; keel#156)"
)


def guard(root: str, spec: str, out: Callable[[str], None],
          output=live.output) -> int:
    """Whether the server may start, as an exit code; may fence it first"""
    try:
        _, _, dropdir, datadir = dbpostgres.cluster_paths(root)
    except FileNotFoundError:
        return exits.OK
    paired = os.path.exists(os.path.join(dropdir,
                                         dbpostgres.PAIR_DROPIN_NAME))
    try:
        doc = Node(root, spec).document()
    except (NodeError, ValueError, OSError) as e:
        if not paired:
            return exits.OK
        out(f"refused: the spec of this pair cannot be read ({e}), so"
            " whether this node may start as a primary is not known")
        return exits.APPLY_FAILED
    server = (doc.get("database") or {}).get("server") or {}
    if str(server.get("engine") or "") != "postgresql":
        return exits.OK
    pair = dbpair.observe_pair(root, doc)
    if pair is None or pair.role is None:
        return exits.OK
    signal = os.path.join(datadir, dbpostgres.STANDBY_SIGNAL)
    if os.path.exists(signal):
        return exits.OK
    if pair.role != dbpair.PRIMARY:
        return _fenced(signal, dropdir, pair.vip, out)
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    iface = wireguard.interface(overlay)
    if vipnet.carried(iface, pair.vip, output) is True:
        return exits.OK
    out(NOT_PROVEN.format(vip=pair.vip, iface=iface))
    return exits.APPLY_FAILED


def _fenced(signal: str, dropdir: str, vip: str,
            out: Callable[[str], None]) -> int:
    try:
        fd = os.open(signal, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        os.close(fd)
        dbpgseed._as_postgres(signal)
        try:
            os.remove(os.path.join(dropdir, dbpostgres.FOLLOW_DROPIN_NAME))
        except FileNotFoundError:
            pass
    except OSError as e:
        out(f"refused: the newest claim of {vip} is the other member's,"
            f" and this server could not be made a standby first:"
            f" {e.strerror or e}")
        return exits.APPLY_FAILED
    out(FENCED_START.format(vip=vip))
    return exits.OK
