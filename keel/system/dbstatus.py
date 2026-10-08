# Copyright (c) 2026 KeelLinux maintainers
"""keel database status: one screen for the operator (0020, 0031, 0049)

The role from the VIP and from the server, the semi-synchronous status,
the replica's lag and what it follows, the GTID positions, the
certificate, a divergence, and the VIP's own lines (keel vip status).
Reads only; never a secret.
"""

import os
from collections.abc import Callable

from keel import exits
from keel.inspect import constants as paths
from keel.inspect.collect import database_servers
from keel.inspect.dbreading import field_lines
from keel.inspect.tree import Tree
from keel.mesh.node import Node, NodeError
from keel.system import dbfollow, dbpair, dbtls


def lines(root: str, spec: str) -> list[str]:
    try:
        doc = Node(root, spec).document()
    except (NodeError, ValueError) as e:
        return [f"database status: {e}"]
    tree = Tree(root)
    found: list[str] = []
    pair = dbpair.observe_pair(root, doc)
    server = ((doc.get("database") or {}).get("server")) or {}
    if pair is None:
        found.append("pair: none (this node declares no appliance.vip);"
                     f" declared role {server.get('role') or 'none'}")
    else:
        role = pair.role or f"unclaimed (declared {server.get('role')})"
        found.append(f"pair: VIP {pair.vip}; role here {role}"
                     + ("; fenced" if pair.fenced else "")
                     + ("; released" if pair.released else ""))
        found.append(f"  other member: {pair.peer_address or 'unknown'}"
                     f" ({pair.peer_key or 'no pair record'})")
        if pair.holder_address:
            found.append(f"  the primary's address: {pair.holder_address}")
    installed = next((one for one in database_servers(tree)
                      if one.engine.name == "mariadb"), None)
    if installed is None:
        found.append("server: no MariaDB server installed here")
        return found + vip_lines(root, spec)
    reading = installed.reading()
    found.append(f"server: {reading.role.value or 'unknown'}"
                 f" ({reading.role.source or reading.role.problem})")
    found.append(f"  read_only: {_shown(reading.read_only)}")
    if reading.semi_sync.known:
        values = reading.semi_sync.value
        found.append(f"  semi-synchronous: master {values.get('master')},"
                     f" slave {values.get('slave')},"
                     f" {values.get('clients')} replica(s) acknowledging,"
                     f" {values.get('acknowledged')} commits acknowledged,"
                     f" {values.get('unacknowledged')} not")
    else:
        found.append(f"  semi-synchronous: {reading.semi_sync.problem}")
    status = field_lines(installed.answers.get("status") or
                         installed.answers["status"])
    if status:
        host = status.get("Master_Host") or status.get("Source_Host")
        found.append(f"  replicating from: [{host}]:"
                     f"{status.get('Master_Port')}; IO"
                     f" {status.get('Slave_IO_Running')}, SQL"
                     f" {status.get('Slave_SQL_Running')}; lag"
                     f" {_shown(reading.lag)}; TLS"
                     f" {status.get('Master_SSL_Allowed')};"
                     f" GTID IO position {status.get('Gtid_IO_Pos')}")
        if status.get("Last_Error"):
            found.append(f"  last error: {status['Last_Error']}")
    else:
        found.append("  replicating from: nobody")
    if reading.gtid.known:
        for name, value in reading.gtid.value.items():
            found.append(f"  gtid {name}: {value or '(empty)'}")
    leaf = dbtls.summary(root)
    found.append("  certificate: " + (
        f"{leaf['subject']}, for {', '.join(leaf['addresses'])}, until"
        f" {leaf['expires']}" if leaf.get("present") and "subject" in leaf
        else leaf.get("problem") or "none"))
    diverged = dbfollow.diverged(root)
    if diverged:
        errant = ", ".join(str(one) for one in diverged.get("errant") or [])
        found.append(f"  diverged: holds {errant} which the holder at"
                     f" {diverged.get('holder')} lacks (since"
                     f" {diverged.get('at')}); read only, not connected")
    return found + vip_lines(root, spec)


def vip_lines(root: str, spec: str) -> list[str]:
    from keel.mesh import vippromote
    from keel.mesh.vipcli import here_of
    import argparse
    args = argparse.Namespace(root=root, spec=spec)
    try:
        return vippromote.lines(here_of(args), root == paths.ROOT_DEFAULT)
    except Exception as e:  # noqa: BLE001 - status says what it could not
        return [f"vip: {e}"]


def _shown(value) -> str:
    if value.known:
        return str(value.value).lower()
    return f"unknown ({value.problem})"


def main(args, out: Callable[[str], None] = print) -> int:
    root = os.path.abspath(getattr(args, "root", paths.ROOT_DEFAULT))
    for line in lines(root, args.spec):
        out(line)
    return exits.OK
