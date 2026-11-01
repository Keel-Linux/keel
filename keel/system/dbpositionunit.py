# Copyright (c) 2026 KeelLinux maintainers
"""keel database position: keel.system.dbposition's loop, for this node's
spec, as keel-database-position.service runs it"""

import signal
import sys
import threading

from keel import exits
from keel.mesh.node import Node
from keel.system import dbfollow, dbpair, dbposition


def pair_of(root: str, spec: str, here) -> tuple[str, bool] | None:
    """The VIP and whether this node holds it; None when this node has
    nothing to publish: no MariaDB pair, or no etcd"""
    doc = Node(root, spec).document()
    server = (doc.get("database") or {}).get("server") or {}
    pair = dbpair.observe_pair(root, doc)
    if pair is None or server.get("engine", "mariadb") != "mariadb" or \
            not dbposition.with_etcd(here):
        return None
    return pair.vip, pair.role == dbpair.PRIMARY


def main(root: str, spec: str) -> int:
    stop = threading.Event()
    for one in (signal.SIGTERM, signal.SIGINT):
        signal.signal(one, lambda *_: stop.set())
    here = dbfollow._here(root, spec)
    dbposition.serve(here, lambda: pair_of(root, spec, here), stop,
                     lambda line: print(line, file=sys.stderr, flush=True))
    return exits.OK
