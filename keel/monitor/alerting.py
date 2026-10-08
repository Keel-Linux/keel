# Copyright (c) 2026 KeelLinux maintainers
"""One alert through the monitor's channels, from keel itself

What Monit's alerts do (decision 0021, keel notify), for the events keel
sees without Monit: a certificate renewal that failed (keel.mesh.etcdcare),
semi-synchronous replication fallen back to asynchronous, a diverged old
primary (keel.system.dbwatch, 0031, 0049). Every channel the monitor's
settings declare gets it; with none, the reason is said and nothing
else happens.
"""

import os
from collections.abc import Callable

from keel.monitor import channelfile
from keel.monitor import notify as notifier
from keel.spec.errors import SpecError


def alert(root: str, err: Callable[[str], None], title: str, text: str,
          check: str, level: str = "critical") -> bool:
    """Whether at least one channel took it"""
    where = os.path.join(root, channelfile.PATH.lstrip("/"))
    try:
        settings = channelfile.load(where)
    except SpecError as e:
        err(f"{check}: {title}; no alert sent ({e})")
        return False
    host = str(settings.get("host") or notifier.hostname())
    taken = False
    for one in notifier.send(settings, notifier.Message(
            f"[{host}] {title}", text, {"check": check}), level):
        err(f"{check}: alert {one.line()}")
        taken = taken or one.problem is None
    return taken
