# Copyright (c) 2026 KeelLinux maintainers
"""What the monitor plan looks at, read once from the root

monit's file as keel last wrote it, and the mounts a check per
filesystem is written for. The mounts are the root's own
/proc/self/mountinfo: on the live system that is the machine's, and
under --root it is whatever the tree holds, usually nothing, in which
case the plan watches / and says why.
"""

from dataclasses import dataclass

from keel.inspect import constants as paths
from keel.inspect.tree import File, Tree


@dataclass(frozen=True)
class MonitorState:
    current: File
    mountinfo: File


def observe_monitor(root: str, doc: dict) -> MonitorState | None:
    """None when the spec has no monitor and keel.conf is not there"""
    tree = Tree(root)
    current = tree.read(paths.MONIT_CONF)
    if doc.get("monitor") is None and not current.readable:
        return None
    return MonitorState(current, tree.read(paths.MOUNTINFO))
