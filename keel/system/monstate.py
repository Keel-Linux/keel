# Copyright (c) 2026 KeelLinux maintainers
"""What the monitor plan looks at, read once from the root

monit's file and the notify settings as keel last wrote them, monit's
cycle as monit reads it, the mounts a check per filesystem is written
for, and whether the secret files the channels name are usable where
notify will read them. The mounts are the root's own /proc/self/
mountinfo: on the live system that is the machine's, and under --root it
is whatever the tree holds, usually nothing, in which case the plan
watches / and says why.
"""

from dataclasses import dataclass

from keel.inspect import constants as paths
from keel.inspect.monitor import Cycle, monit_cycle
from keel.inspect.tree import File, Tree
from keel.monitor import channelfile
from keel.spec.secretstore import secret_file_error


@dataclass(frozen=True)
class MonitorState:
    current: File
    mountinfo: File
    cycle: Cycle
    settings: File
    secret_problems: tuple[str, ...] = ()


def observe_monitor(root: str, doc: dict) -> MonitorState | None:
    """None when the spec has no monitor and keel wrote nothing for one"""
    tree = Tree(root)
    current = tree.read(paths.MONIT_CONF)
    settings = tree.read(paths.MONITOR_SETTINGS)
    if doc.get("monitor") is None and not current.readable \
            and not settings.readable:
        return None
    problems = []
    if (doc.get("monitor") or {}).get("enabled"):
        wanted = channelfile.build(doc)
        for path in channelfile.secret_paths(wanted):
            problem = secret_file_error(tree.path(path.lstrip("/")))
            if problem:
                problems.append(problem)
    return MonitorState(current, tree.read(paths.MOUNTINFO),
                        monit_cycle(tree), settings, tuple(problems))
