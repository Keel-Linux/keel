# Copyright (c) 2026 KeelLinux maintainers
"""Whether keel-vip.service is restarting, as its ExecStopPost asks

`keel vip tend --stopped` drops every VIP this node carries when the
unit stops, except while it restarts: a package upgrade's try-restart
(a restart job of the unit, which systemd keeps until the start that
follows it), or a helper that died, which Restart=always starts again
(systemd gives ExecStopPost the result in $SERVICE_RESULT). Then the
address stays, bounded by its lifetime (keel.mesh.vipnet.lifetime), and
the next controller extends it only once it renewed the same lease.
"""

from collections.abc import Callable, Mapping

CGROUP = "/proc/self/cgroup"
RESTARTS = ("restart", "try-restart", "reload-or-restart")


def own(cgroup: str = CGROUP) -> str | None:
    """The service unit this process runs in, from its cgroup"""
    try:
        with open(cgroup) as fob:
            text = fob.read()
    except OSError:
        return None
    for line in text.splitlines():
        name = line.rpartition("/")[2]
        if name.endswith(".service"):
            return name
    return None


def restarting(env: Mapping[str, str],
               output: Callable[[tuple[str, ...]], str | None],
               cgroup: str = CGROUP) -> bool:
    """Whether the unit will start again: its main process failed, or a
    restart job of it is queued or running"""
    result = env.get("SERVICE_RESULT")
    if result and result != "success":
        return True
    unit = own(cgroup)
    if unit is None:
        return False
    jobs = output(("systemctl", "list-jobs", "--no-legend", "--plain",
                   "--full"))
    for line in (jobs or "").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == unit and fields[2] in RESTARTS:
            return True
    return False
