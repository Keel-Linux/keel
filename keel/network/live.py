# Copyright (c) 2026 KeelLinux maintainers
"""The commands confirm and revert ask the running machine

Kept apart from the decisions (keel.network.confirm, .session) so those
are tested against fixture output, and this stays a thin layer of
subprocess calls.
"""

import subprocess

from keel.network import marker
from keel.network.confirm import Probes

SOCKETS = ("ss", "-Htnp", "state", "established")


def run(argv: tuple[str, ...]) -> str | None:
    """None on success, else what went wrong"""
    try:
        out = subprocess.run(list(argv), capture_output=True, text=True,
                             check=False)
    except OSError as e:
        return f"cannot run {argv[0]}: {e.strerror}"
    if out.returncode != 0:
        detail = out.stderr.strip() or out.stdout.strip()
        return f"{argv[0]} exited {out.returncode}: {detail}"
    return None


def output(argv: tuple[str, ...]) -> str | None:
    """Standard output, or None when the command could not answer"""
    try:
        out = subprocess.run(list(argv), capture_output=True, text=True,
                             check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def sockets() -> str | None:
    return output(SOCKETS)


def addresses(iface: str) -> list[str]:
    """The global addresses the interface holds now, without prefix"""
    text = output(("ip", "-o", "address", "show", "dev", iface,
                   "scope", "global")) or ""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[2] in ("inet", "inet6"):
            found.append(fields[3].split("/")[0])
    return found


def route_via(peer: str) -> str | None:
    """The gateway the route back to `peer` uses, or None when on link"""
    fields = (output(("ip", "route", "get", peer)) or "").split()
    if "via" in fields and fields.index("via") + 1 < len(fields):
        return fields[fields.index("via") + 1]
    return None


def probes() -> Probes:
    return Probes(boot_id=marker.boot_id, addresses=addresses,
                  route_via=route_via)
