# Copyright (c) 2026 KeelLinux maintainers
"""The commands confirm and revert ask the running machine

Kept apart from the decisions (keel.network.confirm, .session) so those
are tested against fixture output, and this stays a thin layer of
subprocess calls.
"""

import ipaddress
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


def holder(address: str) -> str | None:
    """The interface that holds `address` now, or None"""
    return holder_in(output(("ip", "-o", "address", "show")) or "", address)


def holder_in(text: str, address: str) -> str | None:
    """`ip -o address show` output: which interface holds `address`"""
    wanted = ipaddress.ip_address(address)
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[2] in ("inet", "inet6"):
            try:
                found = ipaddress.ip_interface(fields[3]).ip
            except ValueError:
                continue
            if found == wanted:
                return fields[1].split("@")[0]
    return None


def route_via(peer: str) -> str | None:
    """The gateway the route back to `peer` uses, or None when on link"""
    fields = (output(("ip", "route", "get", peer)) or "").split()
    if "via" in fields and fields.index("via") + 1 < len(fields):
        return fields[fields.index("via") + 1]
    return None


def default_gateways() -> list[str] | None:
    """The gateways of the default routes now, IPv6 first; None when
    `ip` gave no answer for a family"""
    found: list[str] = []
    for family in ("-6", "-4"):
        text = output(("ip", family, "route", "show", "default"))
        if text is None:
            return None
        found += gateways_in(text)
    return found


def gateways_in(text: str) -> list[str]:
    """`ip route show default` output: the address after each `via`"""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if "via" in fields and fields.index("via") + 1 < len(fields):
            found.append(fields[fields.index("via") + 1])
    return found


def route_dev(address: str) -> str | None:
    """The interface the route to `address` leaves through, or None
    when `ip` gave no answer (no route, or it could not run)"""
    return route_dev_in(output(("ip", "route", "get", address)) or "")


def route_dev_in(text: str) -> str | None:
    """`ip route get` output: the word after `dev`"""
    fields = text.split()
    if "dev" in fields and fields.index("dev") + 1 < len(fields):
        return fields[fields.index("dev") + 1]
    return None


def link_up(iface: str) -> bool:
    """Whether `iface` exists and is up; False when `ip` cannot say"""
    return link_up_in(output(("ip", "link", "show", "dev", iface)) or "")


def link_up_in(text: str) -> bool:
    """`ip link show` output: UP among the flags between < and >"""
    start, end = text.find("<"), text.find(">")
    if start < 0 or end < start:
        return False
    return "UP" in text[start + 1:end].split(",")


def probes() -> Probes:
    return Probes(boot_id=marker.boot_id, addresses=addresses,
                  route_via=route_via, holder=holder, route_dev=route_dev,
                  gateways=default_gateways)
