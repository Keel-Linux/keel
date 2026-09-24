# Copyright (c) 2026 KeelLinux maintainers
"""What the running machine says, as opposed to what the spec declares"""

import os
import subprocess

from keel.spec.constants import LXC_MARKER


def default_managed_by() -> str:
    """Containers get their addresses from the host, other builds do not"""
    if os.path.exists(LXC_MARKER):
        return "host"
    try:
        out = subprocess.run(
            ["turnkey-version", "-n"], capture_output=True, text=True
        )
    except OSError:
        return "file"
    if out.stdout.strip() == "lxc":
        return "host"
    return "file"


def managed_by(network: dict) -> str:
    """The declared owner of the interface configuration, or the default"""
    return str(network.get("managed_by") or default_managed_by())


def live_ipv6(iface: str) -> list[str]:
    """Global scope IPv6 addresses currently configured on an interface"""
    try:
        out = subprocess.run(
            ["ip", "-6", "addr", "show", iface, "scope", "global"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return []
    addresses = []
    for line in out.stdout.splitlines():
        fields = line.split()
        if fields and fields[0] == "inet6":
            addresses.append(fields[1].split("/")[0])
    return addresses
