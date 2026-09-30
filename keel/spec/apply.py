# Copyright (c) 2026 KeelLinux maintainers
"""Write the rendered conf, and report what apply could not do

Two rules that the firstboot behaviour depends on:

- a conf file that already has content wins and is never clobbered, so a
  hand written or platform supplied preseed keeps priority over the spec;
- warnings (a declared address that is not live, a feature this version
  does not act on) are returned, never raised, so they cannot stop a boot.
"""

import os

from keel.spec.render import unwritten_nameservers
from keel.spec.runtime import live_ipv6, managed_by


def conf_is_populated(path: str) -> bool:
    """True when the conf exists and holds something other than whitespace"""
    try:
        with open(path) as fob:
            return bool(fob.read().strip())
    except OSError:
        return False


def write_conf(text: str, path: str) -> None:
    """Write the rendered conf, readable by root only"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fob:
        fob.write(text)
    os.chmod(path, 0o600)


def check_network(doc: dict) -> list[str]:
    """What the network section will not get, as warnings

    Host managed: the declared addresses that are not live. File managed:
    the declared nameservers the interfaces file 01ipconfig writes from
    the conf cannot hold, which the day two plan names too (keel#45).
    """
    network = doc.get("network") or {}
    if managed_by(network) == "file":
        lost = unwritten_nameservers(network)
        return [
            f"network.nameservers: {', '.join(lost)} cannot be written to"
            " /etc/network/interfaces: ifupdown writes nameservers only in"
            " a static stanza, two per stanza"
        ] if lost else []
    if managed_by(network) != "host":
        return []  # a value validation refuses; nothing to compare

    messages = []
    for name, iface in (network.get("interfaces") or {}).items():
        declared = ((iface or {}).get("ipv6") or {}).get("address")
        if not declared:
            continue
        wanted = str(declared).split("/")[0]
        live = live_ipv6(str(name))
        if wanted not in live:
            found = ", ".join(live) or "none"
            messages.append(
                f"network.interfaces.{name}: declared address {declared}"
                f" is not configured on the interface (found: {found})"
            )
    return messages


def unsupported(doc: dict, system: bool = False) -> list[str]:
    """Return the declared features this run does not act on

    instance.fqdn, users and locale are converged by the system phase
    (keel.system), which is asked for with --system or --system-only;
    without either they are accepted and left alone, and the warning says
    so.

    database.server is converged by the system phase, for MariaDB, and
    database.client is not converged at all: it names where an
    application reaches a database, which is the application's own
    configuration and not this machine's server (decision 0013, phase 1).
    """
    messages = []
    database = doc.get("database") or {}
    if database.get("server") and not system:
        messages.append(
            "database.server: the role of this node is converged by the"
            " system phase (--system, --system-only) only, not in this run"
        )
    if database.get("client"):
        messages.append(
            "database.client: where this machine reaches a database is"
            " read by keel inspect and compared by keel diff; no"
            " application is reconfigured by this version"
        )
    if system:
        return messages
    acme = (doc.get("tls") or {}).get("acme") or {}
    if acme.get("enabled"):
        messages.append(
            "tls.acme: the certificate is requested by the system phase"
            " (--system, --system-only) only, not in this run"
        )
    if (doc.get("instance") or {}).get("fqdn"):
        messages.append(
            "instance.fqdn: the /etc/hosts entry is written by the system"
            " phase (--system, --system-only) only, not in this run"
        )
    if doc.get("users"):
        messages.append(
            "users: accounts and authorized keys are written by the system"
            " phase (--system, --system-only) only, not in this run"
        )
    if doc.get("locale"):
        messages.append(
            "locale: the timezone and language are applied by the system"
            " phase (--system, --system-only) only, not in this run"
        )
    if (doc.get("monitor") or {}).get("enabled"):
        messages.append(
            "monitor: monit's configuration is written by the system phase"
            " (--system, --system-only) only, not in this run"
        )
    return messages
