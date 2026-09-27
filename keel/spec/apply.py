# Copyright (c) 2026 KeelLinux maintainers
"""Write the rendered conf, and report what apply could not do

Two rules that the firstboot behaviour depends on:

- a conf file that already has content wins and is never clobbered, so a
  hand written or platform supplied preseed keeps priority over the spec;
- warnings (a declared address that is not live, a feature this version
  does not act on) are returned, never raised, so they cannot stop a boot.
"""

import os

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
    """Compare declared addresses with the live ones (host managed only)"""
    network = doc.get("network") or {}
    if managed_by(network) != "host":
        return []

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

    The database section is read and compared and never applied, by any
    run: this phase of decision 0013 is vocabulary, reading and
    comparison. The warning says so with either flag and without one,
    because becoming a replica replaces the local data with a copy of the
    primary and no run of apply may do that behind an operator's back.
    """
    messages = []
    if doc.get("database"):
        messages.append(
            "database: no database configuration is written by this"
            " version; the section is read by keel inspect and compared by"
            " keel diff only"
        )
    acme = (doc.get("tls") or {}).get("acme") or {}
    if acme.get("enabled"):
        messages.append(
            "tls.acme: certificates are not requested by this version;"
            " use confconsole to get one"
        )
    if system:
        return messages
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
    return messages
