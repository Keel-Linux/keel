# Copyright (c) 2026 KeelLinux maintainers
"""Accept a pending network change, only over the new configuration

A confirmation is proof that the machine is reachable on the network it
was just given. Over SSH that means a session that started after the
interface came up on the new file, arriving at a static address the new
file declares for the session's family (or, for a family the file leaves
to DHCP or SLAAC, an address the interface holds now). A console or a
process attached from the container's host has seen the machine and
needs no such proof.

Two limits are said rather than hidden: a session tests one family, so a
static address of the other family is reported as not tested; and a
client on the same link reaches the machine without its gateway, so when
the gateway changed, the route back to the client says whether the
gateway was part of the proof.
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from keel.network import marker, session, switch


@dataclass(frozen=True)
class Probes:
    """What confirm asks the live machine, as functions for the tests"""

    boot_id: Callable[[], str | None]
    addresses: Callable[[str], list[str]]
    route_via: Callable[[str], str | None]


def confirm(root: str, origin: session.Origin, probes: Probes,
            run: switch.Runner) -> tuple[bool, list[str]]:
    """(confirmed, what to tell the operator)"""
    with marker.locked(root):
        if not marker.exists(root):
            return False, ["no network change is waiting for a"
                           " confirmation; one not confirmed in time has"
                           " been reverted, and keel diff shows it"]
        pending = marker.read(root)
        refusal = not_ready(pending, probes.boot_id())
        if refusal:
            return False, [refusal]
        refusal = not_proof(pending, origin, probes)
        if refusal:
            return False, [refusal]
        lines = [f"confirmed from {origin.detail}"]
        lines += untested_lines(pending, origin)
        lines += gateway_lines(pending, origin, probes)
        marker.clear(root)
        switch.disarm(run)
    return True, lines + ["the network change stays; the revert is"
                         " cancelled"]


def not_ready(pending: marker.Pending | None, boot_id: str | None) -> (
    str | None
):
    if pending is None:
        return ("the pending change cannot be read; keel network revert"
                " restores the saved file")
    if pending.changed_at is None:
        # the lock is held, so no change is running: this one was never
        # dated (the uptime could not be read after ifup), and reverts
        return ("the change could not be dated when the interface came up,"
                " so it cannot be confirmed; it reverts when its window"
                " ends, or now with keel network revert")
    if pending.boot_id != boot_id:
        return ("the change was made before the last boot and should"
                " have been reverted by it; keel network revert restores"
                " the saved file")
    return None


def not_proof(pending: marker.Pending, origin: session.Origin,
              probes: Probes) -> str | None:
    if origin.kind in (session.CONSOLE_KIND, session.HOST):
        return None
    if origin.kind != session.SSH:
        return f"refused: {origin.detail}"
    if origin.started is None or origin.started <= pending.changed_at:
        return ("refused: this SSH session was open before the change, so"
                " it does not show the new network works; open a new one"
                " to the new address and confirm from there")
    if origin.local is None:
        return f"refused: {origin.detail}"
    held = tuple(probes.addresses(pending.iface))
    if origin.peer and (ipaddress.ip_address(origin.peer).is_loopback
                        or same_address(origin.peer, held)):
        return ("refused: this session comes from the machine itself (an"
                " ssh from the old session), which says nothing about"
                " reaching it from outside")
    # a family with a declared static address is proven by that address
    # alone: with SLAAC kept beside it, a session over a SLAAC address
    # says nothing of the static one (keel#45). A family the file leaves
    # dynamic is proven by what DHCP or SLAAC gave the interface since.
    declared = same_family(origin.local, pending.addresses)
    if declared:
        if not same_address(origin.local, declared):
            return (f"refused: this session arrived at {origin.local}, not"
                    f" at the static address the change declares"
                    f" ({', '.join(declared)}); connect to that address and"
                    " confirm from there")
        return None
    allowed = tuple(dict.fromkeys(pending.addresses + held))
    if not same_address(origin.local, allowed):
        return (f"refused: this session arrived at {origin.local}, which is"
                f" not an address of the new configuration"
                f" ({', '.join(allowed) or 'none found'})")
    return None


def same_family(one: str, among: tuple[str, ...]) -> tuple[str, ...]:
    """The addresses of `among` of the family of `one`"""
    version = ipaddress.ip_address(one).version
    return tuple(other for other in among
                 if ipaddress.ip_interface(other).version == version)


def untested_lines(pending: marker.Pending, origin: session.Origin) -> (
    list[str]
):
    """The declared static addresses this session could not have tested"""
    if origin.kind != session.SSH or origin.local is None:
        return []
    other = tuple(address for address in pending.addresses
                  if address not in same_family(origin.local,
                                                pending.addresses))
    if not other:
        return []
    return [f"the static address {', '.join(other)} was not tested: this"
            f" session arrived at {origin.local}, over the other family"]


def same_address(one: str, among: tuple[str, ...] | list[str]) -> bool:
    wanted = ipaddress.ip_address(one)
    return any(
        ipaddress.ip_interface(other).ip == wanted for other in among
    )


def gateway_lines(pending: marker.Pending, origin: session.Origin,
                  probes: Probes) -> list[str]:
    changed = set(pending.gateways) != set(pending.old_gateways)
    if not changed or not pending.gateways or origin.kind != session.SSH:
        return []
    via = probes.route_via(origin.peer) if origin.peer else None
    if via is not None and same_address(via, pending.gateways):
        return [f"the route back to {origin.peer} goes through the new"
                f" gateway {via}, so it was tested too"]
    return [f"the new gateway ({', '.join(pending.gateways)}) was not"
            f" tested: the route back to {origin.peer} does not use it"]
