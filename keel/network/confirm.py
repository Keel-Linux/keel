# Copyright (c) 2026 KeelLinux maintainers
"""Accept a pending network change, only over the new configuration

A confirmation is proof that the machine is reachable on the network it
was just given. Over SSH that means a session that started after the
interface came up on the new file, arriving at an address the new file
declares (or, for an address the machine was given by DHCP or SLAAC, one
the interface holds now). A console or a process attached from the
container's host has seen the machine and needs no such proof.

One limit is said rather than hidden: a client on the same link reaches
the machine without its gateway, so when the gateway changed, the route
back to the client says whether the gateway was part of the proof.
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
    # the static addresses the file declares, and what DHCP or SLAAC gave
    # the interface since, for a family the file leaves dynamic
    allowed = tuple(dict.fromkeys(pending.addresses + held))
    if not same_address(origin.local, allowed):
        return (f"refused: this session arrived at {origin.local}, which is"
                f" not an address of the new configuration"
                f" ({', '.join(allowed) or 'none found'})")
    return None


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
