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
    """What confirm asks the live machine, as functions for the tests

    `holder` names the interface that holds an address now, or None when
    no interface of this machine does. `route_dev` names the interface
    the route to an address leaves through, or None when `ip` gave no
    answer. `gateways` are the gateways of the default routes in place
    now, IPv6 first, or None when `ip` gave no answer.
    """

    boot_id: Callable[[], str | None]
    addresses: Callable[[str], list[str]]
    route_via: Callable[[str], str | None]
    holder: Callable[[str], str | None] = lambda address: None
    route_dev: Callable[[str], str | None] = lambda address: None
    gateways: Callable[[], list[str] | None] = lambda: []


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
        overlay = pending.kind == marker.OVERLAY
        refusal = captured(pending, origin, probes) or (
            overlay_not_proof if overlay else not_proof)(
            pending, origin, probes)
        if refusal:
            return False, [refusal]
        lines = [f"confirmed from {origin.detail}"]
        if overlay:
            lines += overlay_lines(pending, origin, probes)
        else:
            lines += untested_lines(pending, origin)
            lines += gateway_lines(pending, origin, probes)
        marker.clear(root)
        switch.disarm(run)
        if overlay:
            lines += enabled_lines(pending.iface, run)
    return True, lines + ["the network change stays; the revert is"
                         " cancelled"]


def not_ready(pending: marker.Pending | None, boot_id: str | None) -> (
    str | None
):
    if pending is None:
        return ("the pending change cannot be read; keel network revert"
                " restores the saved file to the file recorded beside it")
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


def overlay_not_proof(pending: marker.Pending, origin: session.Origin,
                      probes: Probes) -> str | None:
    """A change of the WireGuard overlay (decisions 0018 and 0020)

    What such a change can break is two paths: the overlay itself, and
    the uplink, whose replies the routes wg-quick adds for a peer's
    allowed_ips can capture. A new session over either proves the path it
    used survived the change, so either confirms: one arriving at an
    address the overlay declares, or one arriving at an address another
    interface of this machine holds. Waiting for the overlay alone would
    make pairing impossible, since the first node's overlay carries
    nothing until the second node has declared it too. confirm then says
    which path was tested and which was not.
    """
    if origin.kind in (session.CONSOLE_KIND, session.HOST):
        return None
    if origin.kind != session.SSH:
        return f"refused: {origin.detail}"
    if origin.started is None or origin.started <= pending.changed_at:
        return ("refused: this SSH session was open before the change, so"
                " it does not show that the machine can still be reached;"
                " open a new one, over the overlay or the uplink, and"
                " confirm from there")
    if origin.local is None:
        return f"refused: {origin.detail}"
    if origin.peer and (ipaddress.ip_address(origin.peer).is_loopback
                        or probes.holder(origin.peer) is not None):
        return ("refused: this session comes from the machine itself (an"
                " ssh from the old session), which says nothing about"
                " reaching it from outside")
    if same_address(origin.local, pending.addresses):
        return None
    holder = probes.holder(origin.local)
    if holder is not None and holder != pending.iface:
        return None
    return (f"refused: this session arrived at {origin.local}, which is"
            f" neither an address the overlay declares"
            f" ({', '.join(pending.addresses)}) nor one another interface"
            " of this machine holds")


LEFT_TO_REVERT = (
    "it is left to revert when its window ends, or now with keel network"
    " revert"
)


def captured(pending: marker.Pending, origin: session.Origin,
             probes: Probes) -> str | None:
    """An overlay change that routes the uplink into itself

    Whoever confirms, a console included, would keep a change that cuts
    the uplink off. Validation refuses the routes the spec shows (a /0,
    a public prefix, an overlap with what network.interfaces declares);
    this asks the machine where the routes that matter leave through now:
    to each gateway the spec declared, to each gateway of a default route
    in place (what DHCP, SLAAC or a container's host configured, which
    the spec does not show, and what --skip-uplink left), IPv6 first, and
    back to the client of an SSH session that came over the uplink. One
    through the overlay refuses; so does one `ip` gives no answer for,
    since an unknown route is not a clean one.
    """
    if pending.kind != marker.OVERLAY:
        return None
    live_gateways = probes.gateways()
    if live_gateways is None:
        return ("refused: `ip route show default` gave no answer, so it"
                " cannot be told whether the change routes the uplink into"
                f" the overlay; {LEFT_TO_REVERT}")
    for address, what in route_targets(pending, origin, live_gateways):
        dev = probes.route_dev(address)
        if dev is None:
            return (f"refused: `ip route get {address}` ({what}) gave no"
                    " answer, so it cannot be told whether the change"
                    f" routes the uplink into the overlay; {LEFT_TO_REVERT}")
        if dev == pending.iface:
            return (f"refused: the route to {what} {address} leaves through"
                    f" {pending.iface}, so the change routes the uplink's"
                    f" traffic into the overlay; {LEFT_TO_REVERT}. Narrow"
                    " the peers' allowed_ips, then apply again")
    return None


def route_targets(pending: marker.Pending, origin: session.Origin,
                  live_gateways: list[str]) -> list[tuple[str, str]]:
    """(address, what it is) to ask the route of, gateways IPv6 first

    A session that came over the overlay is answered through it, as it
    should be, so only one that came over the uplink has its client
    asked. A zone (`fe80::1%eth0`, which the spec accepts) is dropped:
    `ip route get` refuses it, and the probe would then fail closed.
    """
    gateways = sorted(dict.fromkeys(
        one.split("%", 1)[0]
        for one in (*pending.uplink_gateways, *live_gateways)),
                      key=lambda one: ipaddress.ip_address(one).version,
                      reverse=True)
    found = [(gateway, "the uplink gateway") for gateway in gateways]
    if origin.kind == session.SSH and origin.peer and origin.local and \
            not same_address(origin.local, pending.addresses):
        found.append((origin.peer, "this session's client"))
    return found


def overlay_lines(pending: marker.Pending, origin: session.Origin,
                  probes: Probes) -> list[str]:
    """Which of the two paths this confirmation tested"""
    if origin.kind != session.SSH or origin.local is None:
        return []
    if same_address(origin.local, pending.addresses):
        return [f"the overlay was tested: this session arrived at"
                f" {origin.local} on {pending.iface}, from"
                f" {origin.peer or 'a peer'}"]
    return [f"the overlay itself was not tested: this session arrived at"
            f" {origin.local} on {probes.holder(origin.local)}, which shows"
            f" the change did not cut that path off; a session from a peer"
            f" to {', '.join(pending.addresses)} tests the overlay"]


def enabled_lines(iface: str, run: switch.Runner) -> list[str]:
    """A confirmed overlay comes back at boot; an unconfirmed one never

    wg-quick@ is enabled here and not by apply, so a reboot inside the
    window of a first overlay leaves no interface behind.
    """
    unit = f"wg-quick@{iface}"
    problem = run(("systemctl", "enable", unit))
    if problem:
        return [f"{unit} could not be enabled ({problem}): the overlay is"
                f" up but does not come back after a reboot until"
                f" `systemctl enable {unit}` or the next apply --system"]
    return [f"{unit} enabled: the overlay comes back up at boot"]


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
