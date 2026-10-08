# Copyright (c) 2026 KeelLinux maintainers
"""Build the plan for a spec from the observed state; pure"""

from keel.system.actions import Plan, Step, SwitchNetwork
from keel.system.appliance import plan_appliance
from keel.system.database import plan_database
from keel.system.firewall import plan_firewall
from keel.system.hostname import plan_hostname
from keel.system.hosts import plan_hosts
from keel.system.locale import plan_locale
from keel.system.monitor import plan_monitor
from keel.system.network import DEFAULT_WINDOW, plan_network
from keel.system.overlay import plan_overlay
from keel.system.security import plan_security
from keel.system.state import SystemState
from keel.system.tls import plan_tls
from keel.system.users import plan_users


def plan(
    doc: dict, state: SystemState, confirmed: bool = False,
    defer_certificate: bool = False, network_window: int = DEFAULT_WINDOW,
    skip_network: bool = False, skip_uplink: bool = False,
    spec: str | None = None,
) -> Plan:
    """Steps: instance, users, locale, security, tls, database, monitor,
    the appliance's overlays and Monit file (decision 0041), its firewall
    where the spec enables it, network

    The database after the cheap fields because it is the only phase
    that restarts a database server and the only one that can lose data,
    so everything cheap and reversible is already done when it is
    reached. `confirmed` is the operator saying, in this invocation, that
    becoming a replica may destroy what this server holds; nothing else
    in keel sets it.

    The network after everything, because it is the one step that can
    cut off the session running apply (decision 0018): whatever else the
    run had to do is done before the interface moves. The overlay last
    (decision 0020): one change waits in the window at a time, so an
    overlay change is refused in a run whose uplink moves.
    `skip_uplink` leaves the uplink alone and converges the overlay, for
    a caller that changes only the overlay (the console's screen), so
    what it applies never moves the interface its operator came in on.
    """
    instance = doc.get("instance") or {}
    # the rename first, and the fqdn step on the /etc/hosts it produces
    steps, state = plan_hostname(instance, state)
    steps += plan_hosts(instance, doc.get("network") or {}, state)
    steps += plan_users(doc.get("users") or {}, state)
    steps += plan_locale(doc.get("locale") or {}, state)
    steps += plan_security(doc.get("security") or {}, state)
    steps += plan_tls(doc.get("tls") or {}, state, defer_certificate)
    steps += plan_database(doc, state.database, confirmed, spec)
    steps += plan_monitor(doc.get("monitor"), doc, state.monitor,
                          state.live, state.available)
    steps += plan_appliance(doc, state.appliance, state.live,
                            state.available)
    appliance = state.appliance
    steps += plan_firewall(
        doc, appliance.resolved if appliance else None,
        appliance.firewall if appliance else None, state.live,
        state.available)
    uplink = plan_network(doc.get("network") or {}, state.network,
                          state.live, state.available, network_window,
                          skip_network or skip_uplink,
                          "--skip-network" if skip_network
                          else "--skip-uplink")
    steps += uplink
    steps += plan_overlay(state.overlay, state.live, state.available,
                          network_window, skip_network, moves(uplink))
    return Plan(tuple(steps))


def moves(steps: list[Step]) -> bool:
    """Whether a step of these changes an interface under the window"""
    return any(isinstance(action, SwitchNetwork)
               for step in steps for action in step.actions)
