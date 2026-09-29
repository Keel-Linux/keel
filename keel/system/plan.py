# Copyright (c) 2026 KeelLinux maintainers
"""Build the plan for a spec from the observed state; pure"""

from keel.system.actions import Plan
from keel.system.database import plan_database
from keel.system.hostname import plan_hostname
from keel.system.hosts import plan_hosts
from keel.system.locale import plan_locale
from keel.system.network import DEFAULT_WINDOW, plan_network
from keel.system.security import plan_security
from keel.system.state import SystemState
from keel.system.tls import plan_tls
from keel.system.users import plan_users


def plan(
    doc: dict, state: SystemState, confirmed: bool = False,
    defer_certificate: bool = False, network_window: int = DEFAULT_WINDOW,
    skip_network: bool = False,
) -> Plan:
    """Steps: instance, users, locale, security, tls, database, network

    The database last because it is the only phase that restarts a
    service and the only one that can lose data, so everything cheap and
    reversible is already done when it is reached. `confirmed` is the
    operator saying, in this invocation, that becoming a replica may
    destroy what this server holds; nothing else in keel sets it.

    The network after everything, because it is the one step that can
    cut off the session running apply (decision 0018): whatever else the
    run had to do is done before the interface moves.
    """
    instance = doc.get("instance") or {}
    # the rename first, and the fqdn step on the /etc/hosts it produces
    steps, state = plan_hostname(instance, state)
    steps += plan_hosts(instance, doc.get("network") or {}, state)
    steps += plan_users(doc.get("users") or {}, state)
    steps += plan_locale(doc.get("locale") or {}, state)
    steps += plan_security(doc.get("security") or {}, state)
    steps += plan_tls(doc.get("tls") or {}, state, defer_certificate)
    steps += plan_database(doc, state.database, confirmed)
    steps += plan_network(doc.get("network") or {}, state.network,
                          state.live, state.available, network_window,
                          skip_network)
    return Plan(tuple(steps))
