# Copyright (c) 2026 KeelLinux maintainers
"""Build the plan for a spec from the observed state; pure"""

from keel.spec.constants import SPEC_DEFAULT
from keel.system.actions import Plan
from keel.system.database import plan_database
from keel.system.hostname import plan_hostname
from keel.system.hosts import plan_hosts
from keel.system.locale import plan_locale
from keel.system.monitor import plan_monitor
from keel.system.network import DEFAULT_WINDOW, plan_network
from keel.system.security import plan_security
from keel.system.state import SystemState
from keel.system.tls import plan_tls
from keel.system.users import plan_users


def plan(
    doc: dict, state: SystemState, confirmed: bool = False,
    defer_certificate: bool = False, network_window: int = DEFAULT_WINDOW,
    skip_network: bool = False, spec_path: str = SPEC_DEFAULT,
) -> Plan:
    """Steps: instance, users, locale, security, tls, database, monitor,
    network

    The database after the cheap fields because it is the only phase
    that restarts a database server and the only one that can lose data,
    so everything cheap and reversible is already done when it is
    reached. `confirmed` is the operator saying, in this invocation, that
    becoming a replica may destroy what this server holds; nothing else
    in keel sets it.

    The network after everything, because it is the one step that can
    cut off the session running apply (decision 0018): whatever else the
    run had to do is done before the interface moves.

    `spec_path` is the spec this run read, which monit's alerts have
    keel notify read again for the channels; on a tree other than the
    live system it is the default path, where that machine keeps its own.
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
    steps += plan_monitor(doc.get("monitor"), state.monitor, state.live,
                          state.available,
                          spec_path if state.live else SPEC_DEFAULT)
    steps += plan_network(doc.get("network") or {}, state.network,
                          state.live, state.available, network_window,
                          skip_network)
    return Plan(tuple(steps))
