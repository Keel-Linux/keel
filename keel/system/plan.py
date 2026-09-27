# Copyright (c) 2026 KeelLinux maintainers
"""Build the plan for a spec from the observed state; pure"""

from keel.system.actions import Plan
from keel.system.database import plan_database
from keel.system.hosts import plan_hosts
from keel.system.locale import plan_locale
from keel.system.state import SystemState
from keel.system.users import plan_users


def plan(doc: dict, state: SystemState, confirmed: bool = False) -> Plan:
    """Steps in spec order: instance, users, locale, then the database

    The database last because it is the only phase that restarts a
    service and the only one that can lose data, so everything cheap and
    reversible is already done when it is reached. `confirmed` is the
    operator saying, in this invocation, that becoming a replica may
    destroy what this server holds; nothing else in keel sets it.
    """
    steps = plan_hosts(
        doc.get("instance") or {}, doc.get("network") or {}, state
    )
    steps += plan_users(doc.get("users") or {}, state)
    steps += plan_locale(doc.get("locale") or {}, state)
    steps += plan_database(doc, state.database, confirmed)
    return Plan(tuple(steps))
