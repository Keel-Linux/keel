# Copyright (c) 2026 KeelLinux maintainers
"""Build the plan for a spec from the observed state; pure"""

from keel.system.actions import Plan
from keel.system.locale import plan_locale
from keel.system.state import SystemState
from keel.system.users import plan_users


def plan(doc: dict, state: SystemState) -> Plan:
    """Steps in spec order: users, then locale"""
    steps = plan_users(doc.get("users") or {}, state)
    steps += plan_locale(doc.get("locale") or {}, state)
    return Plan(tuple(steps))
