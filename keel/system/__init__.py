# Copyright (c) 2026 KeelLinux maintainers
"""Converge the system state a spec declares: apply --system

Brief section 4, principle 1: apply converges and is safe to re-run.
The state is read once (keel.system.state), the plan is a pure function
of the spec and that state (keel.system.plan), and keel.system.effects is
the only module that runs a command or writes a file, so every decision
is unit tested against fixture trees and the side effects stay thin.
"""

import os

from keel.inspect import ROOT_DEFAULT
from keel.system.actions import Note, Plan, Step
from keel.system.effects import Effects
from keel.system.execute import Outcome, execute
from keel.system.plan import plan
from keel.system.state import SystemState, observe


def needs_root(root: str) -> str | None:
    """Why --system cannot run on the live system now, or None when it can

    A scratch tree under --root needs no privilege check: useradd --root
    and the file writes fail on their own terms if the user lacks them.
    """
    euid = os.geteuid()
    if os.path.abspath(root) != ROOT_DEFAULT or euid == 0:
        return None
    return (
        f"apply --system on the live system must run as root: creating"
        f" accounts and writing under /etc is not possible as uid {euid};"
        f" use --dry-run to see the plan, or --root DIR for a scratch tree"
    )


__all__ = [
    "Effects",
    "Note",
    "Outcome",
    "Plan",
    "Step",
    "SystemState",
    "execute",
    "needs_root",
    "observe",
    "plan",
]
