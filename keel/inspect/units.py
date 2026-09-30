# Copyright (c) 2026 KeelLinux maintainers
"""What systemd says about the units of an overlay (decision 0041)

One reading for the three commands that need it: inspect writes an
overlay's state from it, diff compares the spec's with it, and apply
plans what to enable, start, stop and disable from it. On the live
system systemctl is asked, `is-enabled` and `is-active`, whose words are
printed whatever the exit code. Under --root nothing runs: a unit is
enabled when a `.wants` link names it, which is what `systemctl enable`
makes, masked when it is linked to /dev/null, and whether it runs is
unknown.
"""

import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from keel.inspect.tree import Tree

UNIT_DIR = "etc/systemd/system"
# systemctl is-enabled: the words keel may undo with `disable`
ENABLED = ("enabled", "enabled-runtime", "linked", "linked-runtime",
           "alias")
# enabled by something else, so neither `enable` nor `disable` moves them
FIXED = ("static", "generated", "indirect", "transient")
MASKED = ("masked", "masked-runtime")
# systemctl is-active: the words of a unit that runs or is starting
RUNNING = ("active", "activating", "reloading", "refreshing")
UNKNOWN = "unknown"


@dataclass(frozen=True)
class UnitState:
    unit: str
    enabled: str
    # None under --root, where nothing is asked
    active: str | None

    @property
    def is_enabled(self) -> bool:
        return self.enabled in ENABLED

    @property
    def is_fixed(self) -> bool:
        return self.enabled in FIXED

    @property
    def is_masked(self) -> bool:
        return self.enabled in MASKED

    @property
    def is_running(self) -> bool:
        return self.active in RUNNING

    def describe(self) -> str:
        if self.active is None:
            return f"{self.unit} {self.enabled}"
        return f"{self.unit} {self.enabled} and {self.active}"


Run = Callable[..., subprocess.CompletedProcess]


def read_units(tree: Tree, units: Iterable[str], live: bool,
               run: Run | None = None) -> dict[str, UnitState]:
    """Each unit's state, asked of systemctl or read off the links"""
    run = run or subprocess.run
    if not live:
        return {unit: UnitState(unit, linked(tree, unit), None)
                for unit in units}
    return {unit: UnitState(unit, ask(run, "is-enabled", unit),
                            ask(run, "is-active", unit, None))
            for unit in units}


def linked(tree: Tree, unit: str) -> str:
    if tree.readlink(f"{UNIT_DIR}/{unit}") == "/dev/null":
        return "masked"
    if tree.glob(f"{UNIT_DIR}/*.wants/{unit}"):
        return "enabled"
    return "disabled"


def ask(run: Run, verb: str, unit: str,
        missing: str | None = UNKNOWN) -> str | None:
    """systemctl's word for UNIT; `missing` when systemctl cannot run"""
    try:
        out = run(["systemctl", verb, unit], capture_output=True,
                  text=True, check=False)
    except OSError:
        return missing
    return out.stdout.strip().splitlines()[0] if out.stdout.strip() \
        else UNKNOWN


def overlay_state(units: list[UnitState]) -> tuple[str | None, str]:
    """`enabled`, `disabled`, or None and what each unit says

    Enabled is every unit enabled, or static as apply leaves it, and,
    where it can be asked, running; disabled is none enabled and none
    running. Anything between is not a
    state of the manifest, and the units are named so the reader sees
    which one is off.
    """
    if all((unit.is_enabled or unit.is_fixed)
           and unit.active in (None, *RUNNING) for unit in units):
        return "enabled", ""
    if all(not unit.is_enabled and not unit.is_running for unit in units):
        return "disabled", ""
    return None, ", ".join(unit.describe() for unit in units)
