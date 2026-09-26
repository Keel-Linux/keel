# Copyright (c) 2026 KeelLinux maintainers
"""Carry a plan out through the effects, or only describe it

One line per action on stdout, in plan order. A failed action fails its
step: the actions after it in that step are skipped (a home directory is
not populated for an account that was not created), the other steps go
on, and the summary counts what happened.
"""

from dataclasses import dataclass

from keel.system.actions import Note, Plan
from keel.system.effects import Effects


@dataclass(frozen=True)
class Outcome:
    lines: tuple[str, ...]
    changed: int
    failed: int
    dry_run: bool

    def summary(self) -> str:
        if self.dry_run:
            return (
                f"dry run: {self.changed} change(s) planned, nothing written"
            )
        return f"apply --system: {self.changed} change(s), {self.failed} failed"


def execute(plan: Plan, effects: Effects, dry_run: bool = False) -> Outcome:
    lines: list[str] = []
    changed = failed = 0
    for step in plan.steps:
        broken = False
        for action in step.actions:
            prefix = f"{step.field}: "
            if isinstance(action, Note):
                lines.append(prefix + action.describe())
            elif dry_run:
                lines.append(prefix + "would " + action.describe())
                changed += 1
            elif broken:
                lines.append(prefix + "skipped: " + action.describe())
            else:
                problem = effects.apply(action)
                if problem is None:
                    lines.append(prefix + action.describe() + ": done")
                    changed += 1
                else:
                    lines.append(prefix + action.describe()
                                 + f": failed: {problem}")
                    failed += 1
                    broken = True
    return Outcome(tuple(lines), changed, failed, dry_run)
