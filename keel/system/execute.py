# Copyright (c) 2026 KeelLinux maintainers
"""Carry a plan out through the effects, or only describe it

One line per action on stdout, in plan order. `label` is how the run was
asked for (--system, --system-only), so the summary names it. A failed
action fails its step: the actions after it in that step are skipped (a
home directory is not populated for an account that was not created),
the other steps go on, and the summary counts what happened. An Attempt
that fails is said with what follows from it and fails nothing: it is
what a machine may not be able to do yet, such as registering with a
central API while offline. An action that ran says what it did when
the effects tell (`Effects.ran`): an overlay changed live or bounced,
a certificate kept because it was not due (keel#120). A refusal
fails its step the same way in a dry run, because a dry run that planned
the actions behind a refusal would describe a run that cannot happen.
"""

from dataclasses import dataclass

from keel.system.actions import Attempt, Note, Plan, Refuse
from keel.system.effects import Effects


@dataclass(frozen=True)
class Outcome:
    lines: tuple[str, ...]
    changed: int
    failed: int
    dry_run: bool
    label: str = "apply --system"

    def summary(self) -> str:
        if self.dry_run:
            return (
                f"dry run: {self.changed} change(s) planned, nothing written"
            )
        return f"{self.label}: {self.changed} change(s), {self.failed} failed"


def execute(
    plan: Plan, effects: Effects, dry_run: bool = False,
    label: str = "apply --system",
) -> Outcome:
    lines: list[str] = []
    changed = failed = 0
    for step in plan.steps:
        broken = False
        for action in step.actions:
            prefix = f"{step.field}: "
            if isinstance(action, Note):
                lines.append(prefix + action.describe())
            elif isinstance(action, Refuse):
                lines.append(prefix + "refused: " + action.describe())
                failed += 1
                broken = True
            elif broken:
                lines.append(prefix + "skipped: " + action.describe())
            elif dry_run:
                lines.append(prefix + "would " + action.describe())
                changed += 1
            else:
                problem = effects.apply(action)
                if problem is None:
                    ran = getattr(effects, "ran", None)
                    lines.append(prefix + action.describe() + ": "
                                 + (ran or "done"))
                    changed += 1
                elif isinstance(action, Attempt):
                    lines.append(prefix + action.describe()
                                 + f": not done: {problem};"
                                 f" {action.otherwise}")
                else:
                    lines.append(prefix + action.describe()
                                 + f": failed: {problem}")
                    failed += 1
                    broken = True
    return Outcome(tuple(lines), changed, failed, dry_run, label)
