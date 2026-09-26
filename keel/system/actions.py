# Copyright (c) 2026 KeelLinux maintainers
"""What apply --system may do, as data

A plan is a tuple of steps; a step is one spec field and the actions that
converge it, in order. Actions are values, so the planners stay pure and
unit testable against fixture trees, and keel.system.effects is the only
code that runs a command or writes a file.
"""

import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class Run:
    """Run a command; `argv` is a list, never a shell string"""

    argv: tuple[str, ...]
    summary: str

    def describe(self) -> str:
        return f"{self.summary} ({shlex.join(self.argv)})"


@dataclass(frozen=True)
class WriteFile:
    """Write `content` to `path` (relative to the root) with mode and owner"""

    path: str
    content: str
    mode: int
    owner: str | None
    summary: str

    def describe(self) -> str:
        owner = f", owner {self.owner}" if self.owner else ""
        return f"{self.summary} (mode {self.mode:04o}{owner})"


@dataclass(frozen=True)
class MakeDir:
    path: str
    mode: int
    owner: str | None
    summary: str

    def describe(self) -> str:
        owner = f", owner {self.owner}" if self.owner else ""
        return f"{self.summary} (mode {self.mode:04o}{owner})"


@dataclass(frozen=True)
class Symlink:
    path: str
    target: str
    summary: str

    def describe(self) -> str:
        return f"{self.summary} (-> {self.target})"


@dataclass(frozen=True)
class Note:
    """Nothing to do for this field, and why: unchanged, or not possible"""

    summary: str

    def describe(self) -> str:
        return self.summary


Change = Run | WriteFile | MakeDir | Symlink
Action = Change | Note


@dataclass(frozen=True)
class Step:
    """One spec field and the actions that converge it, in order"""

    field: str
    actions: tuple[Action, ...]

    @property
    def changes(self) -> int:
        return sum(1 for action in self.actions if not isinstance(action, Note))


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]

    @property
    def changes(self) -> int:
        return sum(step.changes for step in self.steps)


def unchanged(field: str, detail: str) -> Step:
    return Step(field, (Note(f"unchanged ({detail})"),))
