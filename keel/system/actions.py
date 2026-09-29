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
class RunSql:
    """Run statements through an engine's own client, on standard input

    A statement can hold a credential, and an argument vector is world
    readable in the process list, so the statements go on standard input
    and `describe` never prints them. That is also why a dry run of the
    database phase shows what will be done and not the SQL that does it.
    """

    argv: tuple[str, ...]
    statements: str
    summary: str

    def describe(self) -> str:
        count = len([one for one in self.statements.split(";") if one.strip()])
        return (
            f"{self.summary} ({shlex.join(self.argv)}, {count} statement(s)"
            " on standard input)"
        )


@dataclass(frozen=True)
class SwitchNetwork:
    """Bring an interface up on a new file, reverting unless confirmed

    Carried out by keel.network.switch (decision 0018): the old file is
    saved and a revert armed before anything is touched, and the change
    stays only if `keel network confirm` arrives over the new
    configuration within `window` seconds. `addresses` are the static
    addresses the new file declares, `gateways` its gateways and
    `old_gateways` those it replaces, which confirm checks against.
    """

    iface: str
    path: str
    content: str
    window: int
    addresses: tuple[str, ...]
    gateways: tuple[str, ...]
    old_gateways: tuple[str, ...]

    def describe(self) -> str:
        return (
            f"bring {self.iface} up on a new /{self.path}; it reverts in"
            f" {self.window} s unless `keel network confirm` is run from a"
            " new session over the new configuration"
        )


@dataclass(frozen=True)
class Note:
    """Nothing to do for this field, and why: unchanged, or not possible"""

    summary: str

    def describe(self) -> str:
        return self.summary


@dataclass(frozen=True)
class Refuse:
    """This field was not converged and the run failed, with the reason

    A Note says there was nothing to do. A Refuse says there was, and that
    apply would not: becoming a replica over a database that holds data,
    demoting a primary, promoting a replica. It counts as a failure, so
    the exit code says the machine does not match the description, and the
    actions after it in the same step are skipped.
    """

    summary: str

    def describe(self) -> str:
        return self.summary


Change = Run | RunSql | WriteFile | MakeDir | Symlink | SwitchNetwork
Action = Change | Note | Refuse


@dataclass(frozen=True)
class Step:
    """One spec field and the actions that converge it, in order"""

    field: str
    actions: tuple[Action, ...]

    @property
    def changes(self) -> int:
        return sum(
            1 for action in self.actions
            if not isinstance(action, Note | Refuse)
        )


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]

    @property
    def changes(self) -> int:
        return sum(step.changes for step in self.steps)


def unchanged(field: str, detail: str) -> Step:
    return Step(field, (Note(f"unchanged ({detail})"),))
