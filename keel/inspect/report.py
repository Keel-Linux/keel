# Copyright (c) 2026 KeelLinux maintainers
"""What inspect found, field by field, and the spec it built from that

Every field of the produced spec has a Finding saying where its value
came from (a file or a command) or why it could not be inferred. Secret
fields have a third status: their value is never read, so the finding
records the placeholder and what the operator has to provide.
"""

from dataclasses import dataclass

from keel.inspect.constants import REQUIRED
from keel.layers.channel import State

INFERRED = "inferred"
NOT_INFERRED = "not inferred"
NOT_EXTRACTED = "not extracted"


@dataclass(frozen=True)
class Finding:
    """One line of the report"""

    field: str
    status: str
    value: str = ""
    source: str = ""

    def line(self) -> str:
        if self.status == INFERRED:
            return f"{self.field}: {self.value} (from {self.source})"
        if self.status == NOT_EXTRACTED:
            return (
                f"{self.field}: {self.value} ({NOT_EXTRACTED}: {self.source})"
            )
        return f"{self.field}: {NOT_INFERRED}: {self.source}"


def inferred(field: str, value: object, source: str) -> Finding:
    return Finding(field, INFERRED, str(value), source)


def missing(field: str, reason: str) -> Finding:
    return Finding(field, NOT_INFERRED, "", reason)


def placeholder(field: str, value: str, reason: str) -> Finding:
    return Finding(field, NOT_EXTRACTED, value, reason)


@dataclass(frozen=True)
class Inspection:
    """The spec document inspect built and the findings behind it

    `channel` is the record of the channel and release revision this
    machine was last pulled to, when there is one. It sits beside the
    spec rather than in it, because it is not something an operator
    declares: it is where the machine was taken.
    """

    root: str
    appliance: str
    spec: dict
    findings: tuple[Finding, ...]
    channel: State | None = None

    @property
    def missing_required(self) -> tuple[str, ...]:
        return tuple(
            finding.field
            for finding in self.findings
            if finding.status == NOT_INFERRED and finding.field in REQUIRED
        )

    @property
    def complete(self) -> bool:
        return not self.missing_required

    def count(self, status: str) -> int:
        return sum(1 for finding in self.findings if finding.status == status)

    def summary(self) -> str:
        state = "complete" if self.complete else "incomplete"
        return (
            f"inspect: {self.count(INFERRED)} inferred,"
            f" {self.count(NOT_INFERRED)} not inferred"
            f" ({len(self.missing_required)} required),"
            f" {self.count(NOT_EXTRACTED)} secrets to provide; spec {state}"
        )
