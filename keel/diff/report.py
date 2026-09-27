# Copyright (c) 2026 KeelLinux maintainers
"""What diff found, field by field, and the exit code that follows

Every field of the declared spec that inspect can observe gets one
FieldDiff: the same on both sides, drifted, or unknown because inspect
could not infer it. Fields the machine has and the spec does not declare
are listed as not declared; sections whose values leave no trace on the
machine, secrets first of all, are listed as not compared. Only drift and
unknown fields decide the exit code.
"""

from dataclasses import dataclass

from keel import exits

SAME = "same"
DRIFT = "drift"
UNKNOWN = "unknown"
NOT_DECLARED = "not declared"
NOT_COMPARED = "not compared"
STATUSES = (SAME, DRIFT, UNKNOWN, NOT_DECLARED, NOT_COMPARED)
NOTHING = "nothing"


def show(value: object) -> str:
    """One value as the report prints it; None is an absent field"""
    if value is None:
        return NOTHING
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(show(item) for item in value) or "(empty)"
    return str(value)


@dataclass(frozen=True)
class FieldDiff:
    """One line of the report; `declared` and `observed` are None when absent"""

    field: str
    status: str
    declared: object = None
    observed: object = None
    reason: str = ""
    # A warning that belongs on a drift line, where acting on the drift the
    # wrong way round would destroy something. diff itself writes nothing.
    note: str = ""

    @property
    def section(self) -> str:
        return self.field.split(".")[0]

    def line(self) -> str:
        return f"{self.field}: {self.status} ({self._detail()})"

    def _detail(self) -> str:
        if self.status == SAME:
            return show(self.declared)
        if self.status == DRIFT:
            warning = f"; {self.note}" if self.note else ""
            return (
                f"declared {show(self.declared)},"
                f" observed {show(self.observed)}{warning}"
            )
        if self.status == UNKNOWN:
            return (
                f"declared {show(self.declared)}; not inferred: {self.reason}"
            )
        if self.status == NOT_DECLARED:
            return f"observed {show(self.observed)}"
        return self.reason

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "section": self.section,
            "status": self.status,
            "declared": self.declared,
            "observed": self.observed,
            "reason": self.reason,
            "note": self.note,
        }


@dataclass(frozen=True)
class Comparison:
    """Every FieldDiff, in spec order, and what they add up to"""

    root: str
    fields: tuple[FieldDiff, ...]

    def count(self, status: str) -> int:
        return sum(1 for field in self.fields if field.status == status)

    @property
    def drift(self) -> bool:
        return self.count(DRIFT) > 0

    @property
    def incomplete(self) -> bool:
        return self.count(UNKNOWN) > 0

    @property
    def code(self) -> int:
        """Drift wins over unknown fields: it is the actionable finding"""
        if self.drift:
            return exits.DRIFT_FOUND
        if self.incomplete:
            return exits.INSPECT_INCOMPLETE
        return exits.OK

    def state(self) -> str:
        if self.drift:
            return "drift found"
        if self.incomplete:
            return "no drift, but declared fields could not be observed"
        return "no drift"

    def summary(self) -> str:
        counts = ", ".join(
            f"{self.count(status)} {status}" for status in STATUSES
        )
        return f"diff: {counts}; {self.state()}"
