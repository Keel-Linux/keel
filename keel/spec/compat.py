# Copyright (c) 2026 KeelLinux maintainers
"""Field names the spec used to have, and what they are called now

A spec file outlives the vocabulary that was current when it was
written, and an appliance that boots from one must keep booting. So a
renamed field keeps working under its old name: `deprecations()` says
what is out of date and why, and `canonical()` returns a new document
under the current names. Neither touches the document it is given; the
caller's mapping is left exactly as it was read.

Every command reads a spec through keel.commands.read_spec, which warns
and then works on the canonical document, and `validate()` canonicalises
its own input, so a library caller that has not been updated gets the
real errors rather than "unknown key".
"""

from typing import Any

# section -> {old field name: current field name}
RENAMED: dict[str, dict[str, str]] = {
    "security": {"updates": "updates_at_first_boot"},
}
# Why the old name went, said in the warning, so the operator can judge
# whether the value they wrote still says what they meant.
REASONS: dict[str, str] = {
    "security.updates": "it reads as the machine's update policy, and it"
    " only ever controlled whether the first boot installs the pending"
    " security updates; the appliance keeps them current either way",
}


def deprecations(doc: Any) -> list[str]:
    """One warning per deprecated field in `doc`, in spec order"""
    messages = []
    for section, body, renames in _sections(doc):
        for old, new in renames.items():
            if old not in body:
                continue
            message = (
                f"{section}.{old} is deprecated, rename it to"
                f" {section}.{new}: {REASONS[f'{section}.{old}']}"
            )
            if new in body:
                message += (
                    f"; {section}.{new} is also set, and that is the value"
                    " being used"
                )
            messages.append(message)
    return messages


def canonical(doc: Any) -> Any:
    """A copy of `doc` with every deprecated field under its current name

    A document that declares both names keeps the current one: the old
    name is dropped, and `deprecations()` says so. Anything that is not
    a mapping is returned as it came, for the validator to reject.
    """
    if not isinstance(doc, dict):
        return doc
    updated = dict(doc)
    for section, body, renames in _sections(doc):
        updated[section] = _rename(body, renames)
    return updated


def _rename(body: dict, renames: dict[str, str]) -> dict:
    fresh: dict = {}
    for key, value in body.items():
        new = renames.get(key) if isinstance(key, str) else None
        if new is None:
            fresh[key] = value
        elif new not in body:
            fresh[new] = value
    return fresh


def _sections(doc: Any) -> list[tuple[str, dict, dict[str, str]]]:
    """Each section of `doc` that is a mapping and may hold an old name"""
    if not isinstance(doc, dict):
        return []
    return [
        (name, doc[name], renames)
        for name, renames in RENAMED.items()
        if isinstance(doc.get(name), dict)
    ]
