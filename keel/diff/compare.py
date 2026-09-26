# Copyright (c) 2026 KeelLinux maintainers
"""Compare a declared spec with what inspect observed, field by field

Both documents are flattened to dotted leaf paths, the same paths the
inspect report uses, and compared leaf by leaf after normalisation, so a
spelling difference that means the same thing (an upper case keyword, an
address written long hand, a trailing dot on a domain) is not drift.

A value inspect wrote is compared as it stands, even when inspect also
noted something about that field it could not express; that is what
makes inspecting a machine and then diffing the result against it report
no drift. A field inspect could not infer at all is unknown, with
inspect's reason.
"""

import ipaddress
from collections.abc import Iterator

from keel.diff.report import (
    DRIFT,
    NOT_COMPARED,
    NOT_DECLARED,
    SAME,
    UNKNOWN,
    Comparison,
    FieldDiff,
)
from keel.inspect.report import NOT_INFERRED, Finding, Inspection
from keel.spec.constants import TOP_LEVEL_KEYS

OBSERVED_SECTIONS = (
    "instance", "network", "tls", "security", "hub", "users", "locale",
)
NOT_COMPARED_REASONS = {
    "secrets": "values are never read, on either side",
    "app": "inithooks.conf is root only and consumed at first boot, so app"
    " values leave no trace to compare",
    "first_login_wizard": "a first boot switch that leaves no trace on the"
    " running machine",
    "preseed": "raw hook variables that leave no trace on the running"
    " machine",
}
SECRET_REASON = "a secret reference; values are never read"
KEYWORD_FIELDS = ("security.alerts", "security.updates", "hub.api_key")
DOMAIN_LEAVES = ("hostname", "fqdn", "domains")
ADDRESS_LEAVES = ("address",)
HOST_LEAVES = ("gateway", "nameservers")
# Lists whose order carries no meaning: group membership is a set.
UNORDERED_LEAVES = ("groups",)
# Fields inspect derives from another one, so they are unknown together.
DERIVED_FROM = {"network.managed_by": "network.interfaces"}


def compare(declared: dict, inspection: Inspection) -> Comparison:
    """Every observable field of `declared` against `inspection.spec`"""
    unknowns = not_inferred(inspection.findings)
    fields: list[FieldDiff] = []
    for section in TOP_LEVEL_KEYS:
        if section in OBSERVED_SECTIONS:
            fields += compare_section(
                section, declared.get(section), inspection.spec.get(section),
                unknowns,
            )
        elif section in declared and section in NOT_COMPARED_REASONS:
            fields.append(
                FieldDiff(section, NOT_COMPARED,
                          reason=NOT_COMPARED_REASONS[section])
            )
    return Comparison(inspection.root, tuple(fields))


def not_inferred(findings: tuple[Finding, ...]) -> dict[str, str]:
    """The reasons inspect gave for every field it could not infer"""
    reasons: dict[str, list[str]] = {}
    for finding in findings:
        if finding.status == NOT_INFERRED:
            reasons.setdefault(finding.field, []).append(finding.source)
    return {field: "; ".join(found) for field, found in reasons.items()}


def compare_section(
    section: str, declared: object, observed: object, unknowns: dict[str, str]
) -> list[FieldDiff]:
    if section == "hub" and isinstance(
        (declared or {}).get("api_key"), dict
    ):
        return [FieldDiff("hub.api_key", NOT_COMPARED, reason=SECRET_REASON)]
    wanted = dict(flatten(section, declared or {}))
    found = dict(flatten(section, observed or {}))
    fields = [
        compare_field(path, value, found.get(path), unknowns)
        for path, value in wanted.items()
    ]
    fields += [
        FieldDiff(path, NOT_DECLARED, None, value)
        for path, value in found.items()
        if path not in wanted
    ]
    return fields


def compare_field(
    path: str, declared: object, observed: object, unknowns: dict[str, str]
) -> FieldDiff:
    if observed is None:
        reason = unknown_reason(path, unknowns)
        if reason is not None:
            return FieldDiff(path, UNKNOWN, declared, None, reason)
        return FieldDiff(path, DRIFT, declared, None)
    if normalize(path, declared) == normalize(path, observed):
        return FieldDiff(path, SAME, declared, observed)
    return FieldDiff(path, DRIFT, declared, observed)


def unknown_reason(path: str, unknowns: dict[str, str]) -> str | None:
    """The most specific not-inferred finding covering `path`, if any"""
    matching = [
        field for field in unknowns
        if path == field or path.startswith(f"{field}.")
    ]
    if matching:
        return unknowns[max(matching, key=len)]
    source = DERIVED_FROM.get(path)
    if source is None:
        return None
    return unknown_reason(source, unknowns)


def flatten(prefix: str, mapping: dict) -> Iterator[tuple[str, object]]:
    """Dotted leaf paths; mappings recurse, lists and scalars are leaves

    A null value declares nothing (`users.bob:` with no keys) and is left
    out, as an absent key would be.
    """
    for key, value in mapping.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict):
            yield from flatten(path, value)
        elif value is not None:
            yield path, value


def normalize(path: str, value: object) -> object:
    """The comparable form of one value"""
    if isinstance(value, list):
        items = tuple(normalize(path, item) for item in value)
        if path.rsplit(".", 1)[-1] in UNORDERED_LEAVES:
            return tuple(sorted(items, key=str))
        return items
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    leaf = path.rsplit(".", 1)[-1]
    if path in KEYWORD_FIELDS or leaf in DOMAIN_LEAVES:
        return text.lower().rstrip(".")
    if leaf in ADDRESS_LEAVES:
        return _address(text, ipaddress.ip_interface)
    if leaf in HOST_LEAVES:
        return _address(text, ipaddress.ip_address)
    return text


def _address(text: str, parse) -> str:
    try:
        return str(parse(text))
    except ValueError:
        return text
