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
from keel.spec.origins import canonical as canonical_origin

OBSERVED_SECTIONS = (
    "instance", "network", "tls", "security", "hub", "users", "locale",
    "database", "monitor",
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
# Where a secret reference can stand outside the `secrets` section. Each is
# a mapping naming a backend, so the flattened paths below it are the
# reference and not fields of the machine.
SECRET_PREFIXES = (
    "database.server.replication.secret",
    "database.client.primary.secret",
)
# A feature the spec turns off with one field. Its other fields stay in
# the file, ready for the day the switch is turned on, and are not
# compared meanwhile: nothing on the machine is supposed to match them.
DISABLED_FEATURES = {"tls.acme": "enabled", "monitor": "enabled"}
# Fields diff does not compare and never repeats: the channels of the
# monitor (decision 0021), whose URLs can be credentials. apply writes
# them to /etc/keel/monitor.json, root only, for keel notify.
READ_FROM_SPEC = {
    "monitor.notify":
        "the channels are not compared: a webhook or topic URL can be a"
        " credential, and apply writes them for keel notify to"
        " /etc/keel/monitor.json, root only",
}
# Thresholds, compared as numbers, so 2 and 2.0 are one value
NUMERIC_PREFIXES = ("monitor.checks.",)
KEYWORD_FIELDS = (
    "security.alerts", "security.updates_at_first_boot", "hub.api_key",
)
# A field the first boot consumes and the machine keeps no record of.
FIRST_BOOT_FIELDS = {
    "security.updates_at_first_boot":
        "a first boot input: 95secupdates installs the pending security"
        " updates once, and the appliance's update schedule, which is what"
        " the machine shows, is the same whichever value was used",
}
# Consent the spec gives apply, which the machine keeps no record of.
CONSENT_FIELDS = {
    "tls.acme.agree_tos":
        "consent for apply to register a Let's Encrypt account; the machine"
        " keeps no record of it, only of the account",
}
DOMAIN_LEAVES = ("hostname", "fqdn", "domains")
ADDRESS_LEAVES = ("address",)
HOST_LEAVES = ("gateway", "nameservers", "host", "listen")
# An origin an authorization names: an address, a prefix, a host pattern
# or a name. The prefix and the pattern that authorize the same range are
# one value in two spellings (keel.spec.origins). A name is never resolved
# here, so a description that names a host and a server that holds an
# address are drift and not a match, which is the whole reason for reading
# the origins off the server (docs/spec.md).
ORIGIN_LEAVES = ("allowed_from",)
# Lists whose order carries no meaning: group membership is a set, and so
# are the addresses a server answers on and the origins it authorizes.
UNORDERED_LEAVES = ("groups", "listen", "allowed_from")
# Fields inspect derives from another one, so they are unknown together.
DERIVED_FROM = {"network.managed_by": "network.interfaces"}
# A field that describes nothing unless the declared role is one of these.
# The same rule as DISABLED_FEATURES, keyed on a value instead of a switch:
# an operator prepares a primary's authorizations on a standalone before
# promoting it, the way a certificate configuration is prepared behind
# tls.acme.enabled, and comparing them meanwhile reports drift on a correct
# description.
ROLE_ONLY = {
    "database.server.replication.primary": ("replica",),
    "database.server.replication.allowed_from": ("primary",),
}
ROLE_FIELD = "database.server.role"
ROLE_REASON = (
    "the declared role is {role}, so this field describes nothing; it is"
    " compared when the role is {roles}"
)
# Drift that must never be turned into an action. diff writes nothing
# anywhere, so this is a note on the line and a rule in docs/diff.md: the
# operator reading the report is the one who could do the damage.
NEVER_CORRECTED = {
    (ROLE_FIELD, "replica", "primary"): (
        "never correct this automatically: the machine is a primary and"
        " demoting one destroys the data written to it since the replica"
        " last agreed. Demotion is an operator action"
    ),
    (ROLE_FIELD, "primary", "replica"): (
        "never correct this automatically: promoting a replica splits the"
        " pair into two writable servers unless the old primary is known to"
        " be gone. Promotion is an operator action"
    ),
}


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
    if section == "monitor" and isinstance(declared, dict) \
            and "enabled" not in declared:
        # apply turns off a declared section that does not say enabled:
        # true (keel#46), so diff reads it the same way; a section that is
        # not declared at all (None, a bare `monitor:` too) stays not
        # declared, as apply leaves it
        declared = {**declared, "enabled": False}
    wanted = dict(flatten(section, declared or {}))
    found = dict(flatten(section, observed or {}))
    skipped = not_compared(section, wanted)
    fields = [
        FieldDiff(path, NOT_COMPARED,
                  None if withheld(path) else value, found.get(path),
                  skipped[path])
        if path in skipped
        else compare_field(path, value, found.get(path), unknowns)
        for path, value in wanted.items()
    ]
    fields += [
        FieldDiff(path, NOT_DECLARED, None, value)
        for path, value in found.items()
        if path not in wanted
    ]
    return fields


def not_compared(section: str, wanted: dict[str, object]) -> dict[str, str]:
    """Every declared path of this section that diff deliberately skips"""
    skipped = {
        path: reason
        for path, reason in (FIRST_BOOT_FIELDS | CONSENT_FIELDS).items()
        if path in wanted
    }
    skipped.update({
        path: reason for field, reason in READ_FROM_SPEC.items()
        for path in wanted if _under(path, field)
    })
    skipped.update(disabled(section, wanted))
    skipped.update(other_role(wanted))
    skipped.update(secret_references(wanted))
    return skipped


def withheld(path: str) -> bool:
    """A declared value diff never repeats, even in its JSON: a webhook
    or ntfy topic URL is a credential of its own"""
    return any(_under(path, field) for field in READ_FROM_SPEC)


def other_role(wanted: dict[str, object]) -> dict[str, str]:
    """The declared paths that the declared role has nothing to say about

    A standalone or a replica may carry a primary's authorization list, and
    a primary may carry the endpoint it would replicate from after a
    demotion; both are a promotion or a demotion prepared in advance, and
    the machine is not supposed to carry either meanwhile. The role itself
    is always compared.
    """
    role = wanted.get(ROLE_FIELD)
    if role is None:
        return {}
    skipped = {}
    for field, roles in ROLE_ONLY.items():
        if str(role) in roles:
            continue
        reason = ROLE_REASON.format(role=role, roles=" or ".join(roles))
        skipped.update({
            path: reason for path in wanted if _under(path, field)
        })
    return skipped


def _under(path: str, field: str) -> bool:
    """Whether a flattened leaf path is that field or a leaf of it"""
    return path == field or path.startswith(f"{field}.")


def secret_references(wanted: dict[str, object]) -> dict[str, str]:
    """Every declared path that is part of a secret reference

    A credential is a reference and its value is never read, on either
    side, so the path that names the file is not a field to compare. The
    same rule as the `secrets` section and `hub.api_key`, written as a
    table because the database section has one on each side.
    """
    return {
        path: SECRET_REASON for path in wanted
        if any(_under(path, prefix) for prefix in SECRET_PREFIXES)
    }


def disabled(section: str, wanted: dict[str, object]) -> dict[str, str]:
    """The declared paths of a feature the spec turned off, and why

    The switch itself is always compared: turning a feature on behind the
    spec's back is drift. What the switch governs is not, because the
    machine is not supposed to carry it, and refusing the settings in the
    schema instead would leave an operator nowhere to prepare them.
    """
    off: dict[str, str] = {}
    for feature, switch in DISABLED_FEATURES.items():
        if feature != section and not feature.startswith(f"{section}."):
            continue
        key = f"{feature}.{switch}"
        if wanted.get(key):
            continue
        state = "false" if key in wanted else "not declared"
        reason = (
            f"{feature} is off in the spec ({switch} is {state}), so what it"
            f" governs is not compared; it takes effect when {switch}"
            " becomes true"
        )
        off.update({
            path: reason for path in wanted
            if path.startswith(f"{feature}.") and path != key
        })
    return off


def compare_field(
    path: str, declared: object, observed: object, unknowns: dict[str, str]
) -> FieldDiff:
    if observed is None:
        reason = unknown_reason(path, unknowns)
        if reason is not None:
            return FieldDiff(path, UNKNOWN, declared, None, reason)
        return FieldDiff(path, DRIFT, declared, None, note=note(
            path, declared, None
        ))
    if normalize(path, declared) == normalize(path, observed):
        return FieldDiff(path, SAME, declared, observed)
    return FieldDiff(path, DRIFT, declared, observed, note=note(
        path, declared, observed
    ))


def note(path: str, declared: object, observed: object) -> str:
    """The warning that belongs on this drift, when there is one

    Every drift is the operator's to act on, and one of them can destroy
    data if it is acted on the wrong way round, so the line says which.
    """
    return NEVER_CORRECTED.get(
        (path, str(declared), str(observed)), ""
    )


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
    if leaf in ORIGIN_LEAVES:
        return canonical_origin(text)
    if leaf in ADDRESS_LEAVES:
        return _address(text, ipaddress.ip_interface)
    if leaf in HOST_LEAVES:
        return _address(text, ipaddress.ip_address)
    if path.startswith(NUMERIC_PREFIXES):
        return _number(text)
    return text


def _address(text: str, parse) -> str:
    try:
        return str(parse(text))
    except ValueError:
        return text


def _number(text: str) -> str:
    try:
        return repr(float(text))
    except ValueError:
        return text


