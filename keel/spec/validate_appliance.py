# Copyright (c) 2026 KeelLinux maintainers
"""The spec's appliance, installation and overlays (decision 0041)

Two layers, as for secrets. The structure of the three sections is
checked on its own (validate_appliance): the names have the manifest's
shape, the mode is one of 0028's three, and a state is `enabled` or
`disabled`. Holding the spec against the installed manifests, rules 25
to 27 of docs/manifest-v1.md, needs facts the manifests declare
(against_manifests); keel.manifest.facts gathers them under a root, so
this module reads no file and imports nothing of keel.manifest.
"""

import re
from dataclasses import dataclass, field
from typing import Any

from keel.spec.constants import INSTALLATION_MODES, OVERLAY_STATES, SECRET_VARS
from keel.spec.fields import mapping_error

# the manifest's name rule (docs/manifest-v1.md, "Top level"), matched
# whole: `$` would let a trailing newline through
NAME_RE = re.compile(r"[a-z][a-z0-9-]*\Z")
MAX_NAME = 32
NAME_RULE = "[a-z][a-z0-9-]*, at most 32 characters"
ASK = "ask"
SECTION_KEYS = {"appliance": ("name",), "installation": ("mode",)}


@dataclass(frozen=True)
class ManifestFacts:
    """What the resolved chain of the spec's appliance declares

    `overlays` maps each overlay of the chain, in chain order, to what it
    requires; `secrets` maps a secret's name to its generate policy and
    who declared it; `options` pairs each option with who declared it.
    `problems` says why the manifests cannot be used, which is rule 25's
    first error. `resolved` is the keel.manifest Resolved the facts came
    from, for the planners that need more than the rules do.
    """

    appliance: str
    chain: tuple[str, ...] = ()
    overlays: dict = field(default_factory=dict)
    secrets: dict = field(default_factory=dict)
    options: tuple = ()
    problems: tuple[str, ...] = ()
    resolved: Any = None


def is_name(value: Any) -> bool:
    return (isinstance(value, str) and len(value) <= MAX_NAME
            and bool(NAME_RE.fullmatch(value)))


def validate_appliance(doc: dict) -> list[str]:
    """The structure of appliance, installation and overlays"""
    errors = []
    for key, fields in SECTION_KEYS.items():
        errors += _section(key, doc.get(key), fields)
    overlays = doc.get("overlays")
    error = mapping_error("overlays", overlays)
    if error:
        return errors + [error]
    if overlays and not isinstance(doc.get("appliance"), dict):
        errors.append("overlays: needs appliance.name, the appliance whose"
                      " overlays these are")
    for name, state in (overlays or {}).items():
        errors += _state(name, state)
    return errors


def _section(key: str, value: Any, fields: tuple[str, ...]) -> list[str]:
    error = mapping_error(key, value)
    if error or value is None:
        return [error] if error else []
    errors = [f"{key}.{name}: unknown key" for name in value
              if name not in fields]
    for name in fields:
        if name not in value:
            errors.append(f"{key}.{name}: required")
    if "name" in value and not is_name(value["name"]):
        errors.append(f"{key}.name: must match {NAME_RULE}"
                      f" ({value['name']})")
    if "mode" in value and value["mode"] not in INSTALLATION_MODES:
        errors.append(f"{key}.mode: must be simple, cloud_simple or"
                      " cloud_advanced")
    return errors


def _state(name: Any, state: Any) -> list[str]:
    key = f"overlays.{name}"
    if not is_name(name):
        return [f"{key}: not an overlay name ({NAME_RULE})"]
    if isinstance(state, bool):
        return [f"{key}: YAML reads on, off, yes and no as true or false;"
                " write enabled or disabled"]
    if state == ASK:
        return [f"{key}: ask is the manifest's: the spec records the"
                " answer, enabled or disabled"]
    if state not in OVERLAY_STATES:
        return [f"{key}: must be enabled or disabled"]
    return []


def against_manifests(doc: dict, facts: ManifestFacts | None) -> list[str]:
    """Rules 25 to 27; nothing when the spec names no appliance

    A value of the wrong shape is the structure check's error, reported
    there once, so these rules pass over it.
    """
    if facts is None or not isinstance(doc.get("appliance"), dict):
        return []
    if facts.problems:
        return [f"appliance.name: {problem}" for problem in facts.problems]
    return (_overlays(doc.get("overlays"), facts)
            + _generate(doc.get("secrets"), facts)
            + _options(doc.get("app"), facts))


def _overlays(declared: Any, facts: ManifestFacts) -> list[str]:
    """Rule 25: exactly the overlays of the chain, requires enabled"""
    declared = declared if isinstance(declared, dict) else {}
    errors = []
    for name in facts.overlays:
        if name not in declared:
            errors.append(
                f"overlays.{name}: not declared; every overlay of the chain"
                f" of {facts.appliance} is written out, enabled or disabled"
                " (decisions 0027, 0041)")
    chain = ", ".join(facts.chain)
    for name, state in declared.items():
        if name not in facts.overlays:
            errors.append(f"overlays.{name}: not an overlay of the chain of"
                          f" {facts.appliance} ({chain})")
            continue
        if state != "enabled":
            continue
        for required in facts.overlays[name]:
            if declared.get(required) != "enabled":
                errors.append(
                    f"overlays.{name}: enabled, but {name} requires"
                    f" {required}, which is {declared.get(required)}")
    return errors


def allowed_secret(name: str, facts: ManifestFacts | None) -> bool:
    """Rule 26: the three names of the spec, or one a manifest declares"""
    return name in SECRET_VARS or (facts is not None
                                   and name in facts.secrets)


def unknown_secret(key: str, facts: ManifestFacts | None) -> str:
    if facts is None:
        return f"{key}: unknown secret"
    return (f"{key}: unknown secret: neither {', '.join(SECRET_VARS)} nor"
            f" a name the manifests of {facts.appliance} declare")


def _generate(secrets: Any, facts: ManifestFacts) -> list[str]:
    """Rule 26: `generate: true` is refused where a manifest says never"""
    errors = []
    for name, reference in (secrets if isinstance(secrets, dict)
                            else {}).items():
        policy, origin = facts.secrets.get(name, (None, None))
        if (policy == "never" and isinstance(reference, dict)
                and reference.get("generate")):
            errors.append(
                f"secrets.{name}: generate, but the manifest of {origin}"
                " says a person chooses it (generate: never); give a file")
    return errors


def _options(app: Any, facts: ManifestFacts) -> list[str]:
    """Rule 27: declared options, of their type; required ones present"""
    options = (app or {}).get("options") if isinstance(app, dict) else None
    if options is not None and not isinstance(options, dict):
        return []
    options = options or {}
    declared = {item["name"]: (item, origin)
                for item, origin in facts.options}
    errors = []
    for item, origin in facts.options:
        if "default" not in item and item["name"] not in options:
            errors.append(f"app.options.{item['name']}: required by"
                          f" {origin}, which gives no default")
    for name, value in options.items():
        if name not in declared:
            errors.append(f"app.options.{name}: not an option the"
                          f" manifests of {facts.appliance} declare")
            continue
        problem = option_problem(declared[name][0], value)
        if problem:
            errors.append(f"app.options.{name}: {problem}")
    return errors


def option_problem(option: dict, value: Any) -> str | None:
    """Why VALUE is not of the option's declared type, or None"""
    kind = option["type"]
    if kind == "boolean":
        return None if isinstance(value, bool) else "must be true or false"
    if kind == "integer":
        return (None if isinstance(value, int) and not isinstance(value, bool)
                else "must be an integer")
    if kind == "enum":
        values = option["values"]
        return (None if value in values
                else f"must be one of {', '.join(map(str, values))}")
    if not isinstance(value, str):
        return "must be a string"
    pattern = option.get("pattern")
    if pattern and not re.fullmatch(pattern, value):
        return f"does not match {pattern}"
    return None
