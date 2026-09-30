# Copyright (c) 2026 KeelLinux maintainers
"""Validation of one manifest file (docs/manifest-v1.md, "Validation rules")

validate() returns every error it finds, never only the first. It checks
what one file can say on its own, and what the machine under the root
holds for it: its unit files, its first boot hooks, the overlays its
`requires` names. What depends on the chain of an appliance is
keel.manifest.resolve's.
"""

import re
from typing import Any

from keel.manifest import machine
from keel.manifest.constants import (
    APPLIANCE,
    BACKUP,
    CONSTRAINT_RE,
    CORE,
    DUMP_ENGINES,
    ENGINES,
    GENERATE,
    HOOK_DIR,
    HOOK_KEYS,
    KIND_KEYS,
    KINDS,
    MANIFEST_VERSION,
    MAX_NAME,
    MODES,
    NAME_RE,
    NAME_TEXT,
    NO_BASE,
    OPTION_TYPES,
    OVERLAY,
    REPLICATION,
    SHARED_GENERATE,
    STATES,
    VAR_RE,
    VAR_TEXT,
    COMMON_KEYS,
)
from keel.manifest.fields import (
    bool_error,
    choice_error,
    constraint_error,
    keys_errors,
    list_error,
    mapping_error,
    missing,
    named_items,
    path_error,
    quote,
    text_error,
)
from keel.manifest.load import ManifestError
from keel.manifest.validate_app import validate_app
from keel.manifest.validate_process import validate_checks, validate_processes

SECRET_KEYS = ("name", "description", "generate", "shared")
OPTION_KEYS = ("name", "type", "default", "pattern", "values")
DATA_KEYS = ("path", "replication", "backup")
FILES = "files"


def validate(doc: dict, stem: str | None, catalog) -> list[str]:
    """Every error of one manifest; STEM is its file name without .yaml

    `catalog` is the keel.manifest.Catalog of the root the file is
    checked against: its unit files, hooks and installed overlays.
    """
    errors = _top_errors(doc, stem)
    kind = doc.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        return errors
    errors.extend(_kind_keys(doc, kind))
    found, processes = validate_processes(doc.get("processes"), catalog.root)
    errors.extend(found)
    errors.extend(validate_checks(doc.get("checks"), processes,
                                  strict=kind == OVERLAY))
    found, secrets = _secrets_errors(doc.get("secrets"))
    errors.extend(found)
    errors.extend(_hooks_errors(doc.get("hooks"), kind, catalog.root))
    if kind == OVERLAY:
        return errors + _overlay_errors(doc, catalog)
    errors.extend(_appliance_errors(doc))
    errors.extend(_options_errors(doc.get("options")))
    errors.extend(validate_app(doc, secrets, catalog.root))
    return errors


def _top_errors(doc: dict, stem: str | None) -> list[str]:
    """Rule 1"""
    errors = missing("", doc, COMMON_KEYS)
    if "manifest_version" in doc:
        version = doc["manifest_version"]
        whole = isinstance(version, int) and not isinstance(version, bool)
        if whole and version > MANIFEST_VERSION:
            errors.append(f"manifest_version: {version} is newer than this"
                          f" keel reads ({MANIFEST_VERSION})")
        elif not whole or version != MANIFEST_VERSION:
            errors.append(f"manifest_version: must be the integer"
                          f" {MANIFEST_VERSION}")
    if "kind" in doc:
        error = choice_error("kind", doc["kind"], KINDS)
        errors.extend([error] if error else [])
    if "name" in doc:
        name = doc["name"]
        if (not isinstance(name, str) or not NAME_RE.match(name)
                or len(name) > MAX_NAME):
            errors.append(f"name: {quote(name)} must match {NAME_TEXT} and"
                          f" be at most {MAX_NAME} characters")
        elif stem is not None and name != stem:
            errors.append(f'name: "{name}" must be the file name without'
                          f" .yaml, {stem}")
    for field in ("title", "summary"):
        if field in doc:
            error = text_error(field, doc[field])
            errors.extend([error] if error else [])
    summary = doc.get("summary")
    if isinstance(summary, str) and "\n" in summary.strip():
        errors.append("summary: must be one line")
    return errors


def _kind_keys(doc: dict, kind: str) -> list[str]:
    """Rule 2: unknown keys, and keys of the other kind"""
    other = APPLIANCE if kind == OVERLAY else OVERLAY
    allowed = COMMON_KEYS + KIND_KEYS[kind]
    errors = []
    for key in doc:
        if isinstance(key, str) and key in KIND_KEYS[other] \
                and key not in allowed:
            errors.append(f"{key}: a key of an {other} manifest, not of an"
                          f" {kind}")
        else:
            errors.extend(keys_errors("", {key: None}, allowed))
    return errors


def _secrets_errors(value: Any) -> tuple[list[str], set]:
    """Secrets are names with a policy (rules 3 and 20)"""
    errors, items = named_items("secrets", value, VAR_RE, VAR_TEXT)
    for index, item in items:
        key = f"secrets[{index}]"
        errors.extend(keys_errors(key, item, SECRET_KEYS))
        errors.extend(missing(key, item, ("description", "generate")))
        if "description" in item:
            error = text_error(f"{key}.description", item["description"])
            errors.extend([error] if error else [])
        generate = item.get("generate")
        if "generate" in item:
            error = choice_error(f"{key}.generate", generate, GENERATE)
            errors.extend([error] if error else [])
        if "shared" in item:
            error = bool_error(f"{key}.shared", item["shared"])
            errors.extend([error] if error else [])
        if (item.get("shared") is True and isinstance(generate, str)
                and generate not in SHARED_GENERATE):
            errors.append(f"{key}.shared: a shared secret is generated"
                          " (generate: required or allowed): a person"
                          " cannot be relied on to type the same value"
                          " twice")
    names = {item["name"] for _, item in items
             if isinstance(item.get("name"), str)}
    return errors, names


def _hooks_errors(value: Any, kind: str, root: str) -> list[str]:
    """Rule 12, and hooks.migrate for an appliance only"""
    if value is None:
        return []
    error = mapping_error("hooks", value)
    if error:
        return [error]
    errors = []
    for key in value:
        if key in HOOK_KEYS[APPLIANCE] and key not in HOOK_KEYS[kind]:
            errors.append(f"hooks.{key}: a key of an appliance manifest,"
                          " not of an overlay")
        else:
            errors.extend(keys_errors("hooks", {key: None}, HOOK_KEYS[kind]))
    hooks = value.get("first_boot")
    if hooks is None:
        return errors
    error = list_error("hooks.first_boot", hooks)
    if error:
        return errors + [error]
    for index, path in enumerate(hooks):
        key = f"hooks.first_boot[{index}]"
        error = path_error(key, path)
        if error:
            errors.append(error)
        elif not path.startswith(HOOK_DIR):
            errors.append(f"{key}: must be under {HOOK_DIR}")
        else:
            errors.extend(f"{key}: {problem}"
                          for problem in machine.hook_problems(root, path))
    return errors


def _overlay_errors(doc: dict, catalog) -> list[str]:
    """Rules 10 and 11, and the screen of rule 14"""
    errors = _requires_errors(doc, catalog)
    if "provides" in doc:
        errors.extend(_provides_errors(doc["provides"]))
    provides = doc.get("provides")
    engine = provides.get("engine") if isinstance(provides, dict) else None
    errors.extend(_data_errors(doc.get("data"), engine))
    if "screen" in doc:
        error = path_error("screen", doc["screen"])
        errors.extend([error] if error else [])
    return errors


def _requires_errors(doc: dict, catalog) -> list[str]:
    requires = doc.get("requires")
    if requires is None:
        return []
    error = list_error("requires", requires)
    if error:
        return [error]
    errors, names = [], []
    for index, name in enumerate(requires):
        if not isinstance(name, str) or not NAME_RE.match(name):
            errors.append(f"requires[{index}]: {quote(name)} is not an"
                          " overlay name")
        elif name != doc.get("name") and not catalog.exists(OVERLAY, name):
            errors.append(f"requires: {name} is not an installed overlay")
        else:
            names.append(name)
    cycle = _cycle(str(doc.get("name")), names, catalog)
    if cycle:
        errors.append(f"requires: cycle {', '.join(cycle)}")
    return errors


def _cycle(name: str, requires: list[str], catalog) -> list[str] | None:
    """The first cycle of `requires` reachable from NAME, if any"""
    def requires_of(node: str) -> list[str]:
        if node == name:
            return requires
        try:
            found = catalog.read(OVERLAY, node).get("requires")
        except ManifestError:
            return []
        if not isinstance(found, list):
            return []
        return [item for item in found
                if isinstance(item, str) and NAME_RE.match(item)]

    done: set = set()

    def walk(node: str, path: list[str]) -> list[str] | None:
        for required in requires_of(node):
            if required in path:
                return path[path.index(required):] + [required]
            if required not in done:
                found = walk(required, path + [required])
                if found:
                    return found
        done.add(node)
        return None

    return walk(name, [name])


def _provides_errors(value: Any) -> list[str]:
    error = mapping_error("provides", value)
    if error:
        return [error]
    errors = keys_errors("provides", value, ("engine",))
    errors.extend(missing("provides", value, ("engine",)))
    if "engine" in value:
        error = choice_error("provides.engine", value["engine"], ENGINES)
        errors.extend([error] if error else [])
    return errors


def _data_errors(value: Any, engine: Any) -> list[str]:
    if value is None:
        return []
    error = list_error("data", value)
    if error:
        return [error]
    errors = []
    for index, item in enumerate(value):
        key = f"data[{index}]"
        error = mapping_error(key, item)
        if error:
            errors.append(error)
            continue
        errors.extend(keys_errors(key, item, DATA_KEYS))
        errors.extend(missing(key, item, DATA_KEYS))
        if "path" in item:
            error = path_error(f"{key}.path", item["path"])
            errors.extend([error] if error else [])
        if item.get("replication") == FILES:
            errors.append(f"{key}.replication: must be native or none;"
                          " never files: data with its own replication is"
                          " never replicated by file (0032)")
        elif "replication" in item:
            error = choice_error(f"{key}.replication", item["replication"],
                                 REPLICATION)
            errors.extend([error] if error else [])
        if "backup" in item:
            errors.extend(_backup_errors(f"{key}.backup", item["backup"],
                                         engine))
    return errors


def _backup_errors(key: str, backup: Any, engine: Any) -> list[str]:
    error = choice_error(key, backup, BACKUP)
    if error:
        return [error]
    if backup == "dump" and engine not in DUMP_ENGINES:
        return [f"{key}: dump needs a provides engine that has a dump"
                f" ({' or '.join(DUMP_ENGINES)})"]
    return []


def _appliance_errors(doc: dict) -> list[str]:
    """Rule 13 within the file, and rule 14's states"""
    errors = []
    name, base = doc.get("name"), doc.get("base")
    if "base" not in doc:
        errors.append("base: required")
    elif not isinstance(base, str):
        errors.append("base: must be the name of an appliance, or none")
    elif name == CORE and base != NO_BASE:
        errors.append("base: core is built on Debian: its base is none")
    elif base == NO_BASE and name != CORE:
        errors.append("base: none is for core only")
    elif base != NO_BASE and not NAME_RE.match(base):
        errors.append(f"base: {quote(base)} is not an appliance name")
    overlays = doc.get("overlays")
    if overlays is None:
        return errors
    error = mapping_error("overlays", overlays)
    if error:
        return errors + [error]
    for overlay, states in overlays.items():
        if not isinstance(overlay, str) or not NAME_RE.match(overlay):
            errors.append(f"overlays: {quote(overlay)} is not an overlay"
                          " name")
            continue
        errors.extend(_states_errors(f"overlays.{overlay}", states))
    return errors


def _states_errors(key: str, states: Any) -> list[str]:
    error = mapping_error(key, states)
    if error:
        return [error]
    errors = keys_errors(key, states, MODES + ("version",))
    for mode in MODES:
        if mode not in states:
            errors.append(f"{key}.{mode}: required: every overlay has a"
                          " state in all three modes")
            continue
        error = choice_error(f"{key}.{mode}", states[mode], STATES)
        errors.extend([error] if error else [])
    if "version" in states:
        error = constraint_error(f"{key}.version", states["version"],
                                 CONSTRAINT_RE)
        errors.extend([error] if error else [])
    return errors


def _options_errors(value: Any) -> list[str]:
    errors, items = named_items("options", value, VAR_RE, VAR_TEXT)
    for index, item in items:
        key = f"options[{index}]"
        errors.extend(keys_errors(key, item, OPTION_KEYS))
        errors.extend(missing(key, item, ("type",)))
        if "type" not in item:
            continue
        error = choice_error(f"{key}.type", item["type"], OPTION_TYPES)
        if error:
            errors.append(error)
            continue
        errors.extend(_option_errors(key, item, item["type"]))
    return errors


def _option_errors(key: str, item: dict, kind: str) -> list[str]:
    errors = []
    values = item.get("values")
    if kind != "enum" and "values" in item:
        errors.append(f"{key}.values: only for an enum")
    elif kind == "enum" and "values" not in item:
        errors.append(f"{key}.values: required for an enum")
    elif kind == "enum" and not (isinstance(values, list) and values and all(
            isinstance(word, str) for word in values)):
        errors.append(f"{key}.values: must be a non-empty list of strings")
        values = None
    pattern = None
    if "pattern" in item and kind != "string":
        errors.append(f"{key}.pattern: only for a string")
    elif "pattern" in item:
        try:
            pattern = re.compile(str(item["pattern"]))
        except re.error as e:
            errors.append(f"{key}.pattern: not a regular expression: {e}")
    if "default" in item:
        error = _default_error(f"{key}.default", item["default"], kind,
                               values, pattern)
        errors.extend([error] if error else [])
    return errors


def _default_error(key: str, value: Any, kind: str, values: Any,
                   pattern: re.Pattern | None) -> str | None:
    """A default of the declared type (and of the pattern, for a string)"""
    if kind == "boolean":
        return bool_error(key, value)
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{key}: must be an integer"
        return None
    if kind == "enum":
        if isinstance(values, list) and value not in values:
            return f"{key}: {quote(value)} is not one of {', '.join(values)}"
        return None
    if not isinstance(value, str):
        return f"{key}: must be a string"
    if pattern is not None and not pattern.fullmatch(value):
        return f"{key}: {quote(value)} does not match {pattern.pattern}"
    return None
