# Copyright (c) 2026 KeelLinux maintainers
"""Processes and checks (docs/manifest-v1.md, "Processes and checks")

Rules 3, 5, 6, 7, 8 and 9 of the format, within one file. Whether a
check of an appliance names a process of its chain, and whether a port
is free across the chain, is keel.manifest.resolve's to say.
"""

from typing import Any

from keel.manifest import machine
from keel.manifest.constants import (
    CHECK_ADDRESSES,
    CHECK_TYPES,
    EXPOSE,
    ITEM_RE,
    ITEM_TEXT,
    LOOPBACK,
    LOOPBACK_LITERALS,
    MONIT_PROTOCOLS,
    NEVER,
    ON_FAILURE,
    PROTOCOLS,
    RESTART,
    UNIT_SUFFIX,
)
from keel.manifest.fields import (
    argv_errors,
    bool_error,
    choice_error,
    count_error,
    keys_errors,
    list_error,
    missing,
    named_items,
    quote,
    status_error,
    url_path_error,
)
from keel.spec.fields import literal_address_error, port_error

PROCESS_KEYS = ("name", "unit", "listen", "restart")
LISTEN_KEYS = ("port", "protocol", "expose", "address")
RESTART_KEYS = ("attempts", "within_cycles")
CHECK_KEYS = ("name", "process", "type", "on_failure", "every_cycles")
TYPE_FIELDS = {
    "http": ("address", "port", "path", "expect", "tls"),
    "tcp": ("address", "port"),
    "protocol": ("address", "port", "protocol"),
    "command": ("command",),
}
TYPE_REQUIRED = {
    "http": ("address", "port", "path", "expect"),
    "tcp": ("address", "port"),
    "protocol": ("address", "port", "protocol"),
    "command": ("command",),
}
ARTICLE = {"http": "an", "tcp": "a", "protocol": "a", "command": "a"}
ALL_TYPE_FIELDS = ("address", "port", "path", "expect", "tls", "protocol",
                   "command")


def unit_errors(key: str, unit: Any, root: str) -> list[str]:
    """A unit ends in .service and, under the root, has a file (rule 5)"""
    if not isinstance(unit, str) or not unit.endswith(UNIT_SUFFIX):
        return [f"{key}: {quote(unit)} must end in {UNIT_SUFFIX}"]
    problem = machine.unit_problem(root, unit)
    return [f"{key}: {problem}"] if problem else []


def validate_processes(value: Any, root: str) -> tuple[list[str], set]:
    """Errors, and the names of the processes declared"""
    errors, items = named_items("processes", value, ITEM_RE, ITEM_TEXT)
    ports: dict = {}
    for index, item in items:
        key = f"processes[{index}]"
        errors.extend(keys_errors(key, item, PROCESS_KEYS))
        errors.extend(missing(key, item, ("unit",)))
        if "unit" in item:
            errors.extend(unit_errors(f"{key}.unit", item["unit"], root))
        errors.extend(_listen_errors(key, item.get("listen"), ports))
        if "restart" in item:
            errors.extend(_restart_errors(f"{key}.restart", item["restart"]))
    names = {item["name"] for _, item in items
             if isinstance(item.get("name"), str)}
    return errors, names


def _listen_errors(prefix: str, listen: Any, ports: dict) -> list[str]:
    if listen is None:
        return []
    key = f"{prefix}.listen"
    error = list_error(key, listen)
    if error:
        return [error]
    errors = []
    for index, entry in enumerate(listen):
        item_key = f"{key}[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{item_key}: must be a mapping")
            continue
        errors.extend(keys_errors(item_key, entry, LISTEN_KEYS))
        errors.extend(missing(item_key, entry, ("port", "protocol",
                                                "expose")))
        errors.extend(_listen_fields(item_key, entry))
        pair = (entry.get("port"), entry.get("protocol"))
        if all(isinstance(part, (int, str)) for part in pair):
            if pair in ports:
                errors.append(f"{item_key}: {pair[0]}/{pair[1]} is already"
                              f" declared by {ports[pair]}")
            ports.setdefault(pair, item_key)
    return errors


def _listen_fields(key: str, entry: dict) -> list[str]:
    """Rule 6: the port, the protocol, the class and a literal address"""
    errors = []
    if "port" in entry:
        errors.append(port_error(f"{key}.port", entry["port"]))
    if "protocol" in entry:
        errors.append(choice_error(f"{key}.protocol", entry["protocol"],
                                   PROTOCOLS))
    if "expose" in entry:
        errors.append(choice_error(f"{key}.expose", entry["expose"], EXPOSE))
    if "address" in entry:
        errors.append(_address_error(f"{key}.address", entry["address"],
                                     entry.get("expose")))
    return [error for error in errors if error]


def _address_error(key: str, address: Any, expose: Any) -> str | None:
    """A literal loopback address, never a name, only with loopback"""
    error = literal_address_error(key, address)
    if error:
        return error
    if address not in LOOPBACK_LITERALS:
        return f"{key}: must be {' or '.join(LOOPBACK_LITERALS)}"
    if expose != LOOPBACK:
        return (f"{key}: a literal loopback address goes with expose:"
                " loopback only")
    return None


def _restart_errors(key: str, value: Any) -> list[str]:
    """Rule 8: never, or at most N restarts within M cycles"""
    if value == NEVER:
        return []
    if not isinstance(value, dict):
        return [f"{key}: must be never or {{attempts: N, within_cycles:"
                " M}"]
    errors = keys_errors(key, value, RESTART_KEYS)
    errors.extend(missing(key, value, RESTART_KEYS))
    counts = []
    for field in RESTART_KEYS:
        if field in value:
            error = count_error(f"{key}.{field}", value[field])
            if error:
                errors.append(error)
            else:
                counts.append(value[field])
    if len(counts) == 2 and counts[0] > counts[1]:
        errors.append(f"{key}: attempts ({counts[0]}) must be at most"
                      f" within_cycles ({counts[1]})")
    return errors


def validate_checks(
    value: Any, processes: set, strict: bool
) -> list[str]:
    """Rule 7 and rule 9, within one file

    `strict` is for an overlay, whose checks name its own processes; an
    appliance's may name any process of its chain, which the resolution
    checks.
    """
    errors, items = named_items("checks", value, ITEM_RE, ITEM_TEXT)
    for index, item in items:
        key = f"checks[{index}]"
        errors.extend(keys_errors(key, item, CHECK_KEYS + ALL_TYPE_FIELDS))
        errors.extend(missing(key, item, ("type", "on_failure")))
        errors.extend(_check_process(key, item, processes, strict))
        if "type" in item:
            errors.extend(_type_errors(key, item))
        if "every_cycles" in item:
            error = count_error(f"{key}.every_cycles", item["every_cycles"])
            errors.extend([error] if error else [])
    return errors


def _check_process(key: str, item: dict, processes: set,
                   strict: bool) -> list[str]:
    errors = []
    if "on_failure" in item:
        error = choice_error(f"{key}.on_failure", item["on_failure"],
                             ON_FAILURE)
        if error:
            errors.append(error)
        elif item["on_failure"] == RESTART and "process" not in item:
            errors.append(f"{key}.on_failure: restart needs process")
    if "process" not in item:
        return errors
    process = item["process"]
    if not isinstance(process, str):
        errors.append(f"{key}.process: must be the name of a process")
    elif strict and process not in processes:
        errors.append(f"{key}.process: {process} is not a process of this"
                      " overlay")
    return errors


def _type_errors(key: str, item: dict) -> list[str]:
    """The fields of the check's type are present, and no others"""
    kind = item["type"]
    error = choice_error(f"{key}.type", kind, CHECK_TYPES)
    if error:
        return [error]
    errors = [f"{key}.{field}: not a field of {ARTICLE[kind]} {kind} check"
              for field in ALL_TYPE_FIELDS
              if field in item and field not in TYPE_FIELDS[kind]]
    errors.extend(f"{key}.{field}: required for {ARTICLE[kind]} {kind} check"
                  for field in TYPE_REQUIRED[kind] if field not in item)
    errors.extend(_field_errors(key, item, kind))
    return errors


def _field_errors(key: str, item: dict, kind: str) -> list[str]:
    checks = {
        "address": _check_address_error,
        "port": port_error,
        "path": url_path_error,
        "expect": status_error,
        "tls": bool_error,
        "protocol": lambda k, v: choice_error(k, v, MONIT_PROTOCOLS),
    }
    errors = []
    for field in TYPE_FIELDS[kind]:
        if field not in item:
            continue
        if field == "command":
            errors.extend(argv_errors(f"{key}.command", item["command"]))
            continue
        error = checks[field](f"{key}.{field}", item[field])
        if error:
            errors.append(error)
    return errors


def _check_address_error(key: str, value: Any) -> str | None:
    """A class the renderer resolves; never a literal (rule 6)"""
    if isinstance(value, str) and value in CHECK_ADDRESSES:
        return None
    return (f"{key}: must be {' or '.join(CHECK_ADDRESSES)}, never a"
            f" literal address; not {quote(value)}")
