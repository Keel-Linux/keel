# Copyright (c) 2026 KeelLinux maintainers
"""The application sections, within one file (rules 21 to 24)

docs/manifest-v1.md, "Appendix: the application sections". Whether an
embedded service has an enabled overlay that provides its engine, and
whether a replicated path is inside the data of an overlay, depend on
the chain and are keel.manifest.resolve's to say.
"""

from typing import Any

from keel.manifest.constants import (
    CONSTRAINT_RE,
    ENGINES,
    ITEM_RE,
    ITEM_TEXT,
    MODES,
    NEVER_REPLICATED,
    PHP,
    PLACEMENTS,
    SIZE_RE,
    TIMESPAN_RE,
)
from keel.manifest.fields import (
    argv_errors,
    at,
    bool_error,
    choice_error,
    constraint_error,
    count_error,
    inside,
    keys_errors,
    list_error,
    mapping_error,
    missing,
    named_items,
    path_error,
    pattern_error,
    quote,
    status_error,
    text_error,
    url_path_error,
)
from keel.manifest.validate_process import unit_errors
from keel.spec.fields import port_error

SERVICE_KEYS = ("engine", "version", "required", "placement", "durable",
                "rebuild", "secret", "defaults")
SERVICE_REQUIRED = ("engine", "required", "placement", "durable")
WORKER_KEYS = ("name", "unit", "every", "queue", "scaling")
WORKER_HINTS = {"writes": "a worker never writes to local disk (0034, 0041)"}
SCALING_KEYS = ("default", "max", "singleton")
WEB_KEYS = ("root", "routes", "max_body", "health")
ROUTE_KEYS = ("path", "to", "websocket")
MIGRATE_KEYS = ("command", "needs")


def validate_app(doc: dict, secrets: set, root: str) -> list[str]:
    """Every application section the appliance declares"""
    services = doc.get("services")
    errors = _services_errors(services, secrets)
    declared = services if isinstance(services, dict) else {}
    optional = {name for name, item in declared.items()
                if isinstance(item, dict) and item.get("required") is False}
    if "state" in doc:
        errors.extend(_state_errors(doc["state"], optional))
    if "workers" in doc:
        errors.extend(_workers_errors(doc["workers"], set(declared), root))
    if "web" in doc:
        errors.extend(_web_errors(doc["web"]))
    hooks = doc.get("hooks")
    if isinstance(hooks, dict) and "migrate" in hooks:
        errors.extend(_migrate_errors(hooks["migrate"], set(declared)))
    return errors


def _services_errors(services: Any, secrets: set) -> list[str]:
    if services is None:
        return []
    error = mapping_error("services", services)
    if error:
        return [error]
    errors = []
    for name, item in services.items():
        error = pattern_error("services", name, ITEM_RE, ITEM_TEXT)
        if error:
            errors.append(error)
            continue
        errors.extend(_service_errors(f"services.{name}", item, secrets))
    return errors


def _service_errors(key: str, item: Any, secrets: set) -> list[str]:
    error = mapping_error(key, item)
    if error:
        return [error]
    errors = keys_errors(key, item, SERVICE_KEYS)
    errors.extend(missing(key, item, SERVICE_REQUIRED))
    if "engine" in item and not _is_engine(item["engine"]):
        errors.append(f"{key}.engine: must be one of {', '.join(ENGINES)},"
                      " or a list of them")
    if "version" in item:
        error = constraint_error(f"{key}.version", item["version"],
                                 CONSTRAINT_RE)
        errors.extend([error] if error else [])
    for field in ("required", "durable"):
        if field in item:
            error = bool_error(f"{key}.{field}", item[field])
            errors.extend([error] if error else [])
    if "placement" in item:
        errors.extend(_placement_errors(f"{key}.placement",
                                        item["placement"],
                                        item.get("required") is False))
    if "rebuild" in item:
        errors.extend(argv_errors(f"{key}.rebuild", item["rebuild"]))
        if item.get("durable") is not False:
            errors.append(f"{key}.rebuild: only for durable: false")
    if "secret" in item and not known(item["secret"], secrets):
        errors.append(f"{key}.secret: {item['secret']} is not a secret of"
                      " this manifest")
    if "defaults" in item:
        errors.extend(_defaults_errors(f"{key}.defaults", item["defaults"]))
    return errors


def _is_engine(value: Any) -> bool:
    if isinstance(value, list):
        return bool(value) and all(known(item, ENGINES) for item in value)
    return known(value, ENGINES)


def known(value: Any, names) -> bool:
    """VALUE is a string among NAMES; a list or a mapping never is"""
    return isinstance(value, str) and value in names


def _placement_errors(key: str, value: Any, optional: bool) -> list[str]:
    error = mapping_error(key, value)
    if error:
        return [error]
    errors = keys_errors(key, value, MODES)
    errors.extend(missing(key, value, MODES))
    for mode in MODES:
        if mode not in value:
            continue
        error = choice_error(f"{key}.{mode}", value[mode], PLACEMENTS)
        if error:
            errors.append(error)
        elif value[mode] == "none" and not optional:
            errors.append(f"{key}.{mode}: none only when required is false")
    return errors


def _defaults_errors(key: str, value: Any) -> list[str]:
    error = mapping_error(key, value)
    if error:
        return [error]
    errors = keys_errors(key, value, ("name", "user"))
    for field in ("name", "user"):
        if field in value:
            error = text_error(f"{key}.{field}", value[field])
            errors.extend([error] if error else [])
    return errors


def _state_errors(state: Any, optional: set) -> list[str]:
    """Rule 23, within the file"""
    error = mapping_error("state", state)
    if error:
        return [error]
    errors = keys_errors("state", state, ("replicate", "exclude"))
    replicated, more = _replicate_errors(state.get("replicate"), optional)
    errors.extend(more)
    excludes = state.get("exclude")
    if excludes is None:
        return errors
    error = list_error("state.exclude", excludes)
    if error:
        return errors + [error]
    for index, path in enumerate(excludes):
        key = f"state.exclude[{index}]"
        error = path_error(key, path)
        if error:
            errors.append(error)
        elif not any(inside(path, parent) and path != parent
                     for parent in replicated):
            errors.append(f"{key}: {path} is inside no replicated path")
    return errors


def replicate_paths(state: Any) -> list[tuple[int, str]]:
    """The (index, path) of each replicated path of a valid state"""
    found = []
    for index, entry in enumerate((state or {}).get("replicate") or []):
        path = entry.get("path") if isinstance(entry, dict) else entry
        found.append((index, path))
    return found


def _replicate_errors(value: Any,
                      optional: set) -> tuple[list[str], list[str]]:
    if value is None:
        return [], []
    error = list_error("state.replicate", value)
    if error:
        return [], [error]
    errors, paths = [], []
    for index, entry in enumerate(value):
        key = f"state.replicate[{index}]"
        path = entry
        if isinstance(entry, dict):
            errors.extend(keys_errors(key, entry, ("path", "unless")))
            path = entry.get("path")
            unless = entry.get("unless")
            if "unless" in entry and not known(unless, optional):
                errors.append(f"{key}.unless: {unless} is not a service"
                              " with required: false")
        elif not isinstance(entry, str):
            errors.append(f"{key}: must be a path or {{path: P, unless: S}}")
            continue
        error = path_error(key, path)
        if error:
            errors.append(error)
            continue
        errors.extend(_placed_errors(key, path, paths))
        paths.append(path)
    return paths, errors


def _placed_errors(key: str, path: str, earlier: list[str]) -> list[str]:
    errors = [f"{key}: {path} is under a directory that is never"
              f" replicated ({', '.join(NEVER_REPLICATED)})"
              for directory in NEVER_REPLICATED if inside(path, directory)]
    for other in earlier:
        if inside(path, other):
            errors.append(f"{key}: {path} is inside {other}")
        elif inside(other, path):
            errors.append(f"{key}: {other} is inside {path}")
    return errors


def _workers_errors(value: Any, services: set, root: str) -> list[str]:
    """Rule 24"""
    errors, items = named_items("workers", value, ITEM_RE, ITEM_TEXT)
    for index, item in items:
        key = f"workers[{index}]"
        errors.extend(keys_errors(key, item, WORKER_KEYS, WORKER_HINTS))
        errors.extend(missing(key, item, ("unit",)))
        if "unit" in item:
            errors.extend(unit_errors(f"{key}.unit", item["unit"], root))
        every = item.get("every")
        if "every" in item and not (isinstance(every, str)
                                    and TIMESPAN_RE.match(every)):
            errors.append(f"{key}.every: {quote(every)} is not a time span"
                          " such as 5min")
        if "queue" in item and not known(item["queue"], services):
            errors.append(f"{key}.queue: {item['queue']} is not a service"
                          " of this manifest")
        if "scaling" in item:
            errors.extend(_scaling_errors(f"{key}.scaling", item["scaling"]))
    return errors


def _scaling_errors(key: str, value: Any) -> list[str]:
    error = mapping_error(key, value)
    if error:
        return [error]
    errors = keys_errors(key, value, SCALING_KEYS)
    errors.extend(missing(key, value, SCALING_KEYS))
    counts = {}
    for field in ("default", "max"):
        if field in value:
            error = count_error(f"{key}.{field}", value[field])
            if error:
                errors.append(error)
            else:
                counts[field] = value[field]
    if "singleton" in value:
        error = bool_error(f"{key}.singleton", value["singleton"])
        errors.extend([error] if error else [])
    if len(counts) == 2 and counts["default"] > counts["max"]:
        errors.append(f"{key}: default ({counts['default']}) must be at"
                      f" most max ({counts['max']})")
    if value.get("singleton") is True and counts.get("max", 1) != 1:
        errors.append(f"{key}: singleton: true means max: 1")
    return errors


def _web_errors(web: Any) -> list[str]:
    error = mapping_error("web", web)
    if error:
        return [error]
    errors = keys_errors("web", web, WEB_KEYS)
    if "root" in web:
        error = path_error("web.root", web["root"])
        errors.extend([error] if error else [])
    size = web.get("max_body")
    if "max_body" in web and not (isinstance(size, str)
                                  and SIZE_RE.match(size)):
        errors.append(f"web.max_body: {quote(size)} must be a size such as"
                      " 128M")
    if "routes" in web:
        errors.extend(_routes_errors(web["routes"]))
    if "health" in web:
        errors.extend(_health_errors(web["health"]))
    return errors


def _routes_errors(routes: Any) -> list[str]:
    error = list_error("web.routes", routes)
    if error:
        return [error]
    errors = []
    for index, route in enumerate(routes):
        key = f"web.routes[{index}]"
        error = mapping_error(key, route)
        if error:
            errors.append(error)
            continue
        errors.extend(keys_errors(key, route, ROUTE_KEYS))
        errors.extend(missing(key, route, ("path", "to")))
        if "path" in route:
            error = url_path_error(f"{key}.path", route["path"])
            errors.extend([error] if error else [])
        if "to" in route:
            errors.extend(_to_errors(f"{key}.to", route["to"]))
        if "websocket" in route:
            error = bool_error(f"{key}.websocket", route["websocket"])
            errors.extend([error] if error else [])
    return errors


def _to_errors(key: str, value: Any) -> list[str]:
    if value == PHP:
        return []
    if not isinstance(value, dict) or set(value) != {"port"}:
        return [f"{key}: must be php or {{port: N}}"]
    error = port_error(f"{key}.port", value["port"])
    return [error] if error else []


def _health_errors(health: Any) -> list[str]:
    error = mapping_error("web.health", health)
    if error:
        return [error]
    errors = keys_errors("web.health", health, ("path", "expect"))
    errors.extend(missing("web.health", health, ("path", "expect")))
    if "path" in health:
        error = url_path_error("web.health.path", health["path"])
        errors.extend([error] if error else [])
    if "expect" in health:
        error = status_error("web.health.expect", health["expect"])
        errors.extend([error] if error else [])
    return errors


def _migrate_errors(value: Any, services: set) -> list[str]:
    key = at("hooks", "migrate")
    error = mapping_error(key, value)
    if error:
        return [error]
    errors = keys_errors(key, value, MIGRATE_KEYS)
    errors.extend(missing(key, value, ("command",)))
    if "command" in value:
        errors.extend(argv_errors(f"{key}.command", value["command"]))
    needs = value.get("needs")
    if needs is None:
        return errors
    error = list_error(f"{key}.needs", needs)
    if error:
        return errors + [error]
    for index, name in enumerate(needs):
        if not known(name, services):
            errors.append(f"{key}.needs[{index}]: {name} is not a service of"
                          " this manifest")
    return errors
