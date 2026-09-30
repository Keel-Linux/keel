# Copyright (c) 2026 KeelLinux maintainers
"""Field level checks shared by the manifest validators

Every function returns messages, never raises, so that a validator can
report every error of a file at once. A key is the dotted path of the
field, lists indexed from 0: `processes[0].listen[1].port`.
"""

import posixpath
import re
from typing import Any

from keel.manifest.constants import MAX_STATUS, MIN_STATUS

BOOL_HINT = ("YAML 1.1 turns an unquoted on, off, yes or no into a"
             " boolean")


def at(prefix: str, key: Any) -> str:
    """The key of a field inside PREFIX"""
    word = str(key).lower() if isinstance(key, bool) else str(key)
    return f"{prefix}.{word}" if prefix else word


def quote(value: Any) -> str:
    """A value as a message shows it: a string quoted, the rest as is"""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)


def words(choices: tuple) -> str:
    """a, b or c"""
    return f"{', '.join(choices[:-1])} or {choices[-1]}"


def boolean_read(key: str, value: bool, choices: tuple) -> str:
    return (f"{key}: read as the boolean {quote(value)}: {BOOL_HINT};"
            f" write {words(choices)}")


def choice_error(key: str, value: Any, choices: tuple) -> str | None:
    """One word of CHOICES; a YAML boolean is named as the typo it is"""
    if isinstance(value, str) and value in choices:
        return None
    if isinstance(value, bool):
        return boolean_read(key, value, choices)
    return f"{key}: must be {words(choices)}, not {quote(value)}"


def keys_errors(
    prefix: str, mapping: dict, allowed: tuple, hints: dict | None = None
) -> list[str]:
    """Unknown keys are errors at every level (rule 2)"""
    errors = []
    for key in mapping:
        if key in allowed and not isinstance(key, bool):
            continue
        message = f"{at(prefix, key)}: unknown key"
        if isinstance(key, bool):
            message += f" (read as the boolean {quote(key)}: {BOOL_HINT})"
        elif hints and key in hints:
            message += f": {hints[key]}"
        errors.append(message)
    return errors


def missing(prefix: str, mapping: dict, required: tuple) -> list[str]:
    return [f"{at(prefix, key)}: required" for key in required
            if key not in mapping]


def mapping_error(key: str, value: Any) -> str | None:
    if not isinstance(value, dict):
        return f"{key}: must be a mapping"
    return None


def list_error(key: str, value: Any) -> str | None:
    if not isinstance(value, list):
        return f"{key}: must be a list"
    return None


def text_error(key: str, value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return f"{key}: must be a non-empty string"
    return None


def bool_error(key: str, value: Any) -> str | None:
    if not isinstance(value, bool):
        return f"{key}: must be true or false"
    return None


def count_error(key: str, value: Any) -> str | None:
    """A whole number of at least 1; true is not 1"""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"{key}: must be a whole number of at least 1"
    return None


def status_error(key: str, value: Any) -> str | None:
    if (isinstance(value, bool) or not isinstance(value, int)
            or not MIN_STATUS <= value <= MAX_STATUS):
        return f"{key}: must be one HTTP status code"
    return None


def url_path_error(key: str, value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("/"):
        return f"{key}: must start with /"
    return None


def pattern_error(key: str, value: Any, regex: re.Pattern,
                  text: str) -> str | None:
    """A name of the shape REGEX, which the message spells as TEXT"""
    if isinstance(value, str) and regex.match(value):
        return None
    return f"{key}: {quote(value)} must match {text}"


def path_error(key: str, value: Any) -> str | None:
    """Absolute and normalised: no .., no //, no trailing / (rule 4)"""
    if not isinstance(value, str) or not value.startswith("/"):
        return f"{key}: must be an absolute path, not {quote(value)}"
    if (value.endswith("/") or "//" in value
            or posixpath.normpath(value) != value):
        return (f"{key}: {quote(value)} is not normalised: no .., no //,"
                " no trailing /")
    return None


def argv_errors(key: str, value: Any) -> list[str]:
    """An argv list, never a shell string, run from an absolute path"""
    if not isinstance(value, list) or not value:
        return [f"{key}: must be a non-empty argv list, never a shell"
                " string"]
    errors = [f"{key}[{index}]: must be a string"
              for index, item in enumerate(value)
              if not isinstance(item, str)]
    if not errors and not value[0].startswith("/"):
        errors.append(f"{key}[0]: must be an absolute path")
    return errors


def constraint_error(key: str, value: Any, regex: re.Pattern) -> str | None:
    if isinstance(value, str) and regex.match(value):
        return None
    return f"{key}: must be a constraint such as '>= 1.26'"


def inside(path: str, parent: str) -> bool:
    """PATH is PARENT or below it"""
    return path == parent or path.startswith(parent + "/")


def named_items(
    prefix: str, value: Any, regex: re.Pattern, text: str
) -> tuple[list[str], list[tuple[int, dict]]]:
    """A list of mappings with unique names (rule 3)

    Returns the errors and the (index, item) pairs that are mappings, for
    the caller to check field by field.
    """
    if value is None:
        return [], []
    error = list_error(prefix, value)
    if error:
        return [error], []
    errors, items, seen = [], [], set()
    for index, item in enumerate(value):
        key = f"{prefix}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{key}: must be a mapping")
            continue
        items.append((index, item))
        if "name" not in item:
            errors.append(f"{key}.name: required")
            continue
        name = item["name"]
        error = pattern_error(f"{key}.name", name, regex, text)
        if error:
            errors.append(error)
        elif name in seen:
            errors.append(f'{key}.name: "{name}" appears twice in {prefix}')
        seen.add(name if isinstance(name, str) else repr(name))
    return errors, items
