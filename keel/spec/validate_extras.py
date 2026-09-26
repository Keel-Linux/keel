# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the users and locale sections

Both are named by brief section 5.2, written by `keel inspect` and
converged by `spec apply --system` (keel.system). Without --system, apply
warns about them (keel.spec.apply.unsupported) instead of dropping them
silently.
"""

import re
from typing import Any

from keel.spec.fields import list_error, mapping_error

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
SHELL_RE = re.compile(r"^/[A-Za-z0-9_./+-]+$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$")
LANG_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
KEY_TYPES = ("ssh-", "ecdsa-", "sk-")
USER_KEYS = ("authorized_keys", "shell", "groups")


def validate_users(users: Any) -> list[str]:
    """Each user is a mapping of public keys, a shell and groups, or empty"""
    error = mapping_error("users", users)
    if error or not users:
        return [error] if error else []

    errors = []
    for name, user in users.items():
        key = f"users.{name}"
        if not USERNAME_RE.match(str(name)):
            errors.append(f"{key}: not a valid user name")
        error = mapping_error(key, user)
        if error or not user:
            errors.extend([error] if error else [])
            continue
        for field in user:
            if field not in USER_KEYS:
                errors.append(f"{key}.{field}: unknown key")
        keys = user.get("authorized_keys")
        errors.extend(_validate_keys(f"{key}.authorized_keys", keys))
        errors.extend(_validate_shell(f"{key}.shell", user.get("shell")))
        errors.extend(_validate_groups(f"{key}.groups", user.get("groups")))
    return errors


def _validate_keys(key: str, keys: Any) -> list[str]:
    error = list_error(key, keys)
    if error:
        return [error]
    return [
        f"{key}: not a public key line ({str(line)[:24]!r})"
        for line in keys or []
        if not _is_public_key(line)
    ]


def _is_public_key(line: Any) -> bool:
    """An authorized_keys line: a key type, then the base64 blob"""
    if not isinstance(line, str) or "\n" in line:
        return False
    fields = line.split()
    return len(fields) >= 2 and fields[0].startswith(KEY_TYPES)


def _validate_shell(key: str, shell: Any) -> list[str]:
    """An absolute path with no parent references, as useradd -s takes"""
    if shell is None:
        return []
    if not isinstance(shell, str) or not SHELL_RE.match(shell) \
            or ".." in shell:
        return [f"{key}: must be an absolute path such as /bin/bash"]
    return []


def _validate_groups(key: str, groups: Any) -> list[str]:
    error = list_error(key, groups)
    if error:
        return [error]
    return [
        f"{key}: not a valid group name ({str(group)[:24]!r})"
        for group in groups or []
        if not USERNAME_RE.match(str(group))
    ]


def validate_locale(locale: Any) -> list[str]:
    error = mapping_error("locale", locale)
    if error or not locale:
        return [error] if error else []

    errors = []
    for key in locale:
        if key not in ("timezone", "lang"):
            errors.append(f"locale.{key}: unknown key")
    timezone = locale.get("timezone")
    if timezone is not None and not TIMEZONE_RE.match(str(timezone)):
        errors.append("locale.timezone: must be a zoneinfo name such as"
                      " Europe/Lisbon")
    lang = locale.get("lang")
    if lang is not None and not LANG_RE.match(str(lang)):
        errors.append("locale.lang: must be a locale name such as"
                      " en_US.UTF-8")
    return errors
