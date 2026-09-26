# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the sections that are accepted but not acted on yet

users and locale are named by brief section 5.2 and written by
`keel inspect`. Nothing applies them yet, so `apply` warns about them
(see keel.spec.apply.unsupported) instead of dropping them silently.
"""

import re
from typing import Any

from keel.spec.fields import list_error, mapping_error

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$")
LANG_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
KEY_TYPES = ("ssh-", "ecdsa-", "sk-")


def validate_users(users: Any) -> list[str]:
    """Each user is a mapping holding a list of public keys, nothing else"""
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
            if field != "authorized_keys":
                errors.append(f"{key}.{field}: unknown key")
        keys = user.get("authorized_keys")
        errors.extend(_validate_keys(f"{key}.authorized_keys", keys))
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
