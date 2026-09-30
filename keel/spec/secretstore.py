# Copyright (c) 2026 KeelLinux maintainers
"""Secret resolution

Secrets are referenced by the spec, never inlined in it. A reference is
either a file on disk (which must be root owned and 0600 or stricter) or
a request to generate a value at apply time.
"""

import os
import secrets as secrets_module

from keel.spec.constants import (
    GENERATED_BYTES,
    MANIFEST_SECRET_PREFIX,
    SECRET_VARS,
)
from keel.spec.errors import SpecError


def secret_names(doc: dict) -> dict[str, str]:
    """Every declared secret's name and its variable, the three first

    A name a manifest declares (decision 0041) renders as
    KEEL_SECRET_<NAME>; validation has already refused any other.
    """
    declared = doc.get("secrets") or {}
    names = {name: var for name, var in SECRET_VARS.items()
             if name in declared}
    names.update({str(name): MANIFEST_SECRET_PREFIX + str(name).upper()
                  for name in declared if name not in SECRET_VARS})
    return names


def resolve_secrets(doc: dict) -> dict[str, str]:
    """Read or generate every declared secret, keyed by variable name"""
    declared = doc.get("secrets") or {}
    resolved = {}
    for name, var in secret_names(doc).items():
        spec = declared.get(name)
        if isinstance(spec, dict):
            resolved[var] = resolve_secret(spec)

    api_key = (doc.get("hub") or {}).get("api_key")
    if isinstance(api_key, dict):
        resolved["HUB_APIKEY"] = resolve_secret(api_key)
    return resolved


def resolve_secret(spec: dict) -> str:
    """Resolve one secret reference to its value"""
    if spec.get("generate"):
        return secrets_module.token_urlsafe(GENERATED_BYTES)
    return read_secret_file(str(spec["file"]))


def read_secret_file(path: str) -> str:
    """Read a secret file, refusing one that anybody else can read"""
    error = secret_file_error(path)
    if error:
        raise SpecError(error)
    with open(path, "rb") as fob:
        data = fob.read()
    if data.endswith(b"\n"):
        data = data[:-1]
    return data.decode()


def secret_file_error(path: str) -> str | None:
    """Return why a secret file is unusable, or None when it is fine"""
    if not os.path.isfile(path):
        return f"{path}: secret file not found"
    stat = os.stat(path)
    if stat.st_mode & 0o077:
        return f"{path}: secret file mode must be 0600 or stricter"
    if stat.st_uid not in (0, os.geteuid()):
        return f"{path}: secret file must be owned by root"
    return None
