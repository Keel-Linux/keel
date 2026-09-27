# Copyright (c) 2026 KeelLinux maintainers
"""Validation of one secret reference, shared by every section that has one

A secret is a reference, never a value, so the same check serves
`secrets`, `hub.api_key` and the database credentials. It lives apart from
keel.spec.validate so that a section validator can use it without
importing the validator that calls it.

Structure is always checked: exactly one known backend, and a `file:`
value that is a non empty string. The file behind a `file:` reference is
checked only when `check_secret_files` is true, because a secret is a
reference and the machine being described may not hold the value.
"""

from typing import Any

from keel.spec.constants import SECRET_BACKENDS
from keel.spec.secretstore import secret_file_error


def validate_secret(
    key: str, spec: Any, check_secret_files: bool = True
) -> list[str]:
    """Check one secret reference: exactly one backend, and it works

    "Works" means the file exists with the right owner and mode, which is
    skipped when `check_secret_files` is false; the structure is checked
    either way.
    """
    if not isinstance(spec, dict):
        return [f"{key}: must be a mapping"]

    backends = [name for name in SECRET_BACKENDS if name in spec]
    unknown = [name for name in spec if name not in SECRET_BACKENDS]
    errors = [f"{key}.{name}: unknown secret backend" for name in unknown]
    if len(backends) != 1:
        errors.append(
            f"{key}: exactly one of {', '.join(SECRET_BACKENDS)} is required"
        )
        return errors
    if "file" in spec:
        errors.extend(
            _validate_file_backend(key, spec["file"], check_secret_files)
        )
    return errors


def _validate_file_backend(
    key: str, path: Any, check_secret_files: bool
) -> list[str]:
    if not isinstance(path, str) or not path:
        return [f"{key}.file: must be a path"]
    if not check_secret_files:
        return []
    error = secret_file_error(path)
    return [f"{key}: {error}"] if error else []
