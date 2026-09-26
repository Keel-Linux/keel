# Copyright (c) 2026 KeelLinux maintainers
"""The users section: public keys from authorized_keys files, nothing else

Only public key lines are kept. Passwords, shadow entries and private
keys are never read.
"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File
from keel.spec.validate_extras import KEY_TYPES


def probe_users(
    key_files: list[tuple[str, File]]
) -> tuple[dict | None, list[Finding]]:
    """`key_files` pairs a user name with its authorized_keys File"""
    users: dict = {}
    findings: list[Finding] = []
    for name, file in key_files:
        field = f"users.{name}.authorized_keys"
        if not file.readable:
            findings.append(missing(field, f"{file.path} {file.problem}"))
            continue
        keys = [key for key in map(public_key, file.lines()) if key]
        if not keys:
            findings.append(missing(field, f"{file.path} holds no public key"))
            continue
        users[name] = {"authorized_keys": keys}
        findings.append(
            inferred(field, f"{len(keys)} public key(s)", file.path)
        )
    if not users:
        findings.append(
            missing("users", "no authorized_keys file with a public key")
        )
    return (users or None), findings


def public_key(line: str) -> str | None:
    """The key part of an authorized_keys line, without leading options"""
    fields = line.split()
    for index, field in enumerate(fields):
        if field.startswith(KEY_TYPES) and len(fields) > index + 1:
            return " ".join(fields[index:])
    return None
