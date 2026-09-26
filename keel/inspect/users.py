# Copyright (c) 2026 KeelLinux maintainers
"""The users section: public keys, the shell and the groups of each user

Only users with at least one public key are written. Their shell comes
from /etc/passwd and their supplementary groups from /etc/group, the
public columns only. Passwords, shadow entries and private keys are never
read.
"""

from keel.inspect.accounts import group_members, groups_of, passwd_entries
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File
from keel.spec.validate_extras import KEY_TYPES


def probe_users(
    key_files: list[tuple[str, File]], passwd: File, group: File
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
        account, found = probe_account(name, passwd, group)
        users[name].update(account)
        findings += found
    if not users:
        findings.append(
            missing("users", "no authorized_keys file with a public key")
        )
    return (users or None), findings


def probe_account(
    name: str, passwd: File, group: File
) -> tuple[dict, list[Finding]]:
    """shell from passwd; groups from group, only when there are any"""
    account: dict = {}
    findings: list[Finding] = []
    field = f"users.{name}.shell"
    entry = passwd_entries(passwd).get(name) if passwd.readable else None
    if not passwd.readable:
        findings.append(missing(field, f"{passwd.path} {passwd.problem}"))
    elif entry is None:
        findings.append(missing(field, f"no entry in {passwd.path}"))
    else:
        account["shell"] = entry.shell
        findings.append(inferred(field, entry.shell, passwd.path))

    field = f"users.{name}.groups"
    if not group.readable:
        findings.append(missing(field, f"{group.path} {group.problem}"))
    else:
        groups = groups_of(name, group_members(group))
        if groups:
            account["groups"] = groups
            findings.append(inferred(field, ", ".join(groups), group.path))
    return account, findings


def public_key(line: str) -> str | None:
    """The key part of an authorized_keys line, without leading options"""
    fields = line.split()
    for index, field in enumerate(fields):
        if field.startswith(KEY_TYPES) and len(fields) > index + 1:
            return " ".join(fields[index:])
    return None
