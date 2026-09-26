# Copyright (c) 2026 KeelLinux maintainers
"""Pure readers of /etc/passwd and /etc/group

Shared by inspect (which reports a user's shell and groups) and by apply
--system (which decides whether an account needs creating or changing).
Only the public columns are read; a shadow file is never opened.
"""

from dataclasses import dataclass

from keel.inspect.tree import File

PASSWD_FIELDS = 7
GROUP_FIELDS = 4
ROOT_HOME = "/root"
HOME_BASE = "/home"


@dataclass(frozen=True)
class Account:
    """One passwd entry, without the password column"""

    name: str
    uid: int
    gid: int
    home: str
    shell: str


def passwd_entries(passwd: File) -> dict[str, Account]:
    """Accounts by name; a malformed line is skipped, never guessed at"""
    found: dict[str, Account] = {}
    for line in passwd.lines():
        fields = line.split(":")
        if len(fields) < PASSWD_FIELDS:
            continue
        try:
            uid, gid = int(fields[2]), int(fields[3])
        except ValueError:
            continue
        found[fields[0]] = Account(fields[0], uid, gid, fields[5], fields[6])
    return found


def group_members(group: File) -> dict[str, tuple[str, ...]]:
    """Supplementary members of every group, by group name"""
    found: dict[str, tuple[str, ...]] = {}
    for line in group.lines():
        fields = line.split(":")
        if len(fields) < GROUP_FIELDS:
            continue
        found[fields[0]] = tuple(
            member for member in fields[3].split(",") if member
        )
    return found


def groups_of(name: str, members: dict[str, tuple[str, ...]]) -> list[str]:
    """The groups listing `name` as a member, in file order"""
    return [group for group, names in members.items() if name in names]


def home_of(name: str, entries: dict[str, Account]) -> str:
    """The home from passwd, else what useradd --create-home would pick"""
    entry = entries.get(name)
    if entry is not None:
        return entry.home
    return ROOT_HOME if name == "root" else f"{HOME_BASE}/{name}"
