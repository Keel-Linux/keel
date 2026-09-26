# Copyright (c) 2026 KeelLinux maintainers
"""Plan the users section: accounts and authorized keys

Accounts are created when absent, with the declared shell and groups;
an existing account gets its shell changed and missing groups added.
Nothing is ever deleted: not a user, not a group membership. The
authorized_keys file is set to exactly the declared keys. Passwords are
never touched here; ROOT_PASS and friends stay with the hooks.
"""

from keel.inspect.accounts import group_members, groups_of, passwd_entries
from keel.inspect.tree import NOT_PRESENT, File
from keel.system.actions import (
    Action,
    MakeDir,
    Note,
    Run,
    Step,
    WriteFile,
    unchanged,
)
from keel.system.state import SystemState, keys_path

KEYS_MODE = 0o600
SSH_DIR_MODE = 0o700


def plan_users(users: dict, state: SystemState) -> list[Step]:
    steps: list[Step] = []
    for name, user in users.items():
        name, user = str(name), user or {}
        steps.append(account_step(name, user, state))
        keys = user.get("authorized_keys")
        if keys is not None:
            steps.append(keys_step(name, [str(key) for key in keys], state))
    return steps


def account_step(name: str, user: dict, state: SystemState) -> Step:
    field = f"users.{name}"
    if not readable_or_absent(state.passwd):
        return Step(field, (Note(
            f"cannot plan: {state.passwd.path} {state.passwd.problem}"
        ),))
    entries = passwd_entries(state.passwd)
    shell = user.get("shell")
    groups = [str(group) for group in user.get("groups") or []]
    entry = entries.get(name)
    if entry is None:
        return Step(field, (create_user(name, shell, groups, state),))

    actions: list[Action] = []
    if shell is not None and entry.shell != shell:
        actions.append(Run(
            ("usermod",) + root_option(state) + ("--shell", str(shell), name),
            f"change shell from {entry.shell} to {shell}",
        ))
    have = groups_of(name, group_members(state.group))
    missing = [group for group in groups if group not in have]
    if missing:
        actions.append(Run(
            ("usermod",) + root_option(state)
            + ("--append", "--groups", ",".join(missing), name),
            f"add to groups {', '.join(missing)}",
        ))
    if not actions:
        return unchanged(field, f"exists, uid {entry.uid}")
    return Step(field, tuple(actions))


def create_user(
    name: str, shell: object, groups: list[str], state: SystemState
) -> Run:
    argv = ("useradd",) + root_option(state) + ("--create-home",)
    if shell is not None:
        argv += ("--shell", str(shell))
    if groups:
        argv += ("--groups", ",".join(groups))
    return Run(argv + (name,), f"create user {name}")


def root_option(state: SystemState) -> tuple[str, ...]:
    """useradd and usermod take --root; the live system needs none"""
    if state.live:
        return ()
    return ("--root", state.root)


def keys_step(name: str, keys: list[str], state: SystemState) -> Step:
    field = f"users.{name}.authorized_keys"
    entries = passwd_entries(state.passwd)
    path = keys_path(name, entries)
    wanted = "".join(f"{key}\n" for key in keys)
    current = state.key_files.get(name, File(path, problem=NOT_PRESENT))
    if current.readable and current.text == wanted:
        return unchanged(field, f"{len(keys)} key(s) in /{path}")
    ssh_dir = path.rsplit("/", 1)[0]
    return Step(field, (
        MakeDir(ssh_dir, SSH_DIR_MODE, name, f"ensure /{ssh_dir}"),
        WriteFile(path, wanted, KEYS_MODE, name,
                  f"write /{path} with {len(keys)} key(s)"),
    ))


def readable_or_absent(file: File) -> bool:
    """An absent passwd is an empty one; an unreadable one cannot be planned"""
    return file.readable or file.problem == NOT_PRESENT
