# Copyright (c) 2026 KeelLinux maintainers
"""The one module of apply --system with side effects

Every command is run with an argv list, never through a shell, and every
file is written under the root the effects were made for. A failure is
returned as a message, not raised, so the executor can report it and go
on with the next field.
"""

import os
import subprocess

from keel.inspect import constants as paths
from keel.inspect.accounts import passwd_entries
from keel.inspect.tree import Tree
from keel.system.actions import Change, MakeDir, Run, Symlink, WriteFile

NOT_RUNNABLE = 127


class Effects:
    def __init__(self, root: str):
        self.tree = Tree(root)

    def apply(self, action: Change) -> str | None:
        """Carry out one action; None on success, else what went wrong"""
        try:
            if isinstance(action, Run):
                return self.run(action.argv)
            if isinstance(action, WriteFile):
                return self.write(action)
            if isinstance(action, MakeDir):
                return self.make_dir(action)
            return self.symlink(action)
        except OSError as e:
            return f"{e.strerror or e}"

    def run(self, argv: tuple[str, ...]) -> str | None:
        try:
            out = subprocess.run(
                list(argv), capture_output=True, text=True, check=False,
            )
        except OSError as e:
            return f"cannot run {argv[0]}: {e.strerror}"
        if out.returncode != 0:
            detail = out.stderr.strip() or out.stdout.strip()
            return f"{argv[0]} exited {out.returncode}: {detail}"
        return None

    def write(self, action: WriteFile) -> str | None:
        """Write the file; a missing parent such as /etc/default is created"""
        path = self.tree.path(action.path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, action.mode)
        with os.fdopen(fd, "w") as fob:
            fob.write(action.content)
        os.chmod(path, action.mode)
        return self.own(path, action.owner)

    def make_dir(self, action: MakeDir) -> str | None:
        path = self.tree.path(action.path)
        os.makedirs(path, mode=action.mode, exist_ok=True)
        os.chmod(path, action.mode)
        return self.own(path, action.owner)

    def symlink(self, action: Symlink) -> str | None:
        path = self.tree.path(action.path)
        if os.path.lexists(path):
            os.remove(path)
        os.symlink(action.target, path)
        return None

    def own(self, path: str, owner: str | None) -> str | None:
        """chown to the uid and gid the root's passwd gives for `owner`"""
        if owner is None:
            return None
        passwd = self.tree.read(paths.PASSWD)
        entry = passwd_entries(passwd).get(owner)
        if entry is None:
            return f"owner not set: {owner} has no entry in {passwd.path}"
        os.chown(path, entry.uid, entry.gid)
        return None
