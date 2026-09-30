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
from keel.system.actions import (
    AdoptKey,
    Change,
    GenerateKey,
    MakeDir,
    RemoveFile,
    Run,
    RunSql,
    Symlink,
    SwitchNetwork,
    WriteFile,
)
from keel.network import marker, switch, wgkeys

NOT_RUNNABLE = 127


class Effects:
    def __init__(self, root: str):
        self.tree = Tree(root)

    def apply(self, action: Change) -> str | None:
        """Carry out one action; None on success, else what went wrong"""
        try:
            if isinstance(action, Run):
                return self.run(action.argv)
            if isinstance(action, RunSql):
                return self.run(action.argv, action.statements)
            if isinstance(action, WriteFile):
                return self.write(action)
            if isinstance(action, RemoveFile):
                os.remove(self.tree.path(action.path))
                return None
            if isinstance(action, MakeDir):
                return self.make_dir(action)
            if isinstance(action, SwitchNetwork):
                return self.switch_network(action)
            if isinstance(action, GenerateKey):
                return wgkeys.generate(self.tree.path(action.path.lstrip("/")))
            if isinstance(action, AdoptKey):
                return wgkeys.adopt(self.tree.path(action.conf),
                                    self.tree.path(action.path.lstrip("/")))
            return self.symlink(action)
        except OSError as e:
            return f"{e.strerror or e}"

    def run(self, argv: tuple[str, ...], stdin: str | None = None) -> (
        str | None
    ):
        """Run a command, with `stdin` when the action carries statements

        The statements never reach the argument vector, which is world
        readable in the process list, and never reach the message on
        failure either: the client quotes the statement it choked on, so
        the reason is taken from the stream and the statements are not
        echoed back by keel.
        """
        try:
            out = subprocess.run(
                list(argv), capture_output=True, text=True, check=False,
                input=stdin,
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

    def switch_network(self, action: SwitchNetwork) -> str | None:
        """keel.network.switch does the work; this is its only caller"""
        pending = marker.Pending(
            iface=action.iface, path=action.path, window=action.window,
            addresses=action.addresses, gateways=action.gateways,
            old_gateways=action.old_gateways, kind=action.kind,
            down_before=action.down_before,
            uplink_gateways=action.uplink_gateways,
        )
        return switch.change(self.tree.root, pending, action.content,
                             self.run)

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
