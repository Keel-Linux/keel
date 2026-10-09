# Copyright (c) 2026 KeelLinux maintainers
"""The one module of apply --system with side effects

Every command is run with an argv list, never through a shell, and every
file is written under the root the effects were made for. A failure is
returned as a message, not raised, so the executor can report it and go
on with the next field.
"""

import os
import signal
import subprocess

from keel.inspect import constants as paths
from keel.inspect.accounts import passwd_entries
from keel.inspect.tree import Tree
from keel.system.actions import (
    AddBouncer,
    AdoptKey,
    Attempt,
    Change,
    EnsureDatabaseTls,
    FollowVip,
    GenerateKey,
    InstallRuleset,
    LockReplica,
    MakeDir,
    PromoteReplica,
    RemoveFile,
    Run,
    RunSql,
    SeedReplica,
    SetBouncerMode,
    Symlink,
    SwitchNetwork,
    UnlockAccounts,
    WriteFile,
)
from keel.network import marker, switch, wgkeys
from keel.system import crowdsec, dbreadonly, dbseed, fwinstall

NOT_RUNNABLE = 127
LIVE_ADDED = "done with wg set, live: peers added, no other peer touched"
LIVE_CHANGED = ("done with wg set, live: the other peers kept their"
                " sessions")
BOUNCED = "done with wg-quick down, then up"


class Effects:
    def __init__(self, root: str):
        self.tree = Tree(root)
        # what the last action did, when "done" does not say it
        # (keel#120); None for the rest
        self.ran: str | None = None

    def apply(self, action: Change) -> str | None:
        """Carry out one action; None on success, else what went wrong"""
        self.ran = None
        try:
            if isinstance(action, Run):
                return self.run(action.argv, timeout=action.timeout)
            if isinstance(action, Attempt):
                return self.run(action.argv)
            if isinstance(action, AddBouncer):
                return crowdsec.add_bouncer(self.tree.root, action)
            if isinstance(action, SetBouncerMode):
                return crowdsec.set_mode(self.tree.root, action)
            if isinstance(action, InstallRuleset):
                return fwinstall.install(self.tree.root, action)
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
            if isinstance(action, SeedReplica):
                with dbreadonly.replication_locked(self.tree.root):
                    return dbseed.seed(self.tree.root, action)
            if isinstance(action, LockReplica):
                return dbreadonly.lock(self.tree.root)
            if isinstance(action, UnlockAccounts):
                return dbreadonly.unlock(self.tree.root)
            if isinstance(action, PromoteReplica):
                with dbreadonly.replication_locked(self.tree.root):
                    return dbreadonly.promote(self.tree.root, action)
            if isinstance(action, EnsureDatabaseTls):
                return self.database_tls(action)
            if isinstance(action, FollowVip):
                from keel.system import dbfollow
                return dbfollow.followed(self.tree.root, action.spec,
                                         action.confirmed)
            return self.symlink(action)
        except OSError as e:
            return f"{e.strerror or e}"

    def database_tls(self, action: EnsureDatabaseTls) -> str | None:
        """keel.system.dbtls.ensure, with this node on the members'
        channel; None when nothing was due"""
        import sys
        from datetime import datetime, timezone
        from keel.mesh import etcd
        from keel.mesh.etcdstate import StateError
        from keel.mesh.node import Node, NodeError
        from keel.mesh import vippair
        from keel.system import dbtls
        node = Node(self.tree.root, action.spec)
        member = etcd.Etcd(node, lambda: datetime.now(timezone.utc),
                           lambda line: print(line, file=sys.stderr))
        try:
            own = etcd.own_key(member)
            if own is None:
                return "this node's WireGuard key could not be read"
            try:
                pair = vippair.read(self.tree.root, action.vip)
            except ValueError:
                pair = None
            said = dbtls.ensure(member, action.address, action.vip,
                                action.peer, own, pair=pair)
        except (StateError, NodeError, ValueError) as e:
            return str(e)
        if said:
            print(f"database.server.tls: {said}", file=sys.stderr)
        else:
            self.ran = ("kept: the certificate is not due for renewal, and"
                        " no file changed")
        return None

    def run(self, argv: tuple[str, ...], stdin: str | None = None,
            timeout: float | None = None) -> str | None:
        """Run a command, with `stdin` when the action carries statements

        The statements never reach the argument vector, which is world
        readable in the process list, and never reach the message on
        failure either: the client quotes the statement it choked on, so
        the reason is taken from the stream and the statements are not
        echoed back by keel. A command that runs past `timeout` is killed
        and fails.
        """
        if timeout is not None:
            return self.run_within(argv, timeout)
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

    def run_within(self, argv: tuple[str, ...], timeout: float) -> (
        str | None
    ):
        """Run a command in a session of its own, so that on expiry the
        whole of it is killed: a hook's children would otherwise keep its
        output open, and the wait with it"""
        try:
            proc = subprocess.Popen(
                list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True,
            )
        except OSError as e:
            return f"cannot run {argv[0]}: {e.strerror}"
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return (f"{argv[0]} did not finish within {timeout:g} s and was"
                    " killed")
        if proc.returncode != 0:
            detail = stderr.strip() or stdout.strip()
            return f"{argv[0]} exited {proc.returncode}: {detail}"
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
        seen: list[str] = []
        problem = switch.change(self.tree.root, pending, action.content,
                                self.run, seen)
        if problem is None and action.kind == marker.OVERLAY:
            # the way that ran (keel#120)
            self.ran = (LIVE_ADDED if seen == [switch.ADDED] else
                        LIVE_CHANGED if seen else BOUNCED)
        return problem

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
