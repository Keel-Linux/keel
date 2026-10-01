# Copyright (c) 2026 KeelLinux maintainers
"""What apply --system may do, as data

A plan is a tuple of steps; a step is one spec field and the actions that
converge it, in order. Actions are values, so the planners stay pure and
unit testable against fixture trees, and keel.system.effects is the only
code that runs a command or writes a file.
"""

import shlex
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Run:
    """Run a command; `argv` is a list, never a shell string

    `timeout`, in seconds, kills a command that runs longer and fails the
    action; None waits as long as it takes, as every command keel ran
    before the overlays' state hooks.
    """

    argv: tuple[str, ...]
    summary: str
    timeout: float | None = None

    def describe(self) -> str:
        return f"{self.summary} ({shlex.join(self.argv)})"


@dataclass(frozen=True)
class Attempt:
    """Run a command whose failure the run survives, and say what then

    For what a machine may not be able to do yet and does not need to
    work: registering with CrowdSec's central API needs the network, and
    the local API runs without it. A failure is printed with `otherwise`
    and counts neither as a change nor as a failure of the step.
    """

    argv: tuple[str, ...]
    summary: str
    otherwise: str

    def describe(self) -> str:
        return f"{self.summary} ({shlex.join(self.argv)})"


@dataclass(frozen=True)
class AddBouncer:
    """Register CrowdSec's firewall bouncer and store its key

    Carried out by keel.system.crowdsec: `cscli bouncers add` prints the
    key on its standard output, which is read into memory and written to
    `config` with mode 0600, never to an argument vector or a line of
    output (tracker#47). A bouncer this machine registered before, named
    in `id_file`, is deleted first. `mode` is the bouncer's firewall
    backend, written beside the key as the Debian package writes it.
    `pending` is a registration the Debian package left unfinished,
    removed once the new key is stored: the bouncer's unit does not
    start while it is there.
    """

    config: str
    id_file: str
    mode: str
    old_id: str | None
    pending: str | None = None

    def describe(self) -> str:
        finished = (f", and remove /{self.pending}, the registration the"
                    " Debian package left unfinished" if self.pending
                    else "")
        return (f"register CrowdSec's firewall bouncer (cscli bouncers add)"
                f" and write its key to /{self.config} (mode 0600, never"
                f" printed) and its name to /{self.id_file}, mode:"
                f" {self.mode}{finished}")


@dataclass(frozen=True)
class InstallRuleset:
    """Write an nftables ruleset through a copy `nft -c` accepts

    Carried out by keel.system.fwinstall: the content goes to a copy
    beside `path`, mode 0600, nft checks the copy, and only a copy it
    accepts is renamed over `path`; a refused one is removed, so the file
    keel-firewall.service loads at boot is always one nft accepted.
    """

    path: str
    content: str
    summary: str

    def describe(self) -> str:
        return (f"{self.summary}; checked by nft -c as a copy first, so a"
                " file nft refuses is never put in place (mode 0600)")


@dataclass(frozen=True)
class SetBouncerMode:
    """Set the `mode:` line of CrowdSec's bouncer file, keeping the rest

    Carried out by keel.system.crowdsec. The file holds the bouncer's key,
    so it is rewritten in place, mode 0600, and never part of the plan.
    """

    config: str
    mode: str
    was: str | None

    def describe(self) -> str:
        return (f"set mode: {self.mode} in /{self.config} (was"
                f" {self.was or 'unset'}; the rest of the file is kept)")


@dataclass(frozen=True)
class WriteFile:
    """Write `content` to `path` (relative to the root) with mode and owner"""

    path: str
    content: str
    mode: int
    owner: str | None
    summary: str

    def describe(self) -> str:
        owner = f", owner {self.owner}" if self.owner else ""
        return f"{self.summary} (mode {self.mode:04o}{owner})"


@dataclass(frozen=True)
class RemoveFile:
    """Remove `path` (relative to the root): a file keel wrote, and only that

    The planner decides it is keel's before planning this, as the monitor
    does from the header of monit's file; nothing else is ever removed.
    """

    path: str
    summary: str

    def describe(self) -> str:
        return self.summary


@dataclass(frozen=True)
class MakeDir:
    path: str
    mode: int
    owner: str | None
    summary: str

    def describe(self) -> str:
        owner = f", owner {self.owner}" if self.owner else ""
        return f"{self.summary} (mode {self.mode:04o}{owner})"


@dataclass(frozen=True)
class Symlink:
    path: str
    target: str
    summary: str

    def describe(self) -> str:
        return f"{self.summary} (-> {self.target})"


@dataclass(frozen=True)
class RunSql:
    """Run statements through an engine's own client, on standard input

    A statement can hold a credential, and an argument vector is world
    readable in the process list, so the statements go on standard input
    and `describe` never prints them. That is also why a dry run of the
    database phase shows what will be done and not the SQL that does it.
    """

    argv: tuple[str, ...]
    statements: str
    summary: str

    def describe(self) -> str:
        count = len([one for one in self.statements.split(";") if one.strip()])
        return (
            f"{self.summary} ({shlex.join(self.argv)}, {count} statement(s)"
            " on standard input)"
        )


@dataclass(frozen=True)
class SeedReplica:
    """Copy the primary into this server, then replicate from the copy

    Carried out by keel.system.dbseed: the primary is dialled and dumped
    with mariadb-dump in one consistent snapshot, and only once the copy
    is on disk are `drop` and the old replication settings discarded, the
    copy loaded and replication started at the dump's GTID position. The
    password reaches the clients in an options file of mode 0600 that is
    removed afterwards, never an argument vector, and neither `repr` nor
    `describe` holds it.
    """

    host: str
    port: int
    password: str = field(repr=False)
    drop: tuple[str, ...] = ()

    def describe(self) -> str:
        dropped = (
            f", then drop {', '.join(self.drop)}" if self.drop else ""
        )
        return (
            f"copy [{self.host}]:{self.port} with mariadb-dump"
            f" --single-transaction --gtid{dropped}, load the copy and the"
            " primary's accounts this server lacks, and replicate from"
            " its GTID position (the credential in an"
            " options file of mode 0600, removed afterwards)"
        )


# Where keel.system.dbreadonly records the accounts it took READ_ONLY
# ADMIN from, relative to the root, so only those get it back.
READ_ONLY_RECORD = "var/lib/keel/database/read-only-admin"


@dataclass(frozen=True)
class LockReplica:
    """Take READ_ONLY ADMIN from every account on this replica that holds
    it, the server's own aside, recording which (keel.system.dbreadonly)

    Asked of the server when it runs, not planned from `accounts`, which
    is what was observed before a seed brought the primary's grants.
    """

    accounts: tuple[str, ...]

    def describe(self) -> str:
        observed = (f" ({', '.join(self.accounts)} before this run)"
                    if self.accounts else "")
        return (
            "revoke READ_ONLY ADMIN, with sql_log_bin off, from every"
            f" account but root, mysql and mariadb.sys at this machine"
            f"{observed}, recorded in /{READ_ONLY_RECORD} so that a"
            " promotion gives it back"
        )


@dataclass(frozen=True)
class UnlockAccounts:
    """Give READ_ONLY ADMIN back to what a replica took it from"""

    def describe(self) -> str:
        return (
            "grant READ_ONLY ADMIN back, with sql_log_bin off, to the"
            f" accounts /{READ_ONLY_RECORD} records, and remove the record"
        )


@dataclass(frozen=True)
class PromoteReplica:
    """Drain, then promote (keel.system.dbreadonly)

    The I/O thread stops first and the SQL thread applies what was
    received, for at most `timeout` seconds: RESET SLAVE ALL discards the
    relay log, and with it anything received and not applied.
    """

    timeout: int

    def describe(self) -> str:
        return (
            "stop the I/O thread, wait up to"
            f" {self.timeout} s for the SQL thread to apply everything it"
            " received, then stop replicating, forget the primary and turn"
            " read_only off"
        )


@dataclass(frozen=True)
class SwitchNetwork:
    """Bring an interface up on a new file, reverting unless confirmed

    Carried out by keel.network.switch (decision 0018): the old file is
    saved and a revert armed before anything is touched, and the change
    stays only if `keel network confirm` arrives over the new
    configuration within `window` seconds. `addresses` are the static
    addresses the new file declares, `gateways` its gateways and
    `old_gateways` those it replaces, which confirm checks against.
    `kind` is keel.network.marker.UPLINK or OVERLAY, the WireGuard
    interface, which wg-quick moves instead of ifupdown. For an overlay,
    `down_before` says it is down now, so its revert leaves it down, and
    `uplink_gateways` are the gateways network.interfaces declares, which
    confirm checks are not routed into the overlay.
    """

    iface: str
    path: str
    content: str
    window: int
    addresses: tuple[str, ...]
    gateways: tuple[str, ...]
    old_gateways: tuple[str, ...]
    kind: str = "uplink"
    down_before: bool = False
    uplink_gateways: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.kind == "overlay":
            return (
                f"bring the overlay {self.iface} up on a new /{self.path}"
                f" (wg-quick down, then up); it reverts in {self.window} s"
                " unless `keel network confirm` is run from a new session,"
                " over the overlay or the uplink"
                + ("; it is down now, and a revert leaves it down"
                   if self.down_before else "")
            )
        return (
            f"bring {self.iface} up on a new /{self.path}; it reverts in"
            f" {self.window} s unless `keel network confirm` is run from a"
            " new session over the new configuration"
        )


@dataclass(frozen=True)
class GenerateKey:
    """Make a WireGuard private key at `path`, 0600, never printed

    Carried out by keel.network.wgkeys on the machine that will use it,
    never under --root: a key made into an image would be shared by every
    appliance built from it (keel-core#8).
    """

    path: str

    def describe(self) -> str:
        return (f"generate this node's WireGuard private key {self.path}"
                " (wg genkey, mode 0600; never printed)")


@dataclass(frozen=True)
class AdoptKey:
    """Move the PrivateKey line of the overlay's file into the key file

    A file wg-quick was given by hand may hold its key inline. keel
    rewrites the file without it, so the key is first written to `path`
    (0600, created exclusively) by keel.network.wgkeys, which reads it
    from `conf` when it runs: the key is never in the plan, an argument
    vector or the output, and the node keeps its public key, which its
    peers know it by. A key file that already holds another key is
    refused, never overwritten.
    """

    conf: str
    path: str

    def describe(self) -> str:
        return (f"move the PrivateKey of /{self.conf} into {self.path} (mode"
                " 0600; never printed), so this node keeps its public key")


@dataclass(frozen=True)
class Note:
    """Nothing to do for this field, and why: unchanged, or not possible"""

    summary: str

    def describe(self) -> str:
        return self.summary


@dataclass(frozen=True)
class Refuse:
    """This field was not converged and the run failed, with the reason

    A Note says there was nothing to do. A Refuse says there was, and that
    apply would not: becoming a replica over a database that holds data,
    demoting a primary, promoting a replica. It counts as a failure, so
    the exit code says the machine does not match the description, and the
    actions after it in the same step are skipped.
    """

    summary: str

    def describe(self) -> str:
        return self.summary


Change = (Run | RunSql | WriteFile | RemoveFile | MakeDir | Symlink
          | SwitchNetwork | GenerateKey | AdoptKey | SeedReplica
          | LockReplica | UnlockAccounts | PromoteReplica | Attempt
          | AddBouncer | SetBouncerMode | InstallRuleset)
Action = Change | Note | Refuse


@dataclass(frozen=True)
class Step:
    """One spec field and the actions that converge it, in order"""

    field: str
    actions: tuple[Action, ...]

    @property
    def changes(self) -> int:
        return sum(
            1 for action in self.actions
            if not isinstance(action, Note | Refuse)
        )


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]

    @property
    def changes(self) -> int:
        return sum(step.changes for step in self.steps)


def unchanged(field: str, detail: str) -> Step:
    return Step(field, (Note(f"unchanged ({detail})"),))
