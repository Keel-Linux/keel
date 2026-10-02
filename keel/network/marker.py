# Copyright (c) 2026 KeelLinux maintainers
"""The pending change and its lock, under /var/lib/keel/network

A change saves the file it replaces and writes `pending.json` before it
touches the interface. Whoever holds the lock may change, confirm or
revert; the other two wait for it and then find the marker gone or still
there. So a revert that has started finishes before a confirmation is
looked at, and the confirmation then finds nothing to confirm instead of
reporting success on the old network.

The marker records, once the interface is up on the new file, the boot
it happened in and the time since that boot. A session's age is compared
with that, a clock that does not jump when the wall clock is set.
"""

import fcntl
import json
import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone

DIR = "var/lib/keel/network"
LOCK = f"{DIR}/lock"
PENDING = f"{DIR}/pending.json"
SAVED = f"{DIR}/saved"
# which file SAVED is a copy of, apart from PENDING (Target)
TARGET = f"{DIR}/saved.json"
# how the last change ended (Last), which outlives the marker
LAST = f"{DIR}/last.json"
CONFIRMED = "confirmed"
REVERTED = "reverted"
OUTCOMES = (CONFIRMED, REVERTED)
UPLINK_FILE = "etc/network/interfaces"
# an overlay's file: wg-quick's rule for the interface name
OVERLAY_FILE_RE = re.compile(r"^etc/wireguard/[A-Za-z0-9_=+.-]{1,15}\.conf$")
DIR_MODE = 0o700
FILE_MODE = 0o600
BOOT_ID = "proc/sys/kernel/random/boot_id"
UPTIME = "proc/uptime"
AUTOCONF = "proc/sys/net/ipv6/conf/{iface}/autoconf"
UPLINK = "uplink"
OVERLAY = "overlay"
KINDS = (UPLINK, OVERLAY)
# /proc/PID/stat after the command name: the start time is index 19, as
# keel.network.session reads a session's
STARTTIME_INDEX = 19


@dataclass(frozen=True)
class Pending:
    """A change waiting for its confirmation

    `path` is the file the change replaced, relative to the root, and
    SAVED holds what it said before. `addresses` are the static addresses
    the new file declares; `gateways` the new gateways and `old_gateways`
    the ones they replaced, so confirm can say whether it tested them.
    `changed_at` is None until the interface is up on the new file.
    `autoconf` is the interface's IPv6 autoconf setting when no file of
    keel turns SLAAC off, read before the change (keel.network.switch
    writes it back), or None when the interface has no IPv6 settings.

    `kind` says which sequence moves the interface: UPLINK, ifupdown on
    /etc/network/interfaces, or OVERLAY, wg-quick on a file under
    /etc/wireguard (decision 0020). `absent` is a change that created its
    file: its revert removes the file instead of restoring an empty one.
    `down_before` is an overlay that was down before the change: its
    revert puts the file back and leaves it down. `uplink_gateways` are
    the gateways network.interfaces declares, IPv6 first, which confirm
    checks an overlay change has not routed into the overlay.
    """

    iface: str
    path: str
    window: int
    addresses: tuple[str, ...] = ()
    gateways: tuple[str, ...] = ()
    old_gateways: tuple[str, ...] = ()
    boot_id: str | None = None
    changed_at: float | None = None
    autoconf: str | None = None
    kind: str = UPLINK
    absent: bool = False
    down_before: bool = False
    uplink_gateways: tuple[str, ...] = ()

    def up(self, boot_id: str, uptime: float) -> "Pending":
        return replace(self, boot_id=boot_id, changed_at=uptime)

    def target(self) -> "Target":
        return Target(self.path, self.kind, self.absent)


@dataclass(frozen=True)
class Target:
    """The file the saved copy belongs to, recorded beside the copy

    Written apart from the marker, so a marker that cannot be read still
    says where its saved copy goes back to, and a revert never restores
    an overlay's file over /etc/network/interfaces or the reverse.
    """

    path: str
    kind: str = UPLINK
    absent: bool = False


def path(root: str, relative: str) -> str:
    return os.path.join(root, relative)


@contextmanager
def locked(root: str) -> Iterator[None]:
    """Hold the one lock a change, a confirmation and a revert share"""
    os.makedirs(path(root, DIR), mode=DIR_MODE, exist_ok=True)
    fd = os.open(path(root, LOCK), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read(root: str) -> Pending | None:
    """The pending change, or None; a marker that cannot be parsed is None

    An unreadable marker is not a change anyone can confirm, and the
    saved file next to it is what `revert` restores either way.
    """
    try:
        with open(path(root, PENDING)) as fob:
            data = json.load(fob)
    except (OSError, ValueError):
        return None
    try:
        return Pending(
            iface=str(data["iface"]),
            path=str(data["path"]),
            window=int(data["window"]),
            addresses=tuple(data.get("addresses") or ()),
            gateways=tuple(data.get("gateways") or ()),
            old_gateways=tuple(data.get("old_gateways") or ()),
            boot_id=data.get("boot_id"),
            changed_at=data.get("changed_at"),
            autoconf=data.get("autoconf"),
            kind=kind(data.get("kind")),
            absent=bool(data.get("absent")),
            down_before=bool(data.get("down_before")),
            uplink_gateways=tuple(data.get("uplink_gateways") or ()),
        )
    except (KeyError, TypeError, ValueError):
        return None


def kind(value: object) -> str:
    """A marker written before there was an overlay is an uplink change"""
    if value is None:
        return UPLINK
    if value not in KINDS:
        raise ValueError(f"unknown kind {value!r}")
    return str(value)


def exists(root: str) -> bool:
    """Whether a change is pending, parsed or not"""
    return os.path.exists(path(root, PENDING))


def write(root: str, pending: Pending) -> None:
    write_private(root, PENDING, json.dumps(asdict(pending), indent=2) + "\n")


def save(root: str, text: str, target: Target | None = None) -> None:
    """Keep the file the change replaces, and which file it is

    Without `target`, a revert of a marker that cannot be read restores
    nothing: it cannot know which file the copy belongs to.
    """
    write_private(root, SAVED, text)
    if target is not None:
        write_private(root, TARGET, json.dumps(asdict(target)) + "\n")


def saved_target(root: str) -> Target | None:
    """The file the saved copy belongs to; None when it cannot be known

    Only the two files a change replaces are accepted, each with its own
    kind, so a damaged record never sends a revert anywhere else.
    """
    try:
        with open(path(root, TARGET)) as fob:
            data = json.load(fob)
        found = Target(str(data["path"]), kind(data.get("kind")),
                       bool(data.get("absent")))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    wanted = (found.path == UPLINK_FILE if found.kind == UPLINK
              else OVERLAY_FILE_RE.match(found.path) is not None)
    return found if wanted else None


def saved(root: str) -> str | None:
    try:
        with open(path(root, SAVED)) as fob:
            return fob.read()
    except OSError:
        return None


@dataclass(frozen=True)
class Last:
    """How the last change ended, kept after its marker is gone

    Without it, a confirm that found nothing waiting could not tell a
    change another session had confirmed from one that had reverted, and
    said reverted (the maintainer's screenshot 040). `at` is UTC.
    """

    outcome: str
    path: str
    at: str


def record(root: str, outcome: str, changed: str) -> str | None:
    """Keep how a change ended: CONFIRMED or REVERTED, and its file

    Called once the marker is gone and the timers are disarmed, so a
    record that cannot be written (a full disk) never keeps a change
    pending or reverts one that was confirmed: it returns the note that
    says so, and the change's own outcome stands.
    """
    at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        write_private(root, LAST,
                      json.dumps(asdict(Last(outcome, changed, at))) + "\n")
    except OSError as e:
        return (f"how this change ended could not be recorded in /{LAST}"
                f" ({e.strerror or e}): a later keel network confirm cannot"
                " say it")
    return None


def forget_last(root: str) -> str | None:
    """A new change is armed: the record of the one before no longer
    answers for what is pending, whatever ends it. None, or why the
    record could not be removed"""
    try:
        os.remove(path(root, LAST))
    except FileNotFoundError:
        pass
    except OSError as e:
        return f"cannot remove /{LAST}: {e.strerror or e}"
    return None


def last(root: str) -> Last | None:
    """How the last change ended; None when that is not known"""
    try:
        with open(path(root, LAST)) as fob:
            data = json.load(fob)
        found = Last(str(data["outcome"]), str(data["path"]),
                     str(data["at"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return found if found.outcome in OUTCOMES else None


def clear(root: str) -> None:
    """Remove the marker and the saved file: confirmed, or reverted"""
    for relative in (PENDING, SAVED, TARGET):
        try:
            os.remove(path(root, relative))
        except FileNotFoundError:
            pass


def write_private(root: str, relative: str, text: str) -> None:
    """Write through a temporary file, so a crash leaves the old or the new"""
    target = path(root, relative)
    os.makedirs(os.path.dirname(target), mode=DIR_MODE, exist_ok=True)
    temporary = target + ".new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(fd, "w") as fob:
        fob.write(text)
        fob.flush()
        os.fsync(fob.fileno())
    os.replace(temporary, target)


def boot_id(proc_root: str = "/") -> str | None:
    try:
        with open(path(proc_root, BOOT_ID)) as fob:
            return fob.read().strip() or None
    except OSError:
        return None


def autoconf(iface: str, proc_root: str = "/") -> str | None:
    """The interface's IPv6 autoconf setting now, or None without one"""
    try:
        with open(path(proc_root, AUTOCONF.format(iface=iface))) as fob:
            value = fob.read().strip()
    except OSError:
        return None
    return value if value in ("0", "1") else None


def uptime(proc_root: str = "/") -> float | None:
    try:
        with open(path(proc_root, UPTIME)) as fob:
            return float(fob.read().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def process_clock(proc_root: str = "/") -> float | None:
    """Now, on the clock a session's start time is read on

    The start time of a thread started for the purpose, in seconds since
    boot, which is exactly what keel.network.session reads off an
    `sshd-session`. /proc/uptime is not that clock in a container: lxcfs
    counts it from the container's start while process start times count
    from the host's boot, so a change dated by it could not be told from
    a session opened before it. The overlay is converged in containers
    (decision 0018), so its changes are dated here.
    """
    found: list[float | None] = []
    worker = threading.Thread(target=lambda: found.append(
        thread_started(proc_root, threading.get_native_id())))
    worker.start()
    worker.join()
    return found[0] if found else None


def thread_started(proc_root: str, tid: int) -> float | None:
    try:
        with open(path(proc_root, f"proc/self/task/{tid}/stat")) as fob:
            stat = fob.read()
        rest = stat[stat.rindex(")") + 2:].split()
        return int(rest[STARTTIME_INDEX]) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def clock(kind_of: str) -> float | None:
    """The time a change of this kind is dated with"""
    return process_clock() if kind_of == OVERLAY else uptime()
