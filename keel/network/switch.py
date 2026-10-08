# Copyright (c) 2026 KeelLinux maintainers
"""Take the interface from one file to another, and arm the way back

The sequence is the same in both directions, a change and its revert, so
neither leaves an address or a DHCP client of the other behind:

1. `ifdown` on the outgoing file, which stops a DHCP client it started
   and withdraws its resolvconf entries; a failure here is not fatal, an
   interface ifupdown-ng does not think is up has nothing to stop;
2. flush the addresses, since an IPv4 address survives a link going
   down, then set the link down, as 01ipconfig does; a failure here is
   reported but does not stop the file being put in place, because a
   revert that stopped here would leave the bad file there;
3. put the new file in place: it was written, with its mode, and synced
   beside the old one before step 1, so a full or read-only /etc is found
   out before the interface is touched, and this step is a rename;
4. `ifup` the interface (ifupdown-ng has no `ifreload`).

The WireGuard overlay (decision 0020) has no ifdown: its sequence is
`wg-quick down` on the outgoing file under /etc/wireguard, which deletes
the interface with its addresses and routes, the new file put in place
the same way, mode 0600, then `wg-quick up` on it; in both directions
alike. A change that created the file is reverted by removing it.

Two transient timers run the revert, both armed before step 1, so a run
that dies half way still reverts:

- the safety timer, for the window plus the time `ifup` may take (a DHCP
  wait), armed first;
- the window timer, armed once the interface is up, for the window
  itself, so the operator gets the whole window to confirm in.

Their names differ from the unit the package ships
(keel-network-revert.service, which covers a reboot inside the window):
systemd refuses a transient unit whose name has a unit file.
"""

import os
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import replace

from keel.inspect.network import slaac_off_in
from keel.network import marker

WINDOW_UNIT = "keel-network-window"
SAFETY_UNIT = "keel-network-window-safety"
UNITS = (WINDOW_UNIT, SAFETY_UNIT)
# how long ifup may take on top of the window: ifupdown-ng waits for a
# DHCP lease, and the safety timer must not fire before the window starts
UP_ALLOWANCE = 60
INTERFACES = marker.UPLINK_FILE

# A command runner: argv in, None on success or what went wrong
Runner = Callable[[tuple[str, ...]], str | None]


def revert_command() -> tuple[str, ...]:
    """What the timers run: this interpreter, so no PATH is involved"""
    return (sys.executable, "-m", "keel", "network", "revert")


def arm(unit: str, seconds: int, run: Runner) -> str | None:
    """Arm one revert timer; a leftover of an earlier run is cleared first

    An elapsed transient timer stays loaded, and systemd refuses a new
    one under a loaded name, so it is stopped as well as reset.
    """
    run(("systemctl", "stop", f"{unit}.timer"))
    run(("systemctl", "reset-failed", f"{unit}.timer", f"{unit}.service"))
    return run((
        "systemd-run", f"--unit={unit}", f"--on-active={seconds}s",
        "--timer-property=AccuracySec=1s",
        "--description=keel: revert an unconfirmed network change",
        *revert_command(),
    ))


def disarm(run: Runner) -> None:
    """Stop both timers; one that fired or never existed is fine"""
    run(("systemctl", "stop", *(f"{unit}.timer" for unit in UNITS)))


FILE_MODE = 0o644
# wg-quick warns about a file others can read, whatever it holds
OVERLAY_MODE = 0o600


def stage(root: str, relative: str, text: str, mode: int = FILE_MODE) -> (
    tuple[str | None, str | None]
):
    """Write `text` beside the file, synced; (its path, or the problem)"""
    target = marker.path(root, relative)
    staged = target + ".keel-new"
    try:
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fob:
            os.fchmod(fob.fileno(), mode)
            fob.write(text)
            fob.flush()
            os.fsync(fob.fileno())
    except OSError as e:
        return None, f"cannot write /{relative}: {e.strerror or e}"
    return staged, None


def put_file(root: str, relative: str, text: str) -> str | None:
    """Stage and rename: the file is either the old one or the new one"""
    staged, problem = stage(root, relative, text)
    if problem:
        return problem
    return rename(staged, root, relative)


def put_back(root: str, target: marker.Target, text: str) -> str | None:
    """The saved file restored, or removed for a change that created it"""
    if target.kind != marker.OVERLAY:
        return put_file(root, target.path, text)
    if target.absent:
        return remove(root, target.path)
    staged, problem = stage(root, target.path, text, OVERLAY_MODE)
    if problem:
        return problem
    return rename(staged, root, target.path)


def remove(root: str, relative: str) -> str | None:
    try:
        os.remove(marker.path(root, relative))
    except FileNotFoundError:
        pass
    except OSError as e:
        return f"cannot remove /{relative}: {e.strerror or e}"
    return None


def rename(staged: str, root: str, relative: str) -> str | None:
    try:
        os.replace(staged, marker.path(root, relative))
    except OSError as e:
        try:
            os.remove(staged)
        except OSError:
            pass
        return f"cannot write /{relative}: {e.strerror or e}"
    return None


def bounce(root: str, iface: str, relative: str, text: str,
           run: Runner, autoconf: str | None = None) -> (
               tuple[bool, str | None]):
    """Down, flush, put `text` in place, up: (whether it is in place, problem)

    A file that cannot even be staged leaves the interface untouched. One
    that stages but cannot be renamed (rare: the same directory) still
    gets `ifup`, on the file that is there, rather than a dead interface.

    `autoconf` is the IPv6 autoconf setting the interface has when no
    file turns SLAAC off (Pending.autoconf). A file with `slaac: false`
    turns it off in pre-up and on in post-down, but ifupdown-ng records
    an interface as up only once post-up succeeds: a pre-up that ran
    before a failed `up` (a DHCP timeout on the other family) leaves
    autoconf at 0 and no post-down to undo it, since `ifdown` skips an
    interface it does not think is up. So before `ifup` on a file that
    does not turn SLAAC off, the setting is written back, whatever the
    outgoing file did (keel#45).
    """
    staged, problem = stage(root, relative, text)
    if problem:
        return False, problem
    run(("ifdown", iface))
    problems = [run(("ip", "address", "flush", "dev", iface))]
    run(("ip", "link", "set", iface, "down"))
    if autoconf is not None and not slaac_off_in(text, iface):
        problems.append(run(("sysctl", "-q", "-w",
                             f"net/ipv6/conf/{iface}/autoconf={autoconf}")))
    problem = rename(staged, root, relative)
    if problem:
        run(("ifup", iface))
        return False, problem
    problems.append(run(("ifup", iface)))
    found = [one for one in problems if one]
    return True, "; ".join(found) or None


def bounce_overlay(root: str, iface: str, relative: str, text: str | None,
                   run: Runner, up: bool = True) -> tuple[bool, str | None]:
    """wg-quick down, the file put in place (or removed), wg-quick up

    `text` None removes the file and leaves the interface down: the
    revert of a change that created the overlay. `up` False puts the file
    back and leaves it down too: the revert of a change to an overlay
    that was down before it. `wg-quick down` failing is not fatal, an
    interface that is not up has nothing to take down; it runs on the
    outgoing file, which is how it finds the routes and hooks to undo.
    """
    staged = None
    if text is not None:
        staged, problem = stage(root, relative, text, OVERLAY_MODE)
        if problem:
            return False, problem
    run(("wg-quick", "down", iface))
    problem = (rename(staged, root, relative) if staged
               else remove(root, relative))
    if problem:
        if up and os.path.exists(marker.path(root, relative)):
            run(("wg-quick", "up", iface))
        return False, problem
    if text is None or not up:
        return True, None
    return True, run(("wg-quick", "up", iface))


def move(root: str, pending: marker.Pending, text: str | None, run: Runner,
         autoconf: str | None = None, back: bool = False) -> (
             tuple[bool, str | None]):
    """The sequence of the change's kind, in either direction

    `back` is a revert: an overlay that was down before the change is
    left down on the restored file.
    """
    if pending.kind == marker.OVERLAY:
        return bounce_overlay(root, pending.iface, pending.path, text, run,
                              not (back and pending.down_before))
    return bounce(root, pending.iface, pending.path, text or "", run,
                  autoconf)


def stage_for(root: str, pending: marker.Pending, text: str) -> (
    tuple[str | None, str | None]
):
    if pending.kind == marker.OVERLAY:
        return stage(root, pending.path, text, OVERLAY_MODE)
    return stage(root, pending.path, text)


def baseline(current: str, iface: str) -> str | None:
    """The autoconf setting to give back to a file that keeps SLAAC

    What the interface has now, unless the outgoing file is the one that
    turned it off: that file's post-down writes 1, so 1 is its baseline.
    None when the interface has no IPv6 settings, and nothing is written.
    """
    now = marker.autoconf(iface)
    if now is None:
        return None
    return "1" if slaac_off_in(current, iface) else now


def restored_autoconf(pending: marker.Pending) -> str | None:
    """The setting a revert writes back; 1, the kernel's default, for a
    marker written before keel recorded one, when the interface has IPv6
    """
    if pending.autoconf is not None:
        return pending.autoconf
    return "1" if marker.autoconf(pending.iface) is not None else None


def read_current(root: str, relative: str) -> str:
    try:
        with open(marker.path(root, relative)) as fob:
            return fob.read()
    except FileNotFoundError:
        return ""


def change(root: str, pending: marker.Pending, text: str,
           run: Runner) -> str | None:
    """Change the network under the window; None when it is up and waiting

    A hangup is ignored while it runs: the operator's session dying as the
    interface moves is expected, and dying half way would leave a change
    nobody can confirm. Only the main thread may set a signal's handler:
    from any other, the members' service applying an announcement in its
    worker (keel.mesh.sync.announced, keel#96), the change runs as it is,
    that thread having no session to lose.
    """
    if threading.current_thread() is not threading.main_thread():
        return changed(root, pending, text, run)
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        return changed(root, pending, text, run)
    finally:
        signal.signal(signal.SIGHUP, previous)


def changed(root: str, pending: marker.Pending, text: str,
            run: Runner) -> str | None:
    boot_id = marker.boot_id()
    if boot_id is None or marker.clock(pending.kind) is None:
        return ("cannot read the boot id or the uptime under /proc, which"
                " date the change for its confirmation; nothing changed")
    with marker.locked(root):
        if marker.exists(root):
            return ("a network change is already waiting for its"
                    " confirmation: keel network confirm, or let it revert")
        try:
            current = read_current(root, pending.path)
        except OSError as e:
            return f"cannot read /{pending.path}: {e.strerror or e}"
        # a file that cannot even be staged is found out before a marker
        # or a timer exists, so nothing is left waiting on a change that
        # never started
        _, problem = stage_for(root, pending, text)
        if problem:
            return f"{problem}; nothing changed"
        pending = prepared(root, pending, current)
        # what ends this change may record nothing (a saved copy gone),
        # so the record of the one before must not answer for it
        problem = marker.forget_last(root)
        if problem:
            return f"{problem}; nothing changed"
        marker.save(root, current, pending.target())
        marker.write(root, pending)
        problem = arm(SAFETY_UNIT, pending.window + UP_ALLOWANCE, run)
        if problem:
            marker.clear(root)
            return f"revert timer not armed, nothing changed: {problem}"
        written, problem = move(root, pending, text, run, pending.autoconf)
        if written and problem is None:
            up_at = marker.clock(pending.kind)
            if up_at is not None:
                # left undated, the change cannot be confirmed and reverts
                marker.write(root, pending.up(boot_id, up_at))
            # if this one fails, the safety timer still reverts, later
            arm(WINDOW_UNIT, pending.window, run)
            return None
        return rolled_back(root, pending, current, problem, run)


def prepared(root: str, pending: marker.Pending, current: str) -> (
    marker.Pending
):
    """What the marker records before the interface moves

    An uplink records the autoconf setting its revert gives back; an
    overlay whether its file existed, since a revert of the change that
    created it removes the file rather than leaving an empty one.
    """
    if pending.kind == marker.OVERLAY:
        return replace(pending, absent=not os.path.exists(
            marker.path(root, pending.path)))
    return replace(pending, autoconf=baseline(current, pending.iface))


def previous(pending: marker.Pending, text: str) -> str | None:
    """The file a revert goes back to; None when there was none"""
    return None if pending.absent else text


def rolled_back(root: str, pending: marker.Pending, current: str,
                problem: str | None, run: Runner) -> str:
    """The new file did not come up: put the old one back at once

    The marker and the timers stay unless the old file is on disk again,
    so the timer, or the boot unit, still has something to restore.
    """
    written, back = move(root, pending, previous(pending, current), run,
                         pending.autoconf, back=True)
    if not written:
        return (f"{problem}; putting the previous file back failed too"
                f" ({back}); the revert timer will try again")
    marker.clear(root)
    disarm(run)
    note = recorded(root, pending.path)
    if back:
        return (f"{problem}; the previous file is back, but bringing the"
                f" interface up on it failed: {back}{note}")
    return f"{problem}; reverted to the previous file{note}"


def recorded(root: str, changed: str) -> str:
    """Record a revert after the marker is gone; "" or "; <why not>"

    A record that cannot be written is said and never fails the revert.
    """
    problem = marker.record(root, marker.REVERTED, changed)
    return f"; {problem}" if problem else ""


def revert(root: str, run: Runner, boot: bool = False) -> tuple[bool, str]:
    """Put the saved file back; (whether it worked, what was done)

    At boot the network is not up yet, so the file is restored and the
    interface left to networking.service; otherwise it is bounced onto
    the restored file. The marker goes only once the saved file is back
    on disk, so a revert that could not write it can be run again, and
    the boot unit still finds it.

    A marker that cannot be read is restored to the file recorded beside
    the saved copy (marker.Target); when that is unknown too, nothing is
    restored rather than a guess: an overlay's file written over
    /etc/network/interfaces would cut the uplink off.
    """
    with marker.locked(root):
        if not marker.exists(root):
            return True, "no network change is waiting; nothing to revert"
        pending = marker.read(root)
        target = pending.target() if pending else marker.saved_target(root)
        if target is None:
            return False, UNKNOWN_TARGET
        text = marker.saved(root)
        if text is None:
            marker.clear(root)
            return False, (f"the saved copy of /{target.path} is missing;"
                           " nothing was restored")
        if boot or pending is None:
            problem = put_back(root, target, text)
            if problem:
                return False, f"cannot restore: {problem}"
            marker.clear(root)
            if boot:
                return True, (f"{restored(target)} before networking"
                              f" starts{recorded(root, target.path)}")
            disarm(run)
            return True, (f"{restored(target)}; the pending change could"
                          " not be read, so no interface was restarted"
                          f"{recorded(root, target.path)}")
        return moved_back(root, pending, text, run)


# what revert says of a marker that names no file it can restore
UNKNOWN_TARGET = (
    "the pending change cannot be read, and what is beside it does not"
    f" say which file the saved copy /{marker.SAVED} belongs to; nothing"
    " was restored. Put it back by hand where it belongs"
    f" (/{marker.UPLINK_FILE} or a file under /etc/wireguard), then"
    f" remove /{marker.PENDING}"
)


def moved_back(root: str, pending: marker.Pending, text: str,
               run: Runner) -> tuple[bool, str]:
    """The live revert of a readable marker: the interface moved back"""
    autoconf = (None if pending.kind == marker.OVERLAY
                else restored_autoconf(pending))
    written, problem = move(root, pending, previous(pending, text), run,
                            autoconf, back=True)
    if not written:
        return False, f"cannot restore: {problem}"
    marker.clear(root)
    disarm(run)
    done = restored(pending.target())
    note = recorded(root, pending.path)
    if problem:
        return False, f"{done}, but {problem}{note}"
    if pending.absent or pending.down_before:
        return True, (f"{done}; {pending.iface} is down, as it was before"
                      f" the change{note}")
    return True, f"{done} and {pending.iface} is up on it{note}"


def restored(target: marker.Target) -> str:
    if target.absent:
        return f"removed /{target.path}, which the change had created"
    return f"restored /{target.path}"
