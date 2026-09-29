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
from collections.abc import Callable

from keel.network import marker

WINDOW_UNIT = "keel-network-window"
SAFETY_UNIT = "keel-network-window-safety"
UNITS = (WINDOW_UNIT, SAFETY_UNIT)
# how long ifup may take on top of the window: ifupdown-ng waits for a
# DHCP lease, and the safety timer must not fire before the window starts
UP_ALLOWANCE = 60
INTERFACES = "etc/network/interfaces"

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


def stage(root: str, relative: str, text: str) -> tuple[str | None, str | None]:
    """Write `text` beside the file, synced; (its path, or the problem)"""
    target = marker.path(root, relative)
    staged = target + ".keel-new"
    try:
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        with os.fdopen(fd, "w") as fob:
            os.fchmod(fob.fileno(), FILE_MODE)
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


def rename(staged: str, root: str, relative: str) -> str | None:
    try:
        os.replace(staged, marker.path(root, relative))
    except OSError as e:
        return f"cannot write /{relative}: {e.strerror or e}"
    return None


def bounce(root: str, iface: str, relative: str, text: str,
           run: Runner) -> tuple[bool, str | None]:
    """Down, flush, put `text` in place, up: (whether it is in place, problem)

    A file that cannot even be staged leaves the interface untouched. One
    that stages but cannot be renamed (rare: the same directory) still
    gets `ifup`, on the file that is there, rather than a dead interface.
    """
    staged, problem = stage(root, relative, text)
    if problem:
        return False, problem
    run(("ifdown", iface))
    problems = [run(("ip", "address", "flush", "dev", iface))]
    run(("ip", "link", "set", iface, "down"))
    problem = rename(staged, root, relative)
    if problem:
        run(("ifup", iface))
        return False, problem
    problems.append(run(("ifup", iface)))
    found = [one for one in problems if one]
    return True, "; ".join(found) or None


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
    nobody can confirm.
    """
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        return changed(root, pending, text, run)
    finally:
        signal.signal(signal.SIGHUP, previous)


def changed(root: str, pending: marker.Pending, text: str,
            run: Runner) -> str | None:
    boot_id = marker.boot_id()
    if boot_id is None or marker.uptime() is None:
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
        marker.save(root, current)
        marker.write(root, pending)
        problem = arm(SAFETY_UNIT, pending.window + UP_ALLOWANCE, run)
        if problem:
            marker.clear(root)
            return f"revert timer not armed, nothing changed: {problem}"
        written, problem = bounce(root, pending.iface, pending.path, text,
                                  run)
        if written and problem is None:
            up_at = marker.uptime()
            if up_at is not None:
                # left undated, the change cannot be confirmed and reverts
                marker.write(root, pending.up(boot_id, up_at))
            # if this one fails, the safety timer still reverts, later
            arm(WINDOW_UNIT, pending.window, run)
            return None
        return rolled_back(root, pending, current, problem, run)


def rolled_back(root: str, pending: marker.Pending, current: str,
                problem: str | None, run: Runner) -> str:
    """The new file did not come up: put the old one back at once

    The marker and the timers stay unless the old file is on disk again,
    so the timer, or the boot unit, still has something to restore.
    """
    written, back = bounce(root, pending.iface, pending.path, current, run)
    if not written:
        return (f"{problem}; putting the previous file back failed too"
                f" ({back}); the revert timer will try again")
    marker.clear(root)
    disarm(run)
    if back:
        return (f"{problem}; the previous file is back, but bringing the"
                f" interface up on it failed: {back}")
    return f"{problem}; reverted to the previous file"


def revert(root: str, run: Runner, boot: bool = False) -> tuple[bool, str]:
    """Put the saved file back; (whether it worked, what was done)

    At boot the network is not up yet, so the file is restored and the
    interface left to networking.service; otherwise it is bounced onto
    the restored file. The marker goes only once the saved file is back
    on disk, so a revert that could not write it can be run again, and
    the boot unit still finds it.
    """
    with marker.locked(root):
        if not marker.exists(root):
            return True, "no network change is waiting; nothing to revert"
        pending = marker.read(root)
        text = marker.saved(root)
        relative = pending.path if pending else INTERFACES
        if text is None:
            marker.clear(root)
            return False, (f"the saved copy of /{relative} is missing;"
                           " nothing was restored")
        if boot or pending is None:
            problem = put_file(root, relative, text)
            if problem:
                return False, f"cannot restore: {problem}"
            marker.clear(root)
            if boot:
                return True, f"restored /{relative} before networking starts"
            disarm(run)
            return True, (f"restored /{relative}; the pending change could"
                          " not be read, so no interface was restarted")
        written, problem = bounce(root, pending.iface, relative, text, run)
        if not written:
            return False, f"cannot restore: {problem}"
        marker.clear(root)
        disarm(run)
        if problem:
            return False, f"restored /{relative}, but {problem}"
        return True, f"restored /{relative} and {pending.iface} is up on it"
