# Copyright (c) 2026 KeelLinux maintainers
"""Take the interface from one file to another, and arm the way back

The sequence is the same in both directions, a change and its revert, so
neither leaves an address or a DHCP client of the other behind:

1. `ifdown` on the outgoing file, which stops a DHCP client it started
   and withdraws its resolvconf entries; a failure here is not fatal, an
   interface ifupdown-ng does not think is up has nothing to stop;
2. flush the addresses, since an IPv4 address survives a link going
   down, then set the link down, as 01ipconfig does;
3. write the new file;
4. `ifup` the interface (ifupdown-ng has no `ifreload`).

The revert timer is a transient systemd unit armed before step 1, so a
run that dies half way still reverts; the unit shipped in the package
(debian/keel.keel-network-revert.service) covers a reboot inside the
window, since a transient timer does not survive one.
"""

import os
import sys
from collections.abc import Callable

from keel.network import marker

UNIT = "keel-network-revert"
INTERFACES = "etc/network/interfaces"

# A command runner: argv in, None on success or what went wrong
Runner = Callable[[tuple[str, ...]], str | None]


def revert_command() -> tuple[str, ...]:
    """What the timer runs: this interpreter, so no PATH is involved"""
    return (sys.executable, "-m", "keel", "network", "revert")


def arm(window: int, run: Runner) -> str | None:
    """Arm the revert; a leftover unit of an earlier run is reset first"""
    run(("systemctl", "reset-failed", f"{UNIT}.timer", f"{UNIT}.service"))
    return run((
        "systemd-run", f"--unit={UNIT}", f"--on-active={window}s",
        "--timer-property=AccuracySec=1s",
        "--description=keel: revert an unconfirmed network change",
        *revert_command(),
    ))


def disarm(run: Runner) -> None:
    """Stop the timer; one that already fired or never existed is fine"""
    run(("systemctl", "stop", f"{UNIT}.timer"))


def bounce(root: str, iface: str, relative: str, text: str,
           run: Runner) -> str | None:
    """Down on the file in place, flush, write `text`, up on it"""
    run(("ifdown", iface))
    problem = run(("ip", "address", "flush", "dev", iface))
    if problem:
        return problem
    run(("ip", "link", "set", iface, "down"))
    try:
        marker.write_private(root, relative, text)
        os.chmod(marker.path(root, relative), 0o644)
    except OSError as e:
        return f"cannot write /{relative}: {e.strerror or e}"
    return run(("ifup", iface))


def read_current(root: str, relative: str) -> str:
    try:
        with open(marker.path(root, relative)) as fob:
            return fob.read()
    except FileNotFoundError:
        return ""


def change(root: str, pending: marker.Pending, text: str,
           run: Runner) -> str | None:
    """Change the network under the window; None when it is up and waiting

    An `ifup` that fails on the new file reverts at once instead of
    leaving the machine without a network for the rest of the window.
    """
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
        problem = arm(pending.window, run)
        if problem:
            marker.clear(root)
            return f"revert timer not armed, nothing changed: {problem}"
        problem = bounce(root, pending.iface, pending.path, text, run)
        if problem:
            back = bounce(root, pending.iface, pending.path, current, run)
            marker.clear(root)
            disarm(run)
            outcome = ("reverted to the previous file" if back is None
                       else f"and the revert failed too: {back}")
            return f"{problem}; {outcome}"
        marker.write(root, pending.up(marker.boot_id() or "",
                                      marker.uptime() or 0.0))
    return None


def revert(root: str, run: Runner, boot: bool = False) -> tuple[bool, str]:
    """Put the saved file back; (whether it worked, what was done)

    At boot the network is not up yet, so the file is restored and the
    interface left to networking.service; otherwise it is bounced onto
    the restored file. Either way the marker goes, and a second revert
    finds nothing to do.
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
            try:
                marker.write_private(root, relative, text)
                os.chmod(marker.path(root, relative), 0o644)
            except OSError as e:
                return False, f"cannot restore /{relative}: {e.strerror or e}"
            marker.clear(root)
            if boot:
                return True, f"restored /{relative} before networking starts"
            return True, (f"restored /{relative}; the pending change could"
                          " not be read, so no interface was restarted")
        problem = bounce(root, pending.iface, relative, text, run)
        marker.clear(root)
        disarm(run)
        if problem:
            return False, f"restored /{relative}, but {problem}"
        return True, f"restored /{relative} and {pending.iface} is up on it"
