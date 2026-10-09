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
alike. A change that created the file is reverted by removing it. A
change of the peers alone, on an interface that is up, is `wg set` on
it instead, against what `wg show` says it holds, and the file put in
place: the other peers keep their sessions (`live_peers`, keel#99).

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

import ipaddress
import os
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import replace

from keel.inspect.network import slaac_off_in
from keel.network import marker, wireguard

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


def live_peers(old: str, new: str, iface: str, dump: str) -> (
        list[tuple[str, ...]] | None):
    """The `wg set` lines that take `iface`, as `wg show IFACE dump`
    gives it (`dump`), to file `new`, when the files `old` and `new`
    differ in their peers alone; None when the change needs the bounce
    (keel#99)

    `wg-quick down` deletes the interface and every session with it, so
    each peer kept must do a new handshake, and on an etcd voter the
    member lost its leader for about 25 s at each bounce. Here each peer
    the interface holds is compared with the new file: a peer the file
    does not name is removed, a peer the interface lacks is set, and a
    peer that differs gets the fields that differ. So drift of the
    interface is corrected too, as the bounce corrected it (a peer the
    spec names and wg0 lacks, keel#96). The other peers keep their
    sessions. The addresses a peer holds that neither file names were
    set live by another part of keel (a VIP, keel.mesh.vipnet), and are
    kept. An endpoint the file does not name is the one WireGuard
    learned, and is kept.

    The bounce stays for: a change of [Interface] between the files (its
    MTU too, which only wg-quick up sets, keel#119), a
    listen port that is not the file's, a line keel does not write, a
    key named twice, and a change of the addresses of a peer outside
    every prefix of the interface's addresses, which wg-quick routes and
    `wg set` does not.
    """
    before, after = wireguard.parse(old), wireguard.parse(new)
    if before.problems or after.problems or before.inline_key or \
            after.inline_key or before.mtu != after.mtu:
        return None
    if {k: v for k, v in before.section.items() if k != "peers"} != {
            k: v for k, v in after.section.items() if k != "peers"}:
        return None
    if not before.section.get("address") and not before.section.get(
            "ipv4_address"):
        return None
    was, now = by_key(before.section), by_key(after.section)
    live = from_dump(dump)
    if was is None or now is None or live is None:
        return None
    port, held = live
    if port != after.section.get("listen_port", wireguard.DEFAULT_PORT):
        return None
    networks = [ipaddress.ip_interface(str(before.section[name])).network
                for name in ("address", "ipv4_address")
                if before.section.get(name)]
    for key in set(was) | set(now):
        if was.get(key) != now.get(key) and not all(
                on_link(one, networks) for one in (was.get(key),
                                                   now.get(key)) if one):
            return None
    commands: list[tuple[str, ...]] = []
    for key in sorted(set(held) | set(now)):
        if key not in now:
            commands.append(("wg", "set", iface, "peer",
                             held[key]["public_key"], "remove"))
            continue
        old_ips = set(was[key]["allowed_ips"]) if key in was else set()
        found = peer_fix(iface, now[key], held.get(key), old_ips)
        if found:
            commands.append(found)
    return commands


def peer_fix(iface: str, want: dict, have: dict | None,
             old_ips: set[str]) -> tuple[str, ...] | None:
    """The `wg set` line that gives the peer `have` (None: the interface
    lacks it) what the file says (`want`), or None when it has it"""
    wanted = set(want["allowed_ips"])
    if have is None:
        return peer_set(iface, want)
    target = wanted | (have["allowed_ips"] - old_ips - wanted)
    argv = []
    if want.get("endpoint") and want["endpoint"] != have["endpoint"]:
        argv += ["endpoint", want["endpoint"]]
    if target != have["allowed_ips"]:
        argv += ["allowed-ips", ",".join(sorted(target))]
    keepalive = int(want.get("persistent_keepalive") or 0)
    if keepalive != have["persistent_keepalive"]:
        argv += ["persistent-keepalive", str(keepalive or "off")]
    if not argv:
        return None
    return ("wg", "set", iface, "peer", want["public_key"], *argv)


def from_dump(text: str | None) -> tuple[int, dict[bytes, dict]] | None:
    """The listen port and the peers of `wg show IFACE dump`, by their
    key's bytes; None when it cannot be read"""
    lines = [one.split("\t") for one in (text or "").splitlines() if one]
    if not lines or len(lines[0]) != 4 or not lines[0][2].isdigit():
        return None
    peers: dict[bytes, dict] = {}
    for fields in lines[1:]:
        if len(fields) != 8:
            return None
        key = wireguard.key_bytes(fields[0])
        try:
            nets = set() if fields[3] == "(none)" else {
                str(ipaddress.ip_network(one, strict=False))
                for one in fields[3].split(",")}
        except ValueError:
            return None
        keepalive = fields[7]
        if key is None or not (keepalive == "off" or keepalive.isdigit()):
            return None
        peers[key] = {
            "public_key": fields[0], "allowed_ips": nets,
            "endpoint": None if fields[2] == "(none)"
            else wireguard.canonical_endpoint(fields[2]),
            "persistent_keepalive": 0 if keepalive == "off"
            else int(keepalive)}
    return int(lines[0][2]), peers


def wg_dump(iface: str) -> str | None:
    """`wg show IFACE dump`; None when the interface is not up, or wg
    cannot answer"""
    from keel.network import live
    return live.output(("wg", "show", iface, "dump"))


def by_key(section: dict) -> dict[bytes, dict] | None:
    """The peers of a parsed file by their key's bytes, the addresses
    in one spelling; None when a key is no key or is named twice"""
    found: dict[bytes, dict] = {}
    for one in section.get("peers") or []:
        key = wireguard.key_bytes(str(one.get("public_key")))
        if key is None or key in found:
            return None
        try:
            nets = [ipaddress.ip_network(net, strict=False)
                    for net in one.get("allowed_ips") or []]
        except ValueError:
            return None
        found[key] = {**one, "allowed_ips": sorted(str(net) for net in nets),
                      "endpoint": one.get("endpoint") and
                      wireguard.canonical_endpoint(one["endpoint"])}
    return found


def on_link(peer: dict, networks: list) -> bool:
    """Whether every address of `peer` lies in one of `networks`"""
    for text in peer["allowed_ips"]:
        net = ipaddress.ip_network(text)
        if not any(net.version == one.version and net.subnet_of(one)
                   for one in networks):
            return False
    return True


def peer_set(iface: str, peer: dict) -> tuple[str, ...]:
    argv = ["wg", "set", iface, "peer", peer["public_key"]]
    if peer.get("endpoint"):
        argv += ["endpoint", peer["endpoint"]]
    if peer["allowed_ips"]:
        argv += ["allowed-ips", ",".join(peer["allowed_ips"])]
    if peer.get("persistent_keepalive"):
        argv += ["persistent-keepalive", str(peer["persistent_keepalive"])]
    return tuple(argv)


def live_change(root: str, iface: str, relative: str, text: str,
                run: Runner) -> bool:
    """Whether the peers of `text` were set on `iface` live: it is up
    (`wg show` dumps it), and the file there and `text` differ in peers
    alone (`live_peers`). A `wg set` that fails leaves the rest to the
    bounce, on the new file"""
    try:
        current = read_current(root, relative)
    except OSError:
        return False
    if not current:
        return False
    commands = live_peers(current, text, iface, wg_dump(iface) or "")
    if commands is None:
        return False
    return all(run(argv) is None for argv in commands)


def bounce_overlay(root: str, iface: str, relative: str, text: str | None,
                   run: Runner, up: bool = True) -> tuple[bool, str | None]:
    """wg-quick down, the file put in place (or removed), wg-quick up

    `text` None removes the file and leaves the interface down: the
    revert of a change that created the overlay. `up` False puts the file
    back and leaves it down too: the revert of a change to an overlay
    that was down before it. `wg-quick down` failing is not fatal, an
    interface that is not up has nothing to take down; it runs on the
    outgoing file, which is how it finds the routes and hooks to undo.

    A change of the peers alone, on an interface that is up, is made
    live and the file put in place, with no bounce (`live_change`): in
    both directions alike, so the revert of an unconfirmed peer is live
    too. A file that then cannot be put in place gets the bounce on the
    file that is there, so the interface and its file agree again.
    """
    staged = None
    if text is not None:
        staged, problem = stage(root, relative, text, OVERLAY_MODE)
        if problem:
            return False, problem
        if up and live_change(root, iface, relative, text, run):
            problem = rename(staged, root, relative)
            if problem is None:
                return True, None
            run(("wg-quick", "down", iface))
            run(("wg-quick", "up", iface))
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
