# Copyright (c) 2026 KeelLinux maintainers
"""The overlay's MTU on the live interface (keel#139)

The file keel writes sets `MTU = 1280` (keel#119), but only `wg-quick
up` reads it: an interface that was up before the line came keeps its
old MTU (1420 on real nodes after the upgrade to 0.23.13), and a change
made live with `wg set` never sets it. `ip link set dev IFACE mtu N`
sets it with no bounce: no peer, no session and no address changes.

`converge` is what the package's postinst runs (`keel network mtu`), so
an upgrade sets it without a reboot; keel spec apply sets it too
(keel.system.overlay), and keel diff reports a live MTU that is not the
file's (keel.diff.handshakes).
"""

import glob
import os
from collections.abc import Callable

from keel.network import wireguard

Reader = Callable[[tuple[str, ...]], str | None]
Runner = Callable[[tuple[str, ...]], str | None]


def mtu_in(text: str) -> int | None:
    """`ip link show` output: the number after `mtu`, None without one"""
    words = text.split()
    for at, word in enumerate(words[:-1]):
        if word == "mtu" and words[at + 1].isdigit():
            return int(words[at + 1])
    return None


def default_output() -> Reader:
    from keel.network import live
    return live.output


def live_mtu(iface: str, output: Reader | None = None) -> int | None:
    """The MTU `iface` has now; None when it is not up or `ip` cannot say"""
    text = (output or default_output())(("ip", "link", "show", "dev", iface))
    return None if text is None else mtu_in(text)


def set_mtu(iface: str, mtu: int) -> tuple[str, ...]:
    return ("ip", "link", "set", "dev", iface, "mtu", str(mtu))


def converge(root: str, output: Reader | None = None,
             run: Runner | None = None) -> list[str]:
    """Each WireGuard interface up whose MTU is not its file's, set live;
    a line for each one set, or that could not be"""
    if run is None:
        from keel.network import live
        run = live.run
    found = []
    pattern = os.path.join(root, wireguard.CONF_DIR, "*.conf")
    for path in sorted(glob.glob(pattern)):
        iface = os.path.basename(path)[:-len(".conf")]
        try:
            with open(path) as fob:
                wanted = wireguard.parse(fob.read()).mtu
        except OSError as e:
            found.append(f"{iface}: /{wireguard.conf_path(iface)} cannot be"
                         f" read: {e.strerror or e}")
            continue
        now = live_mtu(iface, output)
        if wanted is None or now is None or now == wanted:
            continue
        problem = run(set_mtu(iface, wanted))
        found.append(f"{iface}: MTU {now} set to {wanted}, as its file says"
                     f" (ip link set, no restart)" if problem is None else
                     f"{iface}: MTU {now} is not its file's {wanted}, and"
                     f" ip link set failed: {problem}")
    return found
