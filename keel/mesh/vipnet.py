# Copyright (c) 2026 KeelLinux maintainers
"""The VIP on this node's wg0: carried, dropped, routed (decision 0049)

- **The holder carries it** as a second address of wg0, beside its own:
  `ip -6 addr replace <vip>/128 dev wg0 valid_lft N preferred_lft 0
  nodad`. With etcd, N is what is left of the release time after the
  last renewal the majority confirmed (`lifetime`), so the kernel itself
  removes the address by that deadline when no controller renews it: a
  controller restarting, crashed or frozen never leaves it carried past
  it. Without etcd, it is carried for good (no N). A
  deprecated address (`preferred_lft 0`) answers every connection made
  to it and is never chosen as the source of one this node makes, so
  node-to-node traffic keeps the node's own overlay address (0029:
  never the VIP), which the members' channel needs, since a peer knows
  this node by it.
- **Every other node routes it to the holder**: `wg set wg0 peer
  <holder> allowed-ips <holder>/128,<vip>/128`, which also takes it from
  whichever peer had it (WireGuard gives a prefix to one peer only),
  then the same list in /etc/wireguard/wg0.conf, so a restart keeps it.
  The VIP is inside the overlay prefix, which the node's own address
  already routes to wg0: no kernel route changes on any node.

None of this is under 0018's window (0029, extended by 0049): no key,
endpoint, kernel route or node's own address changes. The checks of
apply.md that matter here are keel.mesh.vip.problem's: the VIP is in
the overlay prefix and nobody's address, so it can capture no gateway
and no operator's client.

`run` and `output` are keel.network.live's: None on success, else why
not; standard output, or None.
"""

import os
import re
from collections.abc import Callable

from keel.mesh import vip as vipstate
from keel.network import wireguard
from keel.network.marker import path, write_private
from keel.network.wireguard import allowed, same_key

Run = Callable[[tuple[str, ...]], str | None]
Output = Callable[[tuple[str, ...]], str | None]


# how late the kernel may remove an address whose valid_lft ran out:
# addrconf's check runs at the expiry, rounded up by a quarter of a second
# at most (net/ipv6/addrconf.c, ADDRCONF_TIMER_FUZZ), and every change of
# the address runs it again; a second covers that and a busy workqueue
EXPIRY_SLACK = 1


def host(vip: str) -> str:
    return f"{vip}/{vipstate.HOST}"


def lifetime(age: float) -> int | None:
    """The valid_lft of an address whose last renewal the majority
    confirmed is `age` seconds old: whole seconds, so that the kernel
    removes it, EXPIRY_SLACK late at most, by RELEASE_AFTER after that
    renewal; None when too little is left to carry it at all"""
    if not 0 <= age < vipstate.RELEASE_AFTER:
        return None
    found = int(vipstate.RELEASE_AFTER - age) - EXPIRY_SLACK
    return found if found >= 1 else None


def carried(iface: str, vip: str, output: Output) -> bool | None:
    """Whether wg0 holds `vip`; None when `ip` does not answer"""
    text = output(("ip", "-6", "-o", "addr", "show", "dev", iface))
    if text is None:
        return None
    return any(f" {host(vip)} " in f" {line} " for line in text.splitlines())


def carry(iface: str, vip: str, run: Run,
          valid: int | None = None) -> str | None:
    """`vip` on wg0, for `valid` seconds (the kernel removes it then), or
    for good"""
    bound = () if valid is None else ("valid_lft", str(valid))
    return run(("ip", "-6", "addr", "replace", host(vip), "dev", iface,
                *bound, "preferred_lft", "0", "nodad"))


def bounded(iface: str, vip: str, output: Output) -> bool | None:
    """Whether wg0 carries `vip` with a lifetime the kernel ends; None
    when it does not carry it, or `ip` does not answer"""
    text = output(("ip", "-6", "-o", "addr", "show", "dev", iface))
    for line in (text or "").splitlines():
        if f" {host(vip)} " in f" {line} ":
            found = re.search(r"valid_lft (\S+)", line)
            return bool(found) and found.group(1) != "forever"
    return None


def drop(iface: str, vip: str, run: Run, output: Output) -> str | None:
    """Remove `vip` from wg0 when it is there; None when it is not
    there afterwards"""
    if carried(iface, vip, output) is False:
        return None
    return run(("ip", "-6", "addr", "del", host(vip), "dev", iface))


def live_routes(iface: str, output: Output) -> dict[str, list[str]] | None:
    """`wg show IFACE allowed-ips`: each peer's key to its prefixes"""
    text = output(("wg", "show", iface, "allowed-ips"))
    if text is None:
        return None
    found = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 2:
            found[fields[0]] = [one for one in fields[1].split()
                                if one != "(none)"]
    return found


def routed_to(iface: str, vip: str, output: Output) -> str | None:
    """The peer this node's table routes `vip` to, or None"""
    for key, nets in (live_routes(iface, output) or {}).items():
        if host(vip) in nets:
            return key
    return None


def route(iface: str, overlay: dict, vip: str, holder: str | None,
          run: Run, output: Output) -> list[str]:
    """This node's table routing `vip` to the peer `holder`, or to no
    peer when the holder is this node or not a peer; the problems, each
    a `wg set` that failed

    Only the peers whose prefixes involve the VIP are set, each to the
    spec's prefixes, the VIP added for the holder."""
    live = live_routes(iface, output)
    if live is None:
        return [f"wg show {iface} did not answer: is the overlay up?"]
    problems = []
    for peer in overlay.get("peers") or []:
        key = str(peer.get("public_key"))
        wanted = allowed(peer)
        if holder is not None and same_key(key, holder):
            wanted = wanted + [host(vip)]
        now = next((nets for one, nets in live.items()
                    if same_key(one, key)), None)
        if now is None or (host(vip) not in now and host(vip) not in
                           wanted) or sorted(now) == sorted(wanted):
            continue
        problem = run(("wg", "set", iface, "peer", key, "allowed-ips",
                       ",".join(wanted)))
        if problem:
            problems.append(problem)
    return problems


def written(root: str, overlay: dict) -> str | None:
    """/etc/wireguard/<iface>.conf as apply renders it, each VIP routed
    to its holder (keel.mesh.vip.routed_here), when it differs from the
    file; None, or why it could not be written"""
    iface = wireguard.interface(overlay)
    relative = wireguard.conf_path(iface)
    text = wireguard.render(vipstate.routed_here(overlay, root))
    try:
        with open(path(root, relative)) as fob:
            if fob.read() == text:
                return None
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"/{relative}: {e.strerror or e}"
    try:
        write_private(os.path.dirname(path(root, relative)),
                      os.path.basename(relative), text)
    except OSError as e:
        return f"/{relative}: {e.strerror or e}"
    return None
