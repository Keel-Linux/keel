# Copyright (c) 2026 KeelLinux maintainers
"""A peer added and reverted live, on the real wg (keel#99)

Run as root in a network namespace of its own by
tests/test_network_overlay_live_netns.py (tests/wgtools.py says how);
never by hand on a machine. Two WireGuard interfaces in this namespace,
wg0 (keel's, its file under a scratch root) and wg1, are each other's
peer over the loopback, with a keepalive, so they complete a handshake.
Then keel.network.switch, with a runner that hands `wg` its commands
and gives wg-quick the file under the scratch root (systemd's timers
are recorded, not armed):

1. a stray peer set on wg0 by hand, and its MTU set to 1420 by hand
   (an interface up before the file's `MTU = 1280` came, keel#139),
   then a change of wg0's file that
   adds a third peer: no wg-quick, the stray peer is gone (the change
   is made against what `wg show wg0 dump` holds), the interface is the
   same one (its index), its handshake with wg1 is the one from
   before the change, and its MTU is the file's 1280;
2. the revert of that change (`keel network revert`): the same;
3. a change of [Interface] (the port): wg-quick down, then up, and a
   new interface, as before;
4. wg0 at 1420 again, then keel.network.mtu.converge (`keel network
   mtu`, which the package's postinst runs): back to 1280.

The result is one JSON line on standard output, `RESULT {...}`.
"""

import json
import os
import subprocess
import tempfile
import time

# keel.network.confirm and keel.inspect import each other: the
# package's own order first
import keel.commands  # noqa: F401, I001
from keel.network import marker, mtu, switch, wireguard

CONF = wireguard.conf_path("wg0")
THIRD = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
# a peer wg0 holds that no file names: drift, which the change removes
STRAY = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="


def sh(*argv: str) -> str:
    return subprocess.run(argv, capture_output=True, text=True,
                          check=True).stdout


def keypair(path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        subprocess.run(["wg", "genkey"], stdout=fob, check=True)
    with open(path) as fob:
        return subprocess.run(["wg", "pubkey"], stdin=fob, check=True,
                              capture_output=True, text=True).stdout.strip()


class Runner:
    """wg as it is; wg-quick on the file under the root; systemd's
    commands recorded"""

    def __init__(self, root: str):
        self.root = root
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> str | None:
        self.calls.append(argv)
        if argv[0] in ("systemctl", "systemd-run"):
            return None
        if argv[0] == "wg-quick":
            argv = (argv[0], argv[1], os.path.join(self.root, CONF))
        done = subprocess.run(list(argv), capture_output=True, text=True,
                              check=False)
        return (done.stderr.strip() or "failed") if done.returncode else None

    def quick(self) -> list[list[str]]:
        return [list(one[:2]) for one in self.calls if one[0] == "wg-quick"]


def index() -> int:
    """wg0's interface index, which a new interface does not keep (/sys
    is the host's here: `ip` asks this namespace)"""
    return int(sh("ip", "-o", "link", "show", "wg0").split(":", 1)[0])


def handshake(key: str) -> int:
    for line in sh("wg", "show", "wg0", "latest-handshakes").splitlines():
        found, _, at = line.partition("\t")
        if found == key:
            return int(at)
    return -1


def shaken(key: str) -> int:
    """wg0's first handshake with `key`, waited for"""
    for _ in range(100):
        at = handshake(key)
        if at > 0:
            return at
        time.sleep(0.2)
    raise RuntimeError("wg0 and wg1 never completed a handshake")


def state(key: str, run: Runner) -> dict:
    found = {"index": index(), "handshake": handshake(key),
             "mtu": mtu.live_mtu("wg0"),
             "peers": sh("wg", "show", "wg0", "peers").split(),
             "quick": run.quick()}
    run.calls.clear()
    return found


def main() -> None:
    sh("ip", "link", "set", "lo", "up")
    root = tempfile.mkdtemp(prefix="keel-live-")
    zero = keypair(os.path.join(root, "etc/wireguard/wg0.key"))
    one = keypair(os.path.join(root, "wg1.key"))
    overlay = {"address": "fd00:1::1/64", "listen_port": 51821,
               "private_key": {"file": os.path.join(
                   root, "etc/wireguard/wg0.key")},
               "peers": [{"public_key": one, "endpoint": "[::1]:51822",
                          "allowed_ips": ["fd00:2::2/128"],
                          "persistent_keepalive": 1}]}
    before = wireguard.render(overlay)
    with open(os.open(os.path.join(root, CONF), os.O_WRONLY | os.O_CREAT,
                      0o600), "w") as fob:
        fob.write(before)
    other = os.path.join(root, "wg1.conf")
    with open(os.open(other, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(wireguard.render({
            "address": "fd00:2::2/64", "listen_port": 51822,
            "private_key": {"file": os.path.join(root, "wg1.key")},
            "peers": [{"public_key": zero, "endpoint": "[::1]:51821",
                       "allowed_ips": ["fd00:1::1/128"],
                       "persistent_keepalive": 1}]}))
    sh("wg-quick", "up", os.path.join(root, CONF))
    sh("wg-quick", "up", other)
    run = Runner(root)
    report = {"first": {"index": index(), "handshake": shaken(one)}}
    # a new handshake would show a later second
    time.sleep(2)
    added = wireguard.render({**overlay, "peers": overlay["peers"] + [{
        "public_key": THIRD, "allowed_ips": ["fd00:1::3/128"]}]})
    sh("wg", "set", "wg0", "peer", STRAY, "allowed-ips", "fd00:1::9/128")
    # wg0 as an upgrade left it: the file says MTU = 1280, wg0 has 1420
    # (keel#139)
    sh("ip", "link", "set", "dev", "wg0", "mtu", "1420")
    report["file_mtu"] = wireguard.parse(added).mtu
    pending = marker.Pending(iface="wg0", path=CONF, window=120,
                             addresses=("fd00:1::1",), kind=marker.OVERLAY)
    report["change"] = switch.change(root, pending, added, run)
    report["added"] = state(one, run)
    time.sleep(2)
    report["revert"] = switch.revert(root, run)
    report["reverted"] = state(one, run)
    report["third"] = THIRD
    report["stray"] = STRAY
    ported = before.replace("ListenPort = 51821", "ListenPort = 51823")
    report["port_change"] = switch.change(root, pending, ported, run)
    report["ported"] = state(one, run)
    switch.revert(root, run)
    # keel network mtu, which the postinst runs, on wg0 at 1420 again
    sh("ip", "link", "set", "dev", "wg0", "mtu", "1420")
    report["converge_before"] = mtu.live_mtu("wg0")
    report["converge"] = mtu.converge(root)
    report["converge_after"] = mtu.live_mtu("wg0")
    print("RESULT " + json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
