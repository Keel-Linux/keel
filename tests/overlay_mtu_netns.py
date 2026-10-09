# Copyright (c) 2026 KeelLinux maintainers
"""The members' answer through wg0 on a path of 1492 bytes (keel#119)

Run as root in a network namespace of its own by
tests/test_network_overlay_mtu_netns.py (tests/wgtools.py says how);
never by hand on a machine. This namespace is node A, on an uplink of
1500 bytes. A child namespace is node B, behind a link of 1492 bytes
(PPPoE, as at site BR2), joined to A by a veth: a packet longer than
1492 bytes from A to B is dropped there, and no ICMPv6 "packet too big"
comes back, as when a router's ICMPv6 is lost or rate limited.

wg-quick brings wg0 up on each node from a file keel renders, with the
real wg and the wireguard module. A serves a 4 KiB answer on its overlay
address, TCP 51821, as the members' channel does; B asks for it with a
deadline. That is done twice:

- `keel`: the files exactly as keel.network.wireguard renders them;
- `plain`: the same files without the MTU line, as keel 0.23.7 wrote
  them. wg-quick then takes the MTU of the route to the endpoint less
  80: 1420 on A, 1412 on B. WireGuard pads a packet to a multiple of 16
  bytes, up to the MTU of wg0, so A sends a full segment as 1500 bytes
  on the wire, which the link to B drops.

The result is one JSON line on standard output, `RESULT {...}`.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

from keel.network import wireguard

LINK = "fd00:119::"
OVERLAY = "fd11:119::"
PORT = 51821
ANSWER = 4096
DEADLINE = 5.0
NARROW = 1492


def sh(*argv: str, pid: int | None = None) -> str:
    prefix = ["nsenter", "-t", str(pid), "-n"] if pid else []
    return subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, check=True).stdout


def keypair(path: str) -> str:
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        subprocess.run(["wg", "genkey"], stdout=fob, check=True)
    with open(path) as fob:
        return subprocess.run(["wg", "pubkey"], stdin=fob, check=True,
                              capture_output=True, text=True).stdout.strip()


def child() -> tuple[subprocess.Popen, int]:
    """Node B, joined to here by a veth whose far end is 1492 bytes"""
    node = subprocess.Popen(["unshare", "-n", "sleep", "300"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    pid = node.pid
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "link", "add", "tob", "type", "veth", "peer", "name", "uplink")
    sh("ip", "link", "set", "uplink", "netns", str(pid))
    sh("ip", "-6", "address", "add", f"{LINK}1/64", "dev", "tob", "nodad")
    sh("ip", "link", "set", "tob", "up")
    for argv in (("ip", "link", "set", "lo", "up"),
                 ("ip", "link", "set", "uplink", "mtu", str(NARROW)),
                 ("ip", "-6", "address", "add", f"{LINK}2/64", "dev",
                  "uplink", "nodad"),
                 ("ip", "link", "set", "uplink", "up")):
        sh(*argv, pid=pid)
    return node, pid


def files(tmp: str) -> dict[str, str]:
    """The wg0 file of each node, as keel renders it"""
    keys = {name: os.path.join(tmp, f"{name}.key") for name in "ab"}
    public = {name: keypair(path) for name, path in keys.items()}
    found = {}
    for here, there, own, end in (("a", "b", "1", "2"),
                                  ("b", "a", "2", "1")):
        found[here] = wireguard.render({
            "address": f"{OVERLAY}{own}/64",
            "private_key": {"file": keys[here]},
            "peers": [{"public_key": public[there],
                       "endpoint": f"[{LINK}{end}]:51820",
                       "allowed_ips": [f"{OVERLAY}{end}/128"],
                       "persistent_keepalive": 1}],
        })
    return found


def without_mtu(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True)
                   if not line.startswith("MTU ="))


def serve(stop: threading.Event) -> None:
    """A's answer: 4 KiB to whoever sends a line"""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((f"{OVERLAY}1", PORT))
    server.listen(4)
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            raw, _ = server.accept()
        except TimeoutError:
            continue
        with raw:
            raw.settimeout(DEADLINE)
            try:
                raw.recv(512)
                raw.sendall(b"x" * ANSWER)
            except OSError:
                pass
    server.close()


ASK = f"""
import socket, time
start = time.monotonic()
got = b""
try:
    raw = socket.create_connection(("{OVERLAY}1", {PORT}), {DEADLINE})
    raw.settimeout({DEADLINE})
    raw.sendall(b"GET /v1/members\\n")
    while len(got) < {ANSWER}:
        part = raw.recv(65536)
        if not part:
            break
        got += part
except OSError:
    pass
print(len(got), round(time.monotonic() - start, 2))
"""


def mtu(pid: int | None) -> int:
    fields = sh("ip", "-o", "link", "show", "dev", "wg0", pid=pid).split()
    return int(fields[fields.index("mtu") + 1])


def attempt(tmp: str, pid: int, texts: dict[str, str]) -> dict:
    paths = {}
    for name, text in texts.items():
        os.makedirs(os.path.join(tmp, name), exist_ok=True)
        paths[name] = os.path.join(tmp, name, "wg0.conf")
        with open(os.open(paths[name], os.O_WRONLY | os.O_CREAT |
                          os.O_TRUNC, 0o600), "w") as fob:
            fob.write(text)
    sh("wg-quick", "up", paths["a"])
    sh("wg-quick", "up", paths["b"], pid=pid)
    stop = threading.Event()
    server = threading.Thread(target=serve, args=(stop,))
    server.start()
    try:
        # a handshake first, so the deadline is for the answer alone
        sh("ping", "-6", "-c", "3", "-W", "2", f"{OVERLAY}1", pid=pid)
        size, seconds = sh(sys.executable, "-c", ASK, pid=pid).split()
        return {"received": int(size), "seconds": float(seconds),
                "mtu_a": mtu(None), "mtu_b": mtu(pid)}
    finally:
        stop.set()
        server.join()
        sh("wg-quick", "down", paths["a"])
        sh("wg-quick", "down", paths["b"], pid=pid)


def main() -> None:
    node, pid = child()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            texts = files(tmp)
            plain = attempt(tmp, pid, {name: without_mtu(text)
                                       for name, text in texts.items()})
            time.sleep(0.5)
            keel = attempt(tmp, pid, texts)
    finally:
        node.kill()
        node.wait()
    print("RESULT " + json.dumps({"plain": plain, "keel": keel,
                                  "answer": ANSWER}), flush=True)


if __name__ == "__main__":
    main()
