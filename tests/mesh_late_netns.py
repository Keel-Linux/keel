# Copyright (c) 2026 KeelLinux maintainers
"""Two members that add each other minutes apart (keel#117)

Run as root in a network namespace of its own by
tests/test_mesh_late_netns.py, with the helpers of tests/mesh_netns.py
and tests/mesh4_netns.py; never by hand on a machine. This namespace is
A; B and C are children joined to it by veths.

On real nodes (handbook PR #62, finding N1), each side of a missing
pair added the other at another time. A new peer was kept only after a
handshake within 120 s, the other side did not have this node yet, so
both reverted and waited an hour, at different times. Here A, B and C
are written by hand with A a peer of both and B and C not peers of each
other, then adopted:

1. `keel mesh create --adopt` on A, then `keel mesh sync --adopt A` on
   B, which takes C from A's roster as a named root and adds it live;
2. LATE seconds after (180 by default), the same on C, which adds B;
3. B and C each say whether they kept the other, and the handshake of
   each with the other, and ping each other over the overlay.

The result is one JSON line on standard output, `RESULT {...}`.
"""

import json
import os
import sys
import time

import mesh4_netns
import mesh_netns
from mesh4_netns import ask, keypair, roots_of, stage, start_adopted
from mesh_netns import (
    PREFIX,
    handshakes,
    link,
    members_service,
    netns_apply,
    node,
    scratch,
    sh,
    utcnow,
)

from keel.mesh import adopt, sync
from keel.network import marker

LINKS = mesh_netns.LINKS
OVERLAY = {"A": f"{PREFIX}::1", "B": f"{PREFIX}::2", "C": f"{PREFIX}::3"}
PEERS = {"A": ("B", "C"), "B": ("A",), "C": ("A",)}
LATE = int(os.environ.get("MESH_LATE", "180"))


def spec(keys: dict[str, str], name: str) -> str:
    lines = ["version: 1", "network:", "  overlay:", "    wireguard:",
             f"      address: {OVERLAY[name]}/64", "      peers:"]
    for other in PEERS[name]:
        lines += [f"      - public_key: {keys[other]}",
                  f"        endpoint: '{mesh4_netns.endpoint(other, name)}'",
                  f"        allowed_ips: [{OVERLAY[other]}/128]"]
    return "\n".join(lines) + "\n"


def inviter() -> None:
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    pids = {name: link(name) for name in ("B", "C")}
    roots, keys, paths = {}, {}, {}
    for name in OVERLAY:
        roots[name], paths[name] = scratch("version: 1\n")
        keys[name] = keypair(roots[name])
    for name in OVERLAY:
        with open(paths[name], "w") as fob:
            fob.write(spec(keys, name))
    report: dict = {"keys": keys, "late_s": LATE}
    a = node(roots["A"], paths["A"])
    netns_apply(a.document(), roots["A"], 120)
    marker.clear(roots["A"])
    journal: list[str] = []
    service, stop = members_service(a, journal.append)
    members = {name: start_adopted(pids[name], roots[name], paths[name])
               for name in ("B", "C")}
    said: list[str] = []
    stage("create --adopt on A")
    report["create"] = adopt.adopt_mesh(
        sync.Syncer(a, utcnow, said.append), said.append)
    started = time.monotonic()
    report["b_adopt"] = ask(members["B"], f"adopt {OVERLAY['A']}", "RESULT")
    report["b_adopt_s"] = round(time.monotonic() - started, 1)
    stage(f"waiting {LATE} s before C adds B")
    time.sleep(max(LATE - (time.monotonic() - started), 0))
    report["c_adopt"] = ask(members["C"], f"adopt {OVERLAY['A']}", "RESULT")
    report["b_check"] = ask(members["B"], f"check {OVERLAY['C']} {keys['C']}",
                            "CHECK")
    report["c_check"] = ask(members["C"], f"check {OVERLAY['B']} {keys['B']}",
                            "CHECK")
    report["handshakes"] = {
        name: ask(members[name], "handshakes", "HANDSHAKES")
        for name in ("B", "C")}
    report["a_handshakes"] = handshakes()
    report["b_roots"] = roots_of(roots["B"])
    for process in members.values():
        process.stdin.close()
        process.wait(60)
    stop.set()
    service.join(30)
    print("RESULT " + json.dumps(report), flush=True)


if __name__ == "__main__":
    try:
        inviter()
    except BaseException:
        import traceback
        for one in mesh_netns.CHILDREN:
            one.kill()
        traceback.print_exc()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(1)
    for one in mesh_netns.CHILDREN:
        one.kill()
