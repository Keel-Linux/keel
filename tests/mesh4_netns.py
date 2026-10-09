# Copyright (c) 2026 KeelLinux maintainers
"""Four nodes in four network namespaces: a join into a mesh built by hand

Run as root in a network namespace of its own by
tests/test_mesh4_netns.py, as tests/mesh_netns.py is, with its helpers.
This namespace is node 1 (A); B, C and D are children joined to it by
veths, with a default route through A.

keel#99 on real nodes: web-1, web-2 and web-3 were a mesh built by hand,
made one with `keel mesh create --adopt` on web-1 and `keel mesh sync
--adopt` on the others, so each holds the others as trust roots with no
admission evidence. db-1, invited by web-1, took only web-1 as a peer,
while web-2 and web-3 took db-1 from web-1's announcement and then
waited in vain for its handshake. Here:

1. A, B and C are written by hand as a full mesh and brought up;
   `keel mesh create --adopt` runs on A, `keel mesh sync --adopt A` on
   B, then on C;
2. A invites, and D joins through A's listener;
3. A announces D to B and C, and each confirms D by D's handshake;
4. every node pings the three others over the overlay, and each says
   the latest WireGuard handshake of each of its three peers.

The result is one JSON line on standard output, `RESULT {...}`.
"""

import json
import os
import subprocess
import sys
import threading
import traceback

import mesh_netns
from mesh_netns import (
    PREFIX,
    Recorder,
    Spawned,
    commands,
    handshakes,
    invite,
    link,
    listening,
    members_service,
    netns_apply,
    node,
    ping,
    result,
    run_joiner,
    scratch,
    sh,
    utcnow,
)

from keel.mesh import adopt, inviting, sync, trust
from keel.mesh.token import parse
from keel.network import marker

# B and C are what mesh_netns has; D is the fourth
mesh_netns.LINKS["D"] = "2001:db8:e2e:3"
LINKS = mesh_netns.LINKS
OVERLAY = {"A": f"{PREFIX}::1", "B": f"{PREFIX}::2", "C": f"{PREFIX}::3"}


def keypair(root: str) -> str:
    """A key under the node's scratch root; its public key"""
    path = os.path.join(root, "etc/wireguard/wg0.key")
    os.makedirs(os.path.dirname(path))
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        subprocess.run(["wg", "genkey"], stdout=fob, check=True)
    with open(path) as fob:
        return subprocess.run(["wg", "pubkey"], stdin=fob, check=True,
                              capture_output=True, text=True).stdout.strip()


def endpoint(name: str, seen_from: str) -> str:
    """Where `seen_from` reaches `name`: A on the veth of the other's
    link, a child on its own link's address"""
    if name == "A":
        return f"[{LINKS[seen_from]}::1]:51820"
    return f"[{LINKS[name]}::2]:51820"


def by_hand(keys: dict[str, str], name: str) -> str:
    """The spec of `name` in the mesh built by hand: the other two as
    peers, as an operator wrote them before keel mesh"""
    lines = ["version: 1", "network:", "  overlay:", "    wireguard:",
             f"      address: {OVERLAY[name]}/64", "      peers:"]
    for other in sorted(set(OVERLAY) - {name}):
        lines += [f"      - public_key: {keys[other]}",
                  f"        endpoint: '{endpoint(other, name)}'",
                  f"        allowed_ips: [{OVERLAY[other]}/128]"]
    return "\n".join(lines) + "\n"


def adopted(root: str, path: str) -> None:
    """In B's or C's namespace: up on the spec by hand, the members'
    channel served, then `keel mesh sync --adopt ADDRESS` when the
    driver says `adopt ADDRESS`, then the driver's commands"""
    here = node(root, path)
    netns_apply(here.document(), root, 120)
    marker.clear(root)
    log: list[str] = []

    def logged(line: str) -> None:
        log.append(line)
        print(line, file=sys.stderr, flush=True)
    service, stop = members_service(here, logged)
    print("READY {}", flush=True)
    words = sys.stdin.readline().split()
    if words[:1] != ["adopt"]:
        # the driver is gone
        os._exit(1)
    err: list[str] = []
    code = adopt.adopt_from(sync.Syncer(here, utcnow, err.append), words[1])
    print("RESULT " + json.dumps({"code": code, "err": err}), flush=True)
    commands(here, root, log)
    stop.set()
    service.join(30)


def start_adopted(pid: int, root: str, path: str) -> subprocess.Popen:
    # its standard error to a file beside its spec, read by nothing
    # here: a pipe nobody reads would stop it once full
    with open(os.path.join(root, "stderr.log"), "w") as said:
        process = subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable, __file__,
             "adopted", root, path], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=said, text=True)
    result(process, "READY ")
    return process


def stage(what: str) -> None:
    """Where the driver is, on standard error, for a run that hangs"""
    print(f"mesh4: {what}", file=sys.stderr, flush=True)


def ask(process: subprocess.Popen, line: str, prefix: str) -> dict:
    stage(f"{line} -> {prefix}")
    process.stdin.write(line + "\n")
    process.stdin.flush()
    return result(process, prefix + " ")


def roots_of(root: str) -> dict[str, list]:
    """Each member of the trust store: [root, has evidence]"""
    store = trust.load(root)
    return {key: [one.root, one.admission is not None]
            for key, one in store.members.items()}


def inviter() -> None:
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    pids = {name: link(name) for name in ("B", "C", "D")}
    roots, keys = {}, {}
    for name in OVERLAY:
        roots[name], _ = scratch("version: 1\n")
        keys[name] = keypair(roots[name])
    paths = {}
    for name in OVERLAY:
        paths[name] = os.path.join(roots[name], "instance.yaml")
        with open(paths[name], "w") as fob:
            fob.write(by_hand(keys, name))
    report: dict = {"keys": keys}
    a = node(roots["A"], paths["A"])
    netns_apply(a.document(), roots["A"], 120)
    marker.clear(roots["A"])
    journal: list[str] = []
    service, stop = members_service(a, journal.append)
    members = {name: start_adopted(pids[name], roots[name], paths[name])
               for name in ("B", "C")}

    # 1. one identity, the others trust roots: keel#77's order
    stage("create --adopt on A")
    said: list[str] = []
    report["create"] = adopt.adopt_mesh(
        sync.Syncer(a, utcnow, said.append), said.append)
    report["create_said"] = said
    report["adopt"] = {name: ask(members[name], f"adopt {OVERLAY['A']}",
                                 "RESULT") for name in ("B", "C")}
    report["a_roots"] = roots_of(roots["A"])

    # 2. A invites, D joins through A's listener and stays a member
    stage("D joins")
    token = invite(roots["A"], paths["A"], "D", 51902)
    serving = inviting.Inviter(a, utcnow, journal.append, journal.append,
                               run=Recorder(), output=lambda argv: None,
                               start=Spawned)
    codes: list[int] = []
    thread = threading.Thread(target=lambda: codes.append(
        inviting.serve_invite(serving, parse(token, utcnow()).invite_id)))
    thread.start()
    listening(f"{LINKS['D']}::1", 51902)
    d_process = run_joiner(pids["D"], token, "D", "serve")
    report["d"] = d = result(d_process)
    thread.join(120)
    report["serve"] = codes
    members["D"] = d_process
    d_address = d["address"].split("/")[0]
    report["d_roots"] = roots_of(d["root"])

    # 3. A announced D to B and C: each confirms D by its handshake
    report["checks"] = {name: ask(members[name],
                                  f"check {d_address} {d['key']}", "CHECK")
                        for name in ("B", "C")}

    # 4. all four over the overlay, and each one's handshakes
    everyone = {**OVERLAY, "D": d_address}
    pings = {"A": {address: ping(address)
                   for name, address in everyone.items() if name != "A"}}
    for name in ("B", "C", "D"):
        others = " ".join(address for other, address in everyone.items()
                          if other != name)
        pings[name] = ask(members[name], f"ping {others}", "PING")
    report["pings"] = pings
    report["handshakes"] = {"A": handshakes()} | {
        name: ask(members[name], "handshakes", "HANDSHAKES")
        for name in ("B", "C", "D")}
    report["addresses"] = everyone
    for process in members.values():
        process.stdin.close()
        process.wait(60)
    stop.set()
    service.join(30)
    report["journal"] = journal
    print("RESULT " + json.dumps(report), flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["adopted"]:
        adopted(sys.argv[2], sys.argv[3])
    else:
        try:
            inviter()
        except BaseException:
            # the members' services are threads that never end by
            # themselves: say why, and leave
            for one in mesh_netns.CHILDREN:
                one.kill()
            traceback.print_exc()
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(1)
        for one in mesh_netns.CHILDREN:
            one.kill()
