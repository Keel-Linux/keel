# Copyright (c) 2026 KeelLinux maintainers
"""Whether two nodes carry the VIP at the same instant (keel#126)

The sampler of tests/vip_netns.py asks each node in turn, every 200 ms,
in a thread of the driver: on a loaded runner, a thread can stop between
two reads, and two reads are two instants. This watcher is a process of
its own that reads the nodes in a tight loop, each round in a
palindromic order (A B C C B A, the first node turned each round), with
CLOCK_MONOTONIC. An overlap is proven only when the node read first and
last in a round carries the VIP at both reads, and another node carries
it at a read between them: the first node carried it through that
instant, so both carried it at that instant. A handover (one node
removes the address, the other adds it) is never an overlap: the node
that removed it does not carry it at its last read.

Run by the netns drivers as
`python3 tests/vip_overlap.py OUT VIP NAME=PID...` until SIGTERM; OUT
gets one JSON line for each change of the holders, one for each proven
overlap, and a summary line at the end. `summary` reads it back.
"""

import ipaddress
import json
import os
import signal
import subprocess
import sys
import time

PERIOD = 0.002
KEPT = 10


def wanted(vip: str) -> str:
    """The VIP as /proc/net/if_inet6 writes it: 32 hex digits"""
    return ipaddress.IPv6Address(vip).exploded.replace(":", "")


def carries(pid: int, hexed: str, iface: str = "wg0") -> bool:
    """Whether the namespace of process `pid` has the VIP on `iface`;
    /proc/PID/net is that namespace, so this forks nothing"""
    try:
        with open(f"/proc/{pid}/net/if_inet6") as fob:
            for line in fob:
                fields = line.split()
                if fields and fields[0] == hexed and fields[-1] == iface:
                    return True
    except OSError:
        return False
    return False


def order(names: list[str], turn: int) -> list[str]:
    """The round's reads: the names turned by `turn`, then reversed"""
    shift = turn % len(names)
    forward = names[shift:] + names[:shift]
    return forward + forward[::-1]


def proven(reads: list[tuple[str, bool]]) -> list[tuple[str, str]]:
    """The pairs that carried the VIP at one instant, from one round of
    palindromic reads: the outer node carries it at its two reads, and
    an inner node at a read between them"""
    found = []
    size = len(reads) // 2
    for outer in range(size):
        name, first = reads[outer]
        last = reads[len(reads) - 1 - outer][1]
        if not (first and last):
            continue
        for inner in range(outer + 1, len(reads) - 1 - outer):
            other, present = reads[inner]
            pair = tuple(sorted((name, other)))
            if present and other != name and pair not in found:
                found.append(pair)
    return found


def holders(reads: list[tuple[str, bool]]) -> list[str]:
    """Every node that carried it at one read of the round or more"""
    return sorted({name for name, present in reads if present})


def watch(out: str, vip: str, nodes: dict[str, int],
          period: float = PERIOD) -> None:
    hexed = wanted(vip)
    names = sorted(nodes)
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    offset = time.time() - time.monotonic()
    rounds, overlaps, gap, last, before = 0, 0, 0.0, None, None
    with open(out, "w") as fob:
        fob.write(json.dumps({"start": time.monotonic(),
                              "wall_offset": offset, "names": names})
                  + "\n")
        while not stopping:
            began = time.monotonic()
            reads = []
            for name in order(names, rounds):
                reads.append((name, carries(nodes[name], hexed)))
            ended = time.monotonic()
            if last is not None:
                gap = max(gap, began - last)
            last = began
            rounds += 1
            now = holders(reads)
            if now != before:
                fob.write(json.dumps({"t": began, "until": ended,
                                      "holders": now}) + "\n")
                before = now
            pairs = proven(reads)
            if pairs:
                overlaps += 1
                fob.write(json.dumps({"t": began, "until": ended,
                                      "overlap": pairs,
                                      "reads": reads}) + "\n")
            fob.flush()
            time.sleep(max(0.0, period - (time.monotonic() - began)))
        fob.write(json.dumps({"end": time.monotonic(), "rounds": rounds,
                              "overlaps": overlaps,
                              "max_gap_ms": round(gap * 1000, 1)}) + "\n")


def summary(path: str) -> dict:
    """What the watcher wrote: its rounds, the longest pause between two
    rounds, the proven overlaps (the first KEPT, with wall-clock times
    beside the monotonic ones) and the changes of the holders"""
    found = {"rounds": 0, "max_gap_ms": None, "overlaps": [],
             "overlap_rounds": 0, "changes": [], "ended": False}
    offset = 0.0
    try:
        with open(path) as fob:
            lines = [json.loads(one) for one in fob if one.strip()]
    except (OSError, ValueError) as e:
        found["error"] = str(e)
        return found
    for one in lines:
        if "start" in one:
            offset = one["wall_offset"]
        elif "end" in one:
            found.update(rounds=one["rounds"], ended=True,
                         overlap_rounds=one["overlaps"],
                         max_gap_ms=one["max_gap_ms"])
        elif "overlap" in one:
            if len(found["overlaps"]) < KEPT:
                found["overlaps"].append({
                    "t": round(one["t"], 4),
                    "wall": round(one["t"] + offset, 3),
                    "pairs": one["overlap"], "reads": one["reads"]})
            if not found["ended"]:
                found["overlap_rounds"] += 1
        elif "holders" in one:
            found["changes"].append({"t": round(one["t"], 4),
                                     "wall": round(one["t"] + offset, 3),
                                     "holders": one["holders"]})
    return found


def start(out: str, vip: str, nodes: dict[str, int]) -> subprocess.Popen:
    """The watcher, as a process of its own"""
    return subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), out, vip,
         *(f"{name}={pid}" for name, pid in sorted(nodes.items()))],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop(process: subprocess.Popen, out: str) -> dict:
    """The watcher stopped, and what it saw"""
    process.terminate()
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(10)
    return summary(out)


if __name__ == "__main__":
    watch(sys.argv[1], sys.argv[2],
          {name: int(pid) for name, _, pid in
           (one.partition("=") for one in sys.argv[3:])})
