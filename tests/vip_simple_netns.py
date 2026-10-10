# Copyright (c) 2026 KeelLinux maintainers
"""keel vip promote in cloud simple with a member outside the pair down
(keel#137), on tests/vip_netns.py's nodes and links

Run as root in a network namespace of its own by
tests/test_vip_simple_netns.py; never run by hand on a machine. The
nodes, the links (250 ms ±25 ms, 2 % loss, measured first), the members'
channel, the VIP's helpers and the watcher of two holders at one instant
(tests/vip_overlap.py) are tests/vip_netns.py's, with every spec in
cloud simple and the etcd overlay disabled: the VIP moves by the
members' channel alone. A and B are the pair, C a member outside it.

1. A promotes: the VIP at A;
2. C is cut off, both ways;
3. B promotes, planned (A releases): timed. On keel 0.23.13 each promote
   waited two 10 s timeouts on C (the epoch query, the announcement);
4. C back: it learns the claim at its next check, or from the
   announcement it missed.

The result is one JSON line, `RESULT {...}`.
"""

import time


def spec_of(root: str, index: int, pairs) -> str:
    """vip_netns.spec_of, in cloud simple with etcd disabled"""
    import yaml
    path = ORIGINAL(root, index, pairs)
    with open(path) as fob:
        doc = yaml.safe_load(fob)
    doc["installation"]["mode"] = "cloud_simple"
    doc["overlays"] = {"etcd": "disabled"}
    with open(path, "w") as fob:
        yaml.safe_dump(doc, fob, sort_keys=False)
    return path


ORIGINAL = None


def play(report: dict, pids: list[int], pairs, roots: list[str],
         samples: list[dict]) -> None:
    import vip_netns
    from vip_netns import NAMES, agent_send, holds, leg, sh, wait_until
    a_pid, b_pid, c_pid = pids
    report["a"] = agent_send("A", "promote")
    report["a_holds_s"] = wait_until(lambda: holds(a_pid), 60)
    report["a_status"] = agent_send("A", "status")
    time.sleep(3)
    leg("to3", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=c_pid)
    started = time.time()
    report["b"] = agent_send("B", "promote", 300)
    report["b_s"] = round(time.time() - started, 2)
    report["b_holds_s"] = wait_until(lambda: holds(b_pid), 60)
    report["a_dropped"] = not holds(a_pid)
    vip_netns.heal(pids, 2)
    time.sleep(5)
    report["holders_after"] = [n for n, p in zip(NAMES, pids) if holds(p)]
    report["b_status"] = agent_send("B", "status")
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def main() -> None:
    global ORIGINAL
    import vip_netns
    ORIGINAL = vip_netns.spec_of
    vip_netns.spec_of = spec_of
    vip_netns.main(play=play)


if __name__ == "__main__":
    main()
