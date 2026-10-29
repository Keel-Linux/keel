# Copyright (c) 2026 KeelLinux maintainers
"""keel vip promote when etcd does not answer the claim's transaction
in time (keel#135), on tests/vip_netns.py's nodes and links

Run as root in a network namespace of its own by
tests/test_vip_claim_netns.py; never run by hand on a machine. The
nodes, the links (250 ms ±25 ms, 2 % loss, measured first), etcd, the
members' channel, the VIP's helpers and the watcher of two holders at
one instant (tests/vip_overlap.py) are tests/vip_netns.py's. The agents
find tests/etcdctl_shim.py first on their PATH, which makes one chosen
transaction time out:

1. A promotes: the VIP at A, epoch 1;
2. B promotes (A releases), its claim's transaction committed in etcd
   and its answer lost: B must find its own claim and hold it;
3. A promotes (B releases), its claim's transaction not run and its
   answer lost: A must try the same compare-and-swap again and win.

At no instant may two nodes carry the VIP. The result is one JSON line,
`RESULT {...}`.
"""

import os
import shutil
import stat
import sys
import tempfile
import time


def shim_dir() -> str:
    """A directory whose `etcdctl` runs a copy of tests/etcdctl_shim.py:
    a copy every user can read, since the VIP's controllers, a dynamic
    user, find the directory on their PATH too (and pass through)"""
    found = tempfile.mkdtemp(prefix="keel-etcdctl-shim-")
    os.chmod(found, 0o755)
    shim = os.path.join(found, "etcdctl_shim.py")
    shutil.copy(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "etcdctl_shim.py"), shim)
    os.chmod(shim, 0o644)
    wrapper = os.path.join(found, "etcdctl")
    with open(wrapper, "w") as fob:
        fob.write(f'#!/bin/sh\nexec {sys.executable} {shim} "{found}" "$@"\n')
    os.chmod(wrapper, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
             stat.S_IROTH | stat.S_IXOTH)
    return found


def armed(root: str, mode: str) -> None:
    with open(os.path.join(root, "txn-shim"), "w") as fob:
        fob.write(mode + "\n")


def fired(root: str) -> str | None:
    try:
        with open(os.path.join(root, "txn-shim.fired")) as fob:
            return fob.read().strip()
    except OSError:
        return None


def play(report: dict, pids: list[int], pairs, roots: list[str],
         samples: list[dict]) -> None:
    import vip_netns
    from vip_netns import NAMES, agent_send, holds, wait_until
    a_pid, b_pid, _ = pids
    report["a"] = agent_send("A", "promote")
    report["a_holds_s"] = wait_until(lambda: holds(a_pid), 60)
    time.sleep(5)
    # B: the transaction commits, its answer is lost
    armed(roots[1], "commit-hang")
    started = time.time()
    report["b"] = agent_send("B", "promote", 300)
    report["b_s"] = round(time.time() - started, 2)
    report["b_fired"] = fired(roots[1])
    report["b_holds_s"] = wait_until(lambda: holds(b_pid), 60)
    report["b_status"] = agent_send("B", "status")
    time.sleep(5)
    # A: the transaction does not run, its answer is lost
    armed(roots[0], "hang")
    started = time.time()
    report["a2"] = agent_send("A", "promote", 300)
    report["a2_s"] = round(time.time() - started, 2)
    report["a2_fired"] = fired(roots[0])
    report["a2_holds_s"] = wait_until(lambda: holds(a_pid), 60)
    report["a2_status"] = agent_send("A", "status")
    time.sleep(10)
    report["holders_after"] = [n for n, p in zip(NAMES, pids) if holds(p)]
    report["epoch"] = agent_send("C", "epoch")
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def main() -> None:
    import vip_netns
    os.environ["PATH"] = shim_dir() + ":" + os.environ.get("PATH", "")
    vip_netns.main(play=play)


if __name__ == "__main__":
    main()
