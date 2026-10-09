# Copyright (c) 2026 KeelLinux maintainers
"""Upgrades on a pair whose VIP is active, three nodes in three namespaces

Run as root in a network namespace of its own by
tests/test_vip_upgrade_netns.py, on the nodes tests/vip_netns.py makes:
A and B a pair, C routing their VIP, all three etcd members, on links of
250 ms ±25 ms with 2% loss measured first. keel vip tend runs as
keel-vip.service runs it (ExecStopPost `--stopped`, Restart=always). A
promotes; C pings the VIP every 50 ms and a sampler reads every node's
wg0 every 200 ms. Then what an `apt full-upgrade` does to each node's
services, one at a time:

1. **(a)** keel-vip.service try-restarted on the holder, A, three times,
   as keel-overlay-vip's postinst and its trigger on keel do; once on the
   replica, B; and the holder's helper killed, as a crash, which
   Restart=always restarts. Each time: the longest gap in C's answers,
   whether the counter's epoch moved (a failover) and the holders;
2. **(b)** etcd restarted as etcd-server's postinst does, through the
   gate keel-overlay-etcd's drop-in runs (`keel mesh etcd gate stop`
   before the stop, `started` after the start), on C, then on the holder
   A, then on B: the other two members keep writing (quorum), and the
   VIP neither moves nor stops answering;
3. **(c)** C's etcd stopped through the gate and left down: B's gate
   refuses to let B stop within its wait, and `keel mesh upgrade-check`
   on A says why; C started again, B's gate lets it through at once;
4. **(d)** the holder's controller frozen (SIGSTOP), the case no restart
   covers: the kernel drops the address within the release time, by the
   lifetime the controller gives it at each renewal, and B claims it once
   A's lease expired, never both at once.

At no sample may two nodes carry the VIP. The result is one JSON line,
`RESULT {...}`.
"""

import os
import signal
import subprocess
import sys
import time

import etcd_netns
import vip_netns
from etcd_netns import NAMES, environment, samples, sh, start_etcd, summary
from vip_netns import (
    OVERLAY,
    agent_send,
    answers,
    first,
    gap,
    holds,
    main,
    main_pid,
    pinger,
    routed_to,
    wait_until,
)

from keel.mesh import etcdstate, vipbridge

# how long after each restart the gap in C's answers is looked for: the
# controller back, renewed, and a few renewals more
SETTLE = 15
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def helper_unit(index: int) -> str:
    return f"keel-vip-test-{NAMES[index]}"


def epoch(upto_s: float = 60) -> dict:
    """The counter's claim, as C reads it from etcd; one linearizable
    read can outlast its 2 s on the lossy link, and then the answer
    holds no epoch (keel#133), so the ask repeats until it does;
    bounded"""
    deadline = time.monotonic() + upto_s
    tries = 0
    while True:
        tries += 1
        found = agent_send("C", "epoch")
        if "epoch" in found or time.monotonic() >= deadline:
            found["tries"] = tries
            return found
        time.sleep(3)


def held_by(pids: list[int]) -> list[str]:
    return [n for n, p in zip(NAMES, pids) if holds(p)]


def window(samples_: list[dict], since: float) -> list[list[str]]:
    return sorted({tuple(one["holders"]) for one in samples_
                   if one["t"] >= since}, key=len)


def restarted(how: str, index: int, pids: list[int], samples_: list[dict],
              log: str) -> dict:
    """keel-vip.service on node `index` restarted as a package upgrade
    does (`try-restart`), or its helper killed (`kill`)"""
    before = epoch()
    unit = helper_unit(index)
    pid = main_pid(unit)
    at = time.time()
    if how == "kill":
        sh("systemctl", "kill", "--signal=KILL", "--kill-whom=main", unit)
    else:
        sh("systemctl", how, unit)
    took = round(time.time() - at, 2)
    back = wait_until(lambda: main_pid(unit) not in (0, pid), 60)
    time.sleep(SETTLE)
    after = epoch()
    return {"how": how, "node": NAMES[index], "systemctl_s": took,
            "helper_back_s": back,
            "gap_s": gap(answers(log), at - 1, time.time()),
            "epoch_before": before.get("epoch"),
            "epoch_after": after.get("epoch"),
            "holder_after": after.get("holder"),
            "holders_seen": window(samples_, at),
            "holders_after": held_by(pids),
            # on the holder: when a sample first missed it there
            "dropped_s": first(samples_, at, lambda h: NAMES[index] not in h)
            if index == 0 else None}


def where(root: str) -> tuple[str, ...]:
    """A node's root and its spec, where tests/vip_netns.py writes it"""
    return ("--root", root, "--spec", os.path.join(root, "instance.yaml"))


def healthy_when_asked(pid: int, root: str, upto_s: float = 90) -> dict:
    """`keel mesh upgrade-check`, asked again until every endpoint is
    healthy. C's etcd restarted a moment ago: one call can answer "not
    now" before C's health reached the others (keel#94); bounded"""
    deadline = time.monotonic() + upto_s
    tries = 0
    while True:
        tries += 1
        found = keel_in(pid, "mesh", "upgrade-check", *where(root))
        found["tries"] = tries
        if found["code"] == 0 or time.monotonic() >= deadline:
            return found
        time.sleep(3)


def keel_in(pid: int, *argv: str, timeout: float = 600) -> dict:
    """`keel ARGV` in a node's namespace: its code, what it said, how long
    it took"""
    at = time.monotonic()
    done = subprocess.run(
        ["nsenter", "-t", str(pid), "-n", "env", f"PYTHONPATH={REPO}",
         sys.executable, "-m", "keel", *argv], capture_output=True,
        text=True, check=False, timeout=timeout)
    return {"code": done.returncode, "took_s": round(time.monotonic() - at, 2),
            "said": (done.stdout + done.stderr).strip().splitlines()[-12:]}


class Etcds:
    """Each member's etcd process, restarted as etcd-server's postinst
    does, through keel-overlay-etcd's gate"""

    def __init__(self, pids: list[int], roots: list[str]):
        self.pids = pids
        self.roots = roots
        self.procs = dict(enumerate(etcd_netns.ETCDS[:len(NAMES)]))

    def gate(self, index: int, step: str, wait: int | None = None) -> dict:
        argv = ["mesh", "etcd", "gate", step, *where(self.roots[index])]
        if wait is not None:
            argv += ["--wait", str(wait)]
        return keel_in(self.pids[index], *argv)

    def stop(self, index: int) -> None:
        process = self.procs[index]
        process.send_signal(signal.SIGTERM)
        process.wait(60)

    def start(self, index: int) -> None:
        root = self.roots[index]
        cluster = etcdstate.cluster(root)
        start_etcd(self.pids[index], root, environment(
            root, OVERLAY.format(n=index + 1), cluster))
        self.procs[index] = etcd_netns.ETCDS[-1]

    def restart(self, index: int) -> dict:
        """ExecStop's gate, the stop, the start and ExecStartPost's gate:
        `systemctl restart etcd` with keel-overlay-etcd's drop-in"""
        at = time.time()
        found = {"node": NAMES[index], "gate_stop": self.gate(index, "stop")}
        stopping = time.time()
        self.stop(index)
        found["stopped_s"] = round(time.time() - stopping, 2)
        self.start(index)
        found["gate_started"] = self.gate(index, "started")
        found["took_s"] = round(time.time() - at, 2)
        found["at"] = at
        return found


def quorum(roots: list[str], index: int, since: float, until: float) -> dict:
    """What the other members' watchers saw while `index` restarted"""
    return {NAMES[other]: summary(samples(
        os.path.join(roots[other], "watch.jsonl"), since, until))
        for other in range(len(NAMES)) if other != index}


def scenario(report: dict, pids: list[int], pairs, roots: list[str],
             samples_: list[dict]) -> None:
    a_pid, b_pid, c_pid = pids
    key = {name: pairs[i][1] for i, name in enumerate(NAMES)}
    log = os.path.join(roots[2], "ping.log")
    report["a"] = agent_send("A", "promote")
    report["a_routed_s"] = wait_until(lambda: routed_to(c_pid) == key["A"],
                                      60)
    pinger(c_pid, log)
    time.sleep(10)
    report["a_answers"] = len(answers(log))
    report["a_holder"] = held_by(pids)

    # (a) keel-vip.service restarted as the packages do
    report["restarts"] = [restarted("try-restart", 0, pids, samples_, log)
                          for _ in range(3)]
    report["replica_restart"] = restarted("try-restart", 1, pids, samples_,
                                          log)
    report["crash"] = restarted("kill", 0, pids, samples_, log)

    # (b) etcd restarted as etcd-server's postinst does, one at a time
    etcds = Etcds(pids, roots)
    report["etcd_restarts"] = []
    for index in (2, 0, 1):
        before = epoch()
        found = etcds.restart(index)
        time.sleep(SETTLE)
        found["gap_s"] = gap(answers(log), found["at"] - 1, time.time())
        found["quorum"] = quorum(roots, index, found["at"], time.time())
        found["epoch_before"] = before.get("epoch")
        found["epoch_after"] = epoch().get("epoch")
        found["holders_seen"] = window(samples_, found["at"])
        report["etcd_restarts"].append(found)

    # (c) two at once: C down through its gate, B must wait
    report["c_gate_stop"] = etcds.gate(2, "stop")
    etcds.stop(2)
    down_at = time.time()
    report["upgrade_check_c_down"] = keel_in(a_pid, "mesh", "upgrade-check",
                                             *where(roots[0]))
    report["b_gate_refused"] = etcds.gate(1, "stop", wait=20)
    report["b_etcd_running"] = etcds.procs[1].poll() is None
    etcds.start(2)
    report["c_gate_started"] = etcds.gate(2, "started")
    report["c_down_s"] = round(time.time() - down_at, 2)
    report["upgrade_check_healthy"] = healthy_when_asked(a_pid, roots[0])
    report["b_gate_after"] = etcds.gate(1, "stop", wait=60)
    report["b_gate_after_started"] = etcds.gate(1, "started")
    report["c_holders_seen"] = window(samples_, down_at)

    # (d) the holder's controller frozen: the kernel drops the address
    time.sleep(5)
    control = main_pid(vipbridge.unit_name(roots[0]))
    report["frozen_controller_pid"] = control
    frozen_at = time.time()
    os.kill(control, signal.SIGSTOP)
    try:
        report["d_dropped_s"] = wait_until(lambda: not holds(a_pid), 30, 0.1)
        report["d_claimed_s"] = wait_until(lambda: holds(b_pid), 60)
        time.sleep(3)
    finally:
        os.kill(control, signal.SIGCONT)
    report["d_dropped_sampled_s"] = first(samples_, frozen_at,
                                          lambda h: "A" not in h)
    report["d_carried_s"] = first(samples_, frozen_at, lambda h: "B" in h)
    report["d_holder"] = held_by(pids)
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        vip_netns.agent(sys.argv[2], sys.argv[3])
    else:
        main(scenario)
