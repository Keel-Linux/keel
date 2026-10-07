# Copyright (c) 2026 KeelLinux maintainers
"""The VIP on the WireGuard mesh, three nodes in three namespaces

Run as root in a network namespace of its own by tests/test_vip_netns.py
(tests/wgtools.py says how); never run by hand on a machine. This
namespace is the internet: it routes between three children, A, B and
C, each a network namespace of its own joined to it by a veth, with the
links of handbook decision 0050's design case on every leg (250 ms
±25 ms with 2% loss), measured before anything runs on them, as
tests/etcd_netns.py does. A and B are a replicated pair: their specs
declare the same `appliance.vip`; C declares none and routes it. All
three are cloud advanced members of one etcd cluster, keel's CA, leaves
and rendered configuration, on the real etcd 3.5, over the real
wg-quick.

Each node runs, in its namespace, what keel-mesh-members and
keel-vip.service run: the members' channel (its root helper, and the
listener as a process of its own with every capability dropped, as
tests/mesh_netns.py runs it), and keel vip tend as a transient systemd
unit joined to the node's namespace, with keel-vip.service's sandbox,
which starts the VIP's controller as its own unit with a dynamic user
and no capability (keel.mesh.vipbridge): the hardening of both is read
from the kernel. A and B are paired with `keel vip pair` first.
The driver tells a node's agent to run `keel vip promote` and reads
what it said. From the start of the scenario a sampler asks every node
every 200 ms whether wg0 carries the VIP, and C pings the VIP every 50
ms.

1. **(a)** A promotes, the first claim, at epoch 1: C reaches the VIP,
   at A;
2. **(b)** B promotes, planned: A releases, B claims; the downtime is
   the longest gap between C's answered pings across the move;
3. **(c)** the primary, B, made etcd's leader (what `etcdctl
   move-leader` does), is cut off (100% loss, both ways): it drops the
   VIP within RELEASE_AFTER of its last renewal the majority confirmed,
   and A claims it once B's lease expired; the times from the cut, as
   the sampler and C's pings saw them;
4. **(d)** healed: B takes A's newer claim and never carries the VIP
   again, for HEALED seconds;
5. **(e)** a stale claim is refused: B's claim at its old epoch, signed
   again, sent to C over the members' channel (409), and written to
   etcd against the counter's old revision (the compare fails);
6. **(f)** the follower case: B promoted again by hand, C made etcd's
   leader, and B, the primary and a follower, cut off; A claims.

At no sample may two nodes carry the VIP. The result is one JSON line,
`RESULT {...}`.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

import etcd_netns
from etcd_netns import (
    NAMES,
    agreed,
    environment,
    leg,
    measured,
    sh,
    start_etcd,
    utcnow,
)

from keel.mesh import (
    etcdca,
    etcdstate,
    identity,
    memberd,
    signing,
    sync,
    trust,
    vipetcd,
    vipnode,
    vippromote,
)
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdstate import Member
from keel.mesh.memberlink import LinkError
from keel.mesh.node import Node
from keel.network import wireguard

MESH = "6b65656c207669702074657374210001"
UPLINK = "2001:db8:f1b:{n}"
OVERLAY = "fd00:6b65:f1b::{n}"
VIP = "fd00:6b65:f1b::100"
SAMPLE = 0.2
PING = "0.05"
HEALED = int(os.environ.get("VIP_HEALED") or 30)
CHILDREN: list[subprocess.Popen] = []
AGENTS: dict[str, subprocess.Popen] = {}
OTHERS: list[subprocess.Popen] = []
# the nodes' scratch roots, removed at the end (VIP_KEEP keeps them)
ROOTS: list[str] = []

# The listener holds no capability, so as root without
# CAP_DAC_READ_SEARCH it cannot traverse a home directory the checkout
# may be in: it imports a copy of keel (tests/mesh_netns.py)
# The controller's unit has PrivateTmp, so its copy is under /run, which
# a private /tmp and /var/tmp do not hide
RUN_BASE = "/run/keel-vip-test"
LISTENER_HOME = os.environ.get("KEEL_VIP_LISTENER_HOME") or ""


def child(index: int) -> int:
    """A namespace joined to this one by a veth on its own /64"""
    found = subprocess.Popen(["unshare", "-n", "sleep", "3600"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    CHILDREN.append(found)
    n = index + 1
    net = UPLINK.format(n=n)
    sh("ip", "link", "add", f"to{n}", "type", "veth", "peer", "name",
       "uplink")
    sh("ip", "link", "set", "uplink", "netns", str(found.pid))
    sh("ip", "-6", "address", "add", f"{net}::1/64", "dev", f"to{n}",
       "nodad")
    sh("ip", "link", "set", f"to{n}", "up")
    for argv in (("ip", "link", "set", "lo", "up"),
                 ("ip", "-6", "address", "add", f"{net}::2/64", "dev",
                  "uplink", "nodad"),
                 ("ip", "link", "set", "uplink", "up"),
                 ("ip", "-6", "route", "add", "default", "via", f"{net}::1",
                  "dev", "uplink")):
        sh(*argv, pid=found.pid)
    leg(f"to{n}")
    return found.pid


def spec_of(root: str, index: int, pairs) -> str:
    """The node's spec: its overlay, every other node a peer; A and B
    declare the VIP"""
    import yaml
    peers = [{"public_key": pairs[other][1],
              "endpoint": f"[{UPLINK.format(n=other + 1)}::2]:51820",
              "allowed_ips": [f"{OVERLAY.format(n=other + 1)}/128"],
              "persistent_keepalive": 25}
             for other in range(len(NAMES)) if other != index]
    doc = {"version": 1,
           "appliance": {"name": "core"},
           "installation": {"mode": "cloud_advanced"},
           "overlays": {"etcd": "enabled"},
           "network": {"overlay": {"wireguard": {
               "address": f"{OVERLAY.format(n=index + 1)}/64",
               "listen_port": 51820,
               "private_key": {"file": "/etc/wireguard/wg0.key"},
               "peers": peers}}}}
    if index < 2:
        doc["appliance"]["vip"] = VIP
    path = os.path.join(root, "instance.yaml")
    with open(path, "w") as fob:
        yaml.safe_dump(doc, fob, sort_keys=False)
    return path


def overlay_up(pid: int, root: str, index: int, pairs, path: str) -> None:
    """wg0 from the file keel renders, where keel keeps it"""
    os.makedirs(os.path.join(root, "etc/wireguard"), exist_ok=True)
    key = os.path.join(root, "etc/wireguard/wg0.key")
    with open(os.open(key, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(pairs[index][0] + "\n")
    # the key is under the node's root, where keel reads it (keel's
    # rendering, with the key's path under the scratch root for wg)
    overlay = {**Node(root, path).overlay(), "private_key": {"file": key}}
    conf = os.path.join(root, "etc/wireguard/wg0.conf")
    with open(os.open(conf, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(wireguard.render(overlay))
    sh("wg-quick", "up", conf, pid=pid)


def mesh_state(roots: list[str], pairs) -> None:
    """The identity, each node's signing key, and each trusting the
    other two as roots: what joins and keel mesh sync leave"""
    signs = []
    for root in roots:
        identity.adopt(root, bytes.fromhex(MESH))
        signs.append(signing.ensure(root))
    for index, root in enumerate(roots):
        store = trust.Store()
        for other in range(len(NAMES)):
            if other != index:
                store.members[pairs[other][1]] = trust.Member(
                    signs[other], True)
        trust.save(root, store)


def keys() -> list[tuple[str, str]]:
    found = []
    for _ in NAMES:
        private = sh("wg", "genkey").strip()
        public = subprocess.run(["wg", "pubkey"], input=private + "\n",
                                capture_output=True, text=True,
                                check=True).stdout.strip()
        found.append((private, public))
    return found


def holds(pid: int) -> bool:
    """Whether the node's wg0 carries the VIP: /proc/PID/net is the net
    namespace of that process, so this forks nothing and three nodes are
    read within a millisecond of each other"""
    wanted = ipaddress.IPv6Address(VIP).exploded.replace(":", "")
    try:
        with open(f"/proc/{pid}/net/if_inet6") as fob:
            return any(line.split()[0] == wanted and
                       line.split()[-1] == "wg0" for line in fob)
    except OSError:
        return False


def sampler(pids: list[int], out: list[dict], stop: threading.Event) -> None:
    """Every SAMPLE seconds, which nodes carry the VIP"""
    while not stop.is_set():
        t = time.time()
        out.append({"t": t, "holders": [NAMES[i] for i, pid in
                                        enumerate(pids) if holds(pid)]})
        stop.wait(max(0.0, SAMPLE - (time.time() - t)))


def pinger(pid: int, log: str) -> subprocess.Popen:
    """C pings the VIP every 50 ms, each answer timestamped"""
    with open(log, "w") as fob:
        found = subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", "ping", "-6", "-D", "-n",
             "-i", PING, "-W", "1", VIP], stdout=fob,
            stderr=subprocess.STDOUT)
    OTHERS.append(found)
    return found


def answers(log: str) -> list[float]:
    """The times C's pings to the VIP were answered"""
    found = []
    with open(log) as fob:
        for line in fob:
            hit = re.match(r"\[(\d+\.\d+)\] \d+ bytes from", line)
            if hit:
                found.append(float(hit.group(1)))
    return found


def gap(times: list[float], start: float, end: float) -> float | None:
    """The longest stretch without an answer within [start, end]"""
    inside = [one for one in times if start <= one <= end]
    if not inside:
        return None
    edges = [start] + inside + [end]
    return round(max(b - a for a, b in zip(edges, edges[1:])), 3)


def first(samples: list[dict], since: float, test) -> float | None:
    for one in samples:
        if one["t"] >= since and test(one["holders"]):
            return round(one["t"] - since, 2)
    return None


def agent_send(name: str, line: str, timeout: float = 180) -> dict:
    """One command to a node's agent, and its JSON answer"""
    process = AGENTS[name]
    process.stdin.write(line + "\n")
    process.stdin.flush()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        said = process.stdout.readline()
        if not said:
            break
        if said.startswith("ANSWER "):
            return json.loads(said[len("ANSWER "):])
    return {"error": f"no answer to {line!r}"}


def routed_to(pid: int) -> str | None:
    done = subprocess.run(["nsenter", "-t", str(pid), "-n", "wg", "show",
                           "wg0", "allowed-ips"], capture_output=True,
                          text=True, check=False)
    for line in done.stdout.splitlines():
        key, _, nets = line.partition("\t")
        if f"{VIP}/128" in nets.split():
            return key
    return None


def wait_until(test, seconds: float, step: float = 0.2) -> float | None:
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if test():
            return round(time.monotonic() - started, 2)
        time.sleep(step)
    return None


def driver() -> None:
    global LISTENER_HOME
    os.makedirs(RUN_BASE, mode=0o755, exist_ok=True)
    LISTENER_HOME = tempfile.mkdtemp(prefix="listener-", dir=RUN_BASE)
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    shutil.copytree(os.path.dirname(os.path.dirname(os.path.abspath(
        memberd.__file__))), os.path.join(LISTENER_HOME, "keel"))
    # the controller's dynamic user reads the copy of keel it runs
    for where, dirs, files in os.walk(LISTENER_HOME):
        os.chmod(where, 0o755)
        for name in files:
            os.chmod(os.path.join(where, name), 0o644)
    os.environ["KEEL_VIP_LISTENER_HOME"] = LISTENER_HOME
    pids = [child(index) for index in range(len(NAMES))]
    roots = [tempfile.mkdtemp(prefix=f"keel-vip-{name}-") for name in NAMES]
    pairs = keys()
    specs = [spec_of(roots[i], i, pairs) for i in range(len(NAMES))]
    for index, pid in enumerate(pids):
        overlay_up(pid, roots[index], index, pairs, specs[index])
    mesh_state(roots, pairs)
    # etcd: keel's CA, intermediates and leaves (tests/etcd_netns.py)
    etcd_netns.KEYS.extend(pair[1] for pair in pairs)
    etcd_netns.OVERLAY = OVERLAY
    etcd_netns.credentials(roots)
    cluster = etcdca.record(roots[0], tuple(
        Member(pairs[i][1], OVERLAY.format(n=i + 1))
        for i in range(len(NAMES))), MESH, utcnow())
    for root in roots:
        etcdstate.save_cluster(root, cluster)
    report = {"netem_leg": etcd_netns.LEG, "ttl_s": vipetcd.TTL,
              "release_after_s": vipetcd.RELEASE_AFTER,
              "sample_s": SAMPLE, "vip": VIP}
    report["link"] = measured(pids[2], OVERLAY.format(n=1))
    began = time.time()
    for index, pid in enumerate(pids):
        start_etcd(pid, roots[index], environment(
            roots[index], OVERLAY.format(n=index + 1), cluster))
    paths = [os.path.join(root, "watch.jsonl") for root in roots]
    for index, pid in enumerate(pids):
        OTHERS.append(subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable,
             etcd_netns.__file__, "watch", roots[index], paths[index],
             NAMES[index]], env=os.environ.copy(),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    formed = wait_until(lambda: agreed(paths, began), 180, 1)
    report["etcd_formed_s"] = formed
    if formed is None:
        print("RESULT " + json.dumps(report), flush=True)
        return
    for index, pid in enumerate(pids):
        AGENTS[NAMES[index]] = subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable, __file__,
             "agent", roots[index], specs[index]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=open(os.path.join(roots[index], "agent.log"), "w"),
            text=True, env=os.environ.copy())
    for name in NAMES:
        report.setdefault("agents", {})[name] = agent_send(name, "ready",
                                                           120)
    # the operator's `keel vip pair`, on A, with B's overlay address
    report["paired"] = agent_send("A", f"pair {OVERLAY.format(n=2)}")
    for index, pid in enumerate(pids):
        tended(index, pid, roots[index], specs[index])
    report["hardening"] = wait_for_hardening(roots)
    samples: list[dict] = []
    stop = threading.Event()
    sampling = threading.Thread(target=sampler, args=(pids, samples, stop))
    sampling.start()
    try:
        scenario(report, pids, pairs, roots, samples)
    except Exception as e:  # noqa: BLE001 - the report says how it ended
        report["error"] = repr(e)
    finally:
        stop.set()
        sampling.join()
    counts = [len(one["holders"]) for one in samples]
    report["samples"] = len(samples)
    steps = [b["t"] - a["t"] for a, b in zip(samples, samples[1:])]
    report["sample_step_max_s"] = round(max(steps), 3) if steps else None
    report["max_holders"] = max(counts) if counts else None
    report["double_holder_samples"] = [one for one in samples
                                       if len(one["holders"]) > 1][:10]
    print("RESULT " + json.dumps(report), flush=True)
    if not os.environ.get("VIP_KEEP"):
        ROOTS.extend(roots)


# keel-overlay-vip's keel-vip.service, as a transient unit in a node's
# namespace: the root helper, which starts the controller as its own
# unit with a dynamic user and no capability (keel.mesh.vipbridge)
# PrivateTmp is left out here alone: the nodes' scratch roots are in the
# host's temporary directory, which it would hide; each helper's
# temporary files (openssl's) go under its root instead
HELPER_PROPERTIES = (
    "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE",
    "NoNewPrivileges=yes",
    "PrivateDevices=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
)
HELPERS: list[str] = []


def tended(index: int, pid: int, root: str, spec: str) -> None:
    unit = f"keel-vip-test-{NAMES[index]}"
    HELPERS.append(unit)
    scratch = os.path.join(root, "tmp")
    os.makedirs(scratch, mode=0o700, exist_ok=True)
    sh("systemd-run", f"--unit={unit}", "--collect", "--quiet",
       f"--setenv=TMPDIR={scratch}",
       f"--property=NetworkNamespacePath=/proc/{pid}/ns/net",
       f"--property=ReadWritePaths={root}",
       *(f"--property={one}" for one in HELPER_PROPERTIES),
       f"--setenv=PYTHONPATH={LISTENER_HOME}",
       f"--setenv=PATH={os.environ.get('PATH', '')}",
       sys.executable, "-m", "keel", "vip", "tend", "--root", root,
       "--spec", spec)


def status_of(pid: int) -> dict:
    found = {}
    try:
        with open(f"/proc/{pid}/status") as fob:
            for line in fob:
                key, _, value = line.partition(":")
                if key in ("Uid", "CapEff", "CapBnd", "NoNewPrivs"):
                    found[key] = value.split()[0]
    except OSError:
        pass
    return found


def main_pid(unit: str) -> int:
    found = sh("systemctl", "show", "--property=MainPID", "--value",
               unit).strip()
    return int(found) if found.isdigit() else 0


def wait_for_hardening(roots: list[str]) -> dict:
    """The helper's and the controller's processes, as the kernel sees
    them: the controller a dynamic user with no capability"""
    from keel.mesh import vipbridge
    found = {}
    for index, root in enumerate(roots):
        control = vipbridge.names(root)[0]
        wait_until(lambda: main_pid(control) > 0, 60)
        helper = f"keel-vip-test-{NAMES[index]}"
        found[NAMES[index]] = {
            "helper": status_of(main_pid(helper)),
            "controller": status_of(main_pid(control))}
    return found


def lead(pid: int, root: str) -> dict:
    """etcd's leadership moved to the member in `pid`'s namespace, what
    `etcdctl move-leader` does"""
    done = subprocess.run(
        ["nsenter", "-t", str(pid), "-n", sys.executable, __file__, "lead",
         root], capture_output=True, text=True, check=False,
        env=os.environ.copy(), timeout=120)
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": done.stderr[-500:]}


def move_leader(root: str) -> None:
    """In a member's namespace: the leader asked to hand its leadership
    to this member, retried while an election settles"""
    from keel.mesh import etcdclient, etcdstate
    local = etcdclient.local(root)
    said = ""
    for _ in range(30):
        try:
            own = local.status(etcdstate.client_url(etcdstate.LOOPBACK))
            if own.leader == own.member_id:
                print(json.dumps({"leader": own.member_id}), flush=True)
                return
            leader = next(one for one in local.members()
                          if one.id == own.leader)
            etcdclient.Client(leader.client_urls, local.tls, 10).ask(
                "/v3/maintenance/transfer-leadership",
                {"targetID": own.member_id})
        except (etcdclient.EtcdError, StopIteration) as e:
            said = str(e)
        time.sleep(2)
    print(json.dumps({"error": said or "not the leader"}), flush=True)


def was_leader(roots: list[str], index: int) -> bool:
    latest = etcd_netns.samples(os.path.join(roots[index], "watch.jsonl"),
                                time.time() - 10)[-1:]
    return bool(latest) and latest[0].get("leader") == latest[0].get("id")


def partition(report: dict, key: str, pids: list[int], roots: list[str],
              samples: list[dict], cut: int, claimant: int, log: str,
              keys: dict[str, str]) -> float:
    """The primary `cut` cut off from the majority, both ways, until the
    other node of the pair carries the VIP; the times from the cut"""
    report[f"{key}_was_etcd_leader"] = was_leader(roots, cut)
    leg(f"to{cut + 1}", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=pids[cut])
    cut_at = time.time()
    report[f"{key}_claimed_s"] = wait_until(
        lambda: holds(pids[claimant]), 120)
    report[f"{key}_routed_s"] = wait_until(
        lambda: routed_to(pids[2]) == keys[NAMES[claimant]], 60)
    time.sleep(5)
    report[f"{key}_dropped_s"] = first(samples, cut_at,
                                       lambda h: NAMES[cut] not in h)
    report[f"{key}_carried_s"] = first(samples, cut_at,
                                       lambda h: NAMES[claimant] in h)
    # an answer in flight when the link was cut is the old primary's
    after = [one for one in answers(log) if one > cut_at + 1.0]
    report[f"{key}_reachable_again_s"] = round(after[0] - cut_at, 2) \
        if after else None
    report[f"{key}_holder"] = [n for n, p in zip(NAMES, pids) if holds(p)]
    return cut_at


def heal(pids: list[int], cut: int) -> float:
    leg(f"to{cut + 1}")
    sh("tc", "qdisc", "del", "dev", "uplink", "root", pid=pids[cut])
    return time.time()


def scenario(report: dict, pids: list[int], pairs, roots: list[str],
             samples: list[dict]) -> None:
    a_pid, b_pid, c_pid = pids
    key = {name: pairs[i][1] for i, name in enumerate(NAMES)}
    log = os.path.join(roots[2], "ping.log")

    # (a) A takes the VIP first, at epoch 1; C reaches it at A
    report["a"] = agent_send("A", "promote")
    report["a_routed_s"] = wait_until(lambda: routed_to(c_pid) == key["A"],
                                      60)
    pinger(c_pid, log)
    time.sleep(10)
    report["a_answers"] = len(answers(log))
    report["a_holder"] = [n for n, p in zip(NAMES, pids) if holds(p)]

    # (b) planned: B promotes, A releases first
    moved_at = time.time()
    report["b"] = agent_send("B", "promote")
    report["b_routed_s"] = wait_until(lambda: routed_to(c_pid) == key["B"],
                                      60)
    time.sleep(10)
    report["b_downtime_s"] = gap(answers(log), moved_at - 1, time.time())
    report["b_holder"] = [n for n, p in zip(NAMES, pids) if holds(p)]

    # (c) B, the primary and etcd's leader, cut off from the majority:
    # a leader renews leases by itself until it steps down, and only
    # renewals the majority confirmed count
    report["c_lead"] = lead(b_pid, roots[1])
    partition(report, "c", pids, roots, samples, 1, 0, log, key)

    # (d) healed: B takes A's newer claim and never carries it again
    healed_at = heal(pids, 1)
    time.sleep(HEALED)
    report["d_b_carried_after_heal"] = any(
        "B" in one["holders"] for one in samples if one["t"] >= healed_at)
    report["d_b_status"] = agent_send("B", "status")
    report["d_c_routes_to_a"] = routed_to(c_pid) == key["A"]
    report["d_holder"] = [n for n, p in zip(NAMES, pids) if holds(p)]

    # (e) a stale claim: B's old epoch, refused by C and by etcd
    report["e"] = agent_send("B", "stale")
    report["e_c_routes_to_a"] = routed_to(c_pid) == key["A"]
    report["e_holder"] = [n for n, p in zip(NAMES, pids) if holds(p)]

    # (f) the follower case: B, fenced since (c), promoted again by
    # hand (A releases), C given etcd's leadership, and B, a follower and
    # the primary, cut off; A claims
    report["f_promote_b"] = agent_send("B", "promote")
    report["f_b_holds_s"] = wait_until(lambda: holds(b_pid), 60)
    report["f_lead"] = lead(c_pid, roots[2])
    partition(report, "f", pids, roots, samples, 1, 0, log, key)
    heal(pids, 1)
    time.sleep(10)
    report["a_status"] = agent_send("A", "status")
    for process in AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def utc() -> datetime:
    return datetime.now(timezone.utc)


class Spawned:
    """`keel mesh members-listen` as its own process, with no capability"""

    def __init__(self, path: str):
        with open(os.path.join(LISTENER_HOME, "listener.log"), "a") as log:
            self.process = subprocess.Popen(
                ["setpriv", "--no-new-privs", "--bounding-set", "-all",
                 "--inh-caps", "-all", "--ambient-caps", "-all",
                 sys.executable, "-m", "keel", "mesh", "members-listen",
                 path], stdout=log, stderr=log, cwd=LISTENER_HOME,
                env={**os.environ, "PYTHONPATH": LISTENER_HOME})

    def trusted(self, pid: int, uid: int) -> bool:
        return pid == self.process.pid

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(10)


def agent(root: str, path: str) -> None:
    """In a node's namespace: keel-mesh-members and keel-vip.service,
    and the driver's commands on standard input"""
    def log(line: str) -> None:
        print(f"{time.time():.3f} {line}", file=sys.stderr, flush=True)
    here = vipnode.Here(Node(root, path), utc, log)
    stop, served = threading.Event(), threading.Event()
    members = threading.Thread(target=memberd.serve, args=(
        sync.Syncer(here.node, utc, log), served),
        kwargs={"start": Spawned}, daemon=True)
    members.start()
    for line in sys.stdin:
        try:
            found = command(here, line.split())
        except Exception as e:  # noqa: BLE001 - the driver reads why
            import traceback
            found = {"error": repr(e),
                     "trace": traceback.format_exc()[-1500:]}
        if found is None:
            break
        print("ANSWER " + json.dumps(found), flush=True)
    stop.set()
    served.set()
    vipetcd.stopped(here)


def command(here: vipnode.Here, words: list[str]) -> dict | None:
    """One of the driver's commands; None to quit"""
    if words[:1] == ["ready"]:
        return {"members": wait_until(lambda: listening(here), 60)}
    if words[:1] == ["promote"]:
        said: list[str] = []
        started = time.monotonic()
        code = vippromote.promote(here, "gone" in words, said.append)
        return {"code": code, "said": said,
                "took_s": round(time.monotonic() - started, 2)}
    if words[:1] == ["status"]:
        return {"lines": vippromote.lines(here, True)}
    if words[:1] == ["pair"]:
        said = []
        return {"code": vippromote.pair(here, words[1], said.append),
                "said": said}
    if words[:1] == ["stale"]:
        return stale(here)
    return None


def listening(here: vipnode.Here) -> bool:
    done = subprocess.run(["ss", "-Hltn", "sport", "= :51821"],
                          capture_output=True, text=True, check=False)
    return bool(done.stdout.strip())


def stale(here: vipnode.Here) -> dict:
    """On the old primary: its claim at its old epoch, signed again,
    sent to the third node, and written to etcd against the counter's
    old revision"""
    held = vipnode.current(here, VIP)
    found = {"held_epoch": held.epoch}
    old = vipnode.signed_claim(here, VIP, held.epoch - 1)
    found["stale_epoch"] = old.epoch
    try:
        here.exchange(OVERLAY.format(n=3), here.iface(), old.raw)
        found["channel"] = "taken"
    except LinkError as e:
        found["channel"] = f"refused: {e}"
    client = vipetcd.local(here)
    # B's etcd member has just come back from its partition: it answers
    # a linearizable read once it caught up with the leader
    now = None
    for _ in range(30):
        try:
            now = vipetcd.seen(client, here.mesh_id()).get(VIP)
            break
        except EtcdError as e:
            found["etcd_retry"] = str(e)[:200]
            time.sleep(1)
    found["counter_epoch"] = now.epoch.epoch if now and now.epoch else None
    revision = (now.revision if now else 1) - 1
    found["etcd_refused"] = vipetcd.stale(client, here.mesh_id(), VIP, old,
                                          revision)
    after = vipetcd.seen(client, here.mesh_id()).get(VIP)
    found["counter_epoch_after"] = after.epoch.epoch \
        if after and after.epoch else None
    return found


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        agent(sys.argv[2], sys.argv[3])
    elif sys.argv[1:2] == ["lead"]:
        move_leader(sys.argv[2])
    else:
        try:
            driver()
        finally:
            for unit in HELPERS:
                subprocess.run(["systemctl", "stop", unit],
                               capture_output=True, check=False)
            for one in list(AGENTS.values()) + OTHERS + etcd_netns.ETCDS + \
                    CHILDREN:
                one.kill()
            for one in list(AGENTS.values()) + etcd_netns.ETCDS:
                one.wait(30)
            for root in ROOTS + ([] if os.environ.get("VIP_KEEP")
                                 else [LISTENER_HOME]):
                shutil.rmtree(root, ignore_errors=True)
