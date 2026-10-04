# Copyright (c) 2026 KeelLinux maintainers
"""etcd over the WireGuard mesh, three members in three namespaces

Run as root in a network namespace of its own by tests/test_etcd_netns.py
(tests/wgtools.py says how); never run by hand on a machine. This
namespace is the internet: it routes between three children, A, B and
C, each a network namespace of its own (`unshare -n`) joined to it by a
veth on its own /64. Each child brings up wg0 from the file keel renders
(keel.network.wireguard) with the real wg-quick, every other child its
peer, and runs the real etcd 3.5 from the configuration keel renders
(keel.mesh.etcdconf) and the credentials keel makes
(keel.mesh.etcdstate): A makes the mesh's root CA, B's intermediate is
signed by A's, C's by B's (any member invites), and each issues its own
leaves. etcd's files point at the scratch roots instead of /etc/etcd.

The links are the design case of handbook decision 0050, as its bench
did it: one egress qdisc on this namespace's end of each veth, half the
round trip and half the jitter each, `125ms 12.5ms`, with 2% loss each
(so 250 ms ±25 ms with 2% loss on every leg, between any two members).

Then:

1. **forms**: the three etcds start at once; the time until every member
   reports the same leader and is healthy;
2. **stays**: for STABLE seconds, every member is asked its leader and
   term each second by a watcher in its namespace (keel's etcd client,
   keel's client certificate, on ::1), and writes a key every two
   seconds; the leaders and terms seen;
3. **partition**: a follower is cut off (100% loss, both ways) for
   PARTITION seconds while the others write; then healed, and the time
   until it reports the leader again;
4. a learner added with keel's client and removed again, on the real
   etcd: what `keel mesh join` and `keel mesh remove` ask of it.

The result is one JSON line, `RESULT {...}`; with ETCD_SOAK=full the
stability is 300 s and the partition 120 s (the brief's), else 60 and
45, which keeps the CI job within its few minutes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from keel.mesh import etcdclient, etcdconf, etcdstate
from keel.mesh.etcdstate import Cluster, Member
from keel.network import wireguard

MESH = "6b65656c206d657368206574636421aa"
NAMES = ("A", "B", "C")
UPLINK = "2001:db8:e7c:{n}"
OVERLAY = "fd00:6b65:e7c::{n}"
FULL = os.environ.get("ETCD_SOAK") == "full"
STABLE = int(os.environ.get("ETCD_STABLE") or (300 if FULL else 60))
PARTITION = int(os.environ.get("ETCD_PARTITION") or (120 if FULL else 45))
LEG = os.environ.get("ETCD_NETEM", "125ms 12.5ms 2%").split()
CHILDREN: list[subprocess.Popen] = []
WATCHERS: list[subprocess.Popen] = []
ETCDS: list[subprocess.Popen] = []


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sh(*argv: str, pid: int | None = None, check: bool = True) -> str:
    prefix = ["nsenter", "-t", str(pid), "-n"] if pid else []
    done = subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, check=False)
    if check and done.returncode:
        raise RuntimeError(f"{' '.join(argv)}: {done.stderr.strip()}")
    return done.stdout


def leg(device: str, loss: str | None = None) -> None:
    delay, jitter, lost = LEG
    sh("tc", "qdisc", "replace", "dev", device, "root", "netem", "delay",
       delay, jitter, "loss", loss or lost)


def child(index: int) -> int:
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


def keys() -> list[tuple[str, str]]:
    found = []
    for _ in NAMES:
        private = sh("wg", "genkey").strip()
        public = subprocess.run(["wg", "pubkey"], input=private + "\n",
                                capture_output=True, text=True,
                                check=True).stdout.strip()
        found.append((private, public))
    return found


def overlay_up(pid: int, root: str, index: int, pairs) -> None:
    """wg0 from the file keel renders, every other member a peer"""
    key = os.path.join(root, "wg0.key")
    with open(os.open(key, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(pairs[index][0] + "\n")
    peers = [{"public_key": pairs[other][1],
              "endpoint": f"[{UPLINK.format(n=other + 1)}::2]:51820",
              "allowed_ips": [f"{OVERLAY.format(n=other + 1)}/128"],
              "persistent_keepalive": 25}
             for other in range(len(NAMES)) if other != index]
    conf = os.path.join(root, "wg0.conf")
    with open(os.open(conf, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(wireguard.render({
            "address": f"{OVERLAY.format(n=index + 1)}/64",
            "listen_port": 51820, "peers": peers,
            "private_key": {"file": key}}))
    sh("wg-quick", "up", conf, pid=pid)


def credentials(roots: list[str]) -> None:
    """A makes the root; B's intermediate by A, C's by B"""
    etcdstate.make_root(roots[0], MESH)
    for issuer, member in ((roots[0], roots[1]), (roots[1], roots[2])):
        etcdstate.take_grant(member, etcdstate.grant_for(
            issuer, etcdstate.ca_request(member), "member"))
    for index, root in enumerate(roots):
        etcdstate.leaves(root, OVERLAY.format(n=index + 1), utcnow())


def environment(root: str, address: str, cluster: Cluster) -> dict:
    """keel's /etc/default/etcd, its files moved under the scratch root"""
    found = dict(line.split("=", 1) for line in etcdconf.environment(
        address, cluster).splitlines() if line and not line.startswith("#"))
    moved = {f"/{etcdconf.MEMBER_CERT}": etcdstate.MEMBER_CERT,
             f"/{etcdconf.MEMBER_KEY}": etcdstate.MEMBER_KEY,
             f"/{etcdconf.TRUSTED}": etcdstate.ROOT_CERT}
    for key, value in found.items():
        if value in moved:
            found[key] = os.path.join(root, moved[value])
    found["ETCD_DATA_DIR"] = os.path.join(root, "etcd-data")
    return found


def start_etcd(pid: int, root: str, env: dict) -> None:
    with open(os.path.join(root, "etcd.log"), "w") as log:
        ETCDS.append(subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", shutil.which("etcd")],
            env={"PATH": os.environ.get("PATH", ""), **env}, stdout=log,
            stderr=log))


def watch(root: str, out: str, name: str) -> None:
    """In a member's namespace: its status every second, a write every
    two, one JSON line each, until killed"""
    client = etcdclient.local(root)
    client.timeout = 3
    url = etcdstate.client_url(etcdstate.LOOPBACK)
    beat = 0
    with open(out, "a") as fob:
        while True:
            sample = {"t": time.time()}
            try:
                found = client.status(url)
                sample.update(leader=found.leader, term=found.raft_term,
                              id=found.member_id)
            except etcdclient.EtcdError as e:
                sample["error"] = str(e)[:120]
            sample["healthy"] = client.health(url)[0]
            if beat % 2 == 0:
                try:
                    client.put(f"probe/{name}", str(beat))
                    sample["put"] = True
                except etcdclient.EtcdError:
                    sample["put"] = False
            beat += 1
            fob.write(json.dumps(sample) + "\n")
            fob.flush()
            time.sleep(1)


def samples(path: str, since: float = 0, until: float = 1e12) -> list[dict]:
    try:
        with open(path) as fob:
            found = [json.loads(line) for line in fob if line.strip()]
    except OSError:
        return []
    return [one for one in found if since <= one["t"] < until]


def agreed(paths: list[str], since: float) -> str | None:
    """The leader every member reports in its latest sample, healthy"""
    latest = [samples(path, since)[-1:] for path in paths]
    if not all(latest):
        return None
    leaders = {one[0].get("leader") for one in latest}
    if len(leaders) == 1 and all(one[0].get("healthy") for one in latest) \
            and None not in leaders and "" not in leaders:
        return leaders.pop()
    return None


def wait_for(test, seconds: float) -> float | None:
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if test():
            return time.monotonic() - started
        time.sleep(1)
    return None


def summary(found: list[dict]) -> dict:
    return {"samples": len(found),
            "leaders": sorted({one["leader"] for one in found
                               if one.get("leader")}),
            "terms": sorted({one["term"] for one in found
                             if one.get("term")}),
            "puts": sum(1 for one in found if one.get("put")),
            "put_failures": sum(1 for one in found
                                if one.get("put") is False),
            "unhealthy": sum(1 for one in found if not one.get("healthy"))}


def driver() -> None:
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    pids = [child(index) for index in range(len(NAMES))]
    roots = [tempfile.mkdtemp(prefix=f"keel-etcd-{name}-") for name in NAMES]
    pairs = keys()
    for index, pid in enumerate(pids):
        overlay_up(pid, roots[index], index, pairs)
    credentials(roots)
    cluster = Cluster("new", tuple(
        Member(pairs[index][1], OVERLAY.format(n=index + 1))
        for index in range(len(NAMES))), MESH)
    report = {"netem_leg": LEG, "stable_s": STABLE, "partition_s": PARTITION,
              "heartbeat_ms": etcdconf.HEARTBEAT_MS,
              "election_ms": etcdconf.ELECTION_MS}
    began = time.time()
    for index, pid in enumerate(pids):
        start_etcd(pid, roots[index], environment(
            roots[index], OVERLAY.format(n=index + 1), cluster))
    paths = [os.path.join(root, "watch.jsonl") for root in roots]
    for index, pid in enumerate(pids):
        WATCHERS.append(subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable, __file__,
             "watch", roots[index], paths[index], NAMES[index]],
            env=os.environ.copy(), stdout=subprocess.DEVNULL,
            stderr=open(os.path.join(roots[index], "watch.err"), "w")))
    formed = wait_for(lambda: agreed(paths, began), 180)
    report["formed_s"] = None if formed is None else round(
        time.time() - began, 1)
    if formed is None:
        report["etcd_log_tail"] = open(os.path.join(
            roots[0], "etcd.log")).read()[-3000:]
        print("RESULT " + json.dumps(report), flush=True)
        return
    report["leader_at_formation"] = agreed(paths, began)
    # the round trip over the overlay, once the tunnels are up
    rtt = sh("ping", "-6", "-c", "20", "-i", "0.5", "-q",
             OVERLAY.format(n=2), pid=pids[0], check=False)
    report["ping_a_b_overlay"] = rtt.strip().splitlines()[-2:]

    # 2. stays: STABLE seconds, every member asked each second
    start = time.time()
    time.sleep(STABLE)
    report["stable"] = {NAMES[i]: summary(samples(paths[i], start))
                        for i in range(len(NAMES))}

    # 3. a follower cut off, both ways, for PARTITION seconds
    ids = {samples(paths[i], start)[-1].get("id"): i
           for i in range(len(NAMES))}
    current = agreed(paths, start)
    cut = next(i for i in (2, 1, 0) if ids.get(current) != i)
    report["partitioned"] = NAMES[cut]
    report["partitioned_was_leader"] = ids.get(current) == cut
    leg(f"to{cut + 1}", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=pids[cut])
    cut_at = time.time()
    time.sleep(PARTITION)
    healed_at = time.time()
    report["during_partition"] = {NAMES[i]: summary(samples(
        paths[i], cut_at + 15, healed_at)) for i in range(len(NAMES))}
    leg(f"to{cut + 1}")
    sh("tc", "qdisc", "del", "dev", "uplink", "root", pid=pids[cut])
    back = wait_for(lambda: agreed(paths, healed_at), 180)
    report["rejoined_s"] = None if back is None else round(back, 1)
    time.sleep(10)
    report["after_heal"] = {NAMES[i]: summary(samples(paths[i], healed_at))
                            for i in range(len(NAMES))}
    report["leader_after_heal"] = agreed(paths, healed_at)

    # 4. a learner added and removed with keel's client, on real etcd
    done = subprocess.run(
        ["nsenter", "-t", str(pids[0]), "-n", sys.executable, __file__,
         "learner", roots[0]], capture_output=True, text=True, check=False,
        env=os.environ.copy(), timeout=120)
    try:
        report["learner"] = json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report["learner"] = {"error": done.stderr[-500:]}
    print("RESULT " + json.dumps(report), flush=True)


def learner_probe(root: str) -> None:
    """In A's namespace: a learner added, listed, and removed"""
    client = etcdclient.local(root)
    # etcd refuses a reconfiguration until every voter has been active a
    # while (strict reconfig check): a member that just rejoined
    for _ in range(30):
        try:
            added = client.add_learner(etcdstate.peer_url(
                "fd00:6b65:e7c::99"))
            break
        except etcdclient.EtcdError as e:
            said = str(e)
            time.sleep(3)
    else:
        print(json.dumps({"error": said}), flush=True)
        return
    listed = [one for one in client.members() if one.id == added.id]
    client.remove(added.id)
    after = [one for one in client.members() if one.id == added.id]
    print(json.dumps({"added": added.learner, "listed_unstarted":
                      bool(listed) and not listed[0].started,
                      "removed": not after}), flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["watch"]:
        watch(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1:2] == ["learner"]:
        learner_probe(sys.argv[2])
    else:
        try:
            driver()
        finally:
            for one in WATCHERS + ETCDS + CHILDREN:
                one.kill()
