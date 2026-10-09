# Copyright (c) 2026 KeelLinux maintainers
"""keel#83 on the WireGuard mesh: three nodes moved from the live layout

Run as root in a network namespace of its own by
tests/test_etcd_auth_netns.py (tests/wgtools.py says how); never run by
hand on a machine. The namespaces, links, overlay, members' channel,
VIP helper and controller units are tests/vip_netns.py's, on the design
case of decision 0050 (250 ms ±25 ms with 2% loss on every leg),
measured before anything runs on them. The difference is the etcd
credentials: the three nodes start in the layout keel ran before keel#83
(`legacy`): each member holds an intermediate CA the root signed,
name-constrained to its /128, and its certificate was issued by that
intermediate; the root's holder, A, recorded the intermediates as the
old keel did. A and B are a VIP's pair, C routes it.

1. A promotes: the VIP at A, C pinging it every 50 ms, a sampler asking
   every node every 200 ms whether wg0 carries it, and a watcher that
   reads every node in a tight loop and proves any instant two carry it
   (tests/vip_overlap.py, keel#126); each member watched
   every second: its leader and term, and a linearizable read of the
   mesh's keys (which needs the quorum);
2. the cost of etcdctl, measured on A: a process with no call, and the
   VIP controller's own calls on the link;
3. **`keel mesh etcd reissue` on A**: every member on a certificate the
   root signed, one at a time, the intermediates revoked, auth on; the
   VIP's holder and the quorum watched throughout, and 20 s after;
4. **RBAC**: C, outside the pair, writes, deletes and revokes the VIP's
   keys and lease: etcd refuses; B, of the pair, may write them (a
   transaction whose comparison fails, so nothing is written);
5. **no member can mint**: no member holds a CA key; a certificate
   signed by C's own key, CN root, does not reach etcd;
6. **renewal through the root**: C's certificate, due (its clock moved
   21 days on), renewed by A's root over the members' channel, and C
   reads etcd with it; with A cut off, the renewal waits, and goes
   through once A is back;
7. **rollback**: auth off on A, and C's write is no longer refused.

The result is one JSON line, `RESULT {...}`.
"""

import ipaddress
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import timedelta

import etcd_netns
import vip_netns
import vip_overlap
from etcd_netns import (
    NAMES,
    environment,
    leg,
    measured,
    sh,
    start_etcd,
    utcnow,
)
from vip_netns import (
    AGENTS,
    OTHERS,
    VIP,
    agent_send,
    answers,
    child,
    gap,
    holds,
    keys,
    mesh_state,
    overlay_up,
    pinger,
    sampler,
    spec_of,
    tended,
    wait_until,
)

from keel.mesh import (
    etcd,
    etcdca,
    etcdcare,
    etcdclient,
    etcdpki,
    etcdreissue,
    etcdstate,
    memberd,
    sync,
    vipetcd,
    vipnode,
)
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdstate import Member
from keel.mesh.node import Change, Node

MESH = vip_netns.MESH
OVERLAY = vip_netns.OVERLAY
AFTER = int(os.environ.get("ETCD_AUTH_AFTER") or 20)
ROUNDS = 10


class Applied(Node):
    """A node whose spec change applies nothing: etcd reads the scratch
    root's files where keel keeps them (tests/etcd_netns.environment)"""

    def change(self, doc: dict, window: int | None = None) -> Change:
        return Change(0, None, ())


def addr(index: int) -> str:
    return OVERLAY.format(n=index + 1)


def signed_by(issuer_key: str, issuer: str, csr: str, name: str,
              extensions: str) -> str:
    """A certificate as keel before keel#83 made them, with openssl"""
    with tempfile.TemporaryDirectory() as scratch:
        files = {}
        for label, body in (("csr", csr), ("issuer", issuer),
                            ("ext", extensions)):
            files[label] = os.path.join(scratch, label)
            with open(files[label], "w") as fob:
                fob.write(body)
        return etcdpki.openssl(
            "x509", "-req", "-in", files["csr"], "-CA", files["issuer"],
            "-CAkey", issuer_key, "-set_serial",
            f"0x{os.urandom(16).hex()}", "-days", "365", "-subj",
            f"/CN={name}", "-extfile", files["ext"])


def intermediate(root_key: str, root: str, csr: str, at: str) -> str:
    net = ipaddress.IPv6Network(f"{at}/128")
    loop = ipaddress.IPv6Network("::1/128")
    return signed_by(root_key, root, csr, etcdstate.name(at), (
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
        "nameConstraints=critical,"
        f"permitted;IP:{net.network_address}/{net.netmask},"
        f"permitted;IP:{loop.network_address}/{loop.netmask}\n"))


def leaf(ca_key: str, ca: str, csr: str, at: str, client: bool) -> str:
    return signed_by(ca_key, ca, csr, (f"keel client {etcdstate.name(at)}"
                                       if client else etcdstate.name(at)), (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        + ("extendedKeyUsage=clientAuth\n" if client else
           "extendedKeyUsage=serverAuth,clientAuth\n"
           f"subjectAltName=IP:{at},IP:::1\n")
        + "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"))


def legacy(roots: list[str], pairs) -> dict:
    """The layout of the live nodes before keel#83: a root on A, an
    intermediate per member signed by it and recorded, leaves issued by
    each intermediate; the serials of the intermediates"""
    holder = roots[0]
    root_key = etcdstate.key(holder, etcdstate.ROOT_KEY)
    root = etcdpki.root(root_key, MESH)
    etcdstate.write(holder, etcdstate.ROOT_CERT, root)
    etcdstate.write(holder, etcdstate.CRL,
                    etcdpki.crl(root_key, root, {}, 1))
    serials, issued = {}, {}
    for index, member in enumerate(roots):
        at = addr(index)
        ca_key = etcdstate.key(member, etcdstate.CA_KEY)
        ca = intermediate(root_key, root, etcdpki.request(ca_key), at)
        serials[NAMES[index]] = etcdpki.serial(ca)
        if index:
            issued[at] = [[etcdpki.serial(ca), etcdpki.stamp(
                etcdpki.not_after(ca)), pairs[index][1]]]
        own = leaf(ca_key, ca, etcdpki.request(etcdstate.key(
            member, etcdstate.MEMBER_KEY)), at, False)
        client = leaf(ca_key, ca, etcdpki.request(etcdstate.key(
            member, etcdstate.CLIENT_KEY)), at, True)
        etcdstate.write(member, etcdstate.ROOT_CERT, root)
        etcdstate.write(member, etcdstate.CA_CERT, ca)
        etcdstate.write(member, etcdstate.CHAIN, "")
        etcdstate.write(member, etcdstate.MEMBER_CERT, own + ca)
        etcdstate.write(member, etcdstate.CLIENT_CERT, client + ca)
        etcdstate.write(member, etcdstate.HOLDER, addr(0) + "\n")
        etcdstate.write(member, etcdstate.CRL, etcdstate.read(
            holder, etcdstate.CRL))
    etcdstate.write(holder, etcdstate.ISSUED, json.dumps(issued))
    return serials


def watch(root: str, out: str) -> None:
    """In a member's namespace: its leader and term, and a linearizable
    read of the mesh's keys, every second, one JSON line each"""
    url = etcdstate.client_url(etcdstate.LOOPBACK)
    with open(out, "a") as fob:
        while True:
            client = etcdclient.local(root)
            client.timeout = 3
            sample = {"t": time.time()}
            try:
                found = client.status(url)
                sample.update(leader=found.leader, term=found.raft_term)
            except EtcdError as e:
                sample["error"] = str(e)[:120]
            try:
                client.prefix(f"/keel/{MESH}/")
                sample["read"] = True
            except EtcdError as e:
                sample["read"] = False
                sample["read_error"] = str(e)[:120]
            fob.write(json.dumps(sample) + "\n")
            fob.flush()
            time.sleep(1)


def quorum(paths: list[str], since: float, until: float) -> dict:
    found = {}
    for index, path in enumerate(paths):
        seen = etcd_netns.samples(path, since, until)
        found[NAMES[index]] = {
            "samples": len(seen),
            "leaders": sorted({one["leader"] for one in seen
                               if one.get("leader")}),
            "terms": sorted({one["term"] for one in seen
                             if one.get("term")}),
            "reads": sum(1 for one in seen if one.get("read")),
            "read_failures": [one.get("read_error") for one in seen
                              if one.get("read") is False][:5],
            "read_failed": sum(1 for one in seen
                               if one.get("read") is False)}
    return found


def cut(pids: list[int], index: int, on: bool) -> None:
    if on:
        leg(f"to{index + 1}", "100%")
        sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem",
           "loss", "100%", pid=pids[index])
    else:
        leg(f"to{index + 1}")
        sh("tc", "qdisc", "del", "dev", "uplink", "root", pid=pids[index])


def driver() -> None:
    os.makedirs(vip_netns.RUN_BASE, mode=0o755, exist_ok=True)
    vip_netns.LISTENER_HOME = tempfile.mkdtemp(prefix="listener-",
                                               dir=vip_netns.RUN_BASE)
    home = vip_netns.LISTENER_HOME
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    shutil.copytree(os.path.dirname(os.path.dirname(os.path.abspath(
        memberd.__file__))), os.path.join(home, "keel"))
    for where, _, files in os.walk(home):
        os.chmod(where, 0o755)
        for name in files:
            os.chmod(os.path.join(where, name), 0o644)
    os.environ["KEEL_VIP_LISTENER_HOME"] = home
    os.makedirs(vip_netns.TOOLS, mode=0o755, exist_ok=True)
    for tool in ("wg", "etcdctl"):
        found = shutil.which(tool)
        if found:
            shutil.copy(found, os.path.join(vip_netns.TOOLS, tool))
    pids = [child(index) for index in range(len(NAMES))]
    roots = [tempfile.mkdtemp(prefix=f"keel-auth-{name}-")
             for name in NAMES]
    vip_netns.ROOTS.extend(roots)
    pairs = keys()
    specs = [spec_of(roots[i], i, pairs) for i in range(len(NAMES))]
    for index, pid in enumerate(pids):
        overlay_up(pid, roots[index], index, pairs, specs[index])
    mesh_state(roots, pairs)
    report = {"netem_leg": etcd_netns.LEG, "vip": VIP}
    report["legacy_serials"] = legacy(roots, pairs)
    report["legacy_files"] = [etcdstate.legacy(one) for one in roots]
    cluster = etcdca.record(roots[0], tuple(
        Member(pairs[i][1], addr(i)) for i in range(len(NAMES))), MESH,
        utcnow())
    for root in roots:
        etcdstate.save_cluster(root, cluster)
    report["link"] = measured(pids[2], addr(0))
    began = time.time()
    for index, pid in enumerate(pids):
        start_etcd(pid, roots[index], environment(roots[index], addr(index),
                                                  cluster))
    paths = [os.path.join(root, "quorum.jsonl") for root in roots]
    for index, pid in enumerate(pids):
        OTHERS.append(subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable, __file__,
             "watch", roots[index], paths[index]], env=os.environ.copy(),
            stdout=subprocess.DEVNULL,
            stderr=open(os.path.join(roots[index], "watch.err"), "w")))
    report["etcd_formed_s"] = wait_until(lambda: all(
        etcd_netns.samples(path, began)[-1:] and etcd_netns.samples(
            path, began)[-1].get("read") for path in paths), 180, 1)
    if report["etcd_formed_s"] is None:
        report["etcd_log_tail"] = open(os.path.join(
            roots[0], "etcd.log")).read()[-3000:]
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
    report["paired"] = agent_send("A", f"pair {addr(1)}")
    for index, pid in enumerate(pids):
        tended(index, pid, roots[index], specs[index])
    samples: list[dict] = []
    stop = threading.Event()
    sampling = threading.Thread(target=sampler, args=(pids, samples, stop))
    sampling.start()
    atomic = os.path.join(roots[2], "overlap.jsonl")
    watcher = vip_overlap.start(atomic, VIP, dict(zip(NAMES, pids)))
    try:
        scenario(report, pids, roots, paths, samples)
    except Exception as e:  # noqa: BLE001 - the report says how it ended
        import traceback
        report["error"] = repr(e)
        report["trace"] = traceback.format_exc()[-2000:]
    finally:
        stop.set()
        sampling.join()
        report["atomic"] = vip_overlap.stop(watcher, atomic)
    report["samples"] = len(samples)
    report["double_holder_samples"] = [one for one in samples
                                       if len(one["holders"]) > 1][:10]
    for index, root in enumerate(roots):
        try:
            with open(os.path.join(root, "agent.log")) as fob:
                report.setdefault("agent_logs", {})[NAMES[index]] = \
                    fob.read()[-1500:]
        except OSError:
            pass
    print("RESULT " + json.dumps(report), flush=True)


def scenario(report: dict, pids: list[int], roots: list[str],
             paths: list[str], samples: list[dict]) -> None:
    log = os.path.join(roots[2], "ping.log")
    # 1. the VIP at A
    report["promote"] = agent_send("A", "promote")
    report["a_holds_s"] = wait_until(lambda: holds(pids[0]), 60)
    pinger(pids[2], log)
    time.sleep(10)
    report["epoch_before"] = agent_send("C", "epoch")
    # 2. what etcdctl costs, on A, at 250 ms
    report["overhead"] = agent_send("A", "overhead")
    # 3. the move, watched
    moved_at = time.time()
    report["reissue"] = agent_send("A", "reissue", 900)
    done_at = time.time()
    time.sleep(AFTER)
    until = time.time()
    report["reissue_s"] = round(done_at - moved_at, 1)
    report["during"] = {
        "holders": sorted({tuple(one["holders"]) for one in samples
                           if moved_at <= one["t"] <= until}),
        "samples": sum(1 for one in samples
                       if moved_at <= one["t"] <= until),
        "ping_gap_s": gap(answers(log), moved_at, until),
        "quorum": quorum(paths, moved_at, until)}
    report["epoch_after"] = agent_send("C", "epoch")
    report["credentials"] = {name: agent_send(name, "credentials")
                             for name in NAMES}
    report["auth"] = agent_send("A", "auth")
    # 4. RBAC
    report["rbac_c"] = agent_send("C", "rbac")
    report["rbac_b"] = agent_send("B", "rbac")
    # 5. no member can mint, nor be certified for another's address
    report["mint_c"] = agent_send("C", "mint")
    report["steal_b"] = agent_send("B", "steal")
    # 6. renewal through the root, and waiting for it
    report["renew_c"] = agent_send("C", "renew")
    cut(pids, 0, True)
    report["renew_c_holder_cut"] = agent_send("C", "renew")
    cut(pids, 0, False)
    time.sleep(10)
    report["renew_c_holder_back"] = agent_send("C", "renew", 300)
    time.sleep(5)
    report["after_renewal"] = quorum(paths, time.time() - 5, time.time())
    # 7. rollback
    report["rollback"] = agent_send("A", "rollback")
    report["rbac_c_rolled_back"] = agent_send("C", "rbac --no-writes")
    for process in AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def agent(root: str, path: str) -> None:
    """In a node's namespace: keel-mesh-members and the driver's
    commands, as tests/vip_netns.agent, with a node that applies
    nothing"""
    def log(line: str) -> None:
        print(f"{time.time():.3f} {line}", file=sys.stderr, flush=True)
    node = Applied(root, path)
    here = vipnode.Here(node, vip_netns.utc, log)
    served = threading.Event()
    members = threading.Thread(target=memberd.serve, args=(
        sync.Syncer(node, vip_netns.utc, log), served),
        kwargs={"start": vip_netns.Spawned}, daemon=True)
    members.start()
    for line in sys.stdin:
        try:
            found = command(here, line.split(), log)
        except Exception as e:  # noqa: BLE001 - the driver reads why
            import traceback
            found = {"error": repr(e),
                     "trace": traceback.format_exc()[-1500:]}
        if found is None:
            break
        print("ANSWER " + json.dumps(found), flush=True)
    served.set()
    vipetcd.stopped(here)


def command(here: vipnode.Here, words: list[str], log) -> dict | None:
    member = etcd.Etcd(here.node, vip_netns.utc, log)
    said: list[str] = []
    if words[:1] == ["reissue"]:
        started = time.monotonic()
        code = etcdreissue.reissue(member, False, said.append)
        return {"code": code, "said": said,
                "took_s": round(time.monotonic() - started, 1)}
    if words[:1] == ["rollback"]:
        return {"code": etcdreissue.rollback(member, said.append),
                "said": said}
    if words[:1] == ["epoch"]:
        now = vipetcd.seen(vipetcd.local(here), here.mesh_id()).get(VIP)
        return {"epoch": now.epoch.epoch if now and now.epoch else None,
                "holder": now.epoch.address if now and now.epoch else None}
    if words[:1] == ["overhead"]:
        return overhead(here)
    if words[:1] == ["credentials"]:
        return credentials(here.root, here.own_address())
    if words[:1] == ["auth"]:
        return {"enabled": etcdclient.admin(here.root).auth_enabled()}
    if words[:1] == ["rbac"]:
        return rbac(here, "--no-writes" not in words)
    if words[:1] == ["mint"]:
        return mint(here)
    if words[:1] == ["steal"]:
        return steal(member, here)
    if words[:1] == ["renew"]:
        return renew(member, here.root)
    return vip_netns.command(here, words)


def timed(call) -> float:
    started = time.monotonic()
    call()
    return (time.monotonic() - started) * 1000


def overhead(here: vipnode.Here) -> dict:
    """etcdctl's cost: the process alone (`version`, no call), and the
    calls the VIP's controller makes every RENEW seconds, on this link"""
    client = vipetcd.local(here)
    spawn = [timed(lambda: subprocess.run(
        [etcdclient.ETCDCTL, "version"], capture_output=True, check=True))
        for _ in range(ROUNDS)]
    lease = client.grant(20)
    keepalive = [timed(lambda: client.keepalive(lease))
                 for _ in range(ROUNDS)]
    read = [timed(lambda: client.prefix(vipetcd.key_of(
        here.mesh_id(), VIP, vipetcd.EPOCH))) for _ in range(ROUNDS)]
    client.revoke(lease)

    def summary(found):
        return {"median_ms": round(statistics.median(found), 1),
                "max_ms": round(max(found), 1)}
    return {"spawn": summary(spawn), "keepalive": summary(keepalive),
            "read": summary(read),
            "renewal_ms_max": round(max(a + b for a, b in zip(keepalive,
                                                              read)), 1),
            "call_timeout_s": vipetcd.CALL_TIMEOUT,
            "release_after_s": vipetcd.RELEASE_AFTER}


def credentials(root: str, at: str) -> dict:
    cert = etcdstate.read(root, etcdstate.MEMBER_CERT) or ""
    anchor = etcdstate.read(root, etcdstate.ROOT_CERT) or ""
    first = etcdpki.blocks(cert)[0] if cert else ""
    return {"legacy": [one for one in etcdstate.LEGACY
                       if os.path.exists(os.path.join(root, one))],
            "root_key": os.path.exists(os.path.join(root,
                                                    etcdstate.ROOT_KEY)),
            "root_signed": bool(first) and etcdpki.verified(first, [],
                                                            anchor),
            "is_ca": etcdpki.is_ca(first) if first else None,
            "cn": etcdpki.subject(first) if first else None,
            "sans": list(etcdpki.addresses(first)) if first else [],
            "name": etcdstate.name(at),
            "crl": sorted(etcdpki.crl_serials(etcdstate.read(
                root, etcdstate.CRL) or ""))}


def attempt(call) -> str:
    try:
        found = call()
    except EtcdError as e:
        return f"refused: {e}"
    return f"done: {found!r}"


def rbac(here: vipnode.Here, writes: bool = True) -> dict:
    """What this member may do to the VIP's keys and lease: write and
    delete them, revoke the holder's lease, and a transaction whose
    comparison fails (permission is checked before it is evaluated, so
    a member that may write is let through, and nothing is written)"""
    client = vipetcd.local(here)
    mesh = here.mesh_id()
    epoch = vipetcd.key_of(mesh, VIP, vipetcd.EPOCH)
    holder = vipetcd.key_of(mesh, VIP, vipetcd.HOLDER)
    now = vipetcd.seen(client, mesh).get(VIP)
    found = {"read": attempt(lambda: len(client.prefix(epoch)))}
    found["swap"] = attempt(lambda: client.swap(
        [etcdclient.modified(epoch, 10 ** 12)], [(epoch, b"{}", None)]))
    if writes and here.own_key() == key_at(here, 2):
        found["put"] = attempt(lambda: client.put(epoch, "{}"))
        found["delete"] = attempt(lambda: client.delete(holder))
        lease = now.epoch.lease if now and now.epoch else None
        found["revoke"] = attempt(lambda: client.revoke(lease)) if lease \
            else "no lease"
    return found


def key_at(here: vipnode.Here, index: int) -> str | None:
    """The WireGuard key of the node at `index`, as this node knows it"""
    for one in here.node.peers(""):
        if one.address == addr(index):
            return one.public_key
    return here.own_key() if here.own_address() == addr(index) else None


def mint(here: vipnode.Here) -> dict:
    """A certificate this member makes itself, CN root, signed by its
    own key: etcd does not take it"""
    root = here.root
    found = {"ca_keys": [one for one in (etcdstate.CA_KEY,
                                         etcdstate.ROOT_KEY)
                         if os.path.exists(os.path.join(root, one))]}
    own_key = os.path.join(root, etcdstate.MEMBER_KEY)
    own = etcdpki.blocks(etcdstate.read(root, etcdstate.MEMBER_CERT))[0]
    with tempfile.TemporaryDirectory() as scratch:
        key = os.path.join(scratch, "k")
        with open(os.open(key, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
            fob.write(etcdpki.new_key())
        made = etcdpki.issue(etcdpki.CLIENT, own_key, own,
                             etcdpki.request(key), "root")
        cert = os.path.join(scratch, "c")
        with open(cert, "w") as fob:
            fob.write(made + own)
        client = etcdclient.Client(
            (etcdstate.client_url(etcdstate.LOOPBACK),),
            etcdclient.Tls(os.path.join(root, etcdstate.ROOT_CERT), cert,
                           key), 5)
        found["minted_root"] = attempt(client.auth_enabled)
    found["own_as_root"] = attempt(vipetcd.local(here).auth_enabled)
    return found


def steal(member: etcd.Etcd, here: vipnode.Here) -> dict:
    """What B, a trusted member, asks the root for and does not get: a
    certificate for C's address with C's key (B is not C and admitted
    no C) or with its own key (the address is C's); its own renewal
    goes through"""
    asked = etcd.join_request(member)

    def issued(address: str, key: str) -> str:
        try:
            etcd.issued(member, asked, address, key)
        except etcdstate.StateError as e:
            return f"refused: {e}"
        return "done"
    return {"as_c": issued(addr(2), key_at(here, 2)),
            "c_address_own_key": issued(addr(2), here.own_key()),
            "own": issued(here.own_address(), here.own_key())}


def renew(member: etcd.Etcd, root: str) -> dict:
    """This member's certificate renewed as tend renews it, its clock
    21 days on, so it is due"""
    before = etcdpki.serial(etcdstate.read(root, etcdstate.MEMBER_CERT))
    started = time.monotonic()
    try:
        changed = etcdcare.renew(member, utcnow() + timedelta(days=21))
        error = None
    except etcdstate.StateError as e:
        changed, error = False, str(e)
    took = round(time.monotonic() - started, 1)
    after = etcdpki.serial(etcdstate.read(root, etcdstate.MEMBER_CERT))
    reads = attempt(lambda: len(etcdclient.local(root).prefix(
        f"/keel/{MESH}/")))
    return {"changed": changed, "error": error, "took_s": took,
            "renewed": before != after, "reads": reads,
            "root_signed": credentials(root, member.node.overlay()[
                "address"].split("/")[0])["root_signed"]}


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        agent(sys.argv[2], sys.argv[3])
    elif sys.argv[1:2] == ["watch"]:
        watch(sys.argv[2], sys.argv[3])
    else:
        try:
            driver()
        finally:
            for unit in vip_netns.HELPERS:
                subprocess.run(["systemctl", "stop", unit],
                               capture_output=True, check=False)
            for one in list(AGENTS.values()) + OTHERS + etcd_netns.ETCDS + \
                    vip_netns.CHILDREN:
                one.kill()
            for one in list(AGENTS.values()) + etcd_netns.ETCDS:
                one.wait(30)
            if not os.environ.get("VIP_KEEP"):
                for root in vip_netns.ROOTS + [vip_netns.LISTENER_HOME,
                                               vip_netns.TOOLS]:
                    shutil.rmtree(root, ignore_errors=True)
