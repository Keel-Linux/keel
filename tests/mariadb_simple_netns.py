# Copyright (c) 2026 KeelLinux maintainers
"""The MariaDB pair in cloud simple: the primary crashes, the operator
promotes the replica 2 s after (keel#108, keel#118)

Run as root in a network namespace of its own by
tests/test_mariadb_simple_netns.py; never run by hand on a machine. The
nodes, links (250 ms ±25 ms, 2 % loss, measured first), servers and
agents are tests/mariadb_netns.py's, with every node's spec in cloud
simple and the etcd overlay disabled: the VIP moves by the members'
channel alone, without a lease (keel.mesh.vippromote.promoted), as on
the real pair of Keel-Linux/handbook#60 and #62. etcd still runs in the
namespaces, as the harness forms it, and no spec uses it.

The case: A primary, B replica, connected and semi-synchronous; C writes
one row at the VIP every 0.1 s. A's server is killed and A is cut off;
exactly 2 s after the kill, `keel database promote --old-primary-gone`
on B. The result is one JSON line, `RESULT {...}`: the write downtime
from the promote's start, its parts, and the acknowledged rows lost.
"""

import os
import subprocess
import sys
import time

import mariadb_netns as base

# the operator's reaction, fixed so the number can be compared
PROMOTE_AFTER = 2.0


def spec_of(root: str, index: int, pairs) -> str:
    """mariadb_netns.spec_of, in cloud simple with etcd disabled"""
    import yaml
    path = base.spec_of(root, index, pairs)
    with open(path) as fob:
        doc = yaml.safe_load(fob)
    doc["installation"]["mode"] = "cloud_simple"
    doc["overlays"] = {"etcd": "disabled"}
    with open(path, "w") as fob:
        yaml.safe_dump(doc, fob, sort_keys=False)
    return path


def scenario(report: dict, pids: list[int], pairs, roots: list[str],
             samples: list[dict]) -> None:
    try:
        play(report, pids, roots)
    except Exception:  # noqa: BLE001 - the report says where it ended
        import traceback
        report["trace"] = traceback.format_exc()[-3000:]
        raise


def play(report: dict, pids: list[int], roots: list[str]) -> None:
    import vip_netns
    from vip_netns import agent_send, wait_until
    for index in range(len(vip_netns.NAMES) - 1):
        base.server(index, pids[index], roots[index])
    report["a_promote"] = agent_send("A", "promote")
    report["a_follow"] = agent_send("A", "follow", 180)
    for statement in (
            f"CREATE DATABASE {base.APP_DB}",
            f"CREATE TABLE {base.APP_DB}.t (id INT AUTO_INCREMENT PRIMARY"
            " KEY, v VARCHAR(64), at DOUBLE)",
            f"CREATE USER '{base.APP_USER}'@'%' IDENTIFIED BY"
            f" '{base.APP_PASSWORD}'",
            f"GRANT ALL ON {base.APP_DB}.* TO '{base.APP_USER}'@'%'"):
        found = agent_send("A", f"sql {statement}")
        if found.get("code"):
            report["setup_error"] = found
            return
    report["a_apply"] = agent_send("A", "apply", 600)
    report["b_apply"] = agent_send("B", "apply", 900)
    report["b_streaming_s"] = wait_until(
        lambda: base.replica_status(agent_send, "B").get(
            "Slave_IO_State", "").startswith(
                "Waiting for master to send event"), 120, 1)
    report["semisync_s"] = wait_until(
        lambda: base.status_value(agent_send, "A",
                                  "Rpl_semi_sync_master_clients") == "1"
        and base.status_value(agent_send, "A",
                              "Rpl_semi_sync_master_status") == "ON",
        120, 1)
    report["with_etcd"] = agent_send("B", "status")
    writer = base.Writer(pids[2])
    watched = base.NewPrimary(pids[1], roots[1])
    writer.start()
    watched.start()
    # writes acknowledged before the kill, so the downtime has a start
    report["first_ack_s"] = wait_until(
        lambda: any(one["ok"] for one in writer.done), 60, 0.2)
    time.sleep(3)
    killed_at = time.time()
    base.sh("systemctl", "kill", "--signal=SIGKILL",
            base.service_of(roots[0]), check=False)
    vip_netns.leg("to1", "100%")
    base.sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem",
            "loss", "100%", pid=pids[0])
    time.sleep(max(0.0, killed_at + PROMOTE_AFTER - time.time()))
    promote_at = time.time()
    report["promote"] = agent_send("B", "dbpromote gone", 300)
    promoted_at = time.time()
    wait_until(lambda: watched.writable_at is not None, 60, 0.2)
    time.sleep(5)
    writer.stop()
    watched.stop()
    report["downtime"] = base.downtime(writer, watched, killed_at,
                                       promote_at, promoted_at)
    report["acked_missing"] = base.acked_missing(writer, agent_send)
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def main() -> None:
    import vip_netns
    vip_netns.spec_of = spec_of
    vip_netns.__file__ = os.path.abspath(__file__)
    try:
        vip_netns.main(play=scenario)
    finally:
        for unit in base.UNITS:
            subprocess.run(["systemctl", "stop", unit], capture_output=True,
                           check=False)
            try:
                os.remove(f"/run/systemd/system/{unit}.service")
            except OSError:
                pass


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        base.agent_main(sys.argv[2], sys.argv[3])
    elif sys.argv[1:2] == ["lead"]:
        import vip_netns
        vip_netns.move_leader(sys.argv[2])
    else:
        main()
