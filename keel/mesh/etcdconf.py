# Copyright (c) 2026 KeelLinux maintainers
"""etcd's configuration, rendered from the cluster; pure

trixie's etcd.service reads `/etc/default/etcd` as its environment
(`EnvironmentFile=-/etc/default/%p`), so keel writes the whole file from
the cluster in /var/lib/keel/etcd (keel.mesh.etcdstate) and this node's
overlay address: peers on the overlay address, clients on the overlay
address and on ::1, never a wildcard address; TLS for both, the client
certificate required of both, TLS 1.3 at least (0048, second round,
point 3); and the timeouts of the design case (0050).

The timeouts, from etcd's tuning guide: the heartbeat interval "around
the round-trip time between members", the election timeout "at least
10 times the round-trip time". The design case is 250 ms ±25 ms with
2% loss. A heartbeat of 300 ms covers the round trip and its jitter.
Peer traffic is a TCP stream, so a lost segment holds it for one
retransmission timeout (200 ms at least, plus the round trip), and
losses back to back double it: 0050's bench, at 3 s, still re-elected
under loss. 5 s is about 17 heartbeats and 20 round trips, room for
three successive retransmission timeouts; a dead leader is seen in 5 to
10 s (the timeout is randomised in [T, 2T)), which beside DNS's one to
five minutes (0020) costs nothing. Pre-vote stays on, etcd 3.5's
default, so a member back from a partition does not depose the leader.

A systemd drop-in orders etcd after the overlay's interface, restarts
it on failure, lets it wait for its quorum as long as it takes
(TimeoutStartSec=infinity: it reports ready only with a quorum, and a
member killed while it waits helps nothing), and gives it systemd's
sandbox: it runs as the etcd user the Debian unit names, writes
/var/lib/etcd alone, and holds no capability.
"""

from keel.mesh.etcdstate import (
    LOOPBACK,
    Cluster,
    client_url,
    name,
    peer_url,
)

ENVIRONMENT = "etc/default/etcd"
DROP_IN = "etc/systemd/system/etcd.service.d/keel.conf"
TLS_DIR = "etc/etcd/keel"
MEMBER_CERT = f"{TLS_DIR}/member.crt"
MEMBER_KEY = f"{TLS_DIR}/member.key"
TRUSTED = f"{TLS_DIR}/ca.crt"
DATA_DIR = "/var/lib/etcd/default"
HEARTBEAT_MS = 300
ELECTION_MS = 5000
HEADER = ("# Written by keel from /var/lib/keel/etcd (handbook decisions"
          " 0025, 0048);\n# keel spec apply rewrites it.\n")


def environment(address: str, cluster: Cluster) -> str:
    """/etc/default/etcd for the member at `address` of `cluster`"""
    initial = ",".join(f"{name(one)}={peer_url(one)}"
                       for one in cluster.addresses())
    values = (
        ("ETCD_NAME", name(address)),
        ("ETCD_DATA_DIR", DATA_DIR),
        ("ETCD_LISTEN_PEER_URLS", peer_url(address)),
        ("ETCD_INITIAL_ADVERTISE_PEER_URLS", peer_url(address)),
        ("ETCD_LISTEN_CLIENT_URLS",
         f"{client_url(address)},{client_url(LOOPBACK)}"),
        ("ETCD_ADVERTISE_CLIENT_URLS", client_url(address)),
        ("ETCD_INITIAL_CLUSTER", initial),
        ("ETCD_INITIAL_CLUSTER_STATE", cluster.state),
        ("ETCD_INITIAL_CLUSTER_TOKEN", cluster.token),
        ("ETCD_HEARTBEAT_INTERVAL", str(HEARTBEAT_MS)),
        ("ETCD_ELECTION_TIMEOUT", str(ELECTION_MS)),
        ("ETCD_CERT_FILE", f"/{MEMBER_CERT}"),
        ("ETCD_KEY_FILE", f"/{MEMBER_KEY}"),
        ("ETCD_TRUSTED_CA_FILE", f"/{TRUSTED}"),
        ("ETCD_CLIENT_CERT_AUTH", "true"),
        ("ETCD_PEER_CERT_FILE", f"/{MEMBER_CERT}"),
        ("ETCD_PEER_KEY_FILE", f"/{MEMBER_KEY}"),
        ("ETCD_PEER_TRUSTED_CA_FILE", f"/{TRUSTED}"),
        ("ETCD_PEER_CLIENT_CERT_AUTH", "true"),
        ("ETCD_TLS_MIN_VERSION", "TLS1.3"),
    )
    return HEADER + "".join(f"{key}={value}\n" for key, value in values)


def drop_in(iface: str) -> str:
    """The drop-in for etcd.service: after `iface`, and sandboxed"""
    return HEADER + f"""[Unit]
After=wg-quick@{iface}.service

[Service]
Restart=on-failure
RestartSec=5s
TimeoutStartSec=infinity
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=/var/lib/etcd
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
"""
