# keel vip

The service VIP of a replicated appliance pair on the WireGuard mesh
(handbook decision 0049, its third round of 2026-10-04). A pair has one
VIP, `appliance.vip` in the spec of each of its two nodes: a `/128` of
the overlay prefix. **The primary is the node that holds it** (third
round, point 2): there is no role field beside it. The primary carries
the address on `wg0`; every other node of the mesh routes it to the
primary by listing it in the `allowed_ips` of the primary's peer entry.
Everything the pair serves to the mesh is reached at it; replication and
node-to-node traffic use the nodes' own addresses, never the VIP (0029).

```
keel vip pair ADDRESS                # once, on one node of the pair
keel vip promote [--old-primary-gone]
keel vip status
keel vip check                       # keel-vip-check.timer
keel vip tend [--stopped]            # keel-vip.service, the root helper
keel vip control SOCKET              # its unprivileged controller
```

`keel database promote` moves the VIP first, with the same
`--old-primary-gone`, when the spec declares one. The units are shipped
by `keel-overlay-vip` (Keel-Linux/common), as the etcd overlay ships
etcd's; the code is keel's.

## The pair record

"Only the nodes of the pair may claim the VIP: the nodes whose spec
declares the same `appliance.vip`, and that are trusted members" (third
round, point 3). A node's word about its own spec is not enough for the
others, so the pair is bound by a **record**: the mesh, the VIP and the
two members' WireGuard keys, signed by both. `keel vip pair ADDRESS`,
run once the operator declared `appliance.vip` on both nodes, signs it
and sends it to the other node over the members' channel, which signs
it too only when its own spec declares that VIP and the record names
both, and both keep it (`/var/lib/keel/vip/<vip>.pair`). A trust root of
0048's amendment may sign in place of a member.

Every claim carries the record, and every node checks it: each signature
by the key its trust store holds for that member, the claim's holder one
of the two, the claim's VIP the record's, the VIP nobody's overlay
address and inside the /112 of its members' region (0051). The first
record a node takes for a VIP is kept, and one naming other members is
refused. A release is taken only from the other member of the record.

## The move, and why it is not under the window

- **The holder carries it**: `ip -6 addr replace <vip>/128 dev wg0
  preferred_lft 0 nodad`. A deprecated address answers every connection
  made to it and is never the source of one the node makes, so the
  members' channel and every other node-to-node exchange keep the node's
  own overlay address.
- **Every other node routes it to the holder**: `wg set wg0 peer <holder>
  allowed-ips <holder>/128,<vip>/128`, which also takes it from the peer
  that had it, then the same list in `/etc/wireguard/wg0.conf`, so a
  restart keeps it. apply renders `wg0.conf` with each VIP routed to its
  holder (from the state below), so a move is never an overlay change to
  apply, and `inspect` reads the peers back without the VIP's `/128`, so
  a move is never drift in `keel diff`.

No step is under 0018's window (0029, extended by 0049): no key,
endpoint, kernel route or node's own address changes. The VIP is in the
overlay prefix and is nobody's address, which `spec validate` checks
(`appliance.vip`, [docs/spec.md](spec.md)), so it can capture no gateway
and no operator's client. The allocator of `keel mesh invite` reserves
every VIP the node knows or declares (0049).

## Claims and the epoch

A claim is a message the holder signs with its Ed25519 key, `keel vip
1\n` and the canonical JSON of the VIP, the holder's overlay address,
the pair record and an **epoch**, a counter that only grows. A node takes
a claim only when it is newer than the one it holds (a higher epoch, or
the same epoch and a lower public key), signed by the key its trust
store holds for the holder, for this mesh, from a peer at the address
the claim names, on a record it takes, and **at most 64 above the epoch
it knows**: a claim far above is refused, so no member can push the
epoch out of every honest node's reach.

On the members' channel, `POST /v1/vip` carries `claim` (the new holder
announces), `release` (the other member asks the holder to let go),
`epoch` (the newest claim a node took, which the asker checks itself)
and `pair` (the record, to be countersigned). A stale claim is refused
with 409 and the epoch known.

State, never the spec, one file per VIP under `/var/lib/keel/vip`,
root's and 0600: the newest claim taken, verbatim; whether this node is
**fenced** (it lost the VIP without letting it go: cut off, or away
while another took it; it never claims it again by itself, only a
promote here clears it); whether it **released** it when asked (a
replica, not fenced); and with etcd the lease of its own claim. When the
lease was last renewed is never kept: a time of one boot means nothing
in the next.

## keel vip promote

On the node that is to become the primary, which must hold the pair
record:

1. it finds the newest claim: before etcd, every peer is asked its epoch
   at once; with etcd, the counter;
2. when another node holds the VIP, it asks it to release, for the next
   epoch: **the old primary drops the address first and answers after**.
   When the old primary does not answer, **it refuses, unless
   `--old-primary-gone`**. With etcd and `--old-primary-gone`, it waits
   for the old primary's lease to expire, up to its TTL, and **never
   revokes another node's lease** (third round, point 5);
3. it claims at the next epoch. Before etcd, the claim is announced to
   every peer, and **this node carries the VIP only when a majority of
   the peers that answered took it**; with none answering, or a
   majority refusing, it exits non-zero and does not carry it. With
   etcd, the claim is the counter's compare-and-swap, and the controller
   adds the address once it renewed the claim's lease;
4. each peer routes the VIP with one `wg set`; one that did not answer
   takes it at its next check.

An old primary that comes back, before etcd, learns the newer claim at
its next `keel vip check` (at boot, then every minute), drops the
address at once and is fenced. That it then catches up and rejoins as a
replica is the database's part of 0049, not yet built.

## With etcd: the lease is the fence

Two keys per VIP in etcd, each a signed claim:

| Key | What it holds |
| --- | --- |
| `/keel/<mesh id>/vip/<vip>/epoch` | the newest claim, kept for good: the counter |
| `/keel/<mesh id>/vip/<vip>/holder` | the same claim, attached to the holder's lease |

A node claims only by one transaction: the epoch key still at the
revision it read and the holder key still at its revision (none, or one
that holds no valid claim), then both written, the holder's on a new
lease. A stale claim, from a counter another claim has moved since,
fails that comparison and is never written. Every node takes from etcd
only claims it verifies as above; a value that is no valid claim neither
holds the VIP nor blocks a failover. The VIP's address is under its
region's /112 (0051), so the keys need no region of their own.

**etcd has no access control here.** Each member issues its own client
certificates with its own intermediate CA (0048, third round, point 1),
and etcd takes a client certificate's CN as its user: any member could
issue itself a certificate in any user's name, so etcd's RBAC would
stop no member. The keys are guarded by the signed claims every node
checks. Making etcd's users mean something needs a change to who issues
client certificates, which is the maintainer's decision.

keel-vip.service runs on every cloud advanced member of a formed
cluster, split as keel#75 splits an invite:

- **the root helper**, `keel vip tend`, with CAP_NET_ADMIN alone, which
  alone holds the state, the trust store and the signing key, and alone
  adds or removes the address and sets a peer's allowed-ips, each
  checked against the pair record. It starts the controller as the
  transient unit `keel-vip-control`, with a dynamic user, no capability
  and the listener's sandbox, in its own network namespace, checks its
  peer with SO_PEERCRED against the unit's MainPID over a 0600 socket in
  a 0700 runtime directory, and hands it etcd's root certificate and
  this member's client certificate and key as memfds;
- **the controller**, `keel vip control`, which faces etcd and the
  overlay and asks the helper for every change:
  - **the holder renews its lease every 2 s, and carries the address
    only while the last renewal the majority confirmed is under 10 s
    old**, counted from the renewal's send on CLOCK_BOOTTIME (suspend
    counts), kept in the controller's memory alone: a controller that
    starts, after a restart or a reboot, carries nothing until it renewed
    the lease itself. A renewal counts once a linearizable read, which
    needs the majority, finds the holder's key on this lease with this
    node's claim; any error of etcd is no renewal. A lease etcd says is
    gone, or a holder key that is not this lease's, fences the node;
  - every node follows the keys and takes a newer claim as from the
    channel;
  - the other node of the pair **claims once no valid holder key is
    left** (the lease expired), when it has taken the counter's claim and
    is not fenced: 0020's automatic failover, which etcd's three voters
    make possible. It announces the claim on the channel for the nodes
    that are not cloud advanced (third round, point 4).

`--stopped`, the unit's `ExecStopPost`, drops every VIP the node carries,
so a helper that died never leaves an unrenewed one behind it, and the
unit has no start limit, so it is never left stopped for good.

**The TTL is 20 s, the release 10 s.** etcd cannot expire a lease before
TTL seconds after the last renewal it answered, so a holder cut off from
the majority has dropped the VIP 10 s before any other node can win it.
Against etcd's 5 s election timeout ([docs/mesh.md](mesh.md),
"Timeouts"): a re-election in the majority takes 5 to 10 s, during which
renewals fail, but etcd gives every lease its full TTL again on a leader
change, so 10 s rides out one re-election without a move. etcd's leader
renews a lease by itself, without the majority, so a leader cut off
would answer renewals until it steps down, up to two election timeouts;
it cannot answer the linearizable read. The cut off holder so drops the
VIP at most 14 s after the last renewal the majority confirmed (one
renewal period and a call's timeout late), and the lease expires no
sooner than 20 s after it (25 s when the majority elects a new leader,
which gives the lease an election timeout more). A frozen process (a
stopped container) is the one case this does not cover: 0020's
watchdog is not built, and a container has none.

## What status, inspect and diff show

`keel vip status`, also at the end of `keel mesh status`: each VIP this
node declares or routes, the role (on the pair's nodes), the epoch and
holder, fenced or released, the etcd lease, whether wg0 carries it and
which peer the table routes it to. `keel inspect` writes `appliance.vip`
from the spec the installer emitted, and reports beside the spec one line
per VIP: the role, the epoch and holder, fenced, and on the live system
carried and routed to. That is what the follow-up of tracker#57 reads to
bind Webmin per role. `keel diff` compares `appliance.vip` like any field
and the peers without the VIP.

## Tests

- the claims, their order, the state file and the routing in and out of
  the overlay's file, pure (`tests/test_mesh_vip.py`);
- the pair record: `keel vip pair`, the countersignature, a trust root's
  signature, a member's address or another region as the VIP, a claim
  by a trusted member outside the pair, a record of its own making, an
  epoch jump, a release from outside the pair, the majority a promote
  needs, the allocator (`tests/test_mesh_vippair.py`);
- promote, release, the announcement, the check and the channel's
  refusals, before etcd, with a pair and a third node in one process
  (`tests/test_mesh_vipmove.py`, `tests/vip_helpers.py`);
- the counter's compare-and-swap, a holder key that is no claim, the
  root half's checks, the controller's renewal, carry, following and
  failover, a holder restarted or rebooted with its state, an error of
  etcd, and promote through etcd, on a fake etcd
  (`tests/test_mesh_vipetcd.py`), the client's lease and transaction
  calls against a fake gateway over real TLS
  (`tests/test_mesh_etcdclient.py`);
- the helper and the controller over their socket, the credentials as
  memfds, a controller with capabilities refused, and the controller's
  unit (`tests/test_mesh_vipbridge.py`);
- the wiring: the channel, the commands, `keel database promote`, the
  spec, inspect and apply's rendering (`tests/test_mesh_vipwiring.py`,
  `tests/test_mesh_vipedges.py`);
- end to end, `tests/test_vip_netns.py` runs `tests/vip_netns.py` as root
  in a network namespace that routes for three others, on links of
  250 ms ±25 ms with 2% loss measured first (judged by the minimum round
  trip), the real wg-quick and etcd 3.5. Each node runs the members'
  channel (its listener without capabilities), and keel vip tend as a
  systemd unit joined to its namespace with keel-vip.service's sandbox,
  which starts the controller as its own unit: the controller's uid and
  capabilities, and the helper's bounding set, are read from the
  kernel. A and B are paired with `keel vip pair`, C routes the VIP and
  pings it every 50 ms; a sampler reads every node's wg0 every 200 ms.
  (a) A promotes and C reaches the VIP; (b) B promotes, planned, A
  releases first, and the longest gap in C's answers is the downtime;
  (c) B, made etcd's leader, is cut off: it drops the VIP within the
  release time and A claims it once B's lease expired; (d) healed, B
  never carries it again; (e) B's claim at its old epoch is refused by C
  on the channel and by etcd's compare; (f) B promoted again, C made
  etcd's leader, and B, a follower, cut off: the same. At no sample do
  two nodes carry it. In CI, `vip / trixie`, with systemd booted.
