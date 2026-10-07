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
keel vip promote [--old-primary-gone]
keel vip status
keel vip check            # keel-vip-check.timer, at boot and every minute
keel vip tend [--stopped] # keel-vip.service, the controller with etcd
```

`keel database promote` moves the VIP first, with the same
`--old-primary-gone`, when the spec declares one. The units are shipped
by `keel-overlay-vip` (Keel-Linux/common), as the etcd overlay ships
etcd's; the code is keel's.

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
and no operator's client.

## Claims and the epoch

Who holds the VIP is decided by **claims**: a message the holder signs
with its Ed25519 key, `keel vip 1\n` and the canonical JSON of the VIP,
the holder's overlay address and an **epoch**, a counter that only
grows. A node takes a claim only when it is newer than the one it holds:
a higher epoch, or the same epoch and a lower public key (two promotes
at once). It is taken only signed by the key the node's trust store
holds for the holder (0048's amendment), for this mesh, from a peer at
the address the claim names. A claim is the holder's signed word that
its own spec declares that VIP: keel signs one only for its own
`appliance.vip` (third round, point 3).

On the members' channel, `POST /v1/vip` carries `claim` (the new holder
announces), `release` (the other node of the pair asks the holder to let
go) and `epoch` (the newest claim a node took, which the asker checks
itself). A stale claim is refused with 409 and the epoch known; a
release only by a node whose own spec declares the VIP, fresh, for a
newer epoch.

State, never the spec, one file per VIP under `/var/lib/keel/vip`,
root's and 0600: the newest claim taken, verbatim; whether this node is
**fenced** (it lost the VIP without letting it go: cut off, or away
while another took it; it never claims it again by itself, only a
promote here clears it); whether it **released** it when asked (a
replica, not fenced); and with etcd the lease of its own claim and when
it was last renewed.

## keel vip promote

On the node that is to become the primary:

1. it finds the newest claim: before etcd, every peer is asked its epoch
   at once; with etcd, the counter;
2. when another node holds the VIP, it asks it to release, for the next
   epoch: **the old primary drops the address first and answers after**.
   When the old primary does not answer, **it refuses, unless
   `--old-primary-gone`**. With etcd and `--old-primary-gone`, it waits
   for the old primary's lease to expire, up to its TTL, and **never
   revokes another node's lease** (third round, point 5);
3. it claims at the next epoch: before etcd, signed and carried at once;
   with etcd, by the counter's compare-and-swap, and the controller adds
   the address once the claim stands;
4. it announces the claim to every peer; each routes the VIP with one
   `wg set`. A peer that did not answer takes it at its next check.

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
revision it read and no holder key, then both written, the holder's on
a new lease. A stale claim, from a counter another claim has moved since,
fails that comparison and is never written. The VIP's address is under
a /112 of the region that holds it (decision 0051), so the keys need no
region of their own.

`keel vip tend` runs on every cloud advanced member of a formed cluster:

- **the holder renews its lease every 2 s, and drops the address when no
  renewal was answered for 10 s**, counted from the send of the last
  renewal etcd answered, then is fenced;
- every node follows the keys, and takes a newer claim as from the
  channel;
- the other node of the pair **claims once the holder key is gone** (the
  lease expired), when it has taken the counter's claim and is not
  fenced: 0020's automatic failover, which etcd's three voters make
  possible. It announces the claim on the channel for the nodes that are
  not cloud advanced (third round, point 4);
- only the controller adds the address on a node with etcd, once its own
  claim stands and its lease is fresh. `--stopped`, the unit's
  `ExecStopPost`, drops every VIP the node carries, so a controller that
  died never leaves an unrenewed one behind it.

**The TTL is 20 s, the release 10 s.** etcd cannot expire a lease before
TTL seconds after the last renewal it answered, so a holder cut off from
the majority has dropped the VIP 10 s before any other node can win it.
Against etcd's 5 s election timeout ([docs/mesh.md](mesh.md),
"Timeouts"): a re-election in the majority takes 5 to 10 s, during which
renewals fail, but etcd gives every lease its full TTL again on a leader
change, so 10 s rides out one re-election without a move. A holder that
is etcd's leader when it is cut off renews locally until it steps down
(an election timeout), so it drops the VIP at most 15 s after the cut;
the new leader gives the lease its TTL and an election timeout more, so
it expires no sooner than 30 s after the cut. A container has no watchdog (0020): the
guarantee rests on the controller running, which the unit restarts.

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
- promote, release, the announcement, the check and the channel's
  refusals, before etcd, with a pair and a third node in one process
  (`tests/test_mesh_vipmove.py`, `tests/vip_helpers.py`);
- the counter's compare-and-swap, the controller's renewal, fence,
  following and failover, and promote through etcd, on a fake etcd
  (`tests/test_mesh_vipetcd.py`), the client's lease and transaction
  calls against a fake gateway over real TLS
  (`tests/test_mesh_etcdclient.py`);
- the wiring: the channel, the commands, `keel database promote`, the
  spec, inspect and apply's rendering (`tests/test_mesh_vipwiring.py`,
  `tests/test_mesh_vipedges.py`);
- end to end, `tests/test_vip_netns.py` runs `tests/vip_netns.py` as root
  in a network namespace that routes for three others, on links of
  250 ms ±25 ms with 2% loss measured first (judged by the minimum round
  trip), the real wg-quick and etcd 3.5, each node running the members'
  channel (its listener without capabilities) and the controller. A and B
  are a pair, C routes the VIP and pings it every 50 ms; a sampler reads
  every node's wg0 every 200 ms. (a) A promotes and C reaches the VIP;
  (b) B promotes, planned, A releases first, and the longest gap in C's
  answers is the downtime; (c) B is cut off: it drops the VIP within the
  release time and A claims it once B's lease expired; (d) healed, B
  never carries it again; (e) B's claim at its old epoch is refused by C
  on the channel and by etcd's compare. At no sample do two nodes carry
  it. In CI, `vip / trixie`.
