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
  valid_lft N preferred_lft 0 nodad`. A deprecated address answers every
  connection made to it and is never the source of one the node makes,
  so the members' channel and every other node-to-node exchange keep the
  node's own overlay address. With etcd, N is what is left of the
  release time after the last renewal the majority confirmed, less the
  1 s the kernel may be late, so the kernel itself removes the address by that
  deadline unless a renewal gives it a new lifetime; before etcd it is
  carried for good.
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
   the peers that answered took it**; with a majority refusing, or none
   answering without `--old-primary-gone`, it exits non-zero and does
   not carry it. With `--old-primary-gone` and no peer answering (a mesh
   of the two nodes alone, the other one gone), the operator's flag is
   the acceptance. With
   etcd, the claim is the counter's compare-and-swap, and the controller
   adds the address once it renewed the claim's lease;
4. each peer routes the VIP with one `wg set`; one that did not answer
   takes it at its next check.

An old primary that comes back, before etcd, learns the newer claim at
its next `keel vip check` (at boot, then every minute), drops the
address at once and is fenced. That it then catches up and rejoins as a
replica is the database's part of 0049, not yet built.

## With etcd: the lease is the fence

A claim with etcd carries, signed into it, the ID of the lease that
holds it. Two keys per VIP:

| Key | What it holds |
| --- | --- |
| `/keel/<mesh id>/vip/<vip>/epoch` | the newest claim, kept for good: the counter |
| `/keel/<mesh id>/vip/<vip>/holder` | the same claim, attached to its lease; shown, and read by no decision |

A node claims only by one transaction: a new lease, the claim signed
with it at the next epoch, both keys written only when the counter is
still at the revision the node read. A stale claim, from a counter
another write has moved since, fails that comparison and is never
written. Every node takes from etcd only counter values it verifies as
above. The VIP's address is under its region's /112 (0051), so the keys
need no region of their own.

**Only the pair writes its keys, and what follows is defence in depth
behind that.** Since keel#83 the root signs every certificate etcd is
shown and names it after its member, so etcd's users are the members,
and once `keel mesh etcd reissue` has turned etcd's auth on, the keys
under `/keel/<mesh>/vip/<vip>/` are read-write for the pair's two
members alone and read-only for everyone else ([docs/mesh.md](mesh.md),
"etcd's users and roles"): a member outside the pair cannot write or
delete them, nor revoke a lease attached to them. The root's holder
gives a pair its role when one of its members sends it the pair record:
`keel vip pair` does, and `keel mesh etcd tend` sends it again on each
member of the pair, so a new pair claims once the holder has answered.
etcd 3.5 checks no permission for a lease's keep-alive, so any member
can still keep a lease alive by its ID, and with auth off (before the
reissue, or after its rollback) any member can write these keys; so no
decision rests on a key's value alone:

- **the holder decides only by its own lease.** A value written to the
  holder key, or the key deleted, neither fences it nor keeps it. A
  lease etcd says is gone after the holder was cut off past its release
  time expired: it fences the holder. One gone while the holder still
  renewed it with the majority was revoked, by anyone: the holder drops
  the address at that renewal (two seconds at most), lost nothing, and
  claims again at the next epoch by the counter's transaction, which
  serialises it with any claim of the other node. Revokes in a row
  never leave the pair fenced;
- **the other node of the pair claims only once the lease of the newest
  claim it verified is gone**, asked of etcd by the ID signed into that
  claim (TimeToLive), never because the holder key was deleted or
  rewritten. A lease that ends before its TTL ran out was revoked, and
  the holder learns that only at its next renewal, or, cut off, at its
  release time, so the other node waits a grace of 14 s (the release
  time, a renewal period and a call) after it saw the lease gone early,
  and by then the holder, connected, has usually claimed again. No
  double holder follows, and no outage longer than the TTL;
- a counter value that is no valid claim, or an older one, is ignored,
  and a claim's transaction replaces it.

keel-vip.service runs on every cloud advanced member of a formed
cluster, split as keel#75 splits an invite:

- **the root helper**, `keel vip tend`, with CAP_NET_ADMIN alone, which
  alone holds the state, the trust store and the signing key, and alone
  adds or removes the address and sets a peer's allowed-ips, each
  checked against the pair record. It starts the controller as the
  transient unit `keel-vip-control`, with a dynamic user, no capability
  and the listener's sandbox, in its own network namespace. They meet on
  an abstract unix socket of that namespace, under a fresh name of 16
  random bytes the helper binds before it starts the controller and
  hands to it, so no process can take the name first: each end checks
  the other by SO_PEERCRED, the helper against the controller's unit's
  MainPID, the controller for root. The helper hands
  it etcd's root certificate and this member's certificate and key as
  memfds, writes them into the same memfds again when a renewal or
  `keel mesh etcd reissue` changes them, and sets no-new-privileges on
  itself when its unit did not;
- **the controller**, `keel vip control`, which faces etcd and the
  overlay and asks the helper for every change:
  - it asks etcd with etcdctl over gRPC (keel.mesh.etcdclient), each
    call a process handed the memfds as /proc/self/fd paths, so the key
    is in no file; about 35 ms of process before etcd answers, measured
    on the design case's links by tests/test_etcd_auth_netns.py, within
    the 2 s a call may take. A call that fails or prints anything but
    etcd's JSON is no renewal;
  - **the holder renews its lease every 2 s, and carries the address
    only while the last renewal the majority confirmed is under 10 s
    old**, counted from the renewal's send on CLOCK_BOOTTIME (suspend
    counts), kept in the controller's memory, and **enforced by the
    kernel**: each confirmed renewal gives the address the rest of the
    10 s as its lifetime, so it is gone by then whatever becomes of the
    controller, stopped, restarting, crashed or frozen. A controller
    that starts after a restart leaves an address a previous one gave a
    lifetime to the kernel and extends it only once it renewed the same
    lease itself; one with no lifetime (an older keel's) it drops. After
    a reboot there is nothing to extend. A renewal counts once a
    linearizable read, which needs the majority, answers after it,
    whichever member relays it: the controller asks this member's etcd
    first, then the others of the cluster record, so the holder renews
    while its own etcd restarts. Any error of etcd is no renewal;
  - every node follows the counter and takes a newer claim as from the
    channel;
  - the other node of the pair claims as above: 0020's automatic
    failover, which etcd's three voters make possible. It announces the
    claim on the channel for the nodes that are not cloud advanced
    (third round, point 4).

`--stopped`, the unit's `ExecStopPost`, drops every VIP the node
carries, **except while the unit restarts**: a restart job of the unit
(an upgrade's `try-restart`), or a helper that died, which Restart=always
starts again 2 s later (`$SERVICE_RESULT` other than `success`). Then an
address with a lifetime stays, and the kernel removes it at the release
time unless the next controller renews the lease. A `systemctl stop`, the
overlay disabled by `keel spec apply`, or a shutdown drops it at once.
The unit has no start limit, so it is never left stopped for good.

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
which gives the lease an election timeout more). The address's lifetime
makes the kernel drop it sooner still, by 10 s after that renewal, also
for a frozen process (a stopped container), which no controller can
cover: `tests/test_vip_upgrade_netns.py` (d).

## Upgrading a pair without downtime

The maintainer's requirement of 2026-10-10: an `apt full-upgrade` on any
node of the pair, or on any etcd member, neither drops the VIP nor moves
it, beyond a short blip, measured below.

What each package does on upgrade:

| Package | On upgrade | The VIP |
| --- | --- | --- |
| `keel-overlay-vip` | `try-restart keel-vip.service`, never a stop first; nothing started that was stopped | kept: the address and its lease survive the restart (above) |
| `keel` | restarts its own units (the members' channel, sync, etcd's tend); a trigger in `keel-overlay-vip` try-restarts `keel-vip.service`, so the new code runs | kept, as above |
| `etcd-server` | `restart etcd.service`, through keel-overlay-etcd's gate: one member at a time ([docs/mesh.md](mesh.md), "keel mesh etcd gate, and upgrades") | kept: the holder renews through the other members while its own etcd restarts |

The procedure, one node at a time:

1. on the node, `keel mesh upgrade-check`: 0 when every other etcd
   member is healthy and none restarts; it also says whether this node
   holds the VIP;
2. `apt full-upgrade` on it; a second node's etcd restart waits in its
   gate until this one is back, so a fleet tool that runs apt on several
   at once loses no majority, only time;
3. once `keel mesh upgrade-check` passes again, the next node. **The
   holder last**, or, to take no risk with it at all, `keel vip promote`
   on the replica first: a planned move, about 3 to 4 s with no answer
   (the vip job's (b)), and the upgraded replica serves meanwhile;
4. a reboot (a new kernel) is a planned move too: promote the replica
   first, as above. Rebooted, a node carries nothing until its own claim
   is renewed, and a former holder never claims again by itself.

The first upgrade *into* the keel that keeps the address over a restart
still blips once on the holder: the old helper, in memory, drops it as
it stops, and the new controller carries it again at its first renewal.

Measured in CI (`vip-upgrade / trixie`, links of 250 ms ±25 ms with 2%
loss, three runs), the longest gap in a third node's answers to the VIP,
pinged every 50 ms. Gaps this short are the links' own loss: the address
never left wg0. Before keel 0.21.0, the same restart of the holder's
keel-vip.service cost 2.8 to 3.2 s, and its helper killed 4.4 s:

| Restart, as the package does it | Gap | Failover |
| --- | --- | --- |
| keel-vip.service on the holder (try-restart) | 0.12 to 0.30 s | none |
| keel-vip.service on the replica | 0.13 to 0.28 s | none |
| the holder's helper killed (Restart=always, 2 s) | 0.14 to 0.17 s | none |
| etcd on the third member, the holder, the replica (10 to 15 s each, through the gate) | 0.13 to 0.39 s | none |

The holder's controller frozen (SIGSTOP) is no upgrade, but the kernel's
part shows there: the address was gone 6.2 to 6.9 s after the freeze, and
the replica carried the VIP once the lease expired, 21 s after it, never
both at once. Before, the frozen holder kept it until the replica's claim
reached it: both carried it for 0.8 s.

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
- the counter's compare-and-swap, the lease signed into a claim, a
  counter value that is no claim, the root half's checks, the
  controller's renewal, carry, following and failover, a holder
  restarted or rebooted with its state, an error of etcd, a member
  outside the pair putting an old claim or the current one without its
  lease under the holder key, deleting it, putting an old claim under
  the counter, and revoking the holder's lease, twice in a row and with
  the holder cut off too, and promote through etcd, on a fake etcd with a clock
  (`tests/test_mesh_vipetcd.py`), the client's lease and transaction
  calls against a recording etcdctl, a failed or unparseable call never
  a renewal (`tests/test_mesh_etcdclient.py`), the pair's role
  (`tests/test_mesh_etcd_auth.py`);
- the helper and the controller over their socket, the fresh abstract
  name the helper binds (the old fixed name taken by another process
  changes nothing) and the credentials checks, the credentials as memfds,
  written again into them when they change, a controller
  with capabilities refused, no-new-privileges, and the controller's
  unit (`tests/test_mesh_vipbridge.py`); a two-node mesh promoted with
  `--old-primary-gone` (`tests/test_mesh_vippair.py`);
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
  etcd's leader, and B, a follower, cut off: the same; (g) B promoted
  again, C, outside the pair, writes the old claim and the current one
  without its lease under the holder key and deletes it (nothing moves),
  then revokes the holder's lease twice in a row: each time it drops the
  VIP at its next renewal and a node carries it again within the TTL.
  At no sample do
  two nodes carry it. In CI, `vip / trixie`, with systemd booted.
- upgrades: the address's lifetime and its arithmetic, a renewal giving
  it a new one, a restarted controller keeping a bounded address and
  dropping one with none, `--stopped` on a restart, a crash and a stop,
  the controller's endpoints (`tests/test_mesh_vipupgrade.py`); etcd's
  gate and `keel mesh upgrade-check` on a fake etcd
  (`tests/test_mesh_etcdgate.py`); end to end,
  `tests/test_vip_upgrade_netns.py` on the nodes and links above:
  keel-vip.service try-restarted on the holder three times and on the
  replica, the holder's helper killed, etcd restarted through its gate on
  C, the holder A and B in turn, C held down while B's gate waits and
  `upgrade-check` names C, and the holder's controller frozen (SIGSTOP),
  the kernel dropping the address. No failover, never two holders, and
  under 1 s without an answer for each upgrade-style restart. In CI,
  `vip-upgrade / trixie`.
