# MariaDB primary and replica on the mesh

Phase 2, step 3 of the roadmap: a MariaDB pair on the WireGuard mesh
whose primary is the holder of the pair's VIP (handbook decisions 0013,
0020, 0028, 0031, 0049 and its third round, 0050, 0051; tracker#57; the
maintainer's answers of 2026-10-03: semi-synchronous replication with a
10 s timeout and the fallback reported as drift, TLS on the replication
channel in addition to WireGuard, dumps on the standby as the interim
backup; and the four points of 2026-10-11 under "Decided" at the end).
Implemented in keel 0.23.0 (Keel-Linux/keel#93); measured under the
design case of 0050 in CI (`mariadb / trixie`), the numbers under
"Measured".

What keel 0.11 built is kept and corrected: a replica seeded from a
dump, GTID, `--destroy-local-database`, the root lock, `keel database
promote`. Two things it does are against 0031 and go: replication was
asynchronous, and a replica served reads.

## The pair

```yaml
appliance:
  name: mariadb
  vip: fd2a:9c41:7e03::ffff:1   # in the overlay's VIP range, no region's
installation:
  mode: cloud_simple          # or cloud_advanced
database:
  server:
    engine: mariadb
    role: primary             # the role chosen at installation (0020)
    listen: [fd2a:9c41:7e03::1, "::1"]
```

- **The primary is the VIP's holder** (0049, third round, point 2). On
  a node that declares `appliance.vip`, `database.server.role` is the
  role chosen at installation: it decides who claims the VIP first, at
  epoch 1, and who seeds from whom; from then on the role is runtime
  state, the VIP's (0020, "One role"). `keel inspect` reports the role
  the server is in, `keel diff` compares the declared role with it as
  **information** on a paired node, never as drift to repair, and
  `apply` never converges the role. On a node without a VIP, 0013's
  rule stands: a promotion by hand is drift, and `apply` refuses to
  demote.
- **The VIP is in the overlay's VIP range**, `<prefix>::ffff:n` (0051,
  keel#97), the same on both members whatever their regions. With etcd,
  `keel vip pair` reserves it there, signed, so no other pair takes it.
  A pair made before 0.23.3, whose VIP is outside the range (such as
  `fd2a:9c41:7e03::100`), keeps it: its signed pair record keeps the VIP
  valid, and replication, the VIP's SAN and the failover work as before
  ([docs/vip.md](vip.md), "VIPs paired before the range").
- **Nothing is typed twice.** With a pair record (`keel vip pair
  <the other node's overlay address>`, [docs/vip.md](vip.md)),
  keel derives `replication.allowed_from` (the other member's /128),
  `replication.primary` (the holder's own overlay address, never the
  VIP: 0029), and the replication credential (below). The three stay
  accepted in the spec and must agree with the record when declared.
- **Clients connect to the VIP**, the embedded WordPress of 0047 among
  them later. The VIP is never on the replica.
- **Both nodes carry the same drop-in**, whatever their role:
  `server_id` (as today), `log_bin` and `binlog_format = ROW` on both
  (a replica with no binary log cannot be promoted into a primary the
  old one can rejoin), `gtid_strict_mode = ON` (0049), `log_slave_updates`,
  the semi-synchronous variables below, the TLS files below, and
  `bind-address` = the declared `listen` plus the VIP. The role flips
  nothing in the file, so a role change restarts nothing.

### The primary answers on the VIP without a restart

MariaDB binds its addresses at start and cannot add one while it runs,
and the VIP moves between nodes without any restart (0049). So keel sets
`net.ipv6.ip_nonlocal_bind = 1` (per network namespace, writable by a
container's root, as the VIP tests write `forwarding`) and both nodes
bind the VIP beside their own address. On the replica the socket exists
and no packet reaches it, since every peer routes the VIP to the holder;
on the primary the connections arrive the moment the address is on
`wg0`. The alternative, a restart of MariaDB on each role change, costs
one to three seconds of refused connections on top of the move and
leaves a drop-in naming an address the node may not hold at its next
boot, which stops the server. See question 2.

## Semi-synchronous replication (0031)

Built into MariaDB 11.8, no plugin to install. On both nodes:

```
rpl_semi_sync_master_enabled = ON
rpl_semi_sync_slave_enabled = ON
rpl_semi_sync_master_wait_point = AFTER_SYNC
rpl_semi_sync_master_timeout = 10000
rpl_semi_sync_master_wait_no_slave = OFF
slave_net_timeout = 10
```

MariaDB waits for one replica's acknowledgement by design; MySQL's
`rpl_semi_sync_master_wait_for_slave_count` does not exist in MariaDB,
and 11.8 refuses to start with it (the first thing the end to end test
found). A node with no replica connected does not wait
(`wait_no_slave = OFF`): with MariaDB's default both sides on made the
replica's own SQL thread a master with no slave, and it waited the 10 s
on the first transaction it applied ("Waiting for semi-sync ACK from
slave" for 9.9 s, the end to end test's trace); a connected replica that
does not answer still costs the primary the 10 s, which is the fallback
below. A replica that hears nothing for 10 s reconnects (heartbeats every
5 s) instead of MariaDB's 60.

Both sides enabled on both nodes, so a promotion flips nothing here: a
replica with `master_enabled` has no replica of its own and waits for
nobody until it is promoted; a primary with `slave_enabled` replicates
from nobody. A commit on the primary returns once the replica has
*received* it (not applied), one round trip, 250 ms in the design case.

**The fallback.** With no acknowledgement within 10 s the primary
commits asynchronously (`Rpl_semi_sync_master_status: OFF`) and stays
so until the replica is back and caught up, when MariaDB turns it on
again by itself. Writes continue (the maintainer's answer). keel reports
it:

- `keel inspect` reports `database.server.semi_sync` (`on`, `off`, the
  clients, the transactions acknowledged and not) and `keel diff` on a
  paired primary reports `off` as **drift**: "the replica does not
  acknowledge; commits are asynchronous and a failover loses them";
- `keel-database-watch.timer` runs `keel database watch` every 30 s,
  which alerts on the change to `off` and on the recovery, through the
  monitor's channels (0021, 0040) as `keel mesh etcd tend` alerts, and
  records the state in `/var/lib/keel/database/semi-sync` so a lasting
  fallback alerts once, not every 30 s.

**What the fallback means at a failover.** A write that was waiting for
the replica when the link broke commits on the old primary after the
10 s, before or around the moment the VIP's fence (the lease's 10 s
release, 0049) takes it read-only; it never reached the replica and is
an errant transaction. So an old primary cut off *while clients were
writing* usually comes back diverged and waits for the operator (below),
and one cut off while idle rejoins by itself. Both are measured in the
test, and docs say so.

## The replica serves nothing (0031, 0049)

- `read_only = ON`, set at run time by `SET GLOBAL` and carried in the
  state the role hook reads, not in the drop-in (the file is the same
  on both nodes).
- `READ_ONLY ADMIN` is revoked from every account but
  `'mysql'@'localhost'`, **root included** (0049, second round, point
  1), recorded in `/var/lib/keel/database/read-only-admin` as today and
  given back on promotion. keel runs its own replica statements through
  `runuser -u mysql -- mariadb` (the seed, `CHANGE MASTER`, the lock,
  the rejoin, the promotion). Root at a shell or through Webmin gets
  error 1290 like the application. docs/apply.md's "root still writes"
  is corrected.
- The replica's server listens on its own overlay address (for its pair
  peer: replication and the rejoin's comparison), `::1`, and the VIP it
  never receives. Clients are configured with the VIP, so they never
  reach it; in cloud advanced the derived firewall accepts 3306 on `wg0`
  from the pair peer and for the VIP only.
- `database.client.replicas` keeps its meaning for a client that reads
  from replicas it names; a paired set names none (0031, "0013, Several
  replicas").

## TLS on the replication channel

Required in addition to WireGuard (the maintainer's answer). The
certificates come from **the mesh root CA** of keel#78/#83/#90: the root's
holder issues a second leaf per node, kind `database`, CN `keel-<address>
mariadb`, IP SANs the node's own /128 and **the pair's VIP** (so a client
verifying the VIP works later), `extendedKeyUsage serverAuth, clientAuth`,
30 days, renewed with a third left as the member certificate is, through
the members' channel. Its CN is no etcd user, so the key, readable by the
`mysql` system user (`/etc/mysql/keel-tls/`, 0640 root:mysql),
opens nothing in etcd if it leaks. The server side: `ssl_ca` the root
(the trust bundle of 0051 when it has several), `ssl_cert`, `ssl_key`.
The replica: `MASTER_SSL=1, MASTER_SSL_CA, MASTER_SSL_CERT, MASTER_SSL_KEY,
MASTER_SSL_VERIFY_SERVER_CERT=1`, the server's certificate verified
against the root and the IP SAN of the address it dialled. The `repl`
account carries `REQUIRE SUBJECT '/CN=<the other member's name> mariadb'
AND ISSUER '/CN=<the root's name>'`: the other member's database
certificate alone, which is `REQUIRE SSL` and more, and refuses an etcd
member's or the admin's leaf of the same root (measured: 1045). The
server checks a client's certificate against the root's CRL
(`ssl_crl`), which `keel database watch` copies from the mesh's when it
changes and reloads with `FLUSH SSL`. The VIP goes into a certificate's
SANs only on the pair's signed record, which the request carries and the
root's holder verifies (both members' signatures, the asker among them).
The seed's `mariadb-dump` and the rejoin's comparison use the same
files. The files live under `/etc/mysql/keel-tls`, which the server
reaches as the `mysql` user: `ca.pem`, `server.pem` and `crl.pem` 0644,
`server.key` 0640 root:mysql.

Why not a separate database CA signed by the root: two CAs per node,
two renewal paths, and 0051's federation would have to carry both. Why
not the member certificate itself: its key is etcd's, and a key the
`mysql` user can read would log in to etcd as the member.

**The root does not exist in cloud simple today** (docs/mesh.md: made
by `keel mesh create` on a cloud advanced node, or `keel mesh etcd
form`). So `keel mesh create` makes it in every cloud mode (the
maintainer, 2026-10-11): in cloud simple the root signs the database's
certificates alone, and the etcd overlay stays disabled there (0041).
The database leaf is asked of the root's holder over the members'
channel (`issue`, kind `database`); the holder signs only for the
address its own spec gives the asker's key. Every member knows the
holder's address from a notice signed by the root's key, which the
rosters carry (docs/mesh.md, keel#105): on a real mesh whose root was
held by a cloud advanced node outside the pair, the pair members knew
no holder, asked each other and were refused. A node that knows no
holder fetches its peers' rosters before it asks, and asks the other
member of the pair only when no roster says where the holder is (a
cloud simple pair whose first node made the mesh). When the node
holds a root certificate, or learned one from a trust root, the leaf
is taken only under that root.

## The replication credential

Generated on the node that is primary at the pair's first apply
(`secrets.token_urlsafe`), stored in
`/var/lib/keel/database/replication.secret` (0600, root), never in the
spec and never typed. The other member of the pair asks for it over the
members' channel, `POST /v1/database` kind `secret`, signed by its mesh
key; the holder answers only the other member of the pair record, over
the channel's TLS inside WireGuard, and the asker stores it the same
way. This is the first use of 0041's `shared` secret policy and the
mechanism later shared secrets take. `replication.secret` in the spec
stays accepted, as a file the operator put on both nodes, and wins when
declared.

## Promotion and the role hook

**`keel database promote [--old-primary-gone]`** on the replica, as
today, in this order: `keel vip promote` (release before take; refused
without the flag when the old primary does not answer: 0049, second
round, point 3), then the database: drain the relay log, `STOP SLAVE`,
`RESET SLAVE ALL`, `read_only = OFF`, `READ_ONLY ADMIN` back. The
semi-synchronous roles need no flip (both sides enabled on both nodes).

**The database follows the VIP** (0020: everything that depends on the
role follows the elected role). `keel-database-follow.path` watches
`/var/lib/keel/vip/` and runs `keel database follow`, which makes the
server match the VIP state keel holds:

| VIP state on this node | `keel database follow` |
| --- | --- |
| holds the VIP, newest epoch, the VIP on `wg0` | promote, as above, when the server is a replica or read only |
| its own claim the newest it knows, the VIP not on `wg0` | `read_only = ON`, the root lock, nothing else: not proven (keel#104) |
| fenced, or released | `read_only = ON` at once, the root lock, then the rejoin below |
| no claim known yet, on a paired node | `read_only = ON`, the root lock: a declared primary is not proven either (keel#104) |

**A claim in the file is not a proof.** A node that crashed and boots
keeps its last claim in `/var/lib/keel/vip`, while the other node can
hold the VIP at a newer epoch. On a real pair (keel#104) the old
primary set `read_only = OFF` from that claim at boot and was writable
for 31 s, until `keel vip check` learned the newer epoch. The server is
read only from its first second (the role's drop-in), and `keel
database follow` lifts `read_only` only when this node's own claim is
the newest it knows and the VIP is on `wg0`. A paired node with no
claim (its state file removed, or before the first promote) stays read
only too. keel adds the VIP to `wg0` only in these cases: `keel vip
promote` after its new claim; with etcd, the controller after a renewal
of its lease that the majority confirmed, with a `valid_lft` that the
kernel ends at the release deadline; without etcd, `keel vip check`
when at least one peer answered and no peer that answered knows a newer
claim. A boot removes the address. Without etcd the address has no
lifetime: it stays on `wg0` until keel removes it or the node boots, so
the proof there is weaker (keel#113). `keel database watch` follows a
server again when it takes writes while the VIP is not on `wg0`. So
with etcd not reachable at boot, or with no peer that answers, the node
stays read only. One follow runs at a time
(`/var/lib/keel/database/follow.lock`). Follow waits up to 15 s for the address, because a promote
records its claim before it adds the VIP; when keel adds the VIP, it
writes the VIP's state again, so `keel-database-follow.path` runs
follow again. `keel database watch` runs follow again within 30 s if
these runs are missed.

So in cloud advanced the controller's failover promotes the database on
the new holder within seconds of the claim, and the old primary turns
read only the moment it drops the address (its lease's release, 10 s);
in cloud simple a promote by hand on the replica does the first, and the
old primary does the second at its next `keel vip check` (boot, then
every minute) once it hears the newer claim. The path unit is the seam
between the VIP's helper, which holds `CAP_NET_ADMIN` alone and cannot
run `runuser`, and the database, which needs root.

## The old primary coming back (0049)

Read only from the moment it learns the higher epoch. Then `keel
database follow` compares GTID sets: its own `@@gtid_binlog_state`
against the holder's, read over the overlay as `repl` at the holder's
own address, under TLS.

- **No errant transaction** (every sequence of this node's domain and
  server id is at or below the holder's): `gtid_slave_pos` set to this
  node's `@@gtid_binlog_pos`, `CHANGE MASTER TO` the holder's address
  with `MASTER_USE_GTID = slave_pos` and the TLS options above, `START
  SLAVE`; the node is a replica, the lock stays. Automatic, since nothing
  is lost. Before anything, as 0020 asks, a dump of what the node held
  is kept under `/var/backups/keel/mariadb/rejoin-<time>.sql.zst`.
- **Some**: the node stays read only and is not connected. keel records
  the errant GTIDs (domain, server id, sequence) in
  `/var/lib/keel/database/diverged`, `keel diff` reports the divergence
  as a finding, `keel database status` lists them, and `keel database
  watch` alerts once through the monitor's channels. The operator
  chooses: `keel spec apply --system-only --destroy-local-database`
  reseeds from the holder (the dump above is kept first), or reconciles
  by hand and runs `keel database follow` again.

The spec is not rewritten by the rejoin: the role in the spec is the one
chosen at installation (0020), `inspect` writes the observed role out,
and keel#69 (one writer for instance.yaml) is open. 0049's "writes
`role: replica` into its own spec" is read as the emitted spec, a
precision the maintainer approved on 2026-10-11 and the handbook records
under 0049.

## Dumps on the standby (interim backup)

`keel-database-dump.timer` on a paired node runs `keel database dump`
daily; it dumps only while the node is the replica (a hot standby that
serves nothing has the room and the idle time), `mariadb-dump
--single-transaction --gtid --all-databases` compressed with zstd into
`/var/backups/keel/mariadb/`, keeping the last 7. The pull request after
this one (the maintainer, 2026-10-11).

## What `keel inspect`, `keel diff` and `keel database status` show

| Line | From |
| --- | --- |
| `database.server.role` | the server: `SHOW REPLICA STATUS`, grants, as today; on a paired node compared as information |
| `database.server.semi_sync` | `Rpl_semi_sync_master_status` / `Rpl_semi_sync_slave_status`, the clients, `yes_tx`, `no_tx`; `off` on a paired primary is drift |
| `database.server.replica_lag` | `Seconds_Behind_Master`, and `Gtid_IO_Pos` against the holder's `gtid_binlog_pos` |
| `database.server.gtid` | `gtid_binlog_pos`, `gtid_slave_pos`, `gtid_current_pos`, `gtid_binlog_state` |
| `database.server.read_only` | as today, now expected `on` on a fenced node too |
| `database.server.tls` | the certificate's subject, SANs, expiry; `Master_SSL_Allowed` and the cipher of the replication connection |
| `database.server.diverged` | the errant GTIDs of an old primary that cannot rejoin |

`keel database status` prints the same for an operator in one screen,
with the VIP's role, epoch and holder (`keel vip status`). The role file
`/var/lib/keel/role` (`role=`, `replicates=database`, `vip=`), written
by `keel database follow`, is what tracker#57's Webmin binding and banner
read; Webmin itself is out of scope here.

## How it is wired

| Piece | Where |
| --- | --- |
| the pair as the planner sees it: the record, the VIP's role, the other member, what is derived | `keel.system.dbpair` |
| the plan of a paired node: TLS, sysctl, drop-in, authorizations, then the role | `keel.system.dbpairplan`, from `keel.system.database.plan_database` |
| the one drop-in of a pair, the role's drop-in, the statements | `keel.system.dbmariadb` |
| the role hook, `keel database follow`: the follow table, the seed, the rejoin by GTID, the divergence | `keel.system.dbfollow`, `keel.system.dbgtid` |
| the database leaf of the mesh root | `keel.system.dbtls`; the root's side `keel.mesh.etcdstate.database_grant`, asked through `issue` with `kind: database` (`keel.mesh.etcdserve`) |
| the shared credential | `keel.system.dbsecret`; the `secret` message on `POST /v1/vip` (`keel.mesh.vipserve`) |
| the fallback and its recovery alerted, the certificate renewed, a role followed again | `keel.system.dbwatch`, `keel database watch`, `keel-database-watch.timer` (30 s) |
| the operator's screen | `keel.system.dbstatus`, `keel database status` |
| the units | `keel-database-follow.path` on `/var/lib/keel/vip`, `keel-database-follow.service` (also at boot), `keel-database-watch.timer` |
| what inspect, diff and the role file say | `keel.inspect.database`, `keel.inspect.dbengines`, `keel.diff.compare`, `/var/lib/keel/role` |

Three seams let the end to end test run several nodes in one container,
each on a scratch root in a network namespace of its own, and are the
clients' and keel's own conventions rather than switches of the code:
`KEEL_LIVE_ROOT` names the tree that stands for the live system of a
node (`keel.inspect.constants.ROOT_DEFAULT`; never set on a machine),
`MYSQL_HOME` names an options file with that node's socket, which the
MariaDB clients read after `/etc/mysql/my.cnf`, and
`KEEL_MARIADB_SERVICE` names the node's unit
(`keel.system.dbmariadb.service()`).

## Tests

Pure, against fixtures and a server replaced at the subprocess boundary
(the coverage gate of 0003): the GTID comparison, the pair, the shared
credential over the in-process channel with its refusals, the leaf
issued by the holder and the refusals of a request for another address
or in another name, the plan of a paired node, every branch of the
follow table, the watch's alerts once each way, inspect's and diff's
lines (`tests/test_system_dbpair.py`, `tests/test_system_dbfollow.py`).

End to end, `tests/test_mariadb_netns.py` runs `tests/mariadb_netns.py`
on `tests/vip_netns.py`'s three nodes: as root in a network namespace
that routes for three others, on links of 250 ms ±25 ms with 2 % loss
measured first, the real wg-quick, etcd 3.5, the members' channel, the
VIP's units, and trixie's MariaDB 11.8 as a server per node in its
namespace, reading the node's scratch root's drop-in directory. A and B
are the pair, C the application at the VIP. **Case (a)** is this pull
request's: A and B applied, B seeded over TLS (`Master_SSL_Allowed:
Yes`, `Using_Gtid: Slave_Pos`), three rows written at the VIP each read
on B with the lag measured from the write's acknowledgement,
semi-synchronous replication on and a commit's cost, the replica read
only with `'mysql'@'localhost'` alone holding `READ_ONLY ADMIN`, `keel
diff` clean on both; then B applied again and written through, its SQL
thread still applying; B's database leaf taken as `repl` on A and B's
etcd member leaf refused; A restarted and read only from its first
second, writable again once `follow` ran. In CI, `mariadb / trixie`,
with systemd booted.

**Cases (b) to (e) are the follow-up pull request's**, with the rest of
the harness (a writer at the VIP, the partitions and heals of
`tests/vip_netns.py`, the webhook that takes the alerts): (b) the
fallback after 10 s with the replica cut, reported as drift and alerted,
writes going on, the recovery; (c) `keel database promote` while the
application writes, the downtime, no acknowledged row lost; (d) the
primary cut off idle, the failover and the database following, the old
primary rejoining by itself; then cut off while written to, coming back
diverged, read only and alerted, reseeded once confirmed; (e) the
replica refusing an `INSERT` as root and as the application. A first
full run on one host measured them (under "Measured", marked local);
the CI harness for three servers on one runner is that pull request's
work.

## Measured

Under the design case, 250 ms ±25 ms with 2 % loss on every leg
(measured over the overlay in CI: 226.5 ms minimum, 251 ms median, 3.75 %
loss). Case (a) is the CI job's (`mariadb / trixie`, 2026-10-08, keel#93);
the rest was measured once on one host by the full harness of the
follow-up, and is marked so.

| What | Measured |
| --- | --- |
| (a) the replica's first connection to the primary (TLS over 250 ms) | 5.3 s after its apply |
| (a) a commit at the VIP, the replica acknowledging (AFTER_SYNC) | 0.28 to 0.31 s: one round trip |
| (a) a client's write at the VIP, connect, TLS and the commit | 1.3 to 1.9 s |
| (a) a write visible on the replica, from its acknowledgement | 0.04 to 0.07 s (three of three) |
| (a) `keel diff` on both nodes | the database section clean, `semi_sync: same (on)` on the primary |
| (a) the replica applied again, then written through | its SQL thread applying, the row 0.04 s after the acknowledgement |
| (a) the replication account with the other member's etcd leaf, with its database leaf | refused (1045); taken |
| (a) the primary restarted | read only at its first second (a 0.8 s restart), writable once `follow` ran |
| (b) the first commit after the replica is cut; the next | 10.04 s, then 0.04 s (local) |
| (b) the fallback alerted; semi-synchronous again after the heal | at the next watch; 7.3 s (local) |
| (c), (d) | the follow-up pull request's |
| (e) `INSERT` as root by the socket, and as the application at the replica's address | refused, 1290 (local) |

## Decided, 2026-10-11

The four questions the design check asked, each approved by the
maintainer as recommended: the mesh root CA in every cloud mode, with a
`database` leaf per node and no database CA per pair; `ip_nonlocal_bind`
on both nodes, so no role change restarts MariaDB; the rejoin leaves
`/etc/keel/instance.yaml` alone, the role being runtime state (0020), a
precision the handbook records under 0049; the dumps on the standby as
the next pull request.
