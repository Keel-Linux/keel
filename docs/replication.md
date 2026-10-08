# MariaDB primary and replica on the mesh

Phase 2, step 3 of the roadmap: a MariaDB pair on the WireGuard mesh
whose primary is the holder of the pair's VIP (handbook decisions 0013,
0020, 0028, 0031, 0049 and its third round, 0050, 0051; tracker#57; the
maintainer's answers of 2026-10-03: semi-synchronous replication with a
10 s timeout and the fallback reported as drift, TLS on the replication
channel in addition to WireGuard, dumps on the standby as the interim
backup). **Status: design, not yet implemented**; the questions at the
end are for the maintainer.

What keel 0.11 built is kept and corrected: a replica seeded from a
dump, GTID, `--destroy-local-database`, the root lock, `keel database
promote`. Two things it does are against 0031 and go: replication was
asynchronous, and a replica served reads.

## The pair

```yaml
appliance:
  name: mariadb
  vip: fd2a:9c41:7e03::100
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
- **Nothing is typed twice.** With a pair record (`keel vip pair`),
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
rpl_semi_sync_master_wait_for_slave_count = 1
```

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
`mysql` system user (`/var/lib/keel/database/tls/`, 0640 root:mysql),
opens nothing in etcd if it leaks. The server side: `ssl_ca` the root
(the trust bundle of 0051 when it has several), `ssl_cert`, `ssl_key`.
The replica: `MASTER_SSL=1, MASTER_SSL_CA, MASTER_SSL_CERT, MASTER_SSL_KEY,
MASTER_SSL_VERIFY_SERVER_CERT=1`, the server's certificate verified
against the root and the IP SAN of the address it dialled. The `repl`
account carries `REQUIRE X509`, a client certificate the root signed,
which is `REQUIRE SSL` and more. The seed's `mariadb-dump` and the
rejoin's comparison use the same files.

Why not a separate database CA signed by the root: two CAs per node,
two renewal paths, and 0051's federation would have to carry both. Why
not the member certificate itself: its key is etcd's, and a key the
`mysql` user can read would log in to etcd as the member.

**The root does not exist in cloud simple today** (docs/mesh.md: made
by `keel mesh create` on a cloud advanced node, or `keel mesh etcd
form`). This design makes `keel mesh create` make it in every cloud
mode and issue the member and database leaves at every join, as the
cloud advanced join does; cloud simple then holds certificates it uses
for the database alone, and the etcd overlay stays disabled there
(0041). See question 1.

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
| holds the VIP, newest epoch | promote, as above, when the server is a replica or read only |
| fenced, or released | `read_only = ON` at once, the root lock, then the rejoin below |
| no claim known yet | nothing |

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
`role: replica` into its own spec" is read as the emitted spec. See
question 3.

## Dumps on the standby (interim backup)

`keel-database-dump.timer` on a paired node runs `keel database dump`
daily; it dumps only while the node is the replica (a hot standby that
serves nothing has the room and the idle time), `mariadb-dump
--single-transaction --gtid --all-databases` compressed with zstd into
`/var/backups/keel/mariadb/`, keeping the last 7. Proposed as a
follow-up pull request, not this one. See question 4.

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

## Tests

Pure: the drop-in, the statements, the GTID comparison, the follow
table, the secret exchange's messages, the leaf's extensions, the diff
and inspect lines, against fixtures (coverage gate 95 %).

End to end, `tests/test_mariadb_netns.py`, as root in a network
namespace in the trixie container (the CI job `mariadb / trixie`,
systemd booted): three namespaces A, B and C on links of 250 ms ±25 ms
with 2 % loss, measured first as `tests/test_vip_netns.py` measures
them; etcd on the three, keel's CA, the VIP's units; a `mariadbd` per
node in its namespace as a systemd unit (`mariadb-keel-<node>`), its
`--defaults-file` including the node's scratch root's
`etc/mysql/mariadb.conf.d/`, the client reaching it by `MYSQL_UNIX_PORT`;
A and B paired with the VIP; C a plain member that writes to the VIP:

- **(a)** A applies as primary, B as replica (seeded with TLS, `REQUIRE
  X509`, `Master_SSL_Allowed: Yes`); a row inserted at the VIP is read
  on B; the lag measured as the time from the insert to its appearance;
- **(b)** a commit at the VIP takes about one round trip; B's leg cut
  (100 % loss): the next commit returns after about 10 s, `semi_sync`
  reads `off`, `keel diff` on A reports drift, the alert reaches the
  test's webhook, and commits keep returning fast; healed, `on` again;
- **(c)** `keel database promote` on B, planned: the longest gap in C's
  writes at the VIP, every 50 ms, is the downtime; every row C wrote
  before the move is on B, none lost;
- **(d)** B (the primary) cut off with C idle: the VIP fails over to A
  within keel#81's times, `keel database follow` promotes A, C's writes
  resume, measured from the cut; healed, B drops the VIP, turns read
  only and rejoins as a replica of A by itself, no errant GTID. Then
  again with C writing through the cut: B comes back diverged, read only,
  the errant GTIDs reported and alerted;
- **(e)** on the replica, `INSERT` as root over the unix socket and as
  the application account at its overlay address are refused with 1290.

## Questions for the maintainer

1. **The mesh root CA in cloud simple.** `keel mesh create` makes the
   root in every cloud mode, and every join issues the member and
   database leaves; the database's TLS rests on it in both modes.
   Recommended. (The alternative is a database CA per pair, made by the
   first primary and handed over the members' channel: self-contained,
   but a second CA on every cloud advanced node, with its own renewal,
   and two things for 0051 to federate.) Yes or no?
2. **`ip_nonlocal_bind`** so both nodes bind the VIP and no role change
   restarts MariaDB; the alternative restarts the server on each
   promotion and demotion with the VIP added to or taken from its
   `bind-address`. Recommended: the sysctl. Yes or no?
3. **The rejoin does not rewrite the spec.** The role in
   `/etc/keel/instance.yaml` stays the one chosen at installation (0020);
   `inspect` writes the observed role out and `diff` reports the
   difference as information on a paired node. 0049's "writes `role:
   replica` into its own spec" is taken as the emitted spec, and
   keel#69 decides who writes the file. Yes or no?
4. **Dumps on the standby as a follow-up PR**, after this one, so the
   replication PR stays reviewable. Yes or no?
