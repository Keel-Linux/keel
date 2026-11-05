# MariaDB primary and replica on the mesh

The PostgreSQL twin of this pair is
[docs/replication-postgresql.md](replication-postgresql.md) (0054).

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
- **Anubis's key comes from the pair too** (0041, `shared: true`;
  Keel-Linux/common#56), on a MariaDB or a PostgreSQL pair. The primary
  makes `/etc/anubis/keel.key` at its first start of Anubis. On the
  node whose spec says `role: replica`, with Anubis enabled, no key
  file and no `secrets.anubis_signing_key` declared, `keel spec apply`
  asks the other member of the pair record for the key, with the same
  signed `secret` message as the replication credential, and writes it
  with mode 0600 before Anubis starts. Before the pair record exists,
  while the primary has no key yet, or while it does not answer, the
  apply starts nothing for Anubis, says why, and a later apply asks
  again. An answer that is no key refuses the step. A key that is there
  is never replaced.
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
rpl_semi_sync_master_timeout = 30000
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
does not answer still costs the primary the 30 s, which is the fallback
below. A replica that hears nothing for 10 s reconnects (heartbeats every
5 s) instead of MariaDB's 60.

Both sides enabled on both nodes, so a promotion flips nothing here: a
replica with `master_enabled` has no replica of its own and waits for
nobody until it is promoted; a primary with `slave_enabled` replicates
from nobody. A commit on the primary returns once the replica has
*received* it (not applied), one round trip, 250 ms in the design case.

**The fallback.** With no acknowledgement within 30 s the primary
commits asynchronously (`Rpl_semi_sync_master_status: OFF`) and stays
so until the replica is back and caught up, when MariaDB turns it on
again by itself. Writes continue (the maintainer's answer).

**The fallback has a second form, and a cut takes it** (keel#270). When
the last replica disconnects, the server releases the commits that wait
and acknowledges the next commits at once (`wait_no_slave = OFF`). It
does not turn the status off, so `Rpl_semi_sync_master_status` stays
`ON`. The sign is `Rpl_semi_sync_master_clients` 0. In MariaDB 11.8 this
is `Repl_semi_sync_master::remove_slave()` and the start of `commit_trx()`
in `sql/semisync_master.cc`. A cut reaches this form before the timeout:
`net.ipv4.tcp_retries2 = 5`, which keel sets for etcd (keel#167), ends the
dump thread to the cut replica after about 12.6 s. So the longest wait of
a commit on a cut measured 15 s on a real pair, not 30 s
(`evidence/2026-11-01-keel-0.23.68-mariadb-faults.md`, case F1). The
timeout runs only for a replica that stays connected and does not
acknowledge, and for a replica that comes back behind.

In both forms an acknowledged write is on one node only, until the
replica caught up. The fallback stays, with an alert (the maintainer's
decision of 2026-11-01, keeping 0031). keel reports it:

- `keel inspect` reports `database.server.semi_sync` (`on`, `off`, the
  clients, the transactions acknowledged and not) and `keel diff` on a
  paired primary reports `off` as **drift**: "the replica does not
  acknowledge; commits are asynchronous and a failover loses them";
- `keel database status` on the primary shows a `FALLBACK:` line in both
  forms;
- `keel-database-watch.timer` runs `keel database watch` every 30 s,
  which alerts on the change to either form and on the recovery, through
  the monitor's channels (0021, 0040) as `keel mesh etcd tend` alerts, and
  records the state in `/var/lib/keel/database/semi-sync` so a lasting
  fallback alerts once, not every 30 s. It does not record an alert that
  no channel took, so it tries again at the next run. A node with no
  channel writes the line to the journal only: set a channel.

**The timeout is longer than the VIP's release** (keel#186). Until
keel 0.23.36 it was 10 s, the maintainer's answer of 2026-10-03. The
VIP's release is 15 s since keel#174 (0049, amendment of 2026-10-15).
So on a cut primary, a write that waited for the replica returned OK
after 10 s, and the next writes returned OK at once, until the old
primary dropped the VIP at about 15 s. These writes never reached the
replica, and the new primary did not have them: acknowledged writes
were lost. The timeout is now 30 s. Since keel#195 the fence comes
earlier than the release, at the doubt of the lease: on real nodes,
6.1 s to 8.8 s after a cut (the cross-site rehearsal of 2026-10-16).
10 s would leave 1.2 s in the worst case measured; 30 s leaves room.
A replica that is lost while the primary keeps the VIP still gives the
fallback, 30 s after the last acknowledgement in place of 10 s.

**A primary that comes back waits for its replica** (keel#242). When
the primary's server stops (a crash, a kill) and starts again while the
node still holds the VIP, the replica's I/O thread is not connected:
it connects again only at its next try, every 2 s, and the TLS
handshake takes more round trips. With `wait_no_slave = OFF` a commit
with no replica connected is acknowledged at once, with no copy. The
end to end test found it: the server started again 1.2 s after the
kill, follow turned `read_only` off at 2.0 s, a write was acknowledged
at 2.7 s, and the cut came before the replica connected. So follow,
on a holder that is read only and replicates from nobody, waits until
`Rpl_semi_sync_master_clients` is 1 or more and
`Rpl_semi_sync_master_status` is `ON`, for 30 s at most (the timeout,
so a primary that comes back gives the fallback no sooner than a
running one). It reads the VIP's proof again after the wait and stays
read only if the VIP is gone. Writes meanwhile get error 1290, not OK.
A promoted replica does not wait: its old primary is the replica to
be, and it is gone or rejoins later.

**The fence starts when the lease is in doubt** (keel#195). A cut
holder that keeps the VIP until the release (15 s) cannot wait for it:
a write that waits for the cut replica returns OK when the dump thread
to that replica ends (`wait_no_slave = OFF`). With
`net.ipv4.tcp_retries2 = 5` that is about 12.6 s after the cut. So
when the holder's lease has had no renewal that the majority confirmed
for 6 s, the controller marks its doubt ([docs/vip.md](vip.md), "The
holder's doubt"). `keel-database-follow.path` starts follow, which
fences the server as below and leaves the role as it is. The server
takes writes again at the next confirmed renewal. `wait_no_slave = ON`
does not help: a new primary has no replica yet, and its first write
would wait for the whole timeout.

**The fence ends the client connections** (keel#186). `SET GLOBAL
read_only = ON` waits for the backup lock behind a write that waits for
the replica's acknowledgement, and that write returns OK when the
timeout ends. So when follow turns a node read only that took writes
(the VIP released or fenced, or a claim that is not proven), it sets
`read_only` in a client of its own and, while that waits, kills every
client connection: not the server's own threads, not this node's own
replication threads. A write that waited gets an error, not OK. The
dump threads of its replicas end too, because a fenced node serves no
replica (keel#193): a dump thread to a cut replica stays, and when
that replica connects again with the same server id, MariaDB 11.8.6
ends the old thread and then takes no connection. Ended by a `KILL`,
the thread ends cleanly. Its row stays on
the old primary as an errant transaction, so an old primary cut off
*while clients were writing* comes back diverged and waits for the
operator's confirmed reseed (below). One cut off while idle rejoins by
itself.

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
  reach it. In cloud advanced the derived firewall accepts 3306 on
  `wg0` only, never on the uplink (0041: a `mesh` port), from every
  member of the mesh, as for every `mesh` port. The accounts decide
  who logs in: `repl` needs the pair's certificate (below). The real
  test of 2026-10-16 found that this text said "from the pair peer and
  for the VIP only", which the firewall does not do.
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
round, point 3; the old primary turns its database read only before it
drops the address, so the commits in flight end, and their clients get
the answer, while the replica is still connected: keel#138), then the
database: drain the relay log, `STOP SLAVE`,
`RESET SLAVE ALL`, `read_only = OFF`, `READ_ONLY ADMIN` back. The
semi-synchronous roles need no flip (both sides enabled on both nodes).
When the old primary is gone, `STOP SLAVE IO_THREAD` takes seconds
(measured on 11.8): a thread that tries to connect ends only when the
try times out (`slave_net_timeout`, 10 s), and a connected thread with
semi-synchronous replication tries to connect to the primary to end its
dump thread (5 s). A `KILL` of the thread does not shorten it. On a real
pair that cost 7.5 s of refused writes while the new primary already
carried the VIP (keel#118). The thread receives nothing from the moment
the stop marks it killed, long before it ends; a thread that connects
again (`MASTER_CONNECT_RETRY=2`) after that ends without receiving. So
the stop runs in a client of its own; once the stop is in the server's
killing phase (its process list `STATE` is `Killing slave`; its `INFO`
is set earlier, when it is dispatched) or ended without an error, the
SQL thread drains, the received position is read again, the killing
phase is checked again, and `read_only = OFF`; `STOP SLAVE` and `RESET
SLAVE ALL` follow while the server already takes writes. The SQL thread
is not stopped first: it has nothing more to apply, and `STOP SLAVE
SQL_THREAD` waits behind the I/O thread's stop (4.7 s measured). On
11.8 against a frozen primary, the server took writes 0.35 s after the
promotion started (0.26 s with the thread connecting), against 5 s and
7 s before. A planned promote takes the same path; its stop ends at
once, since the primary answers. Follow, `keel database watch`'s follow
and spec apply's replication actions take one lock,
`/var/lib/keel/database/follow.lock`. When the position moved after the drain, or
cannot be read, the old order applies: the stop waited for, the SQL
thread started and drained again, then the promotion.
`keel-database-follow.path` starts follow when the claim is written,
and follow looks for the VIP on `wg0` every 0.2 s.

**A replica that lags does not take writes by itself** (keel#271). The
drain proves that a node applied what it received, not that it received
what the primary acknowledged, and `Seconds_Behind_Master` compares only
what it received (0 at 8000 rows behind, on a real pair). So while a node
holds the VIP and its server is writable, `keel-database-position.service`
keeps in etcd, each 2 s, a record of its `gtid_binlog_pos` of about 4 s
ago and whether it has a replica. The key is
`/keel/<mesh>/etcd/database/<vip>`. A read-only holder writes nothing, so
a lagging holder cannot write over the record that refused it.

Before a replica that holds the VIP drains, follow compares what it
received (`gtid_slave_pos`, `Gtid_IO_Pos`, its binary log state) with the
record, by GTID:

| The record | The old primary answers | Follow |
| --- | --- | --- |
| at or below this node, with a replica | not asked | drain and promote |
| none (a holder of an older keel), or no etcd here | not asked | drain and promote |
| above this node, or no replica, or not readable | at or below this node | drain and promote |
| above this node, or no replica, or not readable | above this node | stays a read-only replica, goes on receiving from it, and promotes by itself once it caught up |
| above this node, or no replica, or not readable | no answer | stays a read-only replica |

A refusal goes through the monitor's channels once, shows in `keel
database status` as `PROMOTION REFUSED`, and is the same at each follow.
The VIP stays on this node, so a client gets error 1290. The operator
ends it in one of these ways:

- `keel database promote --accept-lost-writes` here takes writes without
  what this node lacks. The old primary, when it comes back, is diverged.
  The writes stay in its data and its dumps, and nothing puts them back.
- `keel database promote` on the old primary, when it came back, moves the
  VIP to the node that holds everything. The lagging node goes on as its
  replica.

The cost is availability: a primary lost while its replica is away or
behind now stops the writes until an operator acts, or until it comes
back and the replica caught up. What is left is a holder that acknowledges
writes alone and dies within about 2 s of its last replica leaving,
before the record says so. A cut does not reach this: it takes about
12.6 s to end the dump thread, and the first commit that waits moves the
position. `keel database status` on a replica shows the distance to the
record, in transactions.

**The database follows the VIP** (0020: everything that depends on the
role follows the elected role). `keel-database-follow.path` watches
`/var/lib/keel/vip/` and runs `keel database follow`, which makes the
server match the VIP state keel holds:

| VIP state on this node | `keel database follow` |
| --- | --- |
| holds the VIP, newest epoch, the VIP on `wg0` | promote, as above, when the server is a replica or read only; a replica that lags stays read only (keel#271) |
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
(`/var/lib/keel/database/follow.lock`).
`keel spec apply --system` refuses, and changes nothing, when the
appliance replicates files for the node's mode but the spec does not
write `overlays.syncthing` out (keel#224, decisions 0027 and 0041). A
manifest default is not enough: without the key the pair would form with
the files not replicated. Write `enabled`, or `disabled` to turn it off.
`keel database follow` never refuses for this, because that would block
a failover in an outage. It lets the role change run, says in its output
that file replication is off, and sends one alert through the monitor
channels while the condition lasts. Follow waits up to 15 s for the address, because a promote
records its claim before it adds the VIP; when keel adds the VIP, it
writes the VIP's state again, so `keel-database-follow.path` runs
follow again. `keel database watch` runs follow again within 30 s if
these runs are missed.

So in cloud advanced the controller's failover promotes the database on
the new holder within seconds of the claim, and the old primary turns
read only the moment it drops the address (its lease's release, 10 s);
in cloud simple a promote by hand on the replica does the first, and the
old primary does the second once it hears the newer claim: without
etcd, its `keel database follow` asks the other members at boot and at
each watch run (keel#154, [docs/vip.md](vip.md)). The path unit is the seam
between the VIP's helper, which holds `CAP_NET_ADMIN` alone and cannot
run `runuser`, and the database, which needs root.

**A pair of files only** (decision 0076, point 4). Keel Web in a cloud
mode has no database, but its two nodes declare the same
`appliance.vip` and replicate the site files with syncthing (0050). On
a node in `cloud_simple` or `cloud_advanced` that declares
`appliance.vip` and no `database.server`, and whose appliance
replicates a path for its mode with `overlays.syncthing: enabled`,
`keel database follow` takes the direction of the folders from the VIP
(keel.system.filefollow):

| VIP state on this node | the folders |
| --- | --- |
| holds the VIP, newest epoch, not in doubt, the VIP on `wg0` | send |
| its own claim, but in doubt or the VIP not on `wg0` | paused: not proven (keel#104) |
| another member holds it, or this node released it or is fenced | receive |
| no claim yet | paused, until `keel vip promote` on the node that is to send |

`/var/lib/keel/role` then says `replicates=files`. `keel vip promote` on
the other node moves the VIP; `keel-database-follow.path` runs the
follow on both nodes, and the direction flips. `keel database watch`
follows again when the role file is not the VIP's, or when the holder
no longer carries the VIP on `wg0`; it renews no database certificate
there. Before 0076 such a node was refused: "this node declares no
database.server". Any other node without a database keeps that refusal
(a Core pair that replicates nothing, a node in `simple`), and a node
with no `appliance.vip` has nothing to follow.

**The witness has nothing to follow** (decisions 0057 and 0076). A
cloud advanced witness is a Keel Core node with no `appliance.vip` and
no database, but its `/var/lib/keel/vip/` exists, because it routes the
VIPs of the pairs. `keel-database-follow.service` runs `keel database
follow --needed` as its `ExecCondition`: that exits 1 when the spec
declares no `appliance.vip`, and systemd skips the unit, so it is never
failed there (keel#211). It exits 0 when the spec declares one, and also
when the spec cannot be read, so that the follow runs and says why.
`keel database follow` itself says "nothing to follow" and exits 0 on
such a node.

**The VIP fence after a rejoin or a reseed** (keel#192, the twin of
keel#166 for PostgreSQL). A node that lost the VIP while it was cut
off is fenced: it takes the VIP again only by `keel vip promote` there
(0049). After it rejoined by GTID, or after the confirmed reseed, it
holds nothing that the holder lacks. When it replicates from the
holder, with its SQL thread running, and it applied the newest
sequence that the holder logged in each GTID domain, `keel database
follow` clears the fence. `keel database watch` runs follow on a fenced
replica that replicates, so the fence goes within 2 watch runs. Before,
a MariaDB pair failed over by itself once only.

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

## A planned promote of a PostgreSQL pair that fails

A planned promote makes the old PostgreSQL primary a standby before it
releases the VIP (`keel.system.dbpgfollow.quiesce`): CHECKPOINT,
`standby.signal`, a restart. If the release itself fails, the node keeps
the VIP and the quiesce is undone.

If the release works and the other member's promote then fails, the old
primary is a standby that follows nobody. It refuses writes. With etcd
and the other member alive, that member's controller claims the VIP once
`GRACE` has passed (`Controller.fail_over`), and it is promoted, so the
pair gets a writer by itself.

The pair has no writer until an operator acts in these cases:

- there is no etcd;
- the other member is gone too;
- an operator ran `keel vip promote` on the old primary before the other
  member's controller claimed.

The old primary then refuses writes (`FENCED_REFUSED`), because nothing
proves that the other member took no write. If the other member is gone,
run `keel database promote --old-primary-gone` on the old primary. Else
run `keel vip promote` on the other member. A follow after a release
fences an old primary in the same way when no quiesce ran.

## Dumps on the standby (interim backup)

`keel-database-dump.timer` starts each hour on a node of a pair. It runs
`keel database dump --if-due`, and the command reads the spec to find if
a dump is due. keel 0.23.71 added these two names. Before 0.23.71, this
section described them and they did not exist.

```yaml
database:
  server:
    engine: mariadb
    role: primary
    dump:                     # all optional; the values are the defaults
      enabled: true           # false: no dump, no alert
      every_hours: 24         # 1 to 720
      keep: 7                 # 1 to 365: the dumps that stay
      min_free_percent: 10    # 1 to 90: the part of the disk a dump leaves free
```

A pair with no `database.server.dump` has these defaults. The section is
refused on a node with no `appliance.vip`, and for Redis: a standalone server has
no scheduled dump. `keel diff` does not compare the section.

**The dump.** The node dumps only while it is the replica and its server
replicates. A primary, a node that diverged and a server that was not
seeded do not dump: their dump is not the pair's data, and it could push
the good dumps out of the retention. The command is `mariadb-dump
--single-transaction --gtid --master-data=2 --routines --events --triggers
--all-databases`, in a pipe to `zstd`. This is one snapshot, and a comment
in the file gives the GTID position. `--gtid` alone writes no position.
keel does not use `--dump-slave`: it stops the SQL thread for all of the
dump.

**The files.** `/var/backups/keel/mariadb/dump-<UTC time>.sql.zst`, mode
0600, in a directory of mode 0700. The file gets this name only when
`mariadb-dump` and `zstd` both exit 0. A file that is not complete has
the name `.dump-<UTC time>.partial`. keel removes it when the dump fails,
and the next run removes it after a crash.

**The credentials.** There are none: root connects by the server's socket.
No secret is on a command line or in a log. The dump holds the hashes of
the accounts, which is why the mode is 0600.

**A dump cannot fill the disk.** The room is what is free above
`min_free_percent`. With no room, or with less room than the size of the
last dump, there is no dump. During the dump, the kernel stops `zstd` at
that room (`RLIMIT_FSIZE`), and keel removes the file. After a good dump,
only the newest `keep` dumps stay. A failed dump removes nothing.

**A rejoin's dump.** `rejoin-*` files are not in the retention and keel
never removes them: such a file can be the only copy of a diverged node's
writes. The operator removes them after the reseed. A MariaDB rejoin does
not dump again while the node's GTID state does not change. Before 0.23.71,
a diverged node made a new file at each `keel database watch`: 223 files,
246 MB in 2.5 hours on a real node. A rejoin's dump leaves 5% of the disk
free, and the kernel stops the dump at half of the room above that,
because the plain file and its compressed copy are on the disk together.
With no room the rejoin stops, and nothing changes.

**The signal.** `keel database watch` alerts through the monitor's
channels (check `database-dump`), once for each kind of problem and once
at the recovery:

- a failed dump, with the reason;
- a stale dump, on the replica: the newest dump is older than two
  intervals and one hour. This also finds a timer that does not run.

A primary sends no stale alert. On a primary with a replica that is away,
the fallback alert of this document tells the operator.
`keel database status` shows the newest dump and the last problem.

**Restore.** No command restores a dump. `zstd -dc <file> | mariadb` on a
server with no data loads it. A reseed is the way to make a node of a
pair whole again.

## What `keel inspect`, `keel diff` and `keel database status` show

| Line | From |
| --- | --- |
| `database.server.role` | the server: `SHOW REPLICA STATUS`, grants, as today; on a paired node compared as information |
| `database.server.semi_sync` | `Rpl_semi_sync_master_status` / `Rpl_semi_sync_slave_status`, the clients, `yes_tx`, `no_tx`; on a paired primary, `off` is drift (the fallback) and `on` with no replica acknowledging is drift too (keel#107: healthy is clients >= 1 with status ON) |
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
| the fallback in both forms and its recovery alerted, the certificate renewed, a role followed again | `keel.system.dbwatch`, `keel database watch`, `keel-database-watch.timer` (30 s) |
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
