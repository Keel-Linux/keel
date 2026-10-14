# PostgreSQL primary and replica on the mesh

The PostgreSQL pair of handbook decision 0054: the twin of
[docs/replication.md](replication.md)'s MariaDB pair, one engine at a
time the way 0013 has it. What a pair is (the VIP decides the role,
the pair record derives the origins, the credential and the primary's
address), the database leaf of the mesh root CA, the follow of the
VIP's state and the units that run it are the same and are written
there. This file has what PostgreSQL does differently, and the
PostgreSQL wording of the end to end test's cases (a) to (e).

In keel 0.23.18. The numbers under "Measured" come from the CI job
`postgres / trixie`, under the design case of 0050.

## What differs from the MariaDB pair

- **A standby refuses writes while it is in recovery**, so there is
  no `read_only` line, no role drop-in, no account lock and no
  `READ_ONLY ADMIN` to revoke: the enforcement MariaDB builds from a
  privilege is here a property of the role itself. A root at a shell
  gets the same error 25006 the application gets.
- **The seed is a physical copy.** `pg_basebackup` streams the
  primary's whole data directory with the replication protocol, roles
  included, so there is no account alignment step and no dump to
  restore from. The replica is the copy, the empty `standby.signal`
  in its data directory and a follow drop-in (`primary_conninfo`, the
  pair's slot `keel`); a promotion is one statement, `pg_promote()`.
- **Synchronous commit has no timeout and no fallback.**
  `synchronous_standby_names = 'FIRST 1 (keel)'` and
  `synchronous_commit = on`: a commit is acknowledged once the
  standby of application_name `keel` received and flushed it, about
  one round trip, 250 ms in the design case. While the replica is
  away the primary waits; there is no asynchronous fallback to report
  as drift, the way the 10 s timeout of MariaDB's semi-synchronous
  replication is one (one exception: the new primary after
  `--old-primary-gone`, below). `keel database watch` alerts instead, once,
  when no standby streams from the primary or a commit waited more
  than 10 s for it, and once more when the standby acknowledges
  again (the state file's key `sync_commit`).
- **The replication slot `keel`** on the primary keeps its WAL while
  the replica is away; the walreceiver names itself `keel`.
- **The rejoin after a promotion is a confirmed reseed and nothing
  else** (0054): equal timelines do not prove the copy is safe to
  resume from, so there is no `pg_rewind` and no repoint path this
  version. A node holding no user database is seeded without the
  confirmation; one holding data is dumped first
  (`pg_dumpall`, compressed under `/var/backups/keel/postgresql/`)
  and reseeds on `--destroy-local-database`, and until then the
  divergence is recorded (`/var/lib/keel/database/diverged`, the
  timelines this node's own history forked from the holder's) and the
  node stays as it is, read only in recovery. An old primary is not
  in recovery when it comes back, and PostgreSQL cannot be made read
  only while it runs, so follow fences it first: `standby.signal` in
  its data directory, no follow drop-in, a restart. The server is
  then a standby that follows nobody; it refuses every write and
  serves the dump. The dump is taken once per divergence: the record
  names it, and a fenced node takes no write after it. Both
  timelines are numbers (a standby's from its last checkpoint);
  `keel diff` and `keel database status` show them.
- **A fenced node that holds the VIP** (keel#152). A fenced standby
  receives nothing, so the drain of a promotion cannot prove that it
  holds the pair's newest writes. Follow promotes it with no drain
  only in 3 cases:
  - the node never had a role in the pair: no divergence record and
    no `/var/lib/keel/role`. This is a new node that the watch fenced
    because the image has a user database;
  - its divergence record shows 2 system identifiers: the 2 clusters
    never shared a history (2 `initdb` runs);
  - the operator ran `keel database promote --old-primary-gone`.

  Else the holder stays fenced, and follow refuses with what to do.
  The divergence record holds the 2 system identifiers for this rule.
- **The holder makes the pair's slot.** A base backup copies no slot,
  so a promoted standby has none; follow makes the slot `keel` on the
  holder on each run, or the reseed of the old primary would never
  stream.
- **The seed is compressed on the primary** (`pg_basebackup
  --compress=server-zstd`, unpacked by the plain format): a fresh
  cluster is about 40 MB raw and under 3 MB compressed, and the
  design case's link carries about 50 kB/s on one connection.
- **keel's psql client** answers unaligned, a tab between the
  columns, and stops at the first failed statement on its standard
  input (`ON_ERROR_STOP`): without it psql exits 0 after an error.
- **TLS is the same leaf, the libpq spelling.** The files live under
  `/etc/postgresql/keel-tls` (0640 root:postgres for the key);
  `ssl_ca_file`, `ssl_cert_file`, `ssl_key_file`, `ssl_crl_file` in
  the drop-in; the replica's `primary_conninfo` carries
  `sslmode=verify-full`, the root, the certificate and the key. The
  pin of the other member's certificate is pg_hba.conf's cert method
  with a user name map: a replication connection's certificate CN is
  `<member> postgresql`, never the database user `repl`, so
  `pg_ident.conf` maps the CN to `repl`, the twin of MariaDB's
  `REQUIRE SUBJECT` (clientcert=verify-full is deliberately not there:
  it asks the client host's name of a DNS the mesh has not); an etcd
  member's leaf of the same root is refused.
- **The authorization surface is pg_hba.conf as a whole**: the base
  rules Debian ships (local peer, loopback scram-sha-256) plus, per
  declared origin, two lines: `hostssl replication repl <peer>
  cert map=keel` for the replication itself, and `hostssl postgres
  repl <peer> scram-sha-256` so the role can ask the server's own
  `postgres` database what the primary is before a copy (the reach and
  seed probes) — user data stays unreachable. The file
  is rewritten whole on each apply, so a withdrawn origin disappears
  with the lines.
- **Applications stay loopback.** On a pair the socket listens on the
  overlay address and the VIP (a mesh port, for the replication), and
  pg_hba.conf's `all` rules stay loopback: an application co-located
  with the primary connects over `::1`, the way the appliance
  manifest has it. Nothing but the pair peer reaches 5432.

## Case (a), the end to end test

`tests/test_postgres_netns.py` runs `tests/postgres_netns.py` on
`tests/vip_netns.py`'s three nodes: as root in a network namespace
that routes for three others, on links of 250 ms ±25 ms with 2 % loss
measured first, the real wg-quick, etcd 3.5, the members' channel,
the VIP's units, and trixie's PostgreSQL 17 as a server per node in
its namespace, its cluster's configuration under the node's scratch
root. A and B are the pair (A primary, B replica, by their specs), C
the client at the VIP. **Case (a)** is this pull request's: A and B
applied (the certificate first, then the drop-ins, the hba and the
ident map, then the role), B seeded over TLS with `pg_basebackup` —
its walreceiver streaming with `sslmode=verify-full` against the pair
slot, the pair's synchronous commit on A (`FIRST 1 (keel)`) — three
rows written on the primary through its loopback, each read on B with
the lag measured from the write's acknowledgement (a synchronous
commit: the acknowledgement is the replica's flush, so the row is
there within its replay), a commit's cost about one round trip, B
refusing an `INSERT` while it is in recovery (error 25006), B's
database leaf taken as `repl` on A and B's etcd member leaf refused,
A restarted and serving again at once (a primary has no read-only
boot: a standby's refusal is recovery), `keel diff` clean on both. In
CI, `postgres / trixie`, with systemd booted.

## Cases (b) to (e)

The same run goes on after case (a), the twin of MariaDB's cases. The
application is co-located (0054): it writes through the loopback of
the node that carries the VIP. A client whose commit waits for the
standby is killed after 30 s, never cancelled: a cancelled wait
answers success with a warning that the commit is only local.

- **(b) The replica cut off.** B is cut off from everyone, both ways,
  for 40 s. A keeps the VIP: C renews its lease, and B holds no lease
  to release, so nothing is fenced. A commit on A waits for B, with
  no timeout and no fallback. A's watch alerts. After the heal, the
  commit is acknowledged, A has its synchronous standby again, the
  watch alerts the end, and the row is on B.
- **(c) The unplanned failover, the application writing.** A is cut
  off, so the write in flight on it waits for B and is in A's WAL
  unacknowledged. Then A's server and its VIP helper are killed. The
  operator runs `keel database promote --old-primary-gone` on B: with
  etcd it waits for A's lease to end (0049), then B carries the VIP
  and its follow drains, promotes, makes the pair's slot and commits
  alone (the exception below). The writes resume within 5 s of the VIP
  on B (keel#148), B's watch alerts at each run, and no row that the
  application saw acknowledged is missing on B.
- **(e) The diverged old primary.** A boots: its server starts as a
  primary, and its boot follow, with its own old claim not proven,
  stops it. Its VIP helper starts and takes B's newer claim; follow
  fences the server, dumps it, records the divergence (timeline 1
  against B's 2) and alerts once. Every write on A from its boot to
  the fence is unacknowledged. The dump holds A's unacknowledged
  rows. Two watch runs later there is still one dump and one alert.
- **(d) The old primary rejoins.** The operator confirms the reseed
  on A (`keel spec apply --system-only --destroy-local-database`).
  A streams from B, the divergence record is gone, `FIRST 1 (keel)` is
  back on B and each commit waits for A again, B's watch alerts the
  end, and the rows of A and B agree.

Under 0054 every old primary that holds data diverges by its
timeline, so (d) is the confirmed reseed of (e)'s node, one cycle.

## The one exception: the new primary after --old-primary-gone

0054 says the pair's synchronous commit has no timeout and no
fallback. There is one exception (decided 2026-10-14 under the
maintainer's delegation; the handbook records it under 0054). When
`keel database promote --old-primary-gone` promotes a standby, the new
primary commits alone:

- keel empties `synchronous_standby_names` in the pair drop-in and
  reloads the server. It does not restart it: the clients stay
  connected, and the commits that waited are released.
- `keel database watch` alerts at each run while the primary commits
  alone with no standby streaming, on the same path as the "commits
  wait" alert.
- When a standby streams again, after the confirmed reseed, keel
  writes `FIRST 1 (keel)` back and reloads; the watch alerts the end.
  `keel spec apply` does not take the empty line for drift.

The reason: the flag is the operator's statement that the old primary
is gone. A commit then has no second node to wait for, and without the
exception every write on the new primary waits until the old primary
is reseeded, which itself waits for the operator's confirmation. Case
(c) measured that wait at 216 s from the VIP on the new primary, and
keel#148 bounds the writes' return at 5 s. A commit that the new
primary takes alone is on one node only until the reseed; the alert
says so at each run.

Without the flag nothing changes. A planned promote and the cut
replica of case (b) keep the synchronous wait. `keel database promote
--old-primary-gone` writes its statement
(`/var/lib/keel/database/old-primary-gone`) before it moves the VIP,
so the follow that the claim starts uses it at the promotion; the mark
is used once.

## Measured

Under the design case, 250 ms ±25 ms with 2 % loss on every leg.
All rows are the CI job's (`postgres / trixie`), runs of keel#149 on
2026-10-14 (the overlay measured at 227 to 229 ms minimum, 251 ms
median, 3.25 to 5 % loss). Where the runs differ, each number is given.
The rows of (c) after the VIP lands on B are the run with the exception
of --old-primary-gone; the row before it is the run without.

| What | Measured |
| --- | --- |
| (a) B's apply, with its seed (the copy compressed on the primary) | 88 to 108 s; about 730 s before the compression |
| (a) the walreceiver streaming, after B's apply | 0.5 s |
| (a) a write on the primary through its loopback: connect and the synchronous commit | 0.47 to 0.74 s |
| (a) a write visible on the replica, from its acknowledgement | 0.17 to 0.36 s (polled through the agent) |
| (b) the commit on A, with B cut off for 40 s | waits the whole cut: no timeout, no fallback |
| (b) A's watch alerts that its commits wait | 13.5 to 20.5 s after the cut |
| (b) the waiting commit acknowledged, after the heal | 20.9 to 22.2 s (TCP's retry after the cut) |
| (b) A synchronous again, the end alerted | at the acknowledgement; at the next watch |
| (c) `keel database promote --old-primary-gone` on B | 35.0 to 43.8 s: most of it the wait for A's lease (0049) |
| (c) B carries the VIP; B out of recovery | 35.3 s after the cut; 0.3 s later |
| (c) acknowledged rows missing on B | none (15 acknowledged) |
| (c) without the exception: the first write, from the VIP on B | 216 s: B's commits waited until A streamed |
| (c) with the exception: the first write, from the VIP on B | 1.1 to 1.9 s (the bound of keel#148 is 5 s); B out of recovery 0.3 to 1.4 s after the VIP |
| (c) the write downtime, from the last acknowledgement on A | 24.6 to 40.7 s: the wait for A's lease, then 1.1 to 1.9 s |
| (c) B commits alone; its watch alerts | at each run (twice within 12.5 s) |
| (d) after the reseed, on B | `FIRST 1 (keel)` back, synchronous at once, the end alerted |
| (e) A's boot follow (its own old claim, not proven) | the server stopped |
| (e) fenced, dumped, recorded and alerted, from A's VIP helper start | 8 s and 10 s |
| (e) writes on A from its boot to the fence | 7 and 8 tried, none acknowledged; 3 answered "committed locally" when the stop ended their wait |
| (e) the dump; the alert | holds A's unacknowledged row; one dump and one alert after two more watch runs |
| (d) the confirmed reseed (`keel spec apply --system-only --destroy-local-database`) | 98 to 129 s; A streams 0.2 to 0.8 s after |
| (d) after the reseed | B synchronous again, the end alerted, the rows of A and B equal |
| the whole driver | 500 to 536 s |
