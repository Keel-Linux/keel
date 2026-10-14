# PostgreSQL primary and replica on the mesh

The PostgreSQL pair of handbook decision 0054: the twin of
[docs/replication.md](replication.md)'s MariaDB pair, one engine at a
time the way 0013 has it. What a pair is (the VIP decides the role,
the pair record derives the origins, the credential and the primary's
address), the database leaf of the mesh root CA, the follow of the
VIP's state and the units that run it are the same and are written
there. This file has what PostgreSQL does differently, and the case
(a) wording of the end to end test.

In keel 0.23.17; measured under the design case of 0050 in CI
(`postgres / trixie`), the numbers under "Measured" as they come.

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
  replication is one.
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
  node stays as it is, read only in recovery.
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

**Cases (b) to (e) are the follow-up pull request's**, the twin of
MariaDB's: the replica cut (with etcd, the lease's release fences the
VIP first; the synchronous commit waits and the failover is the
operator's `keel database promote`), the unplanned failover with the
application writing, the old primary rejoining, and the diverged old
primary, dumped, recorded and alerted, reseeding once confirmed.

## Measured

Under the design case, 250 ms ±25 ms with 2 % loss on every leg.
Case (a) is the CI job's (`postgres / trixie`); the numbers land here
as the runs come.

| What | Measured |
| --- | --- |
| (a) a synchronous commit on the primary, the standby acknowledging | one round trip, 0.28 to 0.31 s at 250 ms on the MariaDB twin |
| (a) a write visible on the replica, from its acknowledgement | within the replay, 0.04 to 0.07 s on the twin |
| (b) to (e) | the follow-up pull request's |
