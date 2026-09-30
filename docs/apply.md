# keel spec apply

`apply` is the converge operation of brief section 5.2, under principle 1
of section 4: it converges and is safe to re-run. It has two phases, and
the flags select which of them a run carries out: neither flag is the conf
alone, `--system` is both, `--system-only` is the system phase by itself.
Every example uses IPv6.

## Phase 1: the conf

The spec is rendered into the shell `export` lines the firstboot hooks
already source and written to the conf file (default `/etc/inithooks.conf`,
mode 0600). A conf that already holds something other than whitespace is
never clobbered: `apply` warns and leaves it alone. The variables, field by
field, are in [docs/spec.md](spec.md).

Passwords are handled here and nowhere else. The spec names them by
reference (`secrets.root_password: {file: ...}`), the reference is resolved
into `ROOT_PASS`, `DB_PASS` and `APP_PASS`, and the existing hooks set
them. The second phase never reads or writes a password, a shadow entry or
a hash.

## Phase 2: the system (`--system`, `--system-only`)

```
keel spec apply --system
keel spec apply --system-only
keel spec apply --system --dry-run
keel spec apply --system --root /mnt/rootfs
```

With `--system`, after the conf, `apply` converges the parts of the spec
that describe system state rather than hook input: `instance.hostname`,
`instance.fqdn`, `users`, `locale`, `security.alerts`, `tls.acme`,
`database.server`, `monitor` and, last, `network` and its WireGuard
`overlay`. With `--system-only` it converges them and does nothing
else, for a machine whose conf phase has already run. Neither flag is on
by default.

The two phases run at different moments of a first boot, which is why
there is a flag for each. The conf phase must run before every hook,
because the hooks read what it writes; the system phase must run after
`09hostname`, which sets the hostname and rewrites `/etc/hosts` with a
`sed` over the old name, so anything written to `/etc/hosts` before it
would be edited or lost.

The phase is built as brief section 6 and decision 0003 ask: the state is
read once (`keel.system.state`), the plan is a pure function of the spec
and that state (`keel.system.plan`, `hosts`, `users`, `locale`), and one
small module (`keel.system.effects`) is the only code that runs a command
or writes a file. Commands are run with argv lists, never through a shell.
Every decision is unit tested against fixture trees under `--root`,
exactly as `inspect` is.

### Options

| Option | Meaning |
| --- | --- |
| `--system` | Run phase 2 after phase 1. Root on the live system (exit 15 otherwise) |
| `--system-only` | Run phase 2 and not phase 1: the conf is neither read nor written and no secret is resolved. Root on the live system |
| `--dry-run` | With either flag: print the plan and change nothing, not even the conf. Reads no secret, so the secret files need not exist. Needs no root |
| `--root DIR` | The filesystem phase 2 converges: `/` (the default, the live system) or a scratch tree. Phase 1 is not affected; the conf path is `--conf` |
| `--defer-certificate` | With either flag: write `tls.acme` but ask no certificate authority for a certificate in this run. The first boot hook passes it. See "tls.acme" below |
| `--destroy-local-database` | Confirm, for this run only, that making this node a replica may drop the databases this server holds. Without it apply refuses and changes nothing. See "database.server" below |
| `--network-window SECONDS` | With either flag: how long a network change waits for `keel network confirm` before it reverts by itself; 120 by default, at least 30. See "network" below |
| `--skip-network` | With either flag: leave the network alone in this run, the overlay included, except that a missing overlay key is still made. The first boot hook passes it |
| `--skip-uplink` | With either flag: leave `network.interfaces` alone in this run (its step says so) and converge the overlay, under its window. For a caller that changes the overlay only, so a peer added from the console never moves the interface the operator came in on; confconsole's overlay screen passes it. With `--skip-network` too, the overlay is left alone as well |

`--destroy-local-database` with neither flag is a usage error as well:
it confirms one decision of phase 2, so asking for it without phase 2 is
a typo and not a quiet no-op.

`--dry-run` with neither flag is a usage error (exit 1): phase 1 has
`spec render` for that. `--system` and `--system-only` together is a
usage error as well, because the two answers to "which phases" cannot
both be right, and a precedence rule between them would be a rule to
remember rather than a refusal to guess.

### Why a flag and not a subcommand

`--system-only` selects which phases a run of `apply` carries out. It is
the same operation on the same spec, with the same `--spec`, `--root` and
`--dry-run`, so a subcommand (`keel spec converge`) would give one code
path two names, repeat every option, and leave confconsole with two call
sites for one converge. Phase selection is an attribute of the run, so it
is a flag on the run.

### Running it where the conf phase never ran

Nothing in phase 2 depends on phase 1: its inputs are the spec and the
machine, so on a machine whose conf phase never ran it plans and converges
`instance.fqdn`, `users` and `locale` exactly as it would otherwise, and
exits 0, or 16 for an action that failed. What is missing on such a
machine is phase 1's output, the hook variables and the passwords, and
this run will never write them. So every `--system-only` run says so on
its first line, naming the conf:

```
$ keel spec apply --system-only
apply --system-only: /etc/inithooks.conf not read or written
instance.fqdn: write /etc/hosts with '127.0.1.1 blog.example.org blog' (mode 0644): done
apply --system-only: 1 change(s), 0 failed
```

The line is printed whatever the conf holds, because the run cannot tell
a conf that was never written from one that `98finalize` blanked after a
successful first boot, and guessing between the two would be a claim
about a file this phase does not read. An operator who meant to configure
the whole appliance runs `apply --system`, which writes the conf when it
is empty and leaves a populated one alone.

Not resolving the secrets is the point of the flag, not a side effect.
Phase 1 resolves `secrets` into `ROOT_PASS` and friends, and a secret
declared `generate: true` gets a fresh value each time it is resolved. A
first boot that ran phase 1 at hook 00 and phase 1 again at hook 10 would
hand the appliance a password generated after `30rootpass` had already
set and shown the first one: nobody would know it. `--system-only`
resolves nothing, so the value the hooks applied stands. For the same
reason the spec is validated with `check_secret_files=False`, as `diff`
is: the run reads no secret, so a file it will not open is not required
to exist.

A spec that declares none of the fields phase 2 converges is a no-op that
says which it is, so a log shows the difference between an empty plan and
a run that did nothing because it failed:

```
apply --system-only: nothing declared that this phase converges
```

### What is converged

Only what differs from the observed state is planned, so a second run
finds nothing to do. Every action prints one line, `field: action: done`,
and a dry run prints `field: would action`.

**instance.hostname** (`/etc/hostname`, and the files that carry the name)

`09hostname` sets the name once, at first boot. On a running machine a
declared name that differs from the first word of `/etc/hostname`
(compared as `diff` compares it: case insensitively, a trailing dot
ignored and never written) is converged:

- `/etc/hostname` is written with the new name;
- in `/etc/hosts` and `/etc/mailname` the old name is replaced as a whole
  token or as the first label of a dotted name (`blog`,
  `blog.example.org`), and never inside another word (`weblog`,
  `backup-blog`, `mail_name`), unlike the hook's `sed` over the bare
  string; a file that does not carry the name is not written;
- in `/etc/postfix/main.cf`, only in the values of `myhostname` and
  `mydestination`, continuation lines included. A host called `mail`,
  `smtp` or `relay` would otherwise rename `$mail_name` or a parameter
  such as `smtpd_relay_restrictions`, and drop what it enforces;
- on the live system, `hostnamectl set-hostname`, or `hostname` without
  it, and `systemctl try-reload-or-restart postfix.service` when postfix's
  configuration or the mail name changed, which reloads it only if it is
  running.

On the live system the running name is read too: when `/etc/hostname`
already names the host but the kernel does not, which is what a
`hostnamectl` that failed in a container without `systemd-hostnamed`
leaves, the run sets the kernel name again rather than calling the field
unchanged.

The renamed `/etc/hosts` is what the `instance.fqdn` step below plans on,
so a spec that renames `blog` to `news` and declares `news.example.org`
ends with one file and no line for the old name. A file among those four
that exists but cannot be read refuses the whole rename, because it may
carry the old name. The self-signed certificate keeps the name it was
made for, and the run says so with the command that replaces it.

**instance.fqdn** (`/etc/hosts`)

Upstream `09hostname` writes `/etc/hostname` and replaces the old name
wherever it appears, but it never writes a fully qualified entry: a
container that declares `instance.fqdn` boots with `127.0.1.1 forum2`,
`hostname -f` answers `forum2`, and `keel diff` reports the field as
unknown because inspect cannot find the name anywhere. This phase writes
it.

| Observed | Action |
| --- | --- |
| The first line that names the host carries the declared fully qualified name, at any address | `unchanged (/etc/hosts maps forum2 to forum2.keellinux.org)` |
| The entry is in the file, and a line that names the host without it stands before the entry | The file is not settled: a resolver answers from the first line that carries the name, so `hostname -f` answers the short name. The line is dropped and the entry is written |
| A line for the target address naming the host | The line is replaced where it stood, so the entry keeps its position in the file |
| A line that names the host, and nothing else, without a fully qualified name, at any address: the `127.0.1.1 forum2` that `09hostname` leaves | Replaced where it stood, and dropped where the entry went elsewhere, because a name is resolved from the first line that carries it: kept, the short line would answer first and `hostname -f` would still answer `forum2` although the file holds `forum2.keellinux.org` |
| A line that names the host beside another name (`127.0.0.1 localhost forum2`) | Kept: rewriting a line that belongs to another name is not this phase's business. The entry is written all the same, and the plan says in one line that the kept line answers first and has to be edited by hand |
| No such line | The entry is appended |

The address is the static IPv6 address the spec declares for an interface
when it declares one, which is the Debian convention for a machine with a
permanent address, and `127.0.1.1` otherwise, because an address a router
hands out is a lease and must never be frozen into a file. A static IPv4
address alone does not carry the name: the family the appliance is reached
on is IPv6. Either way the entry is local resolution only; what the
appliance is reachable at is its global address.

Everything else in the file, comments and blank lines included, is kept as
it was, and the file is written mode 0644. Whether the name is already
there is decided by the same reader `keel inspect` uses
(`keel.inspect.hostname.fqdn_in_hosts`), which reads the file the way a
resolver does, so what apply writes is what inspect reads back and diff
calls `same`. Otherwise the field is settled only when the file the write
would produce is the file that is already there, which is why an entry
another line shadows is converged instead of being called unchanged.

**users.<name>** (accounts)

| Observed | Action |
| --- | --- |
| No entry in `/etc/passwd` | `useradd --create-home`, with `--shell` and `--groups` when declared |
| Entry with another shell than `shell` | `usermod --shell` |
| Entry missing some of `groups` | `usermod --append --groups` with the missing ones only |
| Entry matching | `unchanged (exists, uid N)` |

Nothing is ever deleted: not an account, not a group membership, not a
home directory. Groups must exist; `apply` does not create them, and a
`useradd` or `usermod` that fails says why and fails that field. Under
`--root DIR` the commands run with `--root DIR`.

**users.<name>.authorized_keys**

The file `<home>/.ssh/authorized_keys` is set to exactly the declared
public key lines, one per line, mode 0600, owned by the user, with
`<home>/.ssh` mode 0700 and owned by the user. The home is the one in
`/etc/passwd`, or the one `useradd` picks (`/root`, `/home/<name>`) for an
account created in the same run. A key present in the file but not in the
spec is removed by the rewrite, which is what "exactly the declared keys"
means; declare every key you want kept. An empty list writes an empty file.

**locale.timezone**

Compared with `/etc/timezone` and the `/etc/localtime` symlink. When they
differ: on the live system with `timedatectl` present, `timedatectl
set-timezone ZONE`; otherwise `/etc/timezone` is written (mode 0644) and
`/etc/localtime` is linked to `/usr/share/zoneinfo/ZONE`.

**locale.lang**

Compared with `LANG` in `/etc/default/locale`. When it differs, the file
is rewritten with that one line replaced or appended, the other lines
kept. Then, on the live system only, the locale is generated unless
`locale -a` already lists it: with `locale-gen` present the `NAME CHARSET`
line is added to `/etc/locale.gen` if absent and `locale-gen` runs;
otherwise `localedef -i SOURCE -c -f CHARSET NAME`. `C`, `POSIX` and
`C.UTF-8` are built in and never generated. Under `--root DIR` the file is
written and the line says `not generated: not the live system`, since a
scratch tree has no locale archive of its own.

**security.alerts** (`/etc/aliases`, `/etc/cron-apt/config`)

The first boot hook `85secalerts` writes this field once. On a running
machine the same two traces are converged, read through the reader
`inspect` uses (`keel.inspect.security.root_alias`), so a converged
machine diffs `same`:

| Declared | Observed | Action |
| --- | --- | --- |
| an address | the root alias is that address, cron-apt has `MAILON="output"` and `MAILTO="root"` | none: `unchanged (address)` |
| an address | another root alias, or none | `/etc/aliases` rewritten with the one `root:` line replaced or appended, the other lines kept; then `newaliases` on the live system |
| an address | cron-apt mails otherwise | `/etc/cron-apt/config` gets `MAILON="output"` and `MAILTO="root"`, replaced in place, comments kept |
| `skip` | a root alias to an external address | that line removed, then `newaliases`; cron-apt is left alone, as the hook leaves it for `skip` |
| `skip` | no root alias, or a local one | none: `unchanged (skip)` |

Under `--root DIR` the line says `aliases database not rebuilt: not the
live system`; on a live system without `newaliases` it says so too. A
machine without cron-apt gets the alias only, and the line says so. An
`/etc/aliases` that exists but cannot be read is refused, since rewriting
it would drop what the run could not see. `updates_at_first_boot` has no
trace on the machine and is not converged ([docs/spec.md](spec.md)).

**tls.acme** (`/etc/dehydrated/confconsole.domains.txt`, the certificate)

Nothing applied this field before, not even at first boot. The decision is
made from the certificate in use, read as `inspect` reads it
(`keel.inspect.certificate`), so a machine `diff` calls `same` is one
`apply` leaves alone:

| Declared | Observed | Action |
| --- | --- | --- |
| `enabled: true` | a certificate a CA issued, covering every domain, more than 30 days from its end | none: `unchanged (domains, valid until ...)` |
| `enabled: true` | self-signed, not covering a domain, or within 30 days of its end | the domains file written when it differs; on the live system, confconsole's `dehydrated-wrapper --log-info --challenge http-01`, with `--register` when no account exists |
| `enabled: false` | a certificate a CA issued | on the live system: the renewal job disabled (`chmod a-x /etc/cron.daily/confconsole-dehydrated`), `turnkey-make-ssl-cert --default --force`, and `systemctl try-restart` of those of nginx, apache2, lighttpd, tomcat10, tomcat11 and Webmin whose unit the machine has (a missing unit makes `try-restart` exit 5) |
| `enabled: false` | self-signed | none: `unchanged (off)` |
| absent | anything | none |

The wrapper answers the challenge, installs the certificate where every
service reads it, keeps the previous one as `.bak` and installs the
renewal job. Let's Encrypt is asked only when the certificate in use needs
it, never on every run, which its rate limits require.

An account is looked for with the CA the dehydrated config names (`CA=`,
`letsencrypt` when unset, under `BASEDIR`), at the directory dehydrated
0.7.2 names after it, so an account left from another CA, staging for
instance, is not taken as consent for this one.

With `--defer-certificate` the domains file is written and nothing is
requested: `certificate request deferred`. The first boot hook passes it.
At first boot DNS rarely points at the machine yet, and a golden image
cloned with its domain would spend Let's Encrypt's limit on failed
validations with every copy; the next `apply --system`, run when the
name resolves, requests it. Turning ACME off asks no outside service and
is not deferred.

Refused, with the reason, and the run fails: `dns-01` (a DNS provider and
its credentials have no field in the spec yet), no Let's Encrypt account
on the machine and no `agree_tos: true` (registering accepts the terms of
service, which confconsole asks the operator on screen), no domains, and
no `dehydrated-wrapper` on the machine. Under `--root DIR` the domains
file is written and the line says `certificate not requested: not the live
system`; nothing is refused there, since nothing would be requested.

**database.server** (MariaDB)

Phase 3 of decision 0013: the role this node is in. `keel inspect` asks
the server what it is and `keel diff` reports the difference; this is the
acting half. MariaDB first; PostgreSQL and Redis are read and compared
and say so rather than being configured.

Every role writes one file,
`/etc/mysql/mariadb.conf.d/99-keel-database.cnf`, and restarts the server
**only when that file changed**, because `server_id`, `bind-address` and
`log_bin` cannot be set while it runs.

| Line | Where it comes from |
| --- | --- |
| `server_id` | Derived from `/etc/machine-id` **and** `listen`, never from the description alone: two appliances deployed from one description would collide, and two nodes with the same server id stop replicating. Both, because the published `core` layer ships a populated machine-id, so every appliance assembled from it holds the same value (docs/traps.md); a pair on one /64 differs in its addresses whatever the layer shipped. A machine with neither is refused rather than given an invented one |
| `bind-address` | `database.server.listen`, written as the literal list it is. Absent from the description means the file says nothing and the packaged setting stands |
| `skip_name_resolve` | `ON`, unless an entry of `allowed_from` is a name: MariaDB matches a grant whose host is a name only while it resolves client addresses. The line of the plan says so, because docs/spec.md calls a name fragile for exactly this reason |
| `log_bin`, `binlog_format` | On a primary alone. A replica reads the primary's log and needs none of its own |

A **primary** then holds its authorizations. Each entry of
`allowed_from` becomes `CREATE USER`, `ALTER USER` and `GRANT REPLICATION
SLAVE` for the account `repl` at that origin, written in the spelling
MariaDB has for it, so `2804:710:d0:5::/64` becomes `2804:710:d0:5:%`
and an address is written compressed, `fd3d:80b2:d0d7::2` for
`fd3d:80b2:d0d7:0:0:0:0:2` (`keel.spec.origins`). An origin the
description no longer names has its account dropped, because `inspect`
reads the authorizations off the server and one left behind would drift
for ever. `allowed_from` absent, as against empty, leaves the server's
authorizations alone.

Three kinds of origin are refused on MariaDB, because authorizing a
wider or a narrower range than the description asked for is not a
decision apply makes. `keel spec validate` refuses them, so apply stops
before it writes the configuration or restarts the server, and before
it grants the other origins of the list; the plan refuses them again
for a description that reaches it some other way:

- a prefix that stops inside a group, a `/56`;
- a host pattern with `::`, on any engine: `::` stands for a number of
  zero groups no wildcard counts, so `2001::5:%` holds
  `2001:0:0:0:0:5:a:b`, outside `2001:0:0:5::/64`;
- an IPv6 prefix with a zero group the address text can compress away:
  its last group is zero, or two groups in a row are. MariaDB compares
  the text of the client's address, and in `fd3d:80b2:d0d7::/64`, what
  `keel network wireguard suggest-address` prints, the replica at
  `fd3d:80b2:d0d7::2` is not written `fd3d:80b2:d0d7:0:...`, so the
  pattern `fd3d:80b2:d0d7:0:%` refuses it. MariaDB 11.8 (Debian 13) has
  no IPv6 netmask or CIDR host either; both were tried and match
  nothing. The refusal names an address the pattern would have missed;
  write each replica's address instead.

An account is dropped unless the description grants exactly its host,
ignoring case. An account 0.11.0 made at the expanded
`fd3d:80b2:d0d7:0:0:0:0:2` names the same origin as the
`fd3d:80b2:d0d7::2` granted now, and MariaDB never matches it, so it is
dropped and not kept beside the new one.

The account name is a constant and not a field. Both ends of a pair must
name the same account, and a field each operator sets on their own
machine is a way to end up with two machines that cannot talk, while
decision 0013 keeps every screen to the machine it runs on.

A **replica** then replicates from `replication.primary`, with
`MASTER_USE_GTID=slave_pos` and an empty `gtid_slave_pos`, which means
from the beginning of the primary's binary log. That is the only seeding
this version does, and it is honest only because of the refusal below: a
node whose database is empty and a primary whose binary log has not been
purged are equal at that moment. Seeding a replica from a backup of a
primary that already held data is the operator's step and keel does not
do it.

A replica already replicating from the declared endpoint is left alone,
which matters more here than anywhere else in keel: apply runs at every
boot, and restarting replication from the beginning of the log on a
machine that had caught up would throw that away.

#### Becoming a replica destroys the local database

A standby is a copy of its primary, so a machine that holds data cannot
become one without losing that data. This is the one step of the whole
feature that loses data and it gets the most explicit treatment:

- **The refusal is the default.** Apply refuses unless the server holds
  no database but its own (`information_schema`, `mysql`,
  `performance_schema`, `sys`).
- **A server that cannot be asked what it holds is refused too.** Not
  knowing is not permission.
- **Pointing a replica at a different primary is the same act**, because
  the copy it holds came from another server.
- **The override is `--destroy-local-database`, in that invocation.** It
  drops the databases the refusal named and then builds the replica, and
  the line of the plan repeats the refusal it is overriding.
- **Nothing else in keel passes it.** `keel diff` writes nothing
  anywhere, and the first boot hook `10keel-system` runs
  `keel spec apply --system-only` with no such flag, so the worst a first
  boot can do is build a replica out of a database that holds nothing.

```
$ keel spec apply --system-only
database.server.replication.primary: refused: becoming a replica replaces the local database with a copy of the primary, and this server holds 1 database(s) that are not its own (wordpress). The server was left as it was: its configuration was not rewritten and it was not restarted. Move the data elsewhere, or run the same command again with --destroy-local-database to drop them and build the replica
apply --system-only: 0 change(s), 1 failed
```

The refusal is decided before the replica's configuration is written, so a
declined replica keeps the file and the running server it had. Every
refusal of the replica step works that way, a missing credential
included.

#### apply never promotes and never demotes

Where the observed role differs from the declared one in a way that would
need either, the plan refuses and configures nothing:

| Declared | Observed | What apply does |
| --- | --- | --- |
| `primary`, `standalone` | `replica` | Refuses, and names `keel database promote`. Promotion is an operator action |
| `replica`, `standalone` | `primary` | Refuses. Demoting a primary destroys everything written to it since a replica last agreed |

This is the same rule `keel diff` states as a rule of the project
([docs/diff.md](diff.md)), on the acting side: the drift it says must
never be corrected automatically is drift apply will not correct.

#### `keel database promote`

Promotion is the one thing keel makes the operator type, because it is
the one decision no machine here can make. It stops replication and
forgets the primary (`STOP SLAVE`, `RESET SLAVE ALL`, not `STOP SLAVE`
alone: a node that still held the coordinates would follow its old
primary again at the next restart), and then says two things:

```
$ keel database promote
database.server.role: stop replicating and forget the primary (mariadb --batch, 2 statement(s) on standard input): done
database.server.role: this node is a primary now and the description still says replica, which keel diff reports as drift and must not be corrected automatically. Change the description to primary and run `keel spec apply --system-only` to give it a binary log of its own
database.server.role: nothing here stopped the old primary or told anybody else about this. There is no failover in Keel: two writable servers on one dataset is what this command can cause, and only the operator knows the old primary is gone
database promote: 1 change(s), 0 failed
```

It refuses anything that is not a replica, and `--dry-run` prints the
plan and needs no root. The drift it leaves behind is by design: the
description is the operator's to change, and changing it is what makes
the node a primary in keel's eyes as well as MariaDB's.

**There is no automatic failover here.** Nothing in this phase looks at
another machine. Replication without failover is not high availability,
and when it is wanted the packaged answers are Galera for MariaDB and
Patroni for PostgreSQL.

**monitor** (`/etc/monit/conf.d/keel.conf`, `/etc/keel/monitor.json`;
handbook decision 0021)

monit watches, keel tells. The section is rendered into two files, both
mode 0600 and owned by root, as apply runs:

- `/etc/monit/conf.d/keel.conf`, the checks monit includes (the replicated
  set of decision 0020 will put monit's HTTP credentials there);
- `/etc/keel/monitor.json`, everything `keel notify` reads: the channels
  resolved from the spec (a literal URL or the path of the secret file
  holding it, a chat id), the paths of the token files and never a token,
  the alerts address, `details`, and the host's name and first static
  address. `keel notify` never reads the spec (see below).

| Declared | Observed | Action |
| --- | --- | --- |
| `enabled: true` | both files already say what would be written | none: `unchanged (/etc/monit/conf.d/keel.conf, ...)` |
| `enabled: true` | anything else | the files that differ written; when keel.conf changed, on the live system `monit -t`, then `systemctl try-reload-or-restart monit.service` |
| `enabled: true` | a keel.conf keel did not write (its first line does not say so) | refused: it is not overwritten |
| `enabled: false`, or a section without `enabled: true` | files keel wrote | both removed, then the same check and reload |
| `enabled: false`, or a section without `enabled: true` | no file, or ones keel did not write | none: `unchanged (off)` |
| no `monitor` section (`monitor:` with no value included, which YAML reads as none) | files keel wrote | none, and the plan says so: `not declared`, left as an earlier apply set it (keel#46). A spec that only declares the network must not end the alerting another one turned on |
| no `monitor` section | nothing keel wrote | no step |

A token or URL file the channels name that is missing, or readable or
writable by others, is a line in the plan, `...: secret file not found:
that channel fails until it is fixed`, and not a failure: `--system-only`
does not require the secret files, and the other channels still work.

What the file holds, and why:

- **One check per filesystem that holds data**, listed from
  `/proc/self/mountinfo` at apply time, since monit has no wildcard: a
  filesystem mounted later is watched from the next apply. Left out:
  pseudo filesystems (proc, sysfs, tmpfs, devtmpfs, cgroup), overlays,
  read only images and media (squashfs, erofs, iso9660, udf), network
  filesystems (nfs, cifs, ceph, 9p, davfs and the like) and every FUSE
  filesystem (sshfs, s3fs, the lxcfs files a container host provides),
  whose space is another machine's or program's and whose stalled
  `statvfs` would stall monit's whole cycle; anything under `/proc`,
  `/sys`, `/dev` and `/run`; a bind mount of part of a filesystem (how a
  container host hands in `/etc/hostname`); and a second mount of the
  same device. A mount point monit cannot take as a path (a space, `@`,
  `:`, `,` or `%` in it, measured with monit 5.34's parser) is named in
  the plan as not watched, unless the device is watched at another of its
  mount points. Under `--root DIR` the tree's own mount table is read,
  which is usually absent: then `/` alone is watched and the plan says so.
- **Warn and critical are separate services** (`keel_disk_warn_root`,
  `keel_disk_critical_root`), and so are inodes, memory, swap, CPU and
  load: tests in one monit service share its one resource event, so going
  from critical back to warn would report a recovery that did not happen.
- **The cycle is monit's, never set.** `set daemon` is global: one in
  this file would reset the cycle and the start delay of every check on
  the machine, the operator's included. So apply reads it as monit does,
  from `/etc/monit/monitrc` and the files it includes, in order, the last
  `set daemon N` winning, and Debian's 120 seconds when none is found.
  `for_minutes` becomes `for N cycles` with N the minutes rounded up to
  whole cycles, and a duration monit cannot hold, more than 64 cycles at
  that cycle, refuses the field, naming the check, the cycle and where it
  was read. The plan line says which cycle was used. The minutes the spec
  declared are kept in a comment above each test (`# for_minutes: 5`),
  which `keel inspect` gives back while the cycles still agree with them,
  since 5 minutes at 120 seconds is 3 cycles, which is 6 minutes.
- **Network rates in bytes per second**, monit's unit: `max_mbit: 800` is
  `upload > 100000000 B/s` and the same for download. Written in bytes,
  so monit's binary `MB` never enters into it. Each direction tells
  `keel notify` which one it is (`--direction upload`), its recovery
  included, so a download recovering is never reported as the upload.
- **Every test runs `keel notify`**, with `repeat every N cycles` for a
  reminder about once an hour while the condition lasts and `else if
  succeeded then exec` for the recovery, because monit runs `exec` once
  when a test fails. The line is `/usr/bin/python3 -B -m keel notify
  --level warn --check disk --path / --threshold 80`: no spec, no URL and
  no token.

monit must be installed for the live step. Without it the field is
refused, `monit is not installed, and keel installs no package: install it
(apt install monit) and run apply again`, and nothing is written. A file
monit refuses fails `monit -t`, the reload after it is skipped, and the
running daemon keeps the configuration it had. A monit that is stopped
stays stopped: `try-reload-or-restart` acts on a running service only.

#### keel notify

What monit runs. It reads the event from monit's environment
(`MONIT_EVENT`, `MONIT_SERVICE`, `MONIT_DESCRIPTION`), the level, the check
and what it is about from its arguments, and the channels from
`/etc/keel/monitor.json` (`--settings` names another file), and sends one
message to every channel there. A channel that fails does not stop the
others.

It never reads the spec. It runs as root at every alert, so a spec it
read would decide where root sends things: a spec that moved, was
deleted, sat in a temporary path or failed validation for a field that
has nothing to do with alerts would silence every alert, and a spec a
user owns could later point a token file at `/etc/keel/secrets/
root_password` and the URL at a server of theirs. The settings file is
written by apply as root and refused unless root owns it and nobody else
can read or write it, and every token or URL file it names is refused the
same way: the rule of every secret file (docs/spec.md).

When no channel takes the message (the settings file missing or refused,
no channel in it, every channel failing), the message goes to syslog
(`logger -p user.crit -t keel-notify`) and to root's mailbox
(`/usr/sbin/sendmail root`), the two places left on the machine itself,
and the exit code is 22 (`NOTIFY_FAILED`).

```
blog (2001:db8:1::10): / is 92.3% full (critical at 90%).
Grow the disk on the host; the container sees the new size:
  host (for example Proxmox, container): pct resize <vmid> rootfs +10G
  here: nothing more
Largest directories: /var/lib/mysql 18G, /var/log 4.1G.
monit: space usage 92.3% matches resource limit [space usage > 90.0%]
```

The machine cannot know its VMID, its disk's name on the host, or that
the host is Proxmox, so the host command carries placeholders and names
Proxmox only as an example. The steps inside the machine are chosen from
what it can see: `systemd-detect-virt`, `findmnt` for the filesystem's type
and device, and `lvs` and `pvs` for LVM. ext4 on a partition gets
`growpart` then `resize2fs`, XFS `xfs_growfs`, LVM `pvresize` then
`lvextend -r`, a container nothing more, with its volume named `rootfs`
for `/` and `<mpN of PATH>` for a mount point. Memory, swap, CPU and load
name `pct set` or `qm set`; a link down and a throughput over the limit
name what to look at. With `details: true` the three largest directories
or processes (`ps`) are added. The directories come from `du -x
--max-depth=2`, at most 20 seconds, taken largest first and never one
inside another already listed, so a directory is listed with its own size
when it is the large one; one alert measures a filesystem at a time (a
lock under `/run/lock`), and the others say it is being measured. Nothing
is run that changes anything.

It writes nothing but that empty lock file on a tmpfs: it runs as
`python3 -B`, reads the tokens from their secret files, and names a
channel, never its URL, in what it prints. The Telegram token is part of
the request path, so no URL appears in an error either, and a redirect is
reported, never followed, since following it would carry the
`Authorization` header to another host. HTTPS is verified against the
system's certificate authorities, every request has a timeout, and only
the standard library is used.

**network** (`/etc/network/interfaces`; handbook decision 0018)

The one field whose converge can cut off the operator running it, so it
is the last step of the plan and, on the live system, never a plain
write. The rules:

- **A container's network is not converged.** With `managed_by: host`
  the host writes the interfaces; the step says so and `keel diff` keeps
  comparing. Declaring `managed_by: file` inside a container is refused
  when there is something to change.
- **Only drift changes anything.** The plan compares the declared section
  with what `keel inspect` reads, exactly as `keel diff` does, so a file
  that says the same thing in other words is left alone, and a field
  inspect could not infer (SLAAC and DHCPv6 look alike in the file) does
  not bounce an interface.
- **One interface**, as `01ipconfig` configures one. A spec declaring
  several, with drift, is refused, and so is one naming another interface
  than the file configures: the old one would stay up with its addresses.
- **What the spec leaves out stays.** A spec declaring IPv6 only keeps
  the machine's IPv4 stanza, and one declaring no nameservers keeps the
  file's, rather than the library's defaults replacing them.
- **Nothing is bounced for a difference the file cannot hold.**
  ifupdown writes nameservers only in a static stanza, two per stanza.
  A dynamic family's servers go into the other family's static stanza
  when there is one (docs/spec.md), but with neither family static, or
  more than two servers, some cannot be written: a difference in the
  nameservers alone is then reported and the interface left alone, and a
  change that rewrites the file for another field says which servers it
  cannot hold rather than dropping them silently. A file that already
  says exactly what would be written is never rewritten, whatever else
  differs.
- **The file's words are kept where they mean the same.** A file that
  says `inet6 auto` for a spec's `method: auto` keeps it, rather than
  becoming `inet6 dhcp`, keel's own word for the same thing.
- **`slaac: false` needs the inithooks that writes it.** The library's
  `IP6_SLAAC` option is what turns SLAAC off (docs/spec.md); an installed
  inithooks older than that option renders the stanza without it, and
  the step is refused ("the installed inithooks cannot write slaac:
  false; update inithooks") rather than writing a file that keeps SLAAC.
  An IPv4 nameserver the static inet6 stanza must carry is refused the
  same way by an older library, with the same advice.
- **SLAAC comes back with the file that keeps it.** Before `ifup` on a
  file without `slaac: false`, in a change and in its revert, the
  interface's IPv6 `autoconf` is set back to what it was before the
  change (1 when the file being left is the one that turned it off).
  ifupdown-ng runs no `post-down` for an interface whose `up` failed
  after its `pre-up` ran, so without this a failed change would leave
  SLAAC off, and an operator reaching the machine over it locked out,
  until a reboot. The boot revert writes nothing: nothing of a `pre-up`
  survives a reboot (docs/spec.md).
- **The file is inithooks' own.** It is rendered by the functions of
  `/usr/lib/inithooks/lib/ipconfig.sh` that `01ipconfig` uses, from the
  same variables, so a first boot and a day two write the same file for
  the same spec. Without inithooks the step is refused.

Under `--root DIR` the file is written and nothing else happens. On the
live system the change is a sequence that reverts by itself:

1. the current file is saved under `/var/lib/keel/network/` with a
   pending marker, and a transient timer, `keel-network-window-safety`,
   is armed for the window plus 60 seconds, the time `ifup` may spend
   waiting for DHCP; no timer, no change;
2. `ifdown` on the old file, the addresses flushed, the link set down,
   the new file written, `ifup` on it. An `ifup` that fails puts the old
   file back at once;
3. once the interface is up, a second timer, `keel-network-window`, is
   armed for the window itself, so the whole window is left to confirm in;
4. the run ends. Within the window, from a **new** session:

```
$ ssh admin@2001:db8:1::20
$ sudo keel network confirm
confirmed from an SSH session
the new gateway (fe80::2) was not tested: the route back to 2001:db8:1::99 does not use it
the network change stays; the revert is cancelled
```

Without a confirmation a timer runs `keel network revert`, which
takes the interface through the same sequence back onto the saved file.
A reboot inside the window is covered too: `keel-network-revert.service`
runs before networking while the marker exists and puts the saved file
back. A change, a confirmation and a revert take the same lock, so a
revert that has started finishes before a confirmation is looked at, and
the confirmation then says there is nothing to confirm rather than
reporting success on the old network.

`keel network confirm` accepts only what shows that the new network
works:

| Run from | Accepted when |
| --- | --- |
| SSH | the session (its `sshd-session` process) started after the interface came up on the new file, and came from another machine (`ssh` to the new address from the old session proves nothing), and arrived at a static address the new file declares for the session's family; for a family the file leaves to DHCP or SLAAC, at an address of the new file or one the interface now holds. With SLAAC kept beside a static address, a session over the SLAAC address does not show the static one works, so it is refused |
| A console (`tty1`, `ttyS0`, `hvc0`, `console`, and in an LXC container `lxc/tty1` and `lxc/console`, which `/dev/tty1` links to and which only `lxc-console` or `pct console` on the host reach) | always: a person there has seen the machine |
| A process attached from a container's host | always, as a console |
| Anything else: a shell that survived the change in tmux, a service | refused |

The session is read from the process tree, not from `SSH_CONNECTION`,
which `sudo` resets. A session tests one family, so when the change
declares a static address of the other family too, confirm says that
address was not tested. When the gateway changed, confirm says whether the
route back to the client used it: a client on the same link reaches the
machine without the gateway, and saying the gateway was tested would be
false. A refusal exits 21 (`NETWORK_NOT_CONFIRMED`) and leaves the timer
running.

`keel network revert` gives up on a change by hand without waiting;
`--boot` restores the file without touching the interface, for the boot
unit. Both need root on the live system.

Beside the saved copy, `saved.json` records which file it is a copy of
(`/etc/network/interfaces`, or the overlay's file under
`/etc/wireguard`), written apart from the marker. A marker that cannot
be read is reverted onto that file, without restarting any interface.
When the record is missing or names any other file, nothing is restored
and revert says so and exits 16, leaving the marker and the copy for the
operator: a guess could write an overlay's file over the uplink's.

**network.overlay** (`/etc/wireguard/<interface>.conf`; handbook decisions
0018 and 0020)

The WireGuard interface the nodes of a replicated appliance share
(docs/spec.md, "overlay"). It is the appliance's own interface on either
kind of machine, so it is converged from inside a container too, where
the uplink is the host's. It is the last step, after the uplink, and it
goes through the same window, marker, lock, timers and boot unit, with
`wg-quick` in place of ifupdown:

- **The key first.** A missing private key is made with `wg genkey` into
  its file, mode 0600, on the live system only; under `--root` the step
  says it is made on the machine itself, never in an image (keel-core#8).
  `--skip-network`, which the first boot passes, still makes the key, so
  the pair exists from the first boot and the public key can be handed
  out before the overlay is brought up. An existing key file that is not
  root's and 0600 is refused.
- **An inline key is kept, not replaced.** A file written by hand may
  hold its key in a `PrivateKey` line. Before the file is rewritten
  without it, the key is moved into the key file (written whole to a
  temporary file beside it, mode 0600, then linked into place, so a full
  disk leaves no truncated key; under `--root` too), so the node keeps the public key its
  peers know it by; no new key is made. The key is read from the one
  file and written to the other when the step runs: it is never in the
  plan, an argument or the output. A key file that already holds the
  same key is fine; one that holds another is refused and both are left
  as they are, since keel cannot tell which one the peers know.
- **keel owns the file.** It is rewritten whenever it is not exactly what
  the spec renders. It holds no private key: a `PostUp` line gives the
  key file to `wg set`.
- **The interface is read too.** On the live system the file alone is
  not the overlay: `ip link show dev <interface>` says whether it is up.
  A right file whose change was confirmed (`wg-quick@<interface>`
  enabled) but whose interface is down is drift, and the step is
  `systemctl restart wg-quick@<interface>`. A right file that was never
  brought up and confirmed on this machine (it came with an image, say)
  is brought up as a change, under the window; its revert puts the file
  back and leaves the interface down, as it was. A right file that is up
  is left alone, and its unit enabled if it is not.
- **Refused, with the reason:** without `wg`, `wg-quick`, `ip`,
  `systemd-run` or `systemctl` (install `wireguard-tools`); in a container
  whose host has not loaded the `wireguard` module (the message names
  `modprobe wireguard` on the host; a VM loads it itself); while another
  change waits for its confirmation; and in a run whose uplink changes,
  since one change waits in the window at a time: confirm the uplink,
  then apply again.
- **The sequence**, both directions alike: `wg-quick down` on the
  outgoing file (a failure is not fatal: an interface that is not up has
  nothing to take down), the new file put in place, `wg-quick up` on it. A
  change that created the file reverts by removing it, which leaves the
  interface down, as it was. A change is dated on the clock a session's
  start time is read on (the start of a thread, in seconds since the
  host's boot), not `/proc/uptime`, which lxcfs counts from a container's
  start.
- **Enabled once confirmed.** `keel network confirm` enables
  `wg-quick@<interface>` after it cancels the revert, so a reboot inside
  the window of a first overlay leaves no interface behind, and a later
  run enables it if that failed. At boot the revert unit runs before
  `network-pre.target`, which every `wg-quick@` instance follows, so an
  unconfirmed change is undone before the overlay comes up.

Which sessions confirm an overlay change is the one rule that differs
from the uplink's. What such a change can break is two paths: the
overlay itself, and the uplink, whose replies the routes `wg-quick` adds
for a peer's `allowed_ips` can capture (a peer given `::/0`, or the
operator's own prefix). A new session over either proves that the path it
used survived, so:

| Run from | Accepted when |
| --- | --- |
| SSH, over the overlay | the session started after the change, came from another machine, and arrived at an address the overlay declares (`address`, `ipv4_address`). confirm says the overlay was tested |
| SSH, over the uplink | the session started after the change, came from another machine, and arrived at an address another interface of this machine holds now. confirm says the overlay itself was not tested, and at which address a peer would test it |
| A console, a process attached from a container's host | always, as for the uplink |
| Anything else, a session older than the change, a session from this machine to itself, or one arriving at an address the overlay does not declare | refused (exit 21) |

Requiring the overlay alone would make pairing impossible: the first
node's overlay carries nothing until the second node declares it too,
and the first change would always revert. An agent of Keel Cloud that
reaches the node again over the overlay confirms the same way.

Whoever confirms, a console included, the uplink's routes are asked
first, with `ip route get`: to each gateway `network.interfaces`
declares and each gateway of a default route in place now (`ip -6` and
`ip -4 route show default`: what DHCP, SLAAC or a container's host
configured, and what `--skip-uplink` left), IPv6 first, and, for an SSH
session that came over the uplink, back to its client. When one of them
leaves through the overlay's interface, the change routes the uplink's
traffic into the overlay, and confirm refuses (exit 21) and leaves the
change to revert when its window ends, or at once with `keel network
revert`. It refuses too when `ip` gives no answer for one of them: an
unknown route is not taken as a clean one. Validation already refuses
what the spec shows (docs/spec.md, "Routes"); this catches what it
cannot.

```
$ ssh root@fd00:6b65:1::1        # from the other node, over the overlay
# keel network confirm
confirmed from an SSH session
the overlay was tested: this session arrived at fd00:6b65:1::1 on wg0, from fd00:6b65:1::2
wg-quick@wg0 enabled: the overlay comes back up at boot
the network change stays; the revert is cancelled
```

`keel network wireguard key` prints this node's public key, and makes the
pair first when there is none (root, live system only); only the public
key is printed. `keel network wireguard suggest-address` prints a fresh
unique local address for the first node of a set.

### Failures and exit codes

A failed action, and a refusal, fail their field: the actions after it in
the same field are skipped (the keys file of an account that could not be created is not
written into a home that does not exist), the other fields go on, and the
summary counts what happened. The exit code is then 16 (`APPLY_FAILED`);
the conf was written and every other change was made, so the run can
simply be repeated after the cause is fixed.

| Code | Name | When |
| --- | --- | --- |
| 15 | `APPLY_NEEDS_ROOT` | `--system` on the live system as a user other than root; nothing was written, not even the conf. `--dry-run` never needs root |
| 16 | `APPLY_FAILED` | At least one action of phase 2 failed; the output names it |

The other codes (absent spec, invalid spec, secret and conf errors) are
those of phase 1 and are listed in the README.

### An example

The `turnkey` fixture tree of the test suite, inspected and then applied
into an empty scratch tree:

```
$ keel inspect --root tests/fixtures/inspect/turnkey --output blog.yaml
$ keel spec apply --spec blog.yaml --conf /tmp/conf --system --root /tmp/scratch --dry-run
dry run: /tmp/conf not written
instance.fqdn: would write /etc/hosts with '2001:db8:1::10 blog.example.org blog' (mode 0644)
users.root: would create user root (useradd --root /tmp/scratch --create-home --shell /bin/bash root)
users.root.authorized_keys: would ensure /root/.ssh (mode 0700, owner root)
users.root.authorized_keys: would write /root/.ssh/authorized_keys with 2 key(s) (mode 0600, owner root)
users.admin: would create user admin (useradd --root /tmp/scratch --create-home --shell /bin/bash --groups adm,sudo admin)
users.admin.authorized_keys: would ensure /home/admin/.ssh (mode 0700, owner admin)
users.admin.authorized_keys: would write /home/admin/.ssh/authorized_keys with 1 key(s) (mode 0600, owner admin)
locale.timezone: would write /etc/timezone (mode 0644)
locale.timezone: would link /etc/localtime (-> /usr/share/zoneinfo/Europe/Lisbon)
locale.lang: would write /etc/default/locale with LANG=en_US.UTF-8 (mode 0644)
locale.lang: not generated: not the live system
dry run: 10 change(s) planned, nothing written
```

Run for real, then run again, and the second run prints `unchanged` on
every line and `apply --system: 0 change(s), 0 failed`. `keel diff --spec
blog.yaml --root /tmp/scratch` then reports `instance.fqdn` and every
`users` and `locale` field as `same`: that round trip is a test
(`tests/test_apply_system_cli.py`, `TestRoundTrip`).

### What is never done

- Passwords: not read, not set, not hashed. `ROOT_PASS` and friends stay
  with phase 1 and the hooks.
- Deletions: no account, group membership, key file or home is removed.
  A key not in the spec disappears from `authorized_keys` only because the
  file is rewritten as declared.
- Creating groups, or anything about a user beyond shell, groups and keys.
- Renaming the machine anywhere but `/etc/hostname`, `/etc/hosts`,
  `/etc/mailname` and postfix's `main.cf`: the SSH public key comments
  and the motd that `09hostname` also edits are labels, not
  configuration. Nor making a new self-signed certificate for the new
  name, which replaces the key and restarts the web servers; the run
  says how.
- Generating a locale for a tree other than the live system.
- Installing a package. A description that declares a database server on
  a machine with none is a refusal, not an installation.
- Anything to the database under `--root DIR`: the server of an offline
  root is another machine's, and a statement sent here would reach the
  wrong one.
- Anything at all to `database.client`: where an application reaches a
  database is the application's own configuration.
- Accepting the Let's Encrypt terms of service without `tls.acme.agree_tos:
  true`, or requesting a certificate with `dns-01`.
- Registering an alerts address with hub.turnkeylinux.org, which the
  first boot hook does: the Hub is one optional backend (brief section
  5.6), and a converge that ran on every apply would subscribe the machine
  to somebody else's service each time.
- Installing monit, or acting on what it finds: the file keel writes for
  it only runs `keel notify`, so nothing grows a disk, restarts a service
  or kills a process behind the operator's back. Growing a disk is the
  operator's act on the host, and the message says how.
- Exposing monit's web interface, writing a token into monit's file or
  the notify settings, or setting monit's cycle.
- Converging a container's network from inside, more than one
  interface, bridges, VLANs or interface names; or changing the network
  on the live system without the revert armed first.
- Making a WireGuard private key anywhere but on the machine that uses
  it, printing one, or writing one into a file keel renders; removing an
  overlay the spec no longer declares; loading a kernel module.
- Touching the conf when a populated one exists, or anything at all with
  `--dry-run`.

## The first boot

The conf phase runs at hook `00declarative`, which renders the description
into the conf every later hook reads. The system phase runs at
`10keel-system`, the hook this package ships into
`/usr/lib/inithooks/firstboot.d`:

```
00declarative     the conf phase: keel renders the description
01ipconfig        the address
09hostname        /etc/hostname, and a sed over the old name in /etc/hosts
10keel-system     the system phase: keel spec apply --system-only
                  --defer-certificate --skip-network
15regen-sslcert   the certificate, on the name settled above
29, 30 ...        the init fence, the root password
```

Position 10 is the one place it fits. Earlier than `09hostname` and the
`sed` that hook runs over the old name would edit or lose the `/etc/hosts`
entry; later than 29 and the certificate and the init fence would be made
on a name the appliance does not yet carry. It asks for `--system-only`
because the conf phase has already run at position 00 and must not run
again: see above for what a second run would do to a generated password.

`security.alerts` is converged here too, which is earlier than the
upstream `85secalerts` hook that used to be the only writer. The two agree
and the order is harmless: hook 10 writes the root alias and the cron-apt
mail settings from the description, and hook 85 reads the same address
from the conf phase's `SEC_ALERTS` and replaces the `root:` line in place
with the same value (its `sed` is idempotent). What hook 85 adds and this
phase never does is register the address with the TurnKey Hub; cutting
that call out of the hook is the Hub decoupling of brief section 5.6, not
part of this converge. A description that declares `skip` makes hook 85
exit at once, and hook 10 has already left no external alias.

The package that owns the `keel` command owns the hook that runs it, so
inithooks keeps no dependency on keel, and an image without keel simply has
no hook there.

The hook exits 0 and converges nothing when:

- `_TURNKEY_INIT` is set, because `turnkey-init` is an interactive run and
  the operator's answers must not be overruled by a file;
- there is no description: `INITHOOKS_DECL` names one outright, otherwise
  `/etc/keel/instance.yaml` and then `/etc/inithooks.yaml` are looked for,
  the same two paths in the same order that `00declarative` searches;
- the description declares nothing this phase converges, which the library
  says in one line rather than printing an empty plan.

Every line of the command's output is logged through the inithooks log
(`logger -t inithooks` and `$INITHOOKS_LOGFILE`), as the other hooks log,
prefixed with the hook name. A failure is logged with its exit code and
the boot carries on: the hook exits 0 whatever `keel` returned, because an
appliance that cannot converge one field must still finish booting, and
because the drift is then visible in `keel diff` where an operator can act
on it. The suite is `tests/hook.bats`, run inside the one gate job by
`tests/test_hook_bats.py`.

## From the library

confconsole calls the command function, as for phase 1, and passes the
extra attributes; a Namespace without them gets phase 1 only:

```python
from argparse import Namespace

from keel import commands, exits

args = Namespace(
    spec="/etc/keel/instance.yaml",
    conf="/etc/inithooks.conf",
    non_interactive=True,
    system=True,
    system_only=False,
    dry_run=False,
    root="/",
)
code = commands.spec_apply(args)
if code != exits.OK:
    show_error(exits.DESCRIPTIONS[code])
```

## Tests

`tests/test_system_plan.py` covers the readers of passwd and group, the
observed state (offline and live, with `locale -a` and the command lookup
replaced), the root check and every branch of the three planners with hand
built states and the fixture trees. `tests/test_system_execute.py` covers
the effects against a temporary root with `subprocess.run` replaced, and
the executor with a fake effects object. `tests/test_apply_system_cli.py`
runs the command end to end, including every `--system-only` path (the
conf left alone, no secret resolved, the empty plan, the refusals): `useradd` and `usermod` are replaced at the
subprocess boundary by a fake that edits the scratch tree's passwd and
group files as the real commands would under `--root`; everything else is
written for real under a temporary root and read back by `keel inspect`
and `keel diff`. No test needs root or touches `/`.

The monitor has its own files. `tests/test_monitor_render.py` checks the
mount filter, the rendered file and its reading back, and walks warn,
critical, warn, ok on one filesystem the way monit plays it, one state per
service; when a monit binary is on `PATH` or named by `KEEL_MONIT`, it also
gives the rendered file to `monit -t`. `tests/test_system_monitor.py`
covers the planner, `tests/test_apply_monitor_cli.py` the round trip
through `keel diff`, and `tests/test_monitor_notify.py` sends every channel
to an HTTPS server on `[::1]` with a certificate made for the run, and
checks that no token reaches what `keel notify` prints.

The overlay has its own files too. `tests/test_spec_overlay.py` covers
the fields, `tests/test_system_overlay.py` the planner and its state,
`tests/test_network_overlay_window.py` the wg-quick sequence, its revert
(a first overlay removed, a changed one restored, the boot revert) and
which sessions confirm, and `tests/test_inspect_overlay.py` the file read
back and compared by `keel diff`. The mocked command boundary once hid
real defects, so `tests/test_network_wireguard.py` hands keel's output to
the real tools when they are at hand (`wireguard-tools` on `PATH`, or
its directory in `KEEL_WG_DIR`; CI installs it, and fails rather than
skips without it): the key pair is made and read by `wg genkey` and `wg
pubkey`, the rendered file is parsed by `wg-quick strip` and brought up
by `wg-quick up` in a network namespace of its own (`unshare -n` as root,
`unshare -rn`, or `sudo -n`), where `wg show` must report the declared
key, port, peers, endpoints, allowed IPs and keepalive.
