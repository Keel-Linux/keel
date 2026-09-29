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
that describe system state rather than hook input: `instance.fqdn`, `users`,
`locale` and `security.alerts`. With `--system-only` it converges them and does nothing
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
| `--destroy-local-database` | Confirm, for this run only, that making this node a replica may drop the databases this server holds. Without it apply refuses and changes nothing. See "database.server" below |

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
MariaDB has for it, so the preferred `2804:710:d0:5::/64` becomes
`2804:710:d0:5:%` (`keel.spec.origins`). An origin the description no
longer names has its account dropped, because `inspect` reads the
authorizations off the server and one left behind would drift for ever.
A prefix that stops inside a group, a `/56`, is refused: authorizing a
wider or a narrower range than the description asked for is not a
decision apply makes. `allowed_from` absent, as against empty, leaves the
server's authorizations alone.

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
database.server: write /etc/mysql/mariadb.conf.d/99-keel-database.cnf: replica, server id 1857420371: done
database.server: restart the server, which is the only way these take effect (systemctl restart mariadb): done
database.server.replication.primary: refused: becoming a replica replaces the local database with a copy of the primary, and this server holds 1 database(s) that are not its own (wordpress). Nothing was changed. Move the data elsewhere, or run the same command again with --destroy-local-database to drop them and build the replica
apply --system-only: 2 change(s), 1 failed
```

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
- The hostname itself: `/etc/hostname` is `09hostname`'s, from the
  `HOSTNAME` variable phase 1 writes. This phase only adds the fully
  qualified name to `/etc/hosts`.
- Generating a locale for a tree other than the live system.
- Installing a package. A description that declares a database server on
  a machine with none is a refusal, not an installation.
- Anything to the database under `--root DIR`: the server of an offline
  root is another machine's, and a statement sent here would reach the
  wrong one.
- Anything at all to `database.client`: where an application reaches a
  database is the application's own configuration.
- Registering an alerts address with hub.turnkeylinux.org, which the
  first boot hook does: the Hub is one optional backend (brief section
  5.6), and a converge that ran on every apply would subscribe the machine
  to somebody else's service each time.
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
15regen-sslcert   the certificate, on the name settled above
29, 30 ...        the init fence, the root password
```

Position 10 is the one place it fits. Earlier than `09hostname` and the
`sed` that hook runs over the old name would edit or lose the `/etc/hosts`
entry; later than 29 and the certificate and the init fence would be made
on a name the appliance does not yet carry. It asks for `--system-only`
because the conf phase has already run at position 00 and must not run
again: see above for what a second run would do to a generated password.

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
