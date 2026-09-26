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
that describe system state rather than hook input: `instance.fqdn`, `users`
and `locale`. With `--system-only` it converges them and does nothing
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
| A line that names the host and carries the declared fully qualified name, at any address | `unchanged (/etc/hosts maps forum2 to forum2.keellinux.org)` |
| A line for the target address naming the host, such as the `127.0.1.1 forum2` that `09hostname` left | The line is replaced where it stood, so nothing resolves the short name ahead of the fully qualified one |
| No such line | The entry is appended |

The address is the static IPv6 address the spec declares for an interface
when it declares one, which is the Debian convention for a machine with a
permanent address, and `127.0.1.1` otherwise, because an address a router
hands out is a lease and must never be frozen into a file. A static IPv4
address alone does not carry the name: the family the appliance is reached
on is IPv6. Either way the entry is local resolution only; what the
appliance is reachable at is its global address.

Everything else in the file, comments and blank lines included, is kept as
it was, and the file is written mode 0644. Whether the entry is already
there is decided by the same reader `keel inspect` uses
(`keel.inspect.hostname.fqdn_in_hosts`), so what apply writes is what
inspect reads back and diff calls `same`.

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

### Failures and exit codes

A failed action fails its field: the actions after it in the same field
are skipped (the keys file of an account that could not be created is not
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
