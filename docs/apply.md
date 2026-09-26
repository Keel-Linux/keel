# keel spec apply

`apply` is the converge operation of brief section 5.2, under principle 1
of section 4: it converges and is safe to re-run. It has two phases. The
first has been there from the start and is unchanged; the second is new
and runs only when asked for with `--system`. Every example uses IPv6.

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

## Phase 2: the system (`--system`)

```
keel spec apply --system
keel spec apply --system --dry-run
keel spec apply --system --root /mnt/rootfs
```

With `--system`, after the conf, `apply` converges the parts of the spec
that describe system state rather than hook input: `users` and `locale`.
The flag is off by default in this version. It becomes the default when
the first-boot hook (`00declarative` in inithooks) calls it, at which point
this document is updated.

The phase is built as brief section 6 and decision 0003 ask: the state is
read once (`keel.system.state`), the plan is a pure function of the spec
and that state (`keel.system.plan`, `users`, `locale`), and one small
module (`keel.system.effects`) is the only code that runs a command or
writes a file. Commands are run with argv lists, never through a shell.
Every decision is unit tested against fixture trees under `--root`,
exactly as `inspect` is.

### Options

| Option | Meaning |
| --- | --- |
| `--system` | Run phase 2 after phase 1. Root on the live system (exit 15 otherwise) |
| `--dry-run` | With `--system`: print the plan and change nothing, not even the conf. Reads no secret, so the secret files need not exist. Needs no root |
| `--root DIR` | The filesystem phase 2 converges: `/` (the default, the live system) or a scratch tree. Phase 1 is not affected; the conf path is `--conf` |

`--dry-run` without `--system` is a usage error (exit 1): phase 1 has
`spec render` for that.

### What is converged

Only what differs from the observed state is planned, so a second run
finds nothing to do. Every action prints one line, `field: action: done`,
and a dry run prints `field: would action`.

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
dry run: 9 change(s) planned, nothing written
```

Run for real, then run again, and the second run prints `unchanged` on
every line and `apply --system: 0 change(s), 0 failed`. `keel diff --spec
blog.yaml --root /tmp/scratch` then reports every `users` and `locale`
field as `same`: that round trip is a test
(`tests/test_apply_system_cli.py`, `TestRoundTrip`).

### What is never done

- Passwords: not read, not set, not hashed. `ROOT_PASS` and friends stay
  with phase 1 and the hooks.
- Deletions: no account, group membership, key file or home is removed.
  A key not in the spec disappears from `authorized_keys` only because the
  file is rewritten as declared.
- Creating groups, or anything about a user beyond shell, groups and keys.
- Generating a locale for a tree other than the live system.
- Touching the conf when a populated one exists, or anything at all with
  `--dry-run`.

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
replaced), the root check and every branch of the two planners with hand
built states and the fixture trees. `tests/test_system_execute.py` covers
the effects against a temporary root with `subprocess.run` replaced, and
the executor with a fake effects object. `tests/test_apply_system_cli.py`
runs the command end to end: `useradd` and `usermod` are replaced at the
subprocess boundary by a fake that edits the scratch tree's passwd and
group files as the real commands would under `--root`; everything else is
written for real under a temporary root and read back by `keel inspect`
and `keel diff`. No test needs root or touches `/`.
