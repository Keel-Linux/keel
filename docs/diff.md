# keel diff

`keel diff` reports drift between the declared spec and the machine,
field by field (brief section 5.2). The declared side is the spec file,
loaded and validated exactly as `spec apply` reads it. The observed side
is what `keel inspect` collects, through the same collector and the same
probes, so there is one code path for reading a machine and a spec
written by inspect diffs clean against the machine it was read from.

It is read only: nothing is written to the system, to the spec or
anywhere else. Secrets are never read, on either side, and the secret
files the spec names are not required to exist: the spec is validated
with `check_secret_files=False`, so the structure of every secret
reference is checked (exactly one backend, a path that is a string) but
not the file behind it. A secret is a reference, and the machine being
compared may not hold the value; a spec fresh from `keel inspect` never
does.

```
keel diff
keel diff --spec /etc/keel/instance.yaml --format json
keel diff --root /mnt/old-appliance --spec old.yaml
```

| Option | Meaning |
| --- | --- |
| `--spec FILE` | The declared side. Default: `$KEEL_SPEC`, else `/etc/keel/instance.yaml`. An absent file is a no-op that exits 0, like every other command |
| `--root DIR` | The observed side. Default `/`, the live system. Any other directory is an offline root: a mounted container filesystem, or the tree `keel assemble` produced |
| `--format text` | One line per field, in spec order, then a summary line. The default |
| `--format json` | One JSON document with the same content, for a calling program such as confconsole |

## Exit codes

| Code | Name | When |
| --- | --- | --- |
| 0 | `OK` | Every declared field that inspect can observe has the same value on the machine |
| 2 | `SPEC_UNREADABLE` | The spec cannot be read or is not valid YAML |
| 3 | `SPEC_INVALID` | The spec fails validation; every error is printed, nothing is inspected. A secret file that does not exist is not such an error for `diff` (see above); a malformed secret reference is |
| 13 | `INSPECT_INCOMPLETE` | No drift, but at least one declared field could not be observed; the line says why, in inspect's words |
| 14 | `DRIFT_FOUND` | At least one declared field has a different value on the machine |

Precedence: the spec is checked first, so 2 and 3 are returned before
anything is inspected. Then drift wins over unknown fields: a report with
drifted and unknown fields exits 14, because the drift is what the
operator acts on, and the unknown fields are listed in the same output.
Only when nothing drifted does an unknown declared field make the code
13. Fields the spec does not declare never change the code.

## The four verdicts

Every field of the declared spec that inspect can observe gets one line:

| Status | Meaning | Exit code |
| --- | --- | --- |
| `same` | The declared and observed values are equal after normalisation | unchanged |
| `drift` | The values differ, or the spec declares a value and the machine has none where inspect looked | 14 |
| `unknown` | inspect could not infer the field; the line carries inspect's reason, for example `/etc/hostname file is empty` or `permission denied (root only)` | 13 |
| `not declared` | The machine has a value the spec is silent about; listed so the operator sees it, never counted as drift | unchanged |

A fifth line describes what is deliberately not compared: `not compared`,
with the reason. It covers a whole section whose values leave no trace,
and the settings of a feature the spec turns off.

```
instance.hostname: same (blog)
instance.fqdn: drift (declared blog.example.org, observed shop.example.org)
network.managed_by: same (file)
network.interfaces.eth0.ipv6.method: same (static)
network.interfaces.eth0.ipv6.address: same (2001:db8:1::10/64)
network.interfaces.eth0.ipv6.gateway: same (fe80::1)
network.interfaces.eth0.ipv4.method: not declared (observed dhcp)
network.nameservers: same (2001:db8:1::53, 2001:db8:1::54)
tls.acme.enabled: same (true)
tls.acme.challenge: same (dns-01)
tls.acme.domains: same (blog.example.org)
secrets: not compared (values are never read, on either side)
hub.api_key: same (skip)
security.alerts: same (admin@example.org)
security.updates_at_first_boot: not compared (a first boot input: 95secupdates installs the pending security updates once, and the appliance's update schedule, which is what the machine shows, is the same whichever value was used)
locale.timezone: same (Europe/Lisbon)
diff: 12 same, 1 drift, 0 unknown, 1 not declared, 2 not compared; drift found
```

## What is compared, and against what

The sections inspect observes are compared: `instance`, `network`, `tls`,
`security`, `hub`, `users`, `locale`, `database` and `monitor`. Each is flattened to the dotted
leaf paths the inspect report uses, so `network.interfaces.eth0.ipv6`
becomes one line per `method`, `address` and `gateway`, and a list
(`network.nameservers`, `tls.acme.domains`, `users.<name>.authorized_keys`)
is one leaf compared as a sequence, in order, except `users.<name>.groups`,
which is a membership and compares as a set. The sources of every observed
value are in [docs/inspect.md](inspect.md).

A field inspect wrote is compared as it stands, even when inspect also
noted something about that field it could not express (a `v4tunnel`
stanza next to a `dhcp` one, a loopback resolver next to real ones). That
is what makes the round trip hold. A field inspect could not infer at all
is `unknown`, never `drift`, and `network.managed_by` is unknown whenever
the interfaces are, because inspect derives one from the other.

Normalisation, so that spelling is not drift: keywords (`security.alerts`,
`security.updates_at_first_boot`, `hub.api_key`) and domain names (`hostname`, `fqdn`,
`tls.acme.domains`) compare case insensitively and without a trailing dot;
addresses, gateways and nameservers compare in canonical form
(`2001:DB8:0001::10/64` equals `2001:db8:1::10/64`); booleans compare as
booleans; the thresholds under `monitor.checks` compare as numbers, so
`2.0` equals `2`. Everything else compares as a stripped string.

Not compared, each with its reason in the output when the spec declares
it:

| Section | Why |
| --- | --- |
| `secrets` | Values are never read, on either side. A `hub.api_key` given as a secret reference is not compared for the same reason |
| `app` | `inithooks.conf` is root only and consumed at first boot, so `app` values leave no trace to compare against; inspect's `app.domain` falls back to the fqdn, which would be a false drift |
| `first_login_wizard`, `preseed` | Render time switches with no trace on the running machine |
| `tls.acme.agree_tos` | Consent the spec gives apply to register a Let's Encrypt account; the machine keeps a record of the account, not of the consent |
| `security.updates_at_first_boot` | A first boot input: the `95secupdates` hook installs the pending security updates once and leaves nothing behind, and the cron-apt schedule the machine does show is shipped with the image whichever value was used. inspect writes the field from that schedule so the spec it produces is applicable, and says in the report that it is a proxy ([docs/inspect.md](inspect.md)) |
| `monitor.notify` | The channels: a webhook or ntfy topic URL can be a credential, so diff neither compares them nor repeats their values, not even as `declared` in its JSON. apply writes them to `/etc/keel/monitor.json`, root only, for `keel notify`. `monitor.enabled` and the checks are compared, read back from `/etc/monit/conf.d/keel.conf` at the cycle monit runs at; like `tls.acme`, the checks are not compared while `monitor.enabled` is false or absent |

`version` is a property of the file, not of the machine, and is not
listed.

### A feature the spec turns off

`tls.acme.enabled: false` with `challenge` and `domains` below it is a
valid and useful spec: the operator has prepared the certificate
configuration and has not turned it on yet, because the name has no DNS
record, or the machine is not reachable, or the proxy in front still
terminates TLS. Those settings describe nothing the machine is supposed
to carry, so comparing them reported drift on a spec that was correct:

```
tls.acme.challenge: drift (declared http-01, observed nothing)
tls.acme.domains: drift (declared forum2.keellinux.org, observed nothing)
```

Diff now compares the switch and nothing else it governs:

```
tls.acme.enabled: same (false)
tls.acme.challenge: not compared (tls.acme is off in the spec (enabled is false), so what it governs is not compared; it takes effect when enabled becomes true)
tls.acme.domains: not compared (tls.acme is off in the spec (enabled is false), so what it governs is not compared; it takes effect when enabled becomes true)
```

The switch itself is always compared, so a machine that has ACME running
behind the spec's back is still drift. `enabled` absent counts as off,
the same way `apply` reads it. The alternative, a schema that refuses
`domains` while ACME is disabled, was rejected: it would force the
operator to write the domains and turn the feature on in the same edit,
which is exactly the change that should be reviewable on its own.

### A field the system phase converges

`instance.fqdn` is the first field `apply` writes and `diff` reads back
(`--system`, `--system-only`, [docs/apply.md](apply.md)). It stays an
ordinary compared field, with the ordinary verdicts, and it is deliberately
not in the table above.

What makes a boot end at exit 0 is that something writes the field, not
that `diff` stopped asking. The hook `10keel-system` runs the system phase
after `09hostname`, so `/etc/hosts` carries the declared name before the
first `diff` an operator ever runs, and the round trip closes without
anybody running `apply` by hand.

Excusing the field from the comparison would have cost the one signal that
the converge happened. `not compared` would read the same on an appliance
that applied its description, on an image too old to carry the hook, and on
a machine where somebody edited `/etc/hosts` afterwards. The rule for that
table is about the machine and not about who writes the value: a field is
`not compared` when the machine keeps no trace of it (`secrets`, `app`,
`preseed`, `security.updates_at_first_boot`) or when the spec turns off the
feature that governs it. A converged field leaves exactly the trace `apply`
wrote, and `apply` asks the reader `inspect` uses before writing it
(`keel.inspect.hostname.fqdn_in_hosts`), so the two sides cannot disagree
about spelling or placement: `same` is reachable and stays.

| On the machine | diff reports | Exit |
| --- | --- | --- |
| The boot ran the hook, or an operator ran `apply --system` | `same` | 0 |
| The value was changed afterwards, in the file or in the spec | `drift` | 14 |
| No trace at all: an image with no hook, and `apply` never run, or an entry another `/etc/hosts` line answers before | `unknown`, and the reason names what writes the field | 13 |

The third row is what an operator meets on an image that predates the hook,
so the reason says so rather than only listing what was checked. It is also
what a shadowed entry reports: the observed side reads `/etc/hosts` the way
a resolver does, from the first line that carries the name, so a file whose
fully qualified entry stands behind a `127.0.1.1 blog` line is not reported
as `same` while `hostname -f` answers `blog`
([docs/inspect.md](inspect.md)).

```
instance.fqdn: unknown (declared blog.example.org; not inferred: /etc/hosts has no fully qualified name for blog; hostname -f not run: the root is not the live system; the system phase of apply writes it (spec apply --system-only))
```

The loop is a test: `tests/test_apply_system_cli.py`, `TestBootThenDiff`,
puts a fixture tree in the state `09hostname` leaves, diffs it (`unknown`,
exit 13, with that reason), runs the system phase, and diffs again
(`same`, exit 0), then checks that editing the file behind the spec is
`drift` and not an excused field.

## The database section

Compared like every other observed section, with three rules of its own.

### A declared replica against an observed primary is never corrected

Demoting a primary destroys data: everything written to it since the replica
last agreed with it is gone, and no amount of care in the code can get it back.
So this drift, and its mirror image, carry a warning on the line and are stated
here as a rule of the project and not of one function:

```
database.server.role: drift (declared replica, observed primary; never correct this automatically: the machine is a primary and demoting one destroys the data written to it since the replica last agreed. Demotion is an operator action)
database.server.role: drift (declared primary, observed replica; never correct this automatically: promoting a replica splits the pair into two writable servers unless the old primary is known to be gone. Promotion is an operator action)
```

**No command in this project may change the role of a database server to make
this line go away.** `keel diff` writes nothing anywhere, which is what makes
saying so cheap today; the rule is written down because the phase that *does*
configure replication comes next (decision 0013, phase 3), and the convergence
it brings must leave promotion and demotion where they belong, which is with
the operator. The most common way to meet this drift is a promotion that
already happened, after a primary failed: the machine is right and the
description is out of date, and editing the description is the correction.

The `note` is carried in the JSON document as well, so a caller such as
confconsole shows the warning without reproducing it.

### A field the declared role has no use for is not compared

A standalone may carry the authorizations it will need as a primary, and a
primary may carry the endpoint it would replicate from after a demotion. Both
are a change prepared before it is made, the same case as a certificate
configuration behind `tls.acme.enabled: false`, and the machine is not supposed
to carry either meanwhile:

```
database.server.role: same (standalone)
database.server.replication.allowed_from: not compared (the declared role is standalone, so this field describes nothing; it is compared when the role is primary)
```

The role itself is always compared, so a machine that became a primary behind
the description's back is still drift.

Where the declared role and the observed role disagree, the role line carries
the drift and the field it governs is `unknown`, with `inspect`'s reason naming
the role the machine is actually in. One fact produces one drift line.

### Origins and addresses compare as sets, and a name is never resolved

`database.server.listen` and `database.server.replication.allowed_from` are
sets: order carries no meaning, and `2001:0DB8:1::/64` equals `2001:db8:1::/64`.

**A prefix and the host pattern MariaDB holds for it are one origin.**
`2804:710:d0:5::/64` and `2804:710:d0:5:%` authorize the same range, and the
second is the only spelling that engine has for it ([docs/spec.md](spec.md)).
So an origin is compared as the prefix it names, counting a group aligned
pattern out at sixteen bits a group. Without that, the form docs/spec.md tells
an operator to prefer would report drift on every MariaDB primary, which would
make the preferred form unusable. A pattern that stops inside a group, or that
names a wider range than the description asked for, is drift as before.

A name in `allowed_from` is compared as a name, lower cased and without a
trailing dot, and **is never resolved**. An authorization that names a host and
a server that holds an address are two different things. MariaDB resolves the
`Host` of a grant and `pg_hba` reverse resolves the client address, both fail
quietly, and a diff that resolved the declared name before comparing would
report `same` for an authorization that matches nothing at all
([docs/spec.md](spec.md)).

### The rest of the section

| Field | Compared against |
| --- | --- |
| `database.server.engine` | the server binary that is installed |
| `database.server.role` | what the server says it is |
| `database.server.listen` | the sockets the machine holds open on that server's port |
| `database.server.replication.primary.*` | the primary the server says it replicates from, when the declared role is `replica` |
| `database.server.replication.allowed_from` | the origins the server holds an authorization for, when the declared role is `primary` |
| `database.server.replication.secret`, `database.client.primary.secret` | not compared: a reference whose value is never read, on either side |
| `database.client.engine`, `database.client.primary.*` | the application's own configuration |
| `database.client.replicas` | `unknown`: no application configuration `inspect` reads expresses a read endpoint ([docs/inspect.md](inspect.md)) |

A machine where the server is installed and could not be asked reports the
whole of `database.server` as `unknown`, with the reason naming the engine, the
binary and the command that failed, so an offline root and a stopped service
are never read as drift. A machine with no database server at all reports
nothing, so a description that declares one **is** drift against it, which is
the true statement: there is no server there.

## JSON

`--format json` prints one document to stdout:

```json
{
  "spec": "/etc/keel/instance.yaml",
  "root": "/",
  "fields": [
    {
      "field": "instance.hostname",
      "section": "instance",
      "status": "same",
      "declared": "blog",
      "observed": "blog",
      "reason": "",
      "note": ""
    },
    {
      "field": "security.alerts",
      "section": "security",
      "status": "unknown",
      "declared": "admin@example.org",
      "observed": null,
      "reason": "/etc/aliases permission denied (root only)",
      "note": ""
    }
  ],
  "counts": {"same": 1, "drift": 0, "unknown": 1, "not_declared": 0, "not_compared": 0},
  "drift": false,
  "incomplete": true,
  "exit_code": 13
}
```

`declared` and `observed` are the values as the spec and inspect hold
them (a string, a boolean, a list), `null` when absent. `note` is the
warning a drift line carries where acting on it the wrong way round would
destroy something; it is empty everywhere else. `exit_code` is the
code the command returns, so a caller shows the right message without
reproducing the precedence rule. From Python, confconsole calls the same
function the CLI does:

```python
from keel import diff, spec

comparison = diff.diff_root(spec.load("/etc/keel/instance.yaml"))
for field in comparison.fields:
    show(field.line())
code = comparison.code
```

## Inspect, then diff

`keel inspect --output FILE` followed by `keel diff --spec FILE` on the
same machine exits 0 with no drift and no unknown field, and does so on
a machine where the secret files the spec names have never been created.
A spec fresh from inspect declares every secret as a placeholder:

```
$ keel inspect --root /mnt/old-appliance --output old.yaml --report old.txt
$ grep -A1 root_password old.yaml
  root_password:
    file: /etc/keel/secrets/root_password
$ ls /etc/keel/secrets/root_password
ls: cannot access '/etc/keel/secrets/root_password': No such file or directory
$ keel diff --spec old.yaml --root /mnt/old-appliance
instance.hostname: same (blog)
instance.fqdn: same (blog.example.org)
network.managed_by: same (file)
network.interfaces.eth0.ipv6.method: same (static)
network.interfaces.eth0.ipv6.address: same (2001:db8:1::10/64)
network.interfaces.eth0.ipv6.gateway: same (fe80::1)
...
secrets: not compared (values are never read, on either side)
hub.api_key: same (skip)
...
diff: 22 same, 0 drift, 0 unknown, 0 not declared, 2 not compared; no drift
$ echo $?
0
```

`diff` does not require those files because it never compares their
values, so their absence is not drift and cannot be an error. `spec
apply`, which does read them, still refuses to run until they exist with
the right owner and mode, and `keel spec validate` still reports each
missing file unless it is given `--no-secret-files`
([docs/spec.md](spec.md)). That remains the intended reminder from
[docs/inspect.md](inspect.md); `diff` is simply not the command that
delivers it.

Whatever the tree, the round trip exits 0, or 13 when a field the spec
declares cannot be observed on the machine (a value the operator added by
hand to a spec inspect wrote from a tree with no `/etc/hostname`, say).
It never exits 3 because of a secret file.

## Tests

`tests/test_diff_database.py` covers the database section: the role, the
warning on the drift that must never be corrected, the fields another role
has no use for, and the set comparison that never resolves a name.
`tests/test_diff.py` covers the model and the comparison as pure
functions, one test per branch, and each observable section with a spec
that matches the `turnkey` fixture and one that drifts on that section.
`tests/test_diff_cli.py` covers the exit codes, their precedence, the
JSON document, the no-write guarantee, a missing secret file being no
error while a malformed reference still is, and the round trip: every
fixture tree under `tests/fixtures/inspect/` inspected into a spec and
diffed against itself reports no drift, no unknown field and exits 0,
with the secret placeholders pointing at files that do not exist.
