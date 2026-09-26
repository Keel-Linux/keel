# keel inspect

`keel inspect` writes an instance spec from a machine and reports, field
by field, where each value came from or why it could not be inferred
(brief section 5.2). It is the first half of the transition from TurnKey
19.0 (brief section 7): inspect on the old machine, apply on a fresh
container, and the service comes back.

It is read only, needs no root for most of what it reads, and never
reads a secret. `keel diff` ([docs/diff.md](diff.md)) compares a spec
with a machine through this same collector, so every source named below
is also what diff observes.

```
keel inspect
keel inspect --output /etc/keel/instance.yaml --report inspect.txt
keel inspect --root /mnt/old-appliance --secrets-dir /etc/keel/secrets
```

| Option | Meaning |
| --- | --- |
| `--root DIR` | The filesystem to inspect. Default `/`, the live system. Any other directory is treated as an offline root: a mounted container filesystem, or the tree `keel assemble` produced |
| `--output FILE` | Write the spec here, mode 0600. Default: stdout |
| `--report FILE` | Write the report here. Default: stderr |
| `--secrets-dir DIR` | Where the secret placeholders point. Default `/etc/keel/secrets`. Nothing is read from or written to it |

## Exit codes

| Code | Name | When |
| --- | --- | --- |
| 0 | `OK` | Every required field was inferred |
| 5 | `CONF_ERROR` | `--output` or `--report` could not be written |
| 13 | `INSPECT_INCOMPLETE` | A required field could not be inferred. The spec was written all the same, with what was found, so the operator edits it instead of starting from scratch |

The required fields are the ones whose first boot hook prompts when its
variable is unset, so a spec without them cannot be applied headless:
`instance.hostname`, `instance.fqdn`, `network.interfaces`,
`security.alerts` and `security.updates`. Every other gap is reported
and leaves the exit code alone.

## What is inferred, and from where

Paths are relative to `--root`. When a file is absent or cannot be read,
the report says so and names the file; `permission denied (root only)`
means running as root would have read it.

| Spec field | Source | Notes |
| --- | --- | --- |
| Appliance (header comment only) | `/etc/turnkey_version` | `turnkey-<name>-<version>-<codename>-<arch>`, hyphenated names included |
| `instance.hostname` | `/etc/hostname` | First word of the first line |
| `instance.fqdn` | `/etc/hosts`, then `hostname -f`, then `/etc/hostname` | The dotted name on the `/etc/hosts` line that names the host. `hostname -f` runs only on the live root, never on an offline tree. A dotted `/etc/hostname` is its own fqdn |
| `network.interfaces.<name>.ipv6` | `/etc/network/interfaces` and `/etc/network/interfaces.d/*` | `iface <name> inet6 <method>` stanzas: `static` (with `address`, a `netmask` prefix length when the address has none, and `gateway`), `dhcp`, `auto`, `manual`. Any other method (`v4tunnel`, `6to4`) is reported as having no spec equivalent |
| `network.interfaces.<name>.ipv4` | same files | `inet` stanzas: `static` (a dotted `netmask` becomes a prefix length), `dhcp`, `manual`. `lo` is skipped |
| `network.managed_by` | the LXC marker `/var/lib/turnkey-info/inithooks.service/lxc`, or the stanzas | `host` when the marker exists or any static IPv6 address was found, because `apply` cannot write a static IPv6 address to a file yet (docs/spec.md); `file` otherwise |
| `network.nameservers` | `/etc/resolv.conf` and `dns-nameservers` options | Deduplicated, IPv6 first. A loopback resolver (`127.0.0.53`, `::1`) is reported, not recorded: the upstream servers are not visible in the file |
| `tls.acme.*` | `/etc/dehydrated/confconsole.domains.txt`, else `/etc/dehydrated/domains.txt`; `/etc/dehydrated/confconsole.config` | The files confconsole's Let's Encrypt plugin writes. `enabled: true` with the domains when a domains file has any; `challenge` from `CHALLENGETYPE`, defaulting to `http-01` as dehydrated does. No `/etc/dehydrated`, or no domains, gives `enabled: false` |
| `app.email`, `app.domain`, `app.options.*` | `/etc/inithooks.conf` | Root only, and often gone after the first boot. `APP_EMAIL`, `APP_DOMAIN` and every other `APP_*` variable except `APP_PASS`. Without a conf, `app.domain` falls back to `instance.fqdn` and `app.email` is reported as not inferred |
| `security.alerts` | `/etc/inithooks.conf`, else `/etc/aliases`, else `/etc/cron-apt/config` | The secalerts hook writes a `root:` alias with the address and sets `MAILON=output`. An external root alias is the address; `MAILON=never`, or an aliases file without one, means `skip` |
| `security.updates` | `/etc/inithooks.conf`, else `/etc/cron-apt/action.d/5-install`, else `/etc/apt/apt.conf.d/20auto-upgrades` | A cron-apt install action or `Unattended-Upgrade "1"` means `force`; nothing configured means `skip` |
| `users.<name>.authorized_keys` | `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` | Public key lines only, with any leading options (`no-pty`, `from=`) removed. Users without a readable file with at least one key are left out |
| `locale.timezone` | `/etc/timezone`, else the `/etc/localtime` symlink | The zone name after `zoneinfo/` in the link target, so an offline tree works without following the link |
| `locale.lang` | `/etc/default/locale` | `LANG` only |
| `hub.api_key` | nothing | Always `skip`: keys are never read, and the Hub is being decoupled (brief section 5.6) |

`users` and `locale` are accepted by the spec and validated, but nothing
applies them yet; `apply` warns about them (docs/spec.md).

## What is never inferred

Secret values. `inspect` never reads a password, a hash or an API key,
not from `/etc/shadow`, not from an application config, and not from an
`inithooks.conf` it could open. Every secret the appliance needs is
declared by reference:

```yaml
secrets:
  root_password:
    file: /etc/keel/secrets/root_password
  db_password:
    file: /etc/keel/secrets/db_password
```

with a report line per secret saying the value was not extracted.
`root_password` is always declared; `db_password` when `/etc/mysql` or
`/etc/postgresql` exists or the conf sets `DB_PASS`; `app_password` when
the conf sets `APP_PASS`. The operator creates those files (mode 0600,
owned by root) before `apply`; until then `keel spec validate` reports
each missing file, which is the intended reminder.

Live state that is not configuration is also left out: the addresses a
DHCP or SLAAC interface holds right now, running services, installed
packages (that is `keel verify`).

## The report

One line per field, then a summary:

```
instance.hostname: blog (from /etc/hostname)
instance.fqdn: blog.example.org (from /etc/hosts)
network.interfaces.eth0.ipv6: static 2001:db8:1::10/64 gateway fe80::1 (from /etc/network/interfaces)
network.managed_by: host (from a static IPv6 address cannot be written by apply yet)
secrets.root_password: file: /etc/keel/secrets/root_password (not extracted: values are never read; create the file (mode 0600) before apply)
app.email: not inferred: /etc/inithooks.conf not present
inspect: 20 inferred, 1 not inferred (0 required), 2 secrets to provide; spec complete
```

The spec itself starts with a comment naming the root it was read from
and the appliance found there.

## Offline use

`--root DIR` reads every path under `DIR` instead of `/`, and skips the
one command (`hostname -f`) that would describe the machine running
inspect rather than the tree. That is how the transition test bench uses
it: mount the old appliance's filesystem, or point at the tree
`keel assemble --rootfs DIR` produced, inspect it, then `apply` the
result in a fresh container.

```
keel assemble core --rootfs /var/tmp/core.rootfs
keel inspect --root /var/tmp/core.rootfs --output core.yaml
```

An assembled tree has no `/etc/hostname` content of its own and no
`inithooks.conf`, so the exit code is 13 and the report lists exactly
what the first boot would have asked.

## Tests

`tests/fixtures/inspect/` holds three trees: `turnkey` (a WordPress like
appliance with a static IPv6 address, dehydrated with `dns-01`, cron-apt,
two users with keys), `dhcp` (a Core container with DHCP on both
families, sourced `interfaces.d`, a readable `inithooks.conf` and a
`localtime` symlink) and `missing` (almost empty). Every probe is tested
as a pure function in `tests/test_inspect_probes.py`; the reader, the
collector, the exit codes and the round trip through `spec validate` and
`spec render` are in `tests/test_inspect_cli.py`.
