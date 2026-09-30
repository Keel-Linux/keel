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
`security.alerts` and `security.updates_at_first_boot`. Every other gap is
reported and leaves the exit code alone.

## What is inferred, and from where

Paths are relative to `--root`. When a file is absent or cannot be read,
the report says so and names the file; `permission denied (root only)`
means running as root would have read it.

| Spec field | Source | Notes |
| --- | --- | --- |
| Appliance (header comment only) | `/etc/turnkey_version` | `turnkey-<name>-<version>-<codename>-<arch>`, hyphenated names included |
| `instance.hostname` | `/etc/hostname` | First word of the first line |
| `instance.fqdn` | `/etc/hosts`, then `hostname -f`, then `/etc/hostname` | The dotted name on the **first** `/etc/hosts` line that names the host, and nothing from any line after it, because that is the line a resolver answers from: where `127.0.1.1 blog` stands before `2001:db8:1::10 blog.example.org blog`, `hostname -f` answers `blog` and the field is not inferred from the file. `hostname -f` runs only on the live root, never on an offline tree. A dotted `/etc/hostname` is its own fqdn. An appliance out of the box has no such entry, because no upstream hook writes one; the system phase does, on a first boot from the hook `10keel-system` and otherwise from `keel spec apply --system` ([docs/apply.md](apply.md)). Where there is no entry, the reason says which command writes it |
| `network.interfaces.<name>.ipv6` | `/etc/network/interfaces` and `/etc/network/interfaces.d/*`, plus `ip -6 addr show` and the DHCPv6 lease files for an `inet6 dhcp` stanza | `iface <name> inet6 <method>` stanzas: `static` (with `address`, a `netmask` prefix length when the address has none, `gateway`, and `slaac`: `false` when the stanza has `pre-up sysctl ... net/ipv6/conf/<name>/autoconf=0` (the slash form inithooks writes for `slaac: false`; the dotted form is read too), `true` otherwise, reported for a static stanza only), `auto`, `manual`. An `inet6 dhcp` stanza stands for both `auto` and `dhcp`, so it is settled by the machine (see below) or reported as not inferred. Any other method (`v4tunnel`, `6to4`) is reported as having no spec equivalent |
| `network.interfaces.<name>.ipv4` | same files | `inet` stanzas: `static` (a dotted `netmask` becomes a prefix length), `dhcp`, `manual`. `lo` is skipped |
| `network.managed_by` | the LXC marker `/var/lib/turnkey-info/inithooks.service/lxc` | `host` when the marker exists, the container case; `file` otherwise, because the stanzas, static IPv6 included, are what the `01ipconfig` hook writes from the `IP_*` and `IP6_*` variables (docs/spec.md) |
| `network.overlay.wireguard.*` | `/etc/wireguard/*.conf` (`wg0.conf` first when there are several; the others are named in the report) | The file wg-quick reads: the interface from its name, `address` and `ipv4_address` from `Address`, `listen_port`, `private_key.file` from the `PostUp = wg set %i private-key PATH` line keel writes, and each `[Peer]`. Lines the spec has no field for (`DNS`, `MTU`, a preshared key) are named in the report, never dropped silently. A `PrivateKey` line is never read by inspect and is reported as inline: `apply --system` moves that key into the key file before it rewrites the file (docs/apply.md), so the node keeps its public key. The public key is reported beside the spec (not written into it, since it follows from the key): `wg pubkey` reads the key file as its standard input, so keel never holds the private key. On the live system, a `wireguard` kernel module that is not loaded is reported, with `modprobe wireguard` on the host for a container (decision 0018) |
| `network.nameservers` | `/etc/resolv.conf` and `dns-nameservers` options | Deduplicated, IPv6 first. A loopback resolver (`127.0.0.53`, `::1`) is reported, not recorded: the upstream servers are not visible in the file |
| `tls.acme.*` | `/etc/dehydrated/confconsole.domains.txt`, else `/etc/dehydrated/domains.txt`; `/etc/dehydrated/confconsole.config`; `/etc/ssl/private/cert.pem` | The domains and `challenge` (from `CHALLENGETYPE`, defaulting to `http-01` as dehydrated does) come from the files confconsole's Let's Encrypt plugin writes; they say what was asked for. `enabled` is what the machine serves: true only when the certificate in `cert.pem`, read with `openssl x509` on standard input (the first one that is not a CA, so a chain in either order works), is not self-signed (its own name as issuer and its own key as authority), has not expired and covers every configured domain (a wildcard covers one label). Otherwise false, with the reason, and the domains and challenge are kept so the spec written is a prepared one. A certificate that cannot be read or parsed leaves `enabled` not inferred. No `/etc/dehydrated`, or no domains, gives `enabled: false` |
| `app.email`, `app.domain`, `app.options.*` | `/etc/inithooks.conf` | Root only, and often gone after the first boot. `APP_EMAIL`, `APP_DOMAIN` and every other `APP_*` variable except `APP_PASS`. Without a conf, `app.domain` falls back to `instance.fqdn` and `app.email` is reported as not inferred |
| `security.alerts` | `/etc/aliases` and `/etc/cron-apt/config`, else `/etc/inithooks.conf` | The secalerts hook writes a `root:` alias with the address and sets `MAILON=output`. Whenever `/etc/aliases` can be read it answers: an external root alias is the address; `MAILON=never`, or no external alias, means `skip`. `SEC_ALERTS` in the conf is first boot input and is read only when the aliases file cannot be, since a conf left behind can be stale and `apply --system` converges the alias |
| `security.updates_at_first_boot` | `/etc/inithooks.conf`, else `/etc/cron-apt/action.d/5-install`, else `/etc/apt/apt.conf.d/20auto-upgrades` | `SEC_UPDATES` while the conf is still there is the value itself. Otherwise the appliance's update posture stands in for it: a cron-apt install action or `Unattended-Upgrade "1"` gives `force`, nothing configured gives `skip`, and the report says the first boot value leaves no trace. `keel diff` does not compare the field for that reason ([docs/diff.md](diff.md)) |
| `users.<name>.authorized_keys` | `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys` | Public key lines only, with any leading options (`no-pty`, `from=`) removed. Users without a readable file with at least one key are left out |
| `users.<name>.shell` | `/etc/passwd` | The shell column of the user's entry; not inferred when the file is unreadable or has no entry for the user |
| `users.<name>.groups` | `/etc/group` | The groups whose member list names the user, in file order; left out when there are none. Only the public columns of either file are read, never `/etc/shadow` |
| `locale.timezone` | `/etc/timezone`, else the `/etc/localtime` symlink | The zone name after `zoneinfo/` in the link target, so an offline tree works without following the link |
| `locale.lang` | `/etc/default/locale` | `LANG` only |
| `hub.api_key` | whether `/var/lib/tklbam/sub_apikey` exists (an `lstat`, the file is never opened), at the default registry and not one `TKLBAM_REGISTRY` moved | `skip` when the machine has no Hub registration. A machine registered with the TurnKey Hub leaves the field not inferred: keys are never read, so a key cannot be told from `skip`, and answering `skip` anyway made `diff` call it the same as one that never registered (brief section 5.6) |
| `database.server.*` | the server itself, over its own client: `mariadb`, `psql`, `redis-cli`, plus `ss -lntH` for the listen addresses | Only on the live root, and only when the engine's server binary is installed. What is asked of each engine, and what the answers mean, is in "The database section" below |
| `monitor.enabled`, `monitor.checks.*` | `/etc/monit/conf.d/keel.conf`, and monit's cycle from `/etc/monit/monitrc` and its includes | The file `apply --system` writes for monit (decision 0021), read from its `if` lines, which are what monit acts on: the thresholds, and `for_minutes` from `for N cycles` at monit's cycle, the last `set daemon` monit reads (Debian's 120 seconds when none is found). The minutes keel wrote in the comment above a test are given back while they still make that test's cycles at that cycle, and the cycles' own duration otherwise. Absent is `enabled: false`; a file keel did not write, or one that cannot be read (it is mode 0600, so without root), leaves the section not inferred. Filesystems that carry different thresholds leave that threshold not inferred. The file says what monit was told, not that monit is installed or running. `monitor.notify` is always not inferred: the channels are not in monit's file, and `/etc/keel/monitor.json`, where apply writes them for `keel notify`, is not read, since a URL there can be a credential. So the spec inspect writes for a monitored machine says `enabled: true` with no channel, which `spec validate` refuses until one is declared, as the report line says: the one place the operator has to add something before apply, like a secret file |
| `database.client.*` | the application's own configuration: `wp-config.php`, NodeBB's `config.json` | The one place the fact lives. No password is read from any of them |
| `appliance.name` | `/usr/share/keel/appliances/*.yaml` | The one installed appliance manifest that no other has as its `base`, the top of the chain (decision 0041). No appliance manifest, no section and no report line: a machine of before 0041. Several tops leave it not inferred |
| `installation.mode` | `/etc/keel/instance.yaml` | The spec the installer emitted: a machine's units do not say which mode chose them, so without that file the mode is not inferred |
| `overlays.<name>` | systemd: `systemctl is-enabled` and `is-active` on the live root; the `.wants` links under `/etc/systemd/system` of an offline one | For an overlay that owns units: `enabled` when every unit is enabled and, where it can be asked, runs; `disabled` when none is enabled and none runs; not inferred otherwise, naming each unit's state. An overlay that runs no unit (the installer, WireGuard) is read from `/etc/keel/instance.yaml`, as the mode is, and not inferred without it |
| `firewall.enabled` | `/etc/keel/firewall/keel-manifest.nft` | `true` when keel's ruleset is there, `false` otherwise, so a spec emitted again keeps the opt-in. Written whenever an appliance manifest is installed |

`users` and `locale` are the sections `keel spec apply --system` converges
([docs/apply.md](apply.md)); a spec inspect wrote applies clean into a
fresh tree and diffs clean against it afterwards.

### SLAAC or DHCPv6, for an `inet6 dhcp` stanza

ifupdown writes `iface <name> inet6 dhcp` for `method: auto` and for
`method: dhcp` alike, so the file settles nothing. The machine does:

| Evidence | Reported |
| --- | --- |
| A DHCPv6 lease file covering the interface: `/var/lib/dhcpcd/<name>.lease6`, `/var/lib/dhcp/dhclient6.<name>.leases`, or a plain `/var/lib/dhcp/dhclient6.leases`, holding anything | `dhcp`, from the lease file |
| No lease, and a global address marked `mngtmpaddr` in `ip -6 addr show`: the mark the kernel puts on an address whose prefix came from a router advertisement | `auto`, from the command |
| Both | `dhcp`, and the report says a router advertisement address is present as well |
| Neither | not inferred, naming the stanza, the state of the command and the lease paths that were searched |

`ip -6 addr show` runs only on the live root, like `hostname -f`; the lease
files are read under `--root` as well, because a lease is on disk. So an
offline root still reads a DHCPv6 machine as `dhcp`, and reports a SLAAC one
as not inferred rather than guessing.

## The database section: two readings, each on its own

A machine that runs a database server has a role; a machine that uses a
database has somewhere it reaches one. They are read independently. A machine
with no server installed reports nothing for `database.server`, a machine with
no application reports nothing for `database.client`, and a machine with both
reports both.

### The server side is asked, never read from a file

The role is what the server says it is. Reading it from a configuration file
would repeat the trap that shipped the PostgreSQL appliance listening on IPv4
only: the file read correctly and the service did something else
(docs/traps.md, "Asserting the configuration is not asserting the behaviour").

An engine counts as installed when its **server** binary is present, not when
its configuration directory is: `mysql-common` puts `/etc/mysql` on a machine
that holds the client alone.

| Engine | Installed when | Asked |
| --- | --- | --- |
| mariadb | `/usr/sbin/mariadbd` or `/usr/sbin/mysqld` | `SHOW REPLICA STATUS`, `SHOW REPLICA HOSTS`, `SHOW GLOBAL VARIABLES` for `wsrep_on` and `port`, and the `Host` of every account with `Repl_slave_priv` |
| postgresql | `/usr/lib/postgresql/*/bin/postgres` or `pg_ctl` | `pg_is_in_recovery()`, `pg_stat_replication`, `pg_stat_wal_receiver`, `primary_conninfo`, and `pg_hba_file_rules` for the `replication` pseudo database |
| redis | `/usr/bin/redis-server` | `INFO replication`, `INFO cluster`, `INFO server` |

Redis is the cleanest of the three and it set the standard rather than the SQL
engines lowering it: `role:master` or `role:slave` with `master_host` and
`master_port`, and `cluster_enabled` in one line. Each SQL engine is asked the
same question in its own words.

| Evidence | `database.server.role` |
| --- | --- |
| Redis `cluster_enabled:1`, or MariaDB `wsrep_on` `ON` | not inferred, naming the mode and saying the spec has no role for it yet |
| Redis `role:slave`, MariaDB a `SHOW REPLICA STATUS` row, PostgreSQL `pg_is_in_recovery()` true | `replica`, with `replication.primary` from the same answer |
| A replica is connected: Redis `connected_slaves` above zero, MariaDB `SHOW REPLICA HOSTS`, PostgreSQL a row in `pg_stat_replication` | `primary` |
| No replica connected, and the server holds an authorization: a MariaDB grant, or a `pg_hba` rule, from anywhere but this machine | `primary` |
| None of the above | `standalone` |

Two consequences worth stating, because they are visible in `keel diff`:

- **A primary whose replicas are all down still reads as a primary on the SQL
  engines**, because a grant and a `pg_hba` rule are durable records of who may
  replicate. **On Redis it reads as `standalone`**, because Redis keeps no such
  record at all; the report says exactly that, so the drift explains itself.
- **A server that is installed and cannot be asked reports the whole section as
  not inferred**, naming the engine, the binary that proved it and the command
  that failed. That is the same shape as an unreadable `/etc/network/interfaces`
  reporting `network.interfaces`, and it means every field under
  `database.server` is `unknown` to `keel diff` rather than drift. An offline
  root (`--root DIR`) is always this case, and so is a stopped service, and so
  is a Redis with `requirepass` set, because `redis-cli` is refused and
  `inspect` never reads a secret to get past it.

Two servers on one machine report the section as not inferred as well, naming
both: the description holds one `database.server`, so there is nowhere to write
two roles down.

`database.server.listen` comes from `ss -lntH`, filtered on the port the server
itself reported, so it is the addresses the machine is really answering on and
not the setting it was given. `database.server.replication.allowed_from` is the
origins the server holds an authorization for, a MariaDB `Host` verbatim and a
`pg_hba` address and netmask joined into a prefix. Redis reports it as not
inferred: it has no per origin authorization, and the reason says so. So is a
MariaDB primary holding a grant no description may declare, such as the
`fd3d:80b2:d0d7:0:%` keel 0.11.0 made for an overlay /64: written into the
description it would not validate, so the reason names it instead.

`database.server.read_only` (MariaDB) is a line of the report and not a field
of the description it writes: a replica is read only and every other role is
writable, so it follows the role and nothing declares it. It is the server's
`read_only` variable, `true` or `false`, and the line names the accounts that
write through it anyway, those holding `READ_ONLY ADMIN` other than the
server's own `root`, `mysql` and `mariadb.sys` at `localhost`, `127.0.0.1` or
`::1` (`'root'@'%'` is named):

```
database.server.read_only: true (from mariadb ... SHOW GLOBAL VARIABLES ...; READ_ONLY ADMIN lets 'admin'@'localhost', 'admin'@'::1', 'admin'@'127.0.0.1' write through it)
```

`keel diff` compares it with the role the server has ([docs/diff.md](diff.md)).

### The client side is the application's own configuration

A server can be asked what it is. An application cannot be asked where it will
connect next, and watching its open sockets would report a connection rather
than a declaration, so this one place is read from configuration, which is
where the fact lives and the only place it lives.

| Application | File | Read |
| --- | --- | --- |
| wordpress | `/var/www/*/wp-config.php`, `/var/www/wp-config.php` | `DB_HOST`, split into a host and a port, with `DB_NAME` and `DB_USER` |
| nodebb | `/var/www/nodebb/config.json`, `/opt/nodebb/config.json` | `database`, which names the engine, and that engine's `host`, `port`, `database` and `username` |

One reader per application, in a table that grows as appliances arrive. A file
that is there and cannot be read or parsed is reported as not inferred, naming
it. No password is read out of any of these files.

`database.client.replicas` is always reported as not inferred when a client
section is written, because no application configuration above expresses a read
endpoint. A description that declares read replicas is therefore `unknown` in
`keel diff` and never drift.

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
DHCP or SLAAC interface holds right now (they are read to tell one method
from the other, never recorded as an address), running services, installed
packages (that is `keel verify`).

## The report

One line per field, then a summary:

```
instance.hostname: blog (from /etc/hostname)
instance.fqdn: blog.example.org (from /etc/hosts)
network.interfaces.eth0.ipv6: static 2001:db8:1::10/64 gateway fe80::1 (from /etc/network/interfaces)
network.managed_by: file (from no LXC marker, the interfaces file owns the addresses)
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

`tests/fixtures/inspect/` holds five trees: `turnkey` (a WordPress like
appliance with a static IPv6 address, dehydrated with `dns-01` and the
certificate it obtained, cron-apt,
two users with keys, their `passwd` and `group` entries), `dhcp` (a Core container with DHCP on both
families, sourced `interfaces.d`, a readable `inithooks.conf` and a
`localtime` symlink), `static` (the `interfaces` file the `01ipconfig`
hook writes when both families are static, so that inspecting it, rendering
the result and diffing it back report the `IP_*` and `IP6_*` keys and no
drift) `database` (a machine that both runs a MariaDB server and holds a
WordPress configuration pointing at it, so both subjects of the database
section are exercised, the server one through the offline path that can ask
nothing) and `missing` (almost empty). Every probe is tested
as a pure function in `tests/test_inspect_probes.py`; the reader, the
collector, the exit codes and the round trip through `spec validate` and
`spec render` are in `tests/test_inspect_cli.py`.
