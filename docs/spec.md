# The instance spec

One file describes one instance (brief section 5.2). This document describes
the format as implemented, not as planned. Every example uses IPv6.

Default path: `/etc/keel/instance.yaml`, overridable with `$KEEL_SPEC` or
`--spec`. The final path is a maintainer decision (brief section 11).

## How to read the tables

| Marking | Meaning |
| --- | --- |
| read | Validated and rendered into the conf by `spec apply` today |
| system | Validated, and converged by `spec apply --system` ([docs/apply.md](apply.md)); without the flag `apply` warns that the section was left alone |
| accepted | Validated, but `spec apply` does not act on it yet; `apply` prints a warning where the gap is silent otherwise |

Anything not listed is rejected. Unknown keys are errors at every level, so a
typo fails validation instead of being ignored.

## What `apply` produces

`apply` renders the spec into shell `export` lines and writes them to the conf
file (default `/etc/inithooks.conf`, mode 0600). Those are the variables the
existing firstboot hooks already source, which is why an appliance gains a
declarative front end without any hook changing.

If the conf file already holds something other than whitespace, `apply` leaves
it alone, warns, and exits 0. The spec never overwrites a preseed.

With `--system`, `apply` then converges the `users`, `locale` and `monitor`
sections and `security.alerts` against the system itself (accounts,
authorized keys, timezone, language, where alerts are mailed, what monit
watches),
only where they differ, and never touches a password. That phase, its flags
and what it never does are in [docs/apply.md](apply.md).

## Top level

```yaml
version: 1
```

| Field | State | Notes |
| --- | --- | --- |
| `version` | read | Must be `1`. Absent or different is an error |

The other top level keys are `instance`, `network`, `tls`, `secrets`, `app`,
`hub`, `security`, `first_login_wizard`, `preseed`, `users`, `locale`,
`database` and `monitor`, each optional and each a mapping except `first_login_wizard`. A file with `version: 1` and nothing else is valid and renders to an
empty conf.

## instance

```yaml
instance:
  hostname: blog
  fqdn: blog.example.org
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `instance.hostname` | read, system | `HOSTNAME` | A domain name. A path, a port or an empty label is an error. `apply --system` renames a running machine to it ([docs/apply.md](apply.md)) |
| `instance.fqdn` | read, system | `FQDN` | Same validation as `hostname`. `apply --system` also writes the `/etc/hosts` entry that makes `hostname -f` answer it, which no upstream hook writes ([docs/apply.md](apply.md)); without `--system`, `apply` warns that it was not written |

## network

```yaml
network:
  managed_by: host
  interfaces:
    eth0:
      ipv6:
        method: static
        address: 2001:db8:1::10/64
        gateway: fe80::1
  nameservers:
    - 2001:db8:1::53
    - 2001:db8:1::54
```

| Field | State | Notes |
| --- | --- | --- |
| `network.managed_by` | read | `host` or `file`. Default: `host` on a container, `file` otherwise, decided at apply time |
| `network.interfaces.<name>.ipv6.method` | read | One of `static`, `dhcp`, `auto`, `manual`, `none`. `auto` is an address from a router advertisement (SLAAC), `dhcp` an address from a DHCPv6 lease; see "auto and dhcp are two things" below |
| `network.interfaces.<name>.ipv6.address` | read | Required when the method is `static`. Must carry a prefix length and must be a unicast address, so link local, loopback and multicast are rejected |
| `network.interfaces.<name>.ipv6.gateway` | read | An IPv6 address. A link local gateway such as `fe80::1` is normal and is accepted |
| `network.interfaces.<name>.ipv4.method` | read | One of `static`, `dhcp`, `manual`, `none`. Optional everywhere |
| `network.interfaces.<name>.ipv4.address` | read | Required when the method is `static`. Must carry a prefix length |
| `network.interfaces.<name>.ipv4.gateway` | read | An IPv4 address |
| `network.nameservers` | read | A list of addresses of either family |

What "read" means per case:

- `managed_by: host` is the container case, where the host owns the interface
  configuration. Nothing is written: no `IP_*` or `IP6_*` variable is
  exported. `apply` compares each declared IPv6 address with the live
  addresses on that interface and warns when they differ, so a mismatch is
  visible without stopping a boot.
- `managed_by: file` exports the variables the `01ipconfig` hook reads, and
  the hook writes `/etc/network/interfaces` from them, one `inet` and one
  `inet6` stanza for the interface it configures (`eth0`, or `br0` in an LXC
  build). The hook configures that one interface, so when the spec declares
  several, the last `ipv4` block and the last `ipv6` block win, each as a
  whole.
- `nameservers` are split by family: the first two IPv4 addresses become
  `IP_DNS1` and `IP_DNS2`, the first two IPv6 addresses `IP6_DNS1` and
  `IP6_DNS2`. An IPv4 address never lands in an `IP6_*` variable, nor the
  other way round. `IP6_DNS*` are exported only when an interface declares an
  `ipv6` block, so a spec without one renders exactly what it rendered before
  IPv6 was written.

| Spec value | Conf variables |
| --- | --- |
| `ipv4.method: dhcp` or `manual` | `IP_CONFIG=dhcp` or `IP_CONFIG=manual` |
| `ipv4.method: static` | `IP_CONFIG=static`, `IP_ADDRESS` (the address alone), `IP_NETMASK` (dotted, from the prefix length), `IP_GW` when set |
| `ipv4.method: none`, or no `ipv4` block | nothing |
| `ipv6.method: static` | `IP6_CONFIG=static`, `IP6_ADDRESS` (address with its prefix length, as an `inet6` stanza has no netmask), `IP6_GW` when set |
| `ipv6.method: dhcp` or `auto` | `IP6_CONFIG=dhcp`. ifupdown has one method for both: `inet6 dhcp` is what the hook writes either way, and it keeps SLAAC on as confconsole does |
| `ipv6.method: manual` | `IP6_CONFIG=manual` |
| `ipv6.method: none`, or no `ipv6` block | nothing, and no `IP6_DNS*` |
| `nameservers` | `IP_DNS1`, `IP_DNS2` from the IPv4 entries; `IP6_DNS1`, `IP6_DNS2` from the IPv6 entries |

### auto and dhcp are two things

`auto` means the address is formed from a router advertisement (SLAAC).
`dhcp` means it comes from a DHCPv6 lease. Both are written to
`/etc/network/interfaces` as `iface <name> inet6 dhcp`, because ifupdown has
no separate method, so the file cannot say which one a spec declared.

The running machine can, and `keel inspect` reads it there:

| Evidence | Method reported |
| --- | --- |
| A DHCPv6 lease file for the interface (`/var/lib/dhcpcd/<name>.lease6`, `/var/lib/dhcp/dhclient6*.leases`) | `dhcp` |
| No lease, and a global address marked `mngtmpaddr` in `ip -6 addr show`, which is how the kernel marks an address whose prefix came from a router advertisement | `auto` |
| Neither | not inferred, naming both candidates and everything that was checked |

The third line is deliberate: inspect used to answer `dhcp` for an `inet6
dhcp` stanza whatever the machine had done with it, so a SLAAC container
reported drift against a spec that correctly declared `auto`. A field that
cannot be read is reported as not inferred, which `keel diff` shows as
unknown with that reason, and never as drift.

An offline root (`--root DIR`) has the lease files but no live addresses, so
a machine that took a DHCPv6 lease is still read as `dhcp` there, and a SLAAC
one is not inferred.

A static address on both families:

```yaml
network:
  managed_by: file
  interfaces:
    eth0:
      ipv6:
        method: static
        address: 2001:db8:1::10/64
        gateway: fe80::1
      ipv4:
        method: static
        address: 192.0.2.10/24
        gateway: 192.0.2.1
  nameservers:
    - 2001:db8:1::53
    - 2001:db8:2::53
    - 192.0.2.53
```

```
export IP_CONFIG=static
export IP_ADDRESS=192.0.2.10
export IP_NETMASK=255.255.255.0
export IP_GW=192.0.2.1
export IP_DNS1=192.0.2.53
export IP6_CONFIG=static
export IP6_ADDRESS=2001:db8:1::10/64
export IP6_GW=fe80::1
export IP6_DNS1=2001:db8:1::53
export IP6_DNS2=2001:db8:2::53
```

The hook validates every `IP6_*` value again before writing anything, with
the same rules as the spec (an IPv6 address, a prefix length on `IP6_ADDRESS`,
no multicast, loopback or link local address as the address itself), so a
value the spec accepted is never rejected at first boot.

## tls

```yaml
tls:
  acme:
    enabled: true
    challenge: http-01
    agree_tos: true
    domains:
      - blog.example.org
```

| Field | State | Notes |
| --- | --- | --- |
| `tls.acme.enabled` | system | `true` or `false`; absent counts as false for `diff`. `true`: `apply --system` requests a certificate for the domains when the one in use does not carry them (docs/apply.md). `false`, stated, over a certificate a CA issued: `apply --system` goes back to a self-signed one. Absent: `apply` leaves the certificate as it is. When false, the fields below it are kept in the file and `keel diff` does not compare them ([docs/diff.md](diff.md)), so an operator prepares a certificate configuration before turning it on |
| `tls.acme.challenge` | system | `http-01` or `dns-01`. `apply` refuses to request with `dns-01`, which needs a DNS provider and credentials the spec has no field for yet |
| `tls.acme.domains` | system | A list of domain names, each validated |
| `tls.acme.agree_tos` | system | `true` accepts the Let's Encrypt terms of service, which registering an account does. Needed only on a machine with no account yet; `keel diff` never compares it |

## secrets

Secrets are referenced, never inlined. A reference names exactly one backend.

```yaml
secrets:
  root_password:
    file: /etc/keel/secrets/root_password
  db_password:
    generate: true
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `secrets.root_password` | read | `ROOT_PASS` | |
| `secrets.db_password` | read | `DB_PASS` | |
| `secrets.app_password` | read | `APP_PASS` | |

| Backend | State | Notes |
| --- | --- | --- |
| `file: PATH` | read | `PATH` must be a non empty string. The file must exist, be owned by root (or by the caller), and be mode 0600 or stricter; a single trailing newline is stripped. The file is checked at validation time by `spec validate`, `spec render` and `spec apply`, and not by `keel diff` or `spec validate --no-secret-files`, see below |
| `generate: true` | read | A value is generated at apply time with `secrets.token_urlsafe` |

`generate` is refused for `root_password` and `app_password` unless
`first_login_wizard` is true, because otherwise nobody can ever log in with
the generated value.

Values are shell quoted, so a password containing spaces, quotes or `$`
survives being sourced.

`spec render` never resolves a secret: it substitutes `[masked]` before
rendering, so a preview cannot read a file or generate a value.

### Checking the structure without the files

A secret is a reference, so a spec can be valid on a machine that does
not hold the value: the operator's workstation, or a fresh container that
`keel inspect` described but where the secrets have not been materialised
yet. `spec.validate()` takes a keyword for that case:

```python
errors = spec.validate(document, check_secret_files=False)
```

With `check_secret_files=False` every secret reference is still checked
for structure (exactly one known backend, a `file:` value that is a non
empty string, `generate` only where `first_login_wizard` allows it), but
the existence, owner and mode of the file are not. The default is `True`,
so `spec apply` and `spec render` behave as before.

`keel diff` always loads the spec this way, because it never compares
secrets ([docs/diff.md](diff.md)). `keel spec validate` checks the files
by default and takes `--no-secret-files` to skip them; its output says
which was done:

```
$ keel spec validate --spec instance.yaml
Error: instance.yaml: secrets.root_password: /etc/keel/secrets/root_password: secret file not found
$ keel spec validate --spec instance.yaml --no-secret-files
instance.yaml: ok (secret files not checked)
```

## app

```yaml
app:
  email: admin@example.org
  domain: blog.example.org
  options:
    ip_bind: "[2001:db8:1::10]"
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `app.email` | read | `APP_EMAIL` | |
| `app.domain` | read | `APP_DOMAIN` | |
| `app.options.<key>` | read | `APP_<KEY>` | The key is upper cased and prefixed. It must be a valid shell variable name. This is where appliance specific inithook parameters go |

## hub

```yaml
hub:
  api_key: skip
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `hub.api_key` | read | `HUB_APIKEY` | Either the string `skip`, which renders as `SKIP`, or a secret reference with the same backends as `secrets` |

Making the endpoint itself configurable is brief section 5.6 and is not part of
this version: only the key is declared here.

## security

```yaml
security:
  alerts: admin@example.org
  updates_at_first_boot: force
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `security.alerts` | read, system | `SEC_ALERTS` | An email address, or `skip`; converged on a running machine by `apply --system` ([docs/apply.md](apply.md)) |
| `security.updates_at_first_boot` | read | `SEC_UPDATES` | `skip` or `force`. Renamed from `security.updates`, which is still accepted with a warning |

`skip` and `force` are upper cased on the way out, because the hooks compare
them upper case. An email address is passed through unchanged.

### What `updates_at_first_boot` controls, and what it does not

`force` makes the `95secupdates` hook install the pending security updates
once, during the first boot, without asking. `skip` makes it install nothing
and log that it was skipped. Unset, the hook asks, which is why the field is
required for a headless boot ([docs/inspect.md](inspect.md)).

It does not control whether the appliance keeps its security updates current
afterwards. That is `cron-apt`, which the image ships configured either way,
so a machine with `updates_at_first_boot: skip` still installs security
updates on a schedule. The field was called `security.updates`, which said
the opposite: `keel inspect` read the cron-apt install action, reported
`force`, and every spec that declared `skip` drifted against a machine that
was doing exactly what the spec asked. The name now says what the value
does, and `keel diff` does not compare it at all, because the machine keeps
no record of which value was used ([docs/diff.md](diff.md)).

### Deprecated names

A field that is renamed keeps working under the old name for the benefit of
specs already on disk:

```
$ keel spec validate --spec instance.yaml
Warning: instance.yaml: security.updates is deprecated, rename it to security.updates_at_first_boot: it reads as the machine's update policy, and it only ever controlled whether the first boot installs the pending security updates; the appliance keeps them current either way
instance.yaml: ok (secret files checked)
```

The table is `keel.spec.compat.RENAMED`. Every command warns once, then
works on the document under the current names, so nothing else in the
library knows the old ones. A file that declares both names keeps the
current one, and the warning says so.

## first_login_wizard

```yaml
first_login_wizard: false
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `first_login_wizard` | read | `AUTO_RUN` | True exports `AUTO_RUN=TRUE`. False exports nothing |

## preseed

```yaml
preseed:
  AUTOGROW: ONCE
```

| Field | State | Notes |
| --- | --- | --- |
| `preseed.<KEY>` | read | An escape hatch: each key is exported verbatim, after being checked as a valid shell variable name. Use it for a hook variable the spec does not model yet |

## users

```yaml
users:
  root:
    authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog
  admin:
    shell: /bin/bash
    groups: [sudo, adm]
    authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@laptop
```

| Field | State | Notes |
| --- | --- | --- |
| `users.<name>` | system | A user name (lower case, as `useradd` accepts). The value is a mapping of the keys below, or empty. `apply --system` creates the account when absent and never deletes one |
| `users.<name>.authorized_keys` | system | A list of public key lines: a key type (`ssh-`, `ecdsa-`, `sk-`) followed by the key material. `apply --system` sets `<home>/.ssh/authorized_keys` to exactly these lines, mode 0600, owned by the user |
| `users.<name>.shell` | system | An absolute path such as `/bin/bash`. Passed to `useradd --shell` on creation, `usermod --shell` when an existing account has another |
| `users.<name>.groups` | system | A list of group names the user belongs to. Passed to `useradd --groups` on creation; missing ones are added with `usermod --append --groups`, none is removed. The groups must exist |

Nothing else about a user is modelled, and in particular no password: the
`secrets` section names the root password by reference and the hooks set it
(`ROOT_PASS`). `keel inspect` writes this section from the `authorized_keys`
files it finds, with the shell from `/etc/passwd` and the groups from
`/etc/group`. Without `--system`, `apply` warns that the section was left
alone.

## locale

```yaml
locale:
  timezone: Europe/Lisbon
  lang: en_US.UTF-8
```

| Field | State | Notes |
| --- | --- | --- |
| `locale.timezone` | system | A zoneinfo name such as `Europe/Lisbon` or `Etc/UTC`. `apply --system` sets it through `timedatectl` on the live system, else writes `/etc/timezone` and the `/etc/localtime` symlink |
| `locale.lang` | system | A locale name such as `en_US.UTF-8` or `C.UTF-8`. `apply --system` writes `LANG` in `/etc/default/locale` and generates the locale on the live system (`locale-gen`, else `localedef`) |

Written by `keel inspect` from `/etc/timezone` (or the `/etc/localtime`
symlink) and `/etc/default/locale`. Applied only where the observed value
differs ([docs/apply.md](apply.md)). Without `--system`, `apply` warns that
the section was left alone.

## database

Two subjects, which one field cannot serve. A machine that **runs** a database
server has a role. A machine that **uses** a database names where that database
is. A machine can have both, either, or neither, so `server` and `client` are
separate mappings and neither implies the other.

```yaml
database:
  server:
    engine: mariadb
    role: standalone
    listen:
      - "::1"
      - 127.0.0.1
  client:
    engine: mariadb
    primary:
      host: "::1"
      port: 3306
      name: wordpress
      user: wordpress
      secret:
        file: /etc/keel/secrets/db_password
```

`database.server` is converged by the system phase of `apply`
([docs/apply.md](apply.md)) for MariaDB, which writes the server id, the
addresses, the binary log, the authorizations of a primary and the
replication of a replica. PostgreSQL and Redis are read
([docs/inspect.md](inspect.md)) and compared ([docs/diff.md](diff.md)) and
say so instead of being configured, which is decision 0013 taking the engines
one at a time.

`database.client` is read and compared and never applied: where an
application reaches a database is the application's own configuration.

### database.server: what this machine is

| Field | State | Notes |
| --- | --- | --- |
| `database.server.engine` | accepted | `mariadb`, `postgresql` or `redis`. Required when the section is declared |
| `database.server.role` | accepted | `standalone`, `primary` or `replica`. Required. A machine in a mode the spec has no value for, a Galera node or a Redis Cluster node, is reported by `inspect` as a role it could not infer rather than forced into one of these three |
| `database.server.listen` | accepted | A list of literal addresses the server answers on. Never a name, see below |
| `database.server.replication.primary.host` | accepted | The literal address this node replicates from. Required when the role is `replica` |
| `database.server.replication.primary.port` | accepted | A port number. Absent means the engine's default: 3306, 5432, 6379 |
| `database.server.replication.allowed_from` | accepted | A list of origins allowed to replicate from this node. Meaningful when the role is `primary`; see "A primary authorizes, it does not enumerate" |
| `database.server.replication.secret` | accepted | The replication credential, by reference, with the same backends as `secrets`. What it unlocks differs per engine, see below |

Three roles and no more. `multi_primary` and the shard roles are not in the
list, and adding them later renames nothing that is in it, which is the point
of naming the field `role` and not `cloud` or `mode` (decision 0013).

### database.client: where the database this machine uses is

| Field | State | Notes |
| --- | --- | --- |
| `database.client.engine` | accepted | `mariadb`, `postgresql` or `redis`. Required when the section is declared |
| `database.client.primary.host` | accepted | Where writes go, as a literal address. Required. A machine using its own server writes `::1`, or `127.0.0.1`, and never `localhost` |
| `database.client.primary.port` | accepted | A port number; absent means the engine's default |
| `database.client.primary.name` | accepted | The database within the server: a schema name for MariaDB and PostgreSQL, the numbered database for Redis |
| `database.client.primary.user` | accepted | The account the application authenticates as. A Redis server without ACL users has none, so the field is left out there |
| `database.client.primary.secret` | accepted | The credential, by reference |
| `database.client.replicas` | accepted | A list of read endpoints, each `host` and optionally `port`. Optional: reads go to the primary when it is empty |

A read endpoint carries no credential of its own. A replica is a copy of the
primary, so it accepts the same account, and a second credential in the file
would be a second thing to rotate.

### Addresses are literal, never `localhost`

Every address in this section is checked as a literal address, and the word
`localhost` is refused by name with the reason in the message:

```
$ keel spec validate --spec instance.yaml
Error: instance.yaml: database.server.listen: "localhost" is a name, not an address: Debian maps ::1 to ip6-localhost and never to localhost, so a resolver asked for localhost answers one family only; write ::1 and 127.0.0.1
```

That is not a style rule. Debian's `/etc/hosts` maps `::1` to `ip6-localhost`
and never to `localhost`, so `listen_addresses = 'localhost'` in PostgreSQL and
`bind localhost` in Redis bind one family, which is how the PostgreSQL
appliance shipped listening on IPv4 only (docs/traps.md). A description that
can say `localhost` can ship that defect again.

`ip6-localhost` and `ip6-loopback` are refused with the same message, because a
description that names one family is the same defect written the other way
round.

### A primary authorizes, it does not enumerate

`allowed_from` is a list of origins that **may** replicate from this node, not
a list of the replicas that do. In asynchronous replication the replica opens
the connection and the primary never holds a list of who is replicating, so a
field that promised one would be a field no machine could ever answer. What the
machine does hold is who is allowed, which is local configuration of the
machine the console runs on, and that keeps the whole subject inside the line
decision 0013 drew: each screen configures the machine it runs on.

| Engine | What an entry becomes |
| --- | --- |
| mariadb | A grant of `REPLICATION SLAVE` to the replication account from that origin, which is the `Host` part of the account |
| postgresql | A line in `pg_hba.conf` for the `replication` pseudo database with that address |
| redis | Reachability: the origin has to be inside `listen`, and the credential is an ACL user or `requirepass`. Redis has no per origin authorization at all, so `inspect` reports this field as one it cannot infer on Redis and says why |

An entry is an address, a prefix, a host pattern, or a name:

```yaml
database:
  server:
    engine: postgresql
    role: primary
    listen: ["::"]
    replication:
      allowed_from:
        - 2001:db8:1::/64        # the prefix a fleet lives on: prefer this
        - 2001:db8:2::20         # one machine
        - 2001:db8:3:%           # a host pattern: MariaDB's own spelling
        - replica.example.org    # a name: accepted, and fragile
      secret:
        file: /etc/keel/secrets/replication_password
```

**A prefix is the form to prefer.** With IPv6 and no NAT the `/64` a fleet
lives on is a stable fact, where a list of single addresses goes stale every
time a container is rebuilt.

**A host pattern is a prefix in MariaDB's own spelling.** MariaDB takes an
address and a netmask for IPv4 only, so a grant that authorizes an IPv6 `/64`
can only be written `2001:db8:1:%`, and that is what the server holds and what
`inspect` reads back off it. The field accepts it for that reason: a schema that
refused it would make `allowed_from` unusable on MariaDB and would report drift
on every primary `inspect` described.

**Write the prefix.** A group aligned prefix and the pattern for it are one
origin: `keel diff` compares them as the same value, and `keel spec apply`
grants the pattern the engine needs from the prefix the description wrote
(`keel.spec.origins`). A prefix that stops inside a group, a `/56` or a `/28`,
has no pattern at all, and apply says so rather than authorizing a wider or a
narrower range than the description asked for.

**A name is accepted and it is fragile.** MariaDB resolves the `Host` of a
grant, and `pg_hba.conf` matches a name by reverse resolving the client address
and then forward resolving the answer. Both fail quietly: the authorization
stays in place, matches nothing, and the replica is refused with no hint that
DNS is the reason. So `inspect` reports the origins the **server** holds rather
than the ones the description asked for, and a name that stopped resolving
shows up in `keel diff` as drift rather than as nothing at all
([docs/diff.md](diff.md)).

### What the credential means, per engine

The replication secret and the client secret are file references, like every
other secret in this format (`secrets` above). What the value unlocks is not
the same thing in all three engines, and a description that pretended
otherwise would mislead whoever creates the file:

| Engine | `database.server.replication.secret` | `database.client.primary.secret` |
| --- | --- | --- |
| mariadb | The password of the replication account, the one `CHANGE MASTER TO ... MASTER_PASSWORD` uses | The password of `database.client.primary.user` |
| postgresql | The password of the replication role, what `primary_conninfo` carries | The password of the role in `primary.user` |
| redis | `masterauth` on the replica: the value of `requirepass`, or the password of the ACL user allowed to replicate. Redis has no database account, so there is no user to name unless an ACL user exists | `requirepass`, or the password of an ACL user |

No value is ever read by `inspect` or compared by `diff`, on any engine.

## monitor

A resource monitor that tells the operator what to do (handbook decision
0021): monit watches the disks, the memory, the CPU and the declared
network interfaces, and every alert runs `keel notify`, which sends the
message to the channels declared here. The operator writes thresholds,
not monit syntax.

```yaml
monitor:
  enabled: true
  checks:
    disk: {warn: 80, critical: 90}       # percent used
    inodes: {critical: 90}
    memory: {warn: 85, for_minutes: 5}
    swap: {warn: 50, for_minutes: 5}
    cpu: {warn: 90, for_minutes: 10}
    load_per_core: {warn: 2.0, for_minutes: 10}
    network:
      eth0: {link: true, max_mbit: 800, for_minutes: 5}
  notify:
    email: true                          # security.alerts' address
    telegram:
      chat_id: "-1001234567890"
      token: {file: /etc/keel/secrets/telegram_token}
    ntfy:
      url: https://ntfy.example.org/keel-blog
      token: {file: /etc/keel/secrets/ntfy_token}
    webhook:
      url: https://hooks.example.org/keel
    details: true                        # directory sizes in the message
```

| Field | State | Notes |
| --- | --- | --- |
| `monitor.enabled` | system | `true` or `false`; absent is off. `apply --system` writes `/etc/monit/conf.d/keel.conf` and `/etc/keel/monitor.json` when true and removes them, if keel wrote them, otherwise ([docs/apply.md](apply.md)). `true` without a working channel under `notify` is an error: a monitor with nobody to tell looks like one and is not |
| `monitor.checks.disk.warn`, `.critical` | system | Percent of the space used, above 0 and below 100, `warn` below `critical`. Default 80 and 90. Watched on every filesystem that holds data, as two separate checks |
| `monitor.checks.inodes.critical` | system | Percent of the inodes used. Default 90 |
| `monitor.checks.memory.warn`, `.for_minutes` | system | Default 85 percent for 5 minutes |
| `monitor.checks.swap.warn`, `.for_minutes` | system | Default 50 percent for 5 minutes |
| `monitor.checks.cpu.warn`, `.for_minutes` | system | Default 90 percent for 10 minutes |
| `monitor.checks.load_per_core.warn`, `.for_minutes` | system | The one minute load average divided by the number of cores, a number above 0. Default 2 for 10 minutes |
| `monitor.checks.network.<name>.link` | system | `true` watches that the link is up. No interface is watched unless declared |
| `monitor.checks.network.<name>.max_mbit` | system | Throughput in Mbit/s, each direction; no default, because what is too much depends on the link |
| `monitor.checks.network.<name>.for_minutes` | system | How long a condition of this interface holds before it is told, link included. Default 5 |
| `monitor.notify.email` | system | `true` mails `security.alerts`' address through the local MTA. An error while `security.alerts` is `skip` or absent. Best effort: postfix needs disk to queue, so a full disk is what this channel cannot report |
| `monitor.notify.telegram.chat_id`, `.token` | system | The Bot API's `sendMessage`. The chat id is a number (`-1001234567890`) or a channel name (`@keel_ops`); the token is a secret reference and must be a `file:` |
| `monitor.notify.ntfy.url`, `.token` | system | One HTTPS POST to the topic URL, given as the URL or, since a public topic is its own credential, as a secret reference `{file: ...}` holding it; the token, optional, is sent as `Authorization: Bearer` and must be a `file:` |
| `monitor.notify.webhook.url` | system | The URL, or a secret reference to a file holding it: a Slack or Discord webhook URL is a credential. One HTTPS POST whose JSON body is Slack compatible, `{"text": ...}`, plus the fields `host`, `address`, `check`, `target`, `direction`, `value`, `threshold`, `level`, `service` and `event`. Slack and Mattermost take it as it is; Discord at its webhook URL with `/slack` appended; Matrix through a bridge such as hookshot |
| `monitor.notify.details` | system | `true` adds the three largest directories (disk, inodes) or processes (memory, swap, CPU, load) to the message. Default `false` |

Every URL must be `https` and carry no user or password: a token is a
secret reference of its own, never part of the spec. No error message
repeats a URL, since it may be a credential. `for_minutes` is a whole
number of minutes. monit holds a condition for at most 64 cycles of the
cycle the machine's monit runs at, which keel reads and never sets, so
whether a duration fits is decided by `apply --system` on that machine,
which refuses one that does not; validation only refuses more than 3840
minutes, which no cycle of an hour or less could hold.

**Privacy.** A message carries the host name, its first static address
and, with `details: true`, the names and sizes of its largest directories
or processes, to whichever service the section declares, Telegram's
servers included. `details: false`, the default, leaves those lists out.
`apply --system` writes the channels to `/etc/keel/monitor.json`, mode
0600, with the paths of the token files and never their values; `keel
notify` reads that file, never the spec, and reads the tokens from their
files when an alert fires. They are never written to monit's
configuration, an argument vector or a line of output.

`keel diff` compares `enabled` and the checks, read back from monit's
file, and never the channels: a URL can be a credential, so diff neither
compares nor repeats them, not even in its JSON ([docs/diff.md](diff.md)).
Without `--system`, `apply` warns that the section was left alone.

## Not in the spec yet

Named in brief section 5.2 but not part of the format today, so declaring them
is an unknown key error rather than a silent no-op: enabled services and the
backup target. Each needs a hook or a converge step behind it before it earns
a field.

## Error reporting

`validate` returns every error it finds rather than stopping at the first, so
an operator fixes the whole file in one pass:

```
$ keel spec validate --spec instance.yaml
Error: instance.yaml: version: must be 1
Error: instance.yaml: network.interfaces.eth0.ipv6.address: prefix length is required (2001:db8:1::10)
```

Exit codes are in the [README](../README.md).
