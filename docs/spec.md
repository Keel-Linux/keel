# The instance spec

One file describes one instance (brief section 5.2). This document describes
the format as implemented, not as planned. Every example uses IPv6.

Default path: `/etc/keel/instance.yaml`, overridable with `$KEEL_SPEC` or
`--spec`. The final path is a maintainer decision (brief section 11).

## How to read the tables

| Marking | Meaning |
| --- | --- |
| read | Validated and acted on by `spec apply` today |
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

## Top level

```yaml
version: 1
```

| Field | State | Notes |
| --- | --- | --- |
| `version` | read | Must be `1`. Absent or different is an error |

The other top level keys are `instance`, `network`, `tls`, `secrets`, `app`,
`hub`, `security`, `first_login_wizard`, `preseed`, `users` and `locale`, each
optional and each a mapping except `first_login_wizard`. A file with `version: 1` and nothing else is valid and renders to an
empty conf.

## instance

```yaml
instance:
  hostname: blog
  fqdn: blog.example.org
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `instance.hostname` | read | `HOSTNAME` | A domain name. A path, a port or an empty label is an error |
| `instance.fqdn` | read | `FQDN` | Same validation as `hostname` |

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
| `network.interfaces.<name>.ipv6.method` | read | One of `static`, `dhcp`, `auto`, `manual`, `none` |
| `network.interfaces.<name>.ipv6.address` | accepted | Required when the method is `static`. Must carry a prefix length and must be a unicast address, so link local, loopback and multicast are rejected |
| `network.interfaces.<name>.ipv6.gateway` | accepted | An IPv6 address. A link local gateway such as `fe80::1` is normal and is accepted |
| `network.interfaces.<name>.ipv4.method` | read | One of `static`, `dhcp`, `manual`, `none`. Optional everywhere |
| `network.interfaces.<name>.ipv4.address` | read | Required when the method is `static`. Must carry a prefix length |
| `network.interfaces.<name>.ipv4.gateway` | read | An IPv4 address |
| `network.nameservers` | read | A list of addresses of either family |

What "read" means per case, because this section is the one with real gaps:

- `managed_by: host` is the container case, where the host owns the interface
  configuration. Nothing is written: no `IP_*` variable is exported. `apply`
  compares each declared IPv6 address with the live addresses on that interface
  and warns when they differ, so a mismatch is visible without stopping a boot.
- `managed_by: file` exports the `IP_*` variables the `01ipconfig` hook reads:
  `IP_CONFIG`, and for a static address `IP_ADDRESS`, `IP_NETMASK` and `IP_GW`.
  Only IPv4 maps onto those variables, because that is all the hook understands
  today. Declaring a static IPv6 address together with `managed_by: file` is
  therefore an error with an explicit message, rather than a value silently
  dropped. Set the address on the host and use `managed_by: host`.
- `nameservers` exports at most two entries, as `IP_DNS1` and `IP_DNS2`, and
  only under `managed_by: file`. IPv6 nameservers are validated and kept in the
  file but are not exported, because those two variables are IPv4 only in the
  hook. An IPv6 resolver belongs in the host configuration or in the router
  advertisement until that hook is replaced.

## tls

```yaml
tls:
  acme:
    enabled: true
    challenge: http-01
    domains:
      - blog.example.org
```

| Field | State | Notes |
| --- | --- | --- |
| `tls.acme.enabled` | accepted | When true, `apply` warns that this version does not request a certificate and points at confconsole |
| `tls.acme.challenge` | accepted | `http-01` or `dns-01` |
| `tls.acme.domains` | accepted | A list of domain names, each validated |

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
| `file: PATH` | read | The file must exist, be owned by root (or by the caller), and be mode 0600 or stricter. A single trailing newline is stripped. All of that is checked at validation time, not only at apply time |
| `generate: true` | read | A value is generated at apply time with `secrets.token_urlsafe` |

`generate` is refused for `root_password` and `app_password` unless
`first_login_wizard` is true, because otherwise nobody can ever log in with
the generated value.

Values are shell quoted, so a password containing spaces, quotes or `$`
survives being sourced.

`spec render` never resolves a secret: it substitutes `[masked]` before
rendering, so a preview cannot read a file or generate a value.

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
  updates: force
```

| Field | State | Conf variable | Notes |
| --- | --- | --- | --- |
| `security.alerts` | read | `SEC_ALERTS` | An email address, or `skip` |
| `security.updates` | read | `SEC_UPDATES` | `skip` or `force` |

`skip` and `force` are upper cased on the way out, because the hooks compare
them upper case. An email address is passed through unchanged.

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
```

| Field | State | Notes |
| --- | --- | --- |
| `users.<name>` | accepted | A user name (lower case, as `useradd` accepts). The value is a mapping with the one key below, or empty |
| `users.<name>.authorized_keys` | accepted | A list of public key lines: a key type (`ssh-`, `ecdsa-`, `sk-`) followed by the key material. Nothing else about a user is modelled |

`keel inspect` writes this section from the `authorized_keys` files it finds.
Nothing creates the accounts or installs the keys yet, so `apply` warns.

## locale

```yaml
locale:
  timezone: Europe/Lisbon
  lang: en_US.UTF-8
```

| Field | State | Notes |
| --- | --- | --- |
| `locale.timezone` | accepted | A zoneinfo name such as `Europe/Lisbon` or `Etc/UTC` |
| `locale.lang` | accepted | A locale name such as `en_US.UTF-8` or `C.UTF-8` |

Written by `keel inspect` from `/etc/timezone` (or the `/etc/localtime`
symlink) and `/etc/default/locale`. Nothing applies it yet, so `apply` warns.

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
