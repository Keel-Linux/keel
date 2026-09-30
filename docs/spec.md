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
`database`, `monitor`, `appliance`, `installation` and `overlays`, each optional and each a mapping except `first_login_wizard`. A file with `version: 1` and nothing else is valid and renders to an
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
| `network.interfaces.<name>.ipv6.slaac` | read | `true` or `false`, only with `method: static`; default `true`. See "static and SLAAC" below |
| `network.interfaces.<name>.ipv4.method` | read | One of `static`, `dhcp`, `manual`, `none`. Optional everywhere |
| `network.interfaces.<name>.ipv4.address` | read | Required when the method is `static`. Must carry a prefix length |
| `network.interfaces.<name>.ipv4.gateway` | read | An IPv4 address |
| `network.nameservers` | read | A list of addresses of either family |
| `network.overlay.wireguard` | system | The WireGuard overlay of a replicated appliance; see "overlay" below |

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
- `nameservers` go where the file can hold them. ifupdown writes
  `dns-nameservers` only in a static stanza, two per stanza, and resolvconf
  takes them from any stanza whatever the server's family. So:
  - when one family is `static` and the other is not (or is not declared,
    which leaves it dynamic), the static stanza carries servers of both
    families, two of them, in the spec's order: the first server of each
    family before a second of either. With IPv4 static, IPv6 `auto` and
    `2001:db8:1::53`, `2001:db8:2::53`, `192.0.2.53` declared, the stanza
    gets `2001:db8:1::53 192.0.2.53`: an upstream of one family that fails
    still leaves a resolver of the other, which matters because `inet6
    auto` adds none to resolv.conf. The price is said here: the static
    family's own second server can be the one left out, as `192.0.2.54`
    would be after `192.0.2.53` and `2001:db8:1::53`;
  - when both are static, or neither, they are split by family: the first
    two IPv4 addresses become `IP_DNS1` and `IP_DNS2`, the first two IPv6
    addresses `IP6_DNS1` and `IP6_DNS2`. With neither static the file holds
    none of them.

  A server left out is never dropped in silence: `keel spec apply` warns
  with the servers the file will not hold, and `apply --system` names them
  in its plan ([docs/apply.md](apply.md)). `IP6_*` variables are exported
  only when an interface declares an `ipv6` block.

  At first boot the conf is written by inithooks' own reader
  (`00declarative`), not by keel, and that reader exports no `IP6_*`
  variable and refuses `ipv6.method: static` with `managed_by: file`; so
  what this section says about IPv6 in the conf applies to `keel spec
  apply` and to `apply --system` on a running machine.

| Spec value | Conf variables |
| --- | --- |
| `ipv4.method: dhcp` or `manual` | `IP_CONFIG=dhcp` or `IP_CONFIG=manual` |
| `ipv4.method: static` | `IP_CONFIG=static`, `IP_ADDRESS` (the address alone), `IP_NETMASK` (dotted, from the prefix length), `IP_GW` when set |
| `ipv4.method: none`, or no `ipv4` block | nothing |
| `ipv6.method: static` | `IP6_CONFIG=static`, `IP6_ADDRESS` (address with its prefix length, as an `inet6` stanza has no netmask), `IP6_GW` when set, `IP6_SLAAC=no` with `slaac: false` |
| `ipv6.method: dhcp` or `auto` | `IP6_CONFIG=dhcp`. ifupdown has one method for both: `inet6 dhcp` is what the hook writes either way, and it keeps SLAAC on as confconsole does |
| `ipv6.method: manual` | `IP6_CONFIG=manual` |
| `ipv6.method: none`, or no `ipv6` block | nothing, and no `IP6_DNS*` |
| `nameservers` | `IP_DNS1`, `IP_DNS2` and `IP6_DNS1`, `IP6_DNS2`, placed as described above |

### static and SLAAC

On ifupdown-ng an `inet6 static` stanza does not stop SLAAC: the interface
keeps taking an address from the router's advertisements beside the static
one. That is the default, `slaac: true`, and it is what a static spec has
always rendered.

`slaac: false` makes the static address the only global one. The stanza
turns `autoconf` off for the interface before the address is added, and
back on when the stanza goes down, so bringing the interface up on another
file gives SLAAC back:

```
iface eth0 inet6 static
    hostname blog
    address 2001:db8:1::10/64
    gateway fe80::1
    pre-up sysctl -q -w net/ipv6/conf/eth0/autoconf=0
    post-down sysctl -q -w net/ipv6/conf/eth0/autoconf=1
```

`accept_ra` stays on, so the routes the router advertises are kept;
ifupdown-ng has no option of its own for this (its `ipv6-ra` setting
toggles `accept_ra`, which would drop them). The key is written with
slashes, so an interface name with a dot (a VLAN such as `eth0.45`) stays
one part of it. The lines are written by inithooks' `lib/ipconfig.sh` from
`IP6_SLAAC=no`, by `01ipconfig` from a conf `keel spec apply` rendered and
by `apply --system` on a running machine; inithooks' first boot reader
accepts the field but, as said above, does not render static IPv6 for a
file managed network yet. An inithooks older than the option cannot write
the lines, and `apply --system` then refuses instead of writing a file that
keeps SLAAC. `slaac` with any other method is a validation error: `auto`
and `dhcp` already take the advertisements, and `manual` configures nothing.

A change on a running machine, and its revert, give the interface's
`autoconf` setting back before `ifup` on a file that keeps SLAAC: the
value it had before the change, or 1 when the file being left is the one
that turned it off. ifupdown-ng runs `post-down` only for an interface it
recorded as up, and it records that only after `post-up`, so a file whose
`pre-up` ran and whose `up` then failed would otherwise leave SLAAC off
until a reboot. The `sysctl -w` of `pre-up` is not persisted and keel
writes nothing under `sysctl.d`, so a reboot starts from the kernel's
default (or the image's own `sysctl.d`), and the boot revert, which runs
before networking, writes nothing.

### auto and dhcp are two things

`auto` means the address is formed from a router advertisement (SLAAC).
`dhcp` means it comes from a DHCPv6 lease. Both are written to
`/etc/network/interfaces` as `iface <name> inet6 dhcp`, because ifupdown has
no separate method, so the file cannot say which one a spec declared. A file
that already says `iface <name> inet6 auto`, as some images ship it, means
`auto` too, and `apply --system` keeps that word when it rewrites the file
for `method: auto` rather than turning it into `dhcp`.

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
no multicast, loopback or link local address as the address itself; a
nameserver of either family), so a value the spec accepted is never rejected
at first boot. An IPv4 nameserver in `IP6_DNS*`, which a static IPv6 beside
IPv4 on DHCP exports, and `IP6_SLAAC` need an inithooks that reads them
(2.3.6+keel9 or later): an older `01ipconfig` stops with a fatal error on
the first, before it touches the file, so the image's file stays and the
declared address is not applied, and it ignores the second. The keel
package therefore declares `Breaks: inithooks (<< 2.3.6+keel9~)`: it does
not depend on inithooks, but it cannot be installed beside an older one.

### overlay: the WireGuard interface

The private network the nodes of a replicated appliance share (handbook
decision 0020): this node's side of it, its address, its port, where its
private key is, and the peers it accepts. Each node declares its own; no
node lists the others' configuration, only their public keys.

```yaml
network:
  managed_by: host
  overlay:
    wireguard:
      interface: wg0
      address: fd00:6b65:1::1/64
      listen_port: 51820
      private_key:
        file: /etc/wireguard/wg0.key
      peers:
        - public_key: 0niNkgzhpbKmTSrWCzukb6jaYogKZkGhW+xWlh52Mh8=
          endpoint: "[2001:db8:2::20]:51820"
          allowed_ips: [fd00:6b65:1::2/128]
          persistent_keepalive: 25
```

| Field | State | Notes |
| --- | --- | --- |
| `network.overlay.wireguard.interface` | system | The interface name, as wg-quick accepts it (at most 15 of `A-Z a-z 0-9 _ = + . -`). Default `wg0`. Not a name `network.interfaces` declares |
| `network.overlay.wireguard.address` | system | Required. This node's IPv6 address on the overlay, with its prefix length: a unique local address (`fc00::/7`, RFC 4193), the whole prefix inside that range. `keel network wireguard suggest-address` prints a random one in `fd00::/8` for the first node, `::1` on its /64, and the others take `::2`, `::3` on the same /64. The prefix may not overlap what `network.interfaces` declares or a peer's endpoint address (see "Routes" below) |
| `network.overlay.wireguard.ipv4_address` | system | Optional, an IPv4 address with its prefix length beside the IPv6 one: private, RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or the shared `100.64.0.0/10` (RFC 6598), the whole prefix inside one of them, and clear of the uplink as the IPv6 one is |
| `network.overlay.wireguard.listen_port` | system | The UDP port. Default 51820, written out so peers can name it in their endpoint |
| `network.overlay.wireguard.private_key.file` | system | Where the private key is. Default `/etc/wireguard/<interface>.key`. Only a file: no other backend, and never a value. An absolute path of letters, digits and `. _ - /`, because wg-quick hands it to a shell. Absent, the key is **made** by `apply --system` on the machine itself, `wg genkey` into the file, mode 0600, the first time the overlay is converged (or by `keel network wireguard key`); never under `--root`, where it would end up in an image every appliance built from it would share (keel-core#8). Present, it must be root's and 0600, as every secret file |
| `network.overlay.wireguard.peers` | system | A list; may be empty. Each peer is known by its public key |
| `...peers[].public_key` | system | Required. The peer's key as `wg pubkey` prints it (44 characters of base64). Each key once |
| `...peers[].endpoint` | system | Optional: where to reach the peer, `host:port`. An IPv6 literal goes in brackets, `[2001:db8:2::20]:51820`, as wg writes it; a name or an IPv4 address without. Without it this node waits for the peer to reach it |
| `...peers[].allowed_ips` | system | Required, at least one prefix: what is routed to this peer and accepted from it. For a node, its overlay address as a `/128` (and `/32`). A prefix with host bits set is an error, and so is a prefix given to two peers, since wg would silently keep it for the last one only. Each prefix must be inside the private ranges the overlay addresses use (`fc00::/7`; RFC 1918 or `100.64.0.0/10`): a `/0`, a public prefix (a `::/1` and `8000::/1` pair takes as much as `::/0`) and a prefix that overlaps the uplink or a peer's endpoint are refused (see "Routes" below) |
| `...peers[].persistent_keepalive` | system | Optional, seconds between 1 and 65535: keeps a path through a NAT or a stateful firewall open. Leave it out for none |

**Routes.** `wg-quick` adds a route for the overlay's own prefixes and
for each peer's `allowed_ips`. A route that covers the uplink would send
the uplink's replies into the overlay, and the machine would be cut off
from the network it is managed over. So an overlay address and every
`allowed_ips` prefix must be private (`fc00::/7`; RFC 1918 or
`100.64.0.0/10`), which refuses a `/0` and any public prefix whatever the
uplink is, and validation refuses one that overlaps anything
`network.interfaces` declares (an address's prefix, a gateway) or the
address of a peer's endpoint. An endpoint given by name, and an uplink
on a private prefix left to DHCP, SLAAC or the container's host, cannot
be checked from the spec: `keel network confirm` asks the machine where
the routes to the gateways, declared and live, and to the confirming
client leave through ([docs/apply.md](apply.md)).

The overlay belongs to the appliance on either kind of machine (decision
0018): its file is `/etc/wireguard/<interface>.conf`, which the host of a
container does not write, so it is converged from inside even with
`managed_by: host`. `apply --system` renders it, brings it up under the
same confirmation window as the uplink and enables `wg-quick@<interface>`
once the change is confirmed ([docs/apply.md](apply.md)); `keel inspect`
reads it back, with the public key the key file gives, and `keel diff`
compares each peer with the peer of the same key. The file holds no
private key: a `PostUp` line gives the key file to `wg set`, so the key
is read by `wg` alone:

```
[Interface]
Address = fd00:6b65:1::1/64
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/wg0.key

[Peer]
PublicKey = 0niNkgzhpbKmTSrWCzukb6jaYogKZkGhW+xWlh52Mh8=
Endpoint = [2001:db8:2::20]:51820
AllowedIPs = fd00:6b65:1::2/128
PersistentKeepalive = 25
```

What it needs from the machine: the `wireguard-tools` package (`wg`,
`wg-quick`), and the `wireguard` kernel module. A VM loads the module
itself when the interface comes up. An unprivileged container cannot: the
host must have it loaded (`modprobe wireguard` on the host, and
`wireguard` in its `/etc/modules-load.d/`), and without it `apply`
refuses and says so, and `keel inspect` reports it.

The overlay is not removed when the section is: a spec without it leaves
the interface as it is.

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

A spec that names an appliance also accepts every secret its manifests
declare (see "appliance, installation and overlays"), rendered as
`KEEL_SECRET_<NAME>`, the name upper cased, and masked like the three
above; `generate: true` is refused for one whose manifest says `generate:
never`, since a person must choose it. Any other name is an error.

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
| `app.options.<key>` | read | `APP_<KEY>` | The key is upper cased and prefixed. It must be a valid shell variable name. This is where appliance specific inithook parameters go. In a spec that names an appliance the keys are the options its manifests declare, each of its declared type (`string`, matching its `pattern` when there is one; `integer`; `boolean`; `enum`, one of its `values`), and an option declared without a default must be given |

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
| mariadb | A grant of `REPLICATION SLAVE` to the replication account from that origin, which is the `Host` part of the account, with `SELECT`, `SHOW VIEW`, `TRIGGER` and `EVENT` beside it so a new replica can copy what the primary already holds ([docs/apply.md](apply.md)) |
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

**On MariaDB, an IPv6 prefix with a zero group the text can drop has no
pattern either.** The pattern is matched against the text of the client's
address, and that text writes the longest run of zero groups as `::`. When
the last group of the prefix is zero, or two of its groups in a row are, some
addresses of the prefix are written without them: in `fd3d:80b2:d0d7::/64`,
which is what `keel network wireguard suggest-address` prints, the replica
`fd3d:80b2:d0d7::2` does not match `fd3d:80b2:d0d7:0:%`. No pattern holds
such a prefix exactly and MariaDB has no IPv6 netmask, so validation refuses
it when the engine is `mariadb`, naming an address it would have missed. A
host pattern with `::` is refused on every engine: `::` stands for a number
of zero groups no wildcard counts, so `2001::5:%` holds addresses outside any
one prefix. **Write each replica's address
instead**, as the overlay's peers are written:

```yaml
    replication:
      allowed_from:
        - fd3d:80b2:d0d7::2      # the replica's overlay address
        - fd3d:80b2:d0d7::3
```

A prefix whose groups are all written, `2804:710:d0:5::/64` or
`2001:db8:0:5::/64` (a lone zero between two groups is never compressed),
keeps working as a pattern, and PostgreSQL takes any prefix as it is.

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
| `monitor.enabled` | system | `true` or `false`; absent inside a declared `monitor` section is off. `apply --system` writes `/etc/monit/conf.d/keel.conf` and `/etc/keel/monitor.json` when true and removes them, if keel wrote them, otherwise ([docs/apply.md](apply.md)). A spec with no `monitor` section at all leaves the monitor as an earlier apply set it, as every other section does when absent, and says so: only `enabled: false`, or a section that does not say `enabled: true`, turns it off (keel#46). `monitor:` with no value is YAML for no section and counts as one. `true` without a working channel under `notify` is an error: a monitor with nobody to tell looks like one and is not |
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

## appliance, installation and overlays

What this machine runs, as the appliance manifests of handbook decision
0041 describe it (docs/manifest-v1.md in the handbook; docs/manifest.md
here). The manifest holds the facts (which overlays an appliance
carries, their default in each mode, what each runs and listens on); the
spec holds this machine's choices.

```yaml
appliance:
  name: core
installation:
  mode: simple              # simple, cloud_simple or cloud_advanced (0028)
overlays:                   # every overlay of the chain, written out (0027)
  installer: enabled
  wireguard: disabled
  etcd: disabled
  crowdsec: disabled
```

| Field | State | Notes |
| --- | --- | --- |
| `appliance.name` | system | The appliance manifest this machine runs, `[a-z][a-z0-9-]*`, at most 32 characters. It must be installed under `/usr/share/keel/appliances/` of the root the command works on, valid, and resolve along its `base` chain |
| `installation.mode` | read | `simple`, `cloud_simple` or `cloud_advanced`. Chosen once, at installation: it picks the column of defaults the installer starts from, and nothing converges it. Moving a machine between modes is out of scope |
| `overlays.<name>` | system | `enabled` or `disabled`, for every overlay of the resolved chain, none left out and none added. `apply --system` enables and starts, or stops and disables, the overlay's units, and derives Monit's checks from what is enabled ([docs/apply.md](apply.md)) |

The words are `enabled` and `disabled`: YAML reads an unquoted `on`,
`off`, `yes` or `no` as a boolean, and such a value is refused with that
reason. `ask` is the manifest's, a question the installer asks, and never
reaches a spec. `overlays` without `appliance` is an error.

**Held against the manifests** (rules 25 to 27 of the format). A spec
that names an appliance is checked against the manifests installed under
the root of the command: `/` for `spec validate`, `spec render` and
`network wireguard key`, `--root` for `spec validate --root`, `apply`,
`diff` and `database promote`. The appliance must be installed and
resolve; `overlays` names exactly the overlays of the chain; an `enabled`
overlay has every overlay it `requires` enabled; a secret is one of the
three above or a name a manifest declares, and `generate: true` is
refused where the manifest says `never`; `app.options` are declared
options of their type, a required one present. A spec that names no
appliance is checked as before, and needs no manifest at all.

`keel inspect` writes `appliance.name` from the one installed appliance
manifest no other is built on, the overlays that own units from systemd,
and `installation.mode` and the overlays without a unit from the spec the
installer emitted at `/etc/keel/instance.yaml`, reporting them as not
inferred otherwise. `keel diff` compares the name, each overlay's state
with systemd, and Monit's derived file with what apply renders
([docs/diff.md](diff.md)).

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
