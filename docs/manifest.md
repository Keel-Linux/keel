# keel manifest

`keel manifest validate` and `keel manifest show` read the appliance
manifest of decision 0041, version 1: an **overlay manifest** says what
one overlay runs (its processes, what they listen on, their checks, its
data), and an **appliance manifest** says what an appliance is built on
(`base`), which overlays it adds with their default state in each
installation mode, and what it runs itself. One schema for both, versioned
by the integer `manifest_version`, with unknown keys refused at every
level. The format, with every field, the worked examples of Keel Core and
Keel Web and the validation rules, is `docs/manifest-v1.md` in the
handbook; this page says what keel does with it.

This is step 1 of the first implementation of 0041: the reader and these
two commands. Nothing else in keel reads a manifest yet: `spec validate`,
`spec apply --system`, `inspect` and `diff` learn about them in step 3.

The appliance manifest is not the **layer manifest** of
[docs/layers.md](layers.md), the key-value file `bt-layer` writes beside a
layer tarball: that one records how a layer was built, this one what an
appliance is. The `kind` key of an appliance manifest keeps the two apart.

## Where the manifests are

| Kind | Path | Shipped by |
| --- | --- | --- |
| `overlay` | `/usr/share/keel/overlays/<name>.yaml` | the overlay's package, `keel-overlay-<name>` |
| `appliance` | `/usr/share/keel/appliances/<name>.yaml` | the appliance's package, `keel-core`, `keel-web` |

Every path is read under `--root` (default `/`, the live system), as for
`inspect` and `diff`: a package build or a test points it at a tree of its
own. The unit files and first boot hooks a manifest names are looked up
under the same root.

## keel manifest validate

```
keel manifest validate
keel manifest validate web
keel manifest validate packages/etcd/debian/keel-overlay-etcd/usr/share/keel/overlays/etcd.yaml
keel manifest validate --root /tmp/build web
```

With no argument, every installed manifest, and every appliance resolved
along its chain. With a NAME, the manifests of that name (an overlay and an
appliance may share one; `--kind` picks one). With a PATH, that file, read
against the manifests installed under `--root`: a target with a `/` or a
`.yaml` suffix is a PATH, anything else a NAME.

Every error is printed at once, each with the file and the key it concerns,
lists indexed from 0:

```
Error: /usr/share/keel/overlays/nginx.yaml: processes[0].listen[1].port: must be a port number between 1 and 65535
Error: /usr/share/keel/appliances/web.yaml: overlays.nginx.simple: read as the boolean true: YAML 1.1 turns an unquoted on, off, yes or no into a boolean; write enabled, disabled or ask
```

A file that passes prints `PATH: ok`, and an appliance also the chain it
resolves along, `web: resolved along core, web`.

| Option | Meaning |
| --- | --- |
| `PATH` or `NAME` | One file, or the manifests of one name. Default: every installed manifest |
| `--kind overlay\|appliance` | Which kind a NAME is. For a PATH, the kind the file must say. Default: either |
| `--root DIR` | Where `/usr/share/keel`, the unit files and the hooks are. Default `/` |

### What is checked

Every rule of the format's "Validation rules" that a manifest can break
alone or with the manifests it names, rules 1 to 24:

| Rules | Checked |
| --- | --- |
| 1, 2 | `manifest_version` is the integer 1 (a newer one is named with the one this keel reads); `kind`; `name` is `[a-z][a-z0-9-]*`, at most 32 characters, and the file name without `.yaml`; `title` and a one line `summary`. Unknown keys at every level, and keys of the other kind (`base` in an overlay) |
| 3, 4 | Names of processes, checks, services and workers are `[a-z][a-z0-9_-]*`, of secrets and options `[a-z][a-z0-9_]*`, unique in their list. Paths are absolute, with no `..`, no `//` and no trailing `/` |
| 5 to 9 | A unit ends in `.service` and has a unit file under the root (in `/usr/lib/systemd/system`, `/lib/systemd/system` or `/etc/systemd/system`, or an init script in `/etc/init.d` for systemd's sysv generator). Ports 1 to 65535; a literal `address` is `::1` or `127.0.0.1`, with `expose: loopback`, and `localhost` is refused with the reason of [docs/spec.md](spec.md). A check has the fields of its type and no others, names a process of its overlay or of its appliance's chain, and has one for `on_failure: restart`. `restart` is `never` or at most `attempts` within `within_cycles`. A command is an argv list starting with an absolute path |
| 10 to 12 | `requires` names installed overlays, without a cycle. `data[].replication` is `native` or `none`, never `files`; `backup: dump` only with a `provides` engine that has a dump. First boot hooks are under `/usr/lib/inithooks/firstboot.d/`, exist, are executable, owned by root and not writable by group or others |
| 13 to 20 | The `base` chain exists, has no cycle and ends at `core`, whose base is `none`. Every overlay is installed and has all three states, each `enabled`, `disabled` or `ask`, and `ask` only with a `screen`. What an `enabled` or `ask` overlay requires is `enabled` in that mode, across the chain. An overlay once in a chain; a `(port, protocol)` once across every process of the chain, whatever the states; process, check, secret and option names once; application sections in one manifest of a chain, its top. A `shared` secret is generated |
| 21 to 24 | The application sections of the appendix: engines, placements, `none` only for an optional service, and `embedded` only where an overlay providing the engine is `enabled`; the secret, `needs` and `queue` a manifest names are its own; replicated paths outside the system directories, not nested, not inside an overlay's `data`, excludes inside them, `unless` naming an optional service; a worker with a unit and no `writes`, `default` at most `max`, `singleton` with `max: 1` |

Rules 25 to 27 check an instance spec against the manifests; `keel spec
validate` runs them from step 3.

**States are words.** A YAML 1.1 reader (PyYAML, which keel uses) reads an
unquoted `on`, `off`, `yes` or `no` as a boolean, so a state written `on`
arrives as `True`. It is refused with that explanation rather than taken
for `enabled`, and the output of `show` never prints a state as a boolean.

**A key twice is an error.** Where YAML would keep the second of two equal
keys in one mapping, the reader refuses the file (`line 12: nginx appears
twice`), so an overlay listed twice cannot lose its first states silently.

## keel manifest show

```
keel manifest show etcd
keel manifest show web --resolved
```

Without `--resolved`, the file as it is installed. With it, the appliance
resolved along its `base` chain, as tables: the overlays with their state in
each mode and the appliance that carries each, the ports grouped by process
with their exposure, then the processes with their restart limit, the
checks with what they probe, the secrets with their policy, the options,
the first boot hooks and the application sections. A manifest that fails
validation, or a chain that does not resolve, is not shown: the errors are
printed as `validate` prints them. `--resolved` is for appliances only.

The first two tables of `show web --resolved` on Keel Web are the format's,
row for row:

```
Keel Web (web), resolved along core, web

Overlays
| Overlay | From | simple | cloud simple | cloud advanced |
| --- | --- | --- | --- | --- |
| installer | core | enabled | enabled | enabled |
| wireguard | core | disabled | enabled | enabled |
| etcd | core | disabled | disabled | enabled |
| crowdsec | core | disabled | enabled | enabled |
| nginx | web | enabled | enabled | enabled |
| coraza | web | disabled | enabled | enabled |
| anubis | web | disabled | enabled | enabled |

Ports
| Port | Process | From | Exposure |
| --- | --- | --- | --- |
| 22/tcp | sshd | core | public |
| 25/tcp | postfix | core | loopback |
| 80/tcp, 443/tcp | nginx | web (nginx) | public |
| 2379/tcp, 2380/tcp | etcd | core (etcd) | mesh |
| 6060/tcp, 8080/tcp | crowdsec | core (crowdsec) | loopback, IPv4 |
| 8923/tcp | anubis | web (anubis) | loopback |
| 12320/tcp | webshell | core | public |
| 12321/tcp | webmin | core | public |

Processes
| Process | Unit | From | Restart |
| --- | --- | --- | --- |
| sshd | ssh.service | core | 3 restarts within 5 cycles |
...

Checks
| Check | Process | From | Probe | On failure | Every |
| --- | --- | --- | --- | --- | --- |
| sshd | sshd | core | ssh loopback port 22 | restart | 1 cycle |
...
| waf-blocks | none | web (coraza) | http loopback port 80 /keel-health?keel-waf-probe=%3Cscript%3Ealert(1)%3C%2Fscript%3E, expects 403 | alert | 10 cycles |
...

Secrets
| Secret | From | Generate | Shared | Description |
| --- | --- | --- | --- | --- |
| root_password | core | allowed | no | The root password, for SSH and Webmin |
| anubis_signing_key | web (anubis) | required | yes | The key Anubis signs its challenge cookies with |

Options
none

First boot hooks
| Hook | From |
| --- | --- |
| /usr/lib/inithooks/firstboot.d/00declarative | core (installer) |
...

Application
none
```

`From` names the appliance, and in brackets the overlay of it that declares
the thing. `loopback, IPv4` is a port whose process binds `127.0.0.1` only
(`IPv6` for `::1` only); plain `loopback` is both. A process without a
`restart` has the default, 3 restarts within 5 cycles.

| Option | Meaning |
| --- | --- |
| `NAME` | The manifest to print |
| `--resolved` | The appliance resolved along its chain, as tables |
| `--kind overlay\|appliance` | Which kind NAME is, when an overlay and an appliance share it |
| `--root DIR` | Where `/usr/share/keel` is. Default `/` |

`show --derived`, which prints what `apply` would write for Monit, the
firewall, the backup and replication, comes with the renderers of step 3.

## Exit codes

The codes of `spec validate`:

| Code | Name | When |
| --- | --- | --- |
| 0 | `OK` | Every manifest checked is valid and every appliance resolves; or none is installed, which says so on standard error |
| 1 | `USAGE` | `show` was asked to resolve an overlay, or a NAME both kinds share without `--kind` |
| 2 | `SPEC_UNREADABLE` | A manifest cannot be read, is not valid YAML, repeats a key or is not a mapping; or no manifest has the NAME. Wins over 3 |
| 3 | `SPEC_INVALID` | A manifest fails validation, or its appliance does not resolve; every error is printed |

## Tests

`tests/fixtures/manifest/` holds the overlay and appliance manifests of the
format's worked examples, Keel Core and Keel Web, byte for byte, and
`tests/manifest_helpers.py` installs them under a temporary root with the
unit files and hooks they name. `tests/test_manifest_rules.py` has one
class per validation rule, 1 to 20, each with the fixture it refuses and
the message; `tests/test_manifest_app.py` does rules 21 to 24 on an
application fixture that uses every section of the appendix, and
`tests/test_manifest_cli.py` checks that `show web --resolved` prints the
format's tables exactly.
