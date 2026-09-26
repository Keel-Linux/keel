# Keel

Keel describes one appliance instance in a single file and applies it
idempotently, so that a machine is declared rather than configured by hand. It
is compatible with TurnKey Linux appliances: the spec is rendered into the
`inithooks.conf` variables the existing firstboot hooks already read, so no
hook has to know that the spec exists. The library is the only implementation
of that logic, and both the `keel` command and confconsole are clients of it,
which means every operation runs headless from the same code path.

## Status

Working today: `spec validate`, `spec render`, `spec apply` (see
[docs/apply.md](docs/apply.md)), `inspect`
(see [docs/inspect.md](docs/inspect.md)), `diff` (see
[docs/diff.md](docs/diff.md)), `pull`, `assemble`, and the layers half of
`verify` (see [docs/layers.md](docs/layers.md)).

One stub prints what it will do, names the brief section covering it and
exits 9: the packages half of `verify`. It never pretends to work.

## Commands

| Command | What it does |
| --- | --- |
| `keel spec validate` | Check the spec and report every error it finds, not just the first; the secret files are checked too, unless `--no-secret-files` |
| `keel spec render` | Print the conf that `apply` would write, with every secret masked |
| `keel spec apply` | Write the conf, leaving an existing non empty conf untouched; with `--system`, also converge users (accounts, authorized keys), timezone and locale, only where they differ, never touching a password (brief section 4, principle 1) |
| `keel inspect` | Write a spec from the running machine, or from an offline root, and report every field with its source or why it was not inferred; secrets are never read (brief sections 5.2 and 7) |
| `keel diff` | Report drift between the spec and the running machine, or an offline root, field by field, through the same collector `inspect` uses; secrets are never compared and their files need not exist, nothing is written (brief section 5.2) |
| `keel verify` | Check the installed layers against their manifests, one line per layer (brief section 5.4; packages not implemented yet) |
| `keel pull` | Fetch the layers of an appliance that the cache does not have yet, from a directory or an http(s) URL, checking every digest (brief section 5.1) |
| `keel assemble` | Extract a cached chain into a rootfs, honouring whiteouts and opaque directories, and pack it as a Proxmox template with its sha512 (brief section 5.1; root only) |

Every command accepts the same three options, so a caller never has to branch:

| Option | Meaning |
| --- | --- |
| `--spec FILE` | Instance spec to read. Default: `$KEEL_SPEC`, else `/etc/keel/instance.yaml` |
| `--conf FILE` | Conf file to write. Default: `$KEEL_CONF`, else `/etc/inithooks.conf` |
| `--non-interactive` | Never prompt. This is already the only behaviour; the flag is accepted so that callers can pass it unconditionally |

`keel spec validate` also accepts:

| Option | Meaning |
| --- | --- |
| `--no-secret-files` | Check the structure of every secret reference but not that the file exists with the right owner and mode. For a machine that does not hold the secrets. The output says whether the files were checked |

`keel spec apply` also accepts:

| Option | Meaning |
| --- | --- |
| `--system` | After the conf, converge the system state the spec declares: users with their authorized keys, timezone, locale. Root on the live system. Off by default in this version |
| `--dry-run` | With `--system`: print the plan and change nothing, not even the conf; reads no secret and needs no root |
| `--root DIR` | The filesystem `--system` converges: `/` (the default, the live system) or a scratch tree. The conf path stays `--conf` |

`keel verify` also accepts:

| Option | Meaning |
| --- | --- |
| `--layers-dir DIR` | Directory of layer manifests. Default: `$KEEL_LAYERS_DIR`, else `/var/lib/keel/layers` |
| `--tarballs-dir DIR` | Directory of the tarballs and `.hash` files. Default: the layers directory |

`keel inspect` accepts:

| Option | Meaning |
| --- | --- |
| `--root DIR` | Filesystem to inspect: `/` (the default, the live system), a mounted container rootfs, or the tree `keel assemble` produced |
| `--output FILE` | Write the spec here, mode 0600. Default: stdout |
| `--report FILE` | Write the field by field report here. Default: stderr |
| `--secrets-dir DIR` | Where the secret placeholders point. Default: `/etc/keel/secrets`. Never read or written |

`keel diff` accepts:

| Option | Meaning |
| --- | --- |
| `--root DIR` | Filesystem to compare with the spec: `/` (the default, the live system), a mounted container rootfs, or the tree `keel assemble` produced |
| `--format text|json` | One line per field and a summary (the default), or one JSON document for a calling program |

`keel pull` and `keel assemble` accept:

| Option | Meaning |
| --- | --- |
| `LAYER` | The layer to pull (a name at the source, or the path of its manifest file) or to assemble (a name in the cache) |
| `--cache-dir DIR` | The layer cache. Default: `$KEEL_CACHE_DIR`, else `/var/cache/keel/layers` |
| `--source URL-or-DIR` | `pull` only, required: where manifests and tarballs are served, for example `http://[2001:db8:19::1]/layers` or `/mnt/builds/layers` |
| `--rootfs DIR` | `assemble` only, required: the directory to extract into; created, must be empty |
| `--template FILE` | `assemble` only: also pack the rootfs into this `.tar.zst`, with `FILE.sha512` next to it |
| `--sha256 HEX` | `assemble` only: which cached version of `LAYER`, when more than one is cached |

`keel` and `python3 -m keel` are the same program.

## Exit codes

Defined in one place, `keel/exits.py`, and reproduced here.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `OK` | Success, including the no-op cases: an absent spec file, and an `apply` that left a populated conf alone |
| 1 | `USAGE` | Usage error: unknown command, option or argument |
| 2 | `SPEC_UNREADABLE` | The spec file cannot be read, or is not valid YAML, or is not a mapping |
| 3 | `SPEC_INVALID` | The spec file is valid YAML but fails validation; every error is printed |
| 4 | `SECRET_ERROR` | A referenced secret is missing, or is readable by somebody other than its owner |
| 5 | `CONF_ERROR` | The conf file, or the spec or report `inspect` writes, cannot be written |
| 6 | `MANIFEST_INVALID` | A layer manifest cannot be read or fails validation; every problem is printed |
| 7 | `LAYER_MISMATCH` | A layer tarball, parent chain or `.hash` digest does not match its manifest |
| 8 | `SIGNATURE_UNVERIFIED` | Every layer matches, but a `.hash` file is present whose signature was not verified (no trusted key is configured yet) |
| 9 | `NOT_IMPLEMENTED` | The command is a documented stub, or the part of it that is (`verify` exits 9 after the layers pass, because packages are not checked yet) |
| 10 | `LAYER_UNAVAILABLE` | `pull` could not fetch a manifest or tarball from the source or write the cache; `assemble` found a layer of the chain missing from the cache |
| 11 | `ASSEMBLE_NEEDS_ROOT` | `assemble` was run by a user other than root; nothing was written |
| 12 | `ASSEMBLE_FAILED` | The rootfs is not empty or cannot be created, or `tar` or `zstd` failed while extracting or packing |
| 13 | `INSPECT_INCOMPLETE` | `inspect` wrote the spec, but a required field (hostname, fqdn, interfaces, alerts, updates) could not be inferred; or `diff` found no drift, but a declared field could not be observed. The report says which and why |
| 14 | `DRIFT_FOUND` | `diff` found at least one declared field whose observed value differs. Drift wins over unobserved fields, so a report with both exits 14 |
| 15 | `APPLY_NEEDS_ROOT` | `apply --system` on the live system was run by a user other than root; nothing was written, not even the conf |
| 16 | `APPLY_FAILED` | `apply --system` could not make at least one change; the output names it. The conf was written and every other change was made, so the run can be repeated |

Two rules that callers depend on:

- an absent spec file is a no-op and exits 0, so an image without a spec
  behaves exactly as it does today;
- a conf file that already holds something other than whitespace wins and is
  never clobbered, so a hand written or platform supplied preseed keeps
  priority over the spec;
- `verify` never claims more than it checked: a signature is reported as
  present, never as verified, until a trusted key exists;
- `pull` never puts a tarball in the cache under a digest it does not
  have, and `assemble` never extracts a tarball it did not check;
- `inspect` never reads a secret: every secret is written as a file
  reference and reported as not extracted, and the spec is written even
  when the exit code says it is incomplete;
- `diff` compares only what the spec declares, never reads a secret and
  writes nothing; a spec `inspect` wrote diffs clean against the machine
  it was read from, even when the secret files it names do not exist
  there, because secrets are references and a machine that is only being
  compared may not hold them;
- `apply --system` changes only what differs, deletes nothing and never
  touches a password; a second run changes nothing, and `--dry-run`
  changes nothing at all ([docs/apply.md](docs/apply.md)).

## An instance file

IPv6 is the primary family. IPv4 is optional and never assumed.

```yaml
version: 1

instance:
  hostname: blog
  fqdn: blog.example.org

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

tls:
  acme:
    enabled: true
    challenge: http-01
    domains:
      - blog.example.org

secrets:
  root_password:
    file: /etc/keel/secrets/root_password
  db_password:
    generate: true

app:
  email: admin@example.org
  domain: blog.example.org
  options:
    ip_bind: "[2001:db8:1::10]"

security:
  alerts: admin@example.org
  updates: force

hub:
  api_key: skip
```

The same file is in `examples/instance.yaml`. Field by field, including which
fields are read today and which are accepted but not yet acted on, see
[docs/spec.md](docs/spec.md).

## How confconsole calls this

confconsole is a thin TUI over this library and holds no logic of its own
(brief section 6). A dialog collects values, writes them into the spec file,
and then calls the library. It does not shell out to the CLI and it does not
reimplement any check.

```python
from keel import exits, spec

document = spec.load("/etc/keel/instance.yaml")
errors = spec.validate(document)
if errors:
    show_errors(errors)
else:
    preview = spec.mask(spec.render_env(document, spec.masked_secrets(document)))
    show_preview(preview)
```

`spec.masked_secrets()` is what makes a preview safe: rendering for display
never reads a secret file and never generates a value.

To converge, a dialog calls the command function rather than the parts,
because that is where the no-clobber rule and the warnings live:

```python
from argparse import Namespace

from keel import commands, exits

args = Namespace(
    spec="/etc/keel/instance.yaml",
    conf="/etc/inithooks.conf",
    non_interactive=True,
)
code = commands.spec_apply(args)
if code != exits.OK:
    show_error(exits.DESCRIPTIONS[code])
```

The same call with `system=True`, `dry_run=False` and `root="/"` in the
Namespace runs the system phase as well ([docs/apply.md](docs/apply.md)).

Every menu action has a headless equivalent with the same exit code, and the
tests exercise the CLI, so the TUI cannot drift away from it. The layer
check is `keel.layers.verify_layers()`, described in
[docs/layers.md](docs/layers.md).

## Tests

```
pytest
python3 -m unittest discover tests
```

Both runners run the same suite. It needs `tar`, `zstd` and the IPv6
loopback, no other network, no root and no installed package. The coverage standard (95 percent, lines and branches) and the
commands that check it are in `tests/README.md`.

## License

GPL-3.0-or-later. See LICENSE. Parts are derived from TurnKey Linux inithooks (GPL-2.0-or-later, Copyright 2009 Alon Swartz and 2010-2026 TurnKey Linux maintainers).
