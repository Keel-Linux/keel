# Keel

Keel describes one appliance instance in a single file and applies it
idempotently, so that a machine is declared rather than configured by hand. It
is compatible with TurnKey Linux appliances: the spec is rendered into the
`inithooks.conf` variables the existing firstboot hooks already read, so no
hook has to know that the spec exists. The library is the only implementation
of that logic, and both the `keel` command and confconsole are clients of it,
which means every operation runs headless from the same code path.

## Status

Working today: `spec validate`, `spec render`, `spec apply`, and the layers
half of `verify` (see [docs/layers.md](docs/layers.md)).

Stubs that print what they will do, name the brief section covering them and
exit 9: `inspect`, `diff`, and the packages half of `verify`. They never
pretend to work.

## Commands

| Command | What it does |
| --- | --- |
| `keel spec validate` | Check the spec and report every error it finds, not just the first |
| `keel spec render` | Print the conf that `apply` would write, with every secret masked |
| `keel spec apply` | Write the conf, leaving an existing non empty conf untouched |
| `keel inspect` | Write a spec from the running machine (brief section 5.2, not implemented yet) |
| `keel diff` | Report drift between the declared and the running state (brief section 5.2, not implemented yet) |
| `keel verify` | Check the installed layers against their manifests, one line per layer (brief section 5.4; packages not implemented yet) |

Every command accepts the same three options, so a caller never has to branch:

| Option | Meaning |
| --- | --- |
| `--spec FILE` | Instance spec to read. Default: `$KEEL_SPEC`, else `/etc/keel/instance.yaml` |
| `--conf FILE` | Conf file to write. Default: `$KEEL_CONF`, else `/etc/inithooks.conf` |
| `--non-interactive` | Never prompt. This is already the only behaviour; the flag is accepted so that callers can pass it unconditionally |

`keel verify` also accepts:

| Option | Meaning |
| --- | --- |
| `--layers-dir DIR` | Directory of layer manifests. Default: `$KEEL_LAYERS_DIR`, else `/var/lib/keel/layers` |
| `--tarballs-dir DIR` | Directory of the tarballs and `.hash` files. Default: the layers directory |

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
| 5 | `CONF_ERROR` | The conf file cannot be written |
| 6 | `MANIFEST_INVALID` | A layer manifest cannot be read or fails validation; every problem is printed |
| 7 | `LAYER_MISMATCH` | A layer tarball, parent chain or `.hash` digest does not match its manifest |
| 8 | `SIGNATURE_UNVERIFIED` | Every layer matches, but a `.hash` file is present whose signature was not verified (no trusted key is configured yet) |
| 9 | `NOT_IMPLEMENTED` | The command is a documented stub, or the part of it that is (`verify` exits 9 after the layers pass, because packages are not checked yet) |

Two rules that callers depend on:

- an absent spec file is a no-op and exits 0, so an image without a spec
  behaves exactly as it does today;
- a conf file that already holds something other than whitespace wins and is
  never clobbered, so a hand written or platform supplied preseed keeps
  priority over the spec;
- `verify` never claims more than it checked: a signature is reported as
  present, never as verified, until a trusted key exists.

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

Every menu action has a headless equivalent with the same exit code, and the
tests exercise the CLI, so the TUI cannot drift away from it. The layer
check is `keel.layers.verify_layers()`, described in
[docs/layers.md](docs/layers.md).

## Tests

```
pytest
python3 -m unittest discover tests
```

Both runners run the same suite. It needs no network, no root and no installed
package. The coverage standard (95 percent, lines and branches) and the
commands that check it are in `tests/README.md`.
