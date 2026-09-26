# keel diff

`keel diff` reports drift between the declared spec and the machine,
field by field (brief section 5.2). The declared side is the spec file,
loaded and validated exactly as `spec apply` reads it. The observed side
is what `keel inspect` collects, through the same collector and the same
probes, so there is one code path for reading a machine and a spec
written by inspect diffs clean against the machine it was read from.

It is read only: nothing is written to the system, to the spec or
anywhere else. Secrets are never read, on either side.

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
| 3 | `SPEC_INVALID` | The spec fails validation; every error is printed, nothing is inspected |
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

Two more lines describe what is deliberately not compared, one per
declared section: `not compared`, with the reason.

```
instance.hostname: same (blog)
instance.fqdn: drift (declared blog.example.org, observed shop.example.org)
network.managed_by: same (host)
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
security.updates: unknown (declared force; not inferred: /etc/cron-apt/config permission denied (root only))
locale.timezone: same (Europe/Lisbon)
diff: 12 same, 1 drift, 1 unknown, 1 not declared, 1 not compared; drift found
```

## What is compared, and against what

The sections inspect observes are compared: `instance`, `network`, `tls`,
`security`, `hub`, `users` and `locale`. Each is flattened to the dotted
leaf paths the inspect report uses, so `network.interfaces.eth0.ipv6`
becomes one line per `method`, `address` and `gateway`, and a list
(`network.nameservers`, `tls.acme.domains`, `users.<name>.authorized_keys`)
is one leaf compared as a sequence, in order. The sources of every
observed value are in [docs/inspect.md](inspect.md).

A field inspect wrote is compared as it stands, even when inspect also
noted something about that field it could not express (a `v4tunnel`
stanza next to a `dhcp` one, a loopback resolver next to real ones). That
is what makes the round trip hold. A field inspect could not infer at all
is `unknown`, never `drift`, and `network.managed_by` is unknown whenever
the interfaces are, because inspect derives one from the other.

Normalisation, so that spelling is not drift: keywords (`security.alerts`,
`security.updates`, `hub.api_key`) and domain names (`hostname`, `fqdn`,
`tls.acme.domains`) compare case insensitively and without a trailing dot;
addresses, gateways and nameservers compare in canonical form
(`2001:DB8:0001::10/64` equals `2001:db8:1::10/64`); booleans compare as
booleans. Everything else compares as a stripped string.

Not compared, each with its reason in the output when the spec declares
it:

| Section | Why |
| --- | --- |
| `secrets` | Values are never read, on either side. A `hub.api_key` given as a secret reference is not compared for the same reason |
| `app` | `inithooks.conf` is root only and consumed at first boot, so `app` values leave no trace to compare against; inspect's `app.domain` falls back to the fqdn, which would be a false drift |
| `first_login_wizard`, `preseed` | Render time switches with no trace on the running machine |

`version` is a property of the file, not of the machine, and is not
listed.

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
      "reason": ""
    },
    {
      "field": "security.updates",
      "section": "security",
      "status": "unknown",
      "declared": "force",
      "observed": null,
      "reason": "/etc/cron-apt/config permission denied (root only)"
    }
  ],
  "counts": {"same": 1, "drift": 0, "unknown": 1, "not_declared": 0, "not_compared": 0},
  "drift": false,
  "incomplete": true,
  "exit_code": 13
}
```

`declared` and `observed` are the values as the spec and inspect hold
them (a string, a boolean, a list), `null` when absent. `exit_code` is the
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
same machine exits 0 with no drift and no unknown field. A spec fresh from
inspect names secret files that do not exist yet, and `diff` validates
the spec like every other command, so it reports those files as missing
(exit 3) until the operator creates them, or points `inspect
--secrets-dir` at a directory that has them. That is the intended
reminder from [docs/inspect.md](inspect.md), not a diff of its own.

## Tests

`tests/test_diff.py` covers the model and the comparison as pure
functions, one test per branch, and each observable section with a spec
that matches the `turnkey` fixture and one that drifts on that section.
`tests/test_diff_cli.py` covers the exit codes, their precedence, the
JSON document, the no-write guarantee, and the round trip: every fixture
tree under `tests/fixtures/inspect/` inspected into a spec and diffed
against itself reports no drift, no unknown field and exits 0.
