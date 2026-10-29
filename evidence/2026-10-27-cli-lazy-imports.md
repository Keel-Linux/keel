# Evidence: the keel CLI builds its parser without loading the library, 2026-10-27

Change: `keel/cli.py` keeps handler references as dotted names and imports
one at dispatch; `keel/commands.py` imports `diff`, `inspect`, `layers`,
`network` and `system` inside the handlers that use them; parser constants
live in `keel/constants.py`; `keel.monitor.constants` holds the notify
names; `keel.mesh.parser` and `keel.mesh.vipcli` import their heavy
modules on use. `keel.network.live` imports `Probes` on call, breaking a
cycle the old eager `keel.commands` import had hidden. `keel.version()`
reads metadata only when `--version` or `__version__` asks.

This is 0.23.56+perf1, ported from the 0.20.0 measurement to the 0.23.55
source the image's 0.23.56 package is built from.

## Host measurement, not the appliance

Python 3.14.8, this checkout, `PYTHONPATH=.`:

```text
python3 -X importtime -c 'import keel.cli'    10743 us
```

After the change, `keel.cli` loads none of `keel.commands`, `keel.diff`,
`keel.inspect`, `keel.layers`, `keel.manifest`, `keel.mesh.commands`,
`keel.system` or `importlib.metadata` (the `tests/test_lazy_imports.py`
asserts it). `keel --help` and `keel --version` both exit 0.

The 0.20.0 source measured 37637 us on the same host; the image's 0.23.56
`keel.cli` import on the Core layer was 179676 us, and the 0.20.0 lazy
package measured `keel --help` 40 ms cold / 31 ms warm against 274 / 215
before. The 0.23.56+perf1 package is the one this port builds; its
real-image number is the next run.

## Tests

The relevant subset passes:

```text
201 passed, 28 subtests passed in 4.99s
```

The full suite includes the multi-node netns tests, which exceed a
10-minute local run on this workstation; the 0.20.0 full suite was 3129
passed, 21 skipped. The package build runs the subset on the TKLDev VM.

## Files

- `keel/cli.py`, `keel/commands.py`, `keel/__init__.py`
- `keel/constants.py`, `keel/monitor/constants.py`
- `keel/mesh/parser.py`, `keel/mesh/vipcli.py`
- `keel/monitor/channelfile.py`, `keel/monitor/notify.py`
- `keel/network/live.py`, `keel/network/wireguard.py`
- `keel/layers/constants.py`, `keel/layers/layout.py`
- `keel/spec/constants.py`, `keel/inspect/constants.py`
- `keel/system/network.py`
- tests whose patch target moved with the imports

## Real image, 2026-10-27

The Core layer shipped keel 0.23.56. On the same image, the local
0.23.56+perf1 was installed with `dpkg -i` (an upgrade):

```text
             before (0.23.56)   after (0.23.56+perf1)
keel --help cold      230 ms           42 ms
keel --help warm      182 ms           29 ms
import keel.cli     153949 us         8230 us
```

`keel --version` after is `0.23.56+perf1`; `dpkg` reported an upgrade,
not a downgrade, and `systemctl --failed` is empty. The 0.23.56 code is
the same source; the comparison isolates the import change.

## Latest real image, 2026-10-28

The same 0.23.56 -> 0.23.56+perf1 upgrade on a new Core build:

```text
             before (0.23.56)   after (0.23.56+perf1)
keel --help cold      255 ms           45 ms
keel --help warm      753 ms           31 ms
import keel.cli     170471 us         8688 us
```

The 753 ms warm-before number is an outlier in that boot (slower than
its own cold call); the import and cold numbers agree with the earlier
run (230/182 ms, 153949 us before; 42/29 ms, 8230 us after). The import
is 19.6x faster and the cold help 5.7x. The package is 0.23.56+perf1,
the 201 relevant tests pass in the image build, and there are no failed
units.

## Masks and boot layer, 2026-10-28

The Core image with the six mount masks and the 6.12.113 boot layer:

```text
             before (0.23.56)   after (0.23.56+perf1)
keel --help cold      213 ms           38 ms
keel --help warm      179 ms           29 ms
import keel.cli     146356 us         7510 us
```

1054 pyc after install (1052 core + the local keel), 0 failed units.
The import is 19.5x faster; the cold help 5.6x.

## Final Core, 2026-10-28

With the Webmin/Python trims and the 6.12.113 boot layer: `keel --help`
35 / 27 ms; `import keel.cli` 8302 us; 1054 pyc; 0 failed units.

## Final stable Core, 2026-10-28

`keel --help` 37/29 ms; `import keel.cli` 7922 us; 1054 pyc; 0 failed.
