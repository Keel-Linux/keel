# Tests

The standard for code authored by the project is at least 95 percent line
and branch coverage, with every subcommand, exit code and error path
exercised (docs/decisions/0003-test-coverage-standard.md).

Run the suite from the repository root. It needs pytest, PyYAML,
coverage, the `tar`, `zstd` and `bats` commands and the IPv6 loopback (the pull
tests serve a directory on `[::1]` from a thread), no other network, no
root and no installed package: the assemble tests stand root in by
patching `os.geteuid`, and their synthetic layers never need a device
node created or a `trusted.*` attribute restored. Both runners run
the same tests:

```
PYTHONPATH=. pytest
PYTHONPATH=. python3 -m unittest discover tests
```

Measure and check the coverage. The threshold and the branch setting live
in `pyproject.toml` (`[tool.coverage.run]` and `[tool.coverage.report]`),
so the third command exits non zero when the package falls under the bar:

```
PYTHONPATH=. coverage run -m pytest tests
coverage report
coverage report --fail-under=95
```

The commands that inspect the running host (`turnkey-version`, `ip` and
`hostname -f`) are replaced at the subprocess boundary in
`tests/test_spec_runtime.py` and `tests/test_inspect_cli.py`, so the suite
gives the same answer on every host. The `keel inspect` and `keel diff`
tests read the fixture trees under `tests/fixtures/inspect/` through
`--root`, never `/` (docs/inspect.md and docs/diff.md, Tests). The `keel
spec apply --system` tests converge temporary trees through `--root`, with
`useradd` and `usermod` replaced at the subprocess boundary and root stood
in by patching `os.geteuid` (docs/apply.md, Tests).

The monitor tests (decision 0021) send `keel notify`'s channels to an
HTTPS server on `[::1]`, with a certificate `openssl` makes for `::1` in a
temporary directory each run, so no certificate is committed and nothing
leaves the machine. When a monit binary is on `PATH`, or named by
`KEEL_MONIT` (`apt-get download monit` and `dpkg-deb -x` give one without
installing it), `tests/test_monitor_render.py` also hands the rendered
file to `monit -t`; without one those two tests skip.

The WireGuard overlay tests hand the rendered file and the key pair to
the real `wg` and `wg-quick` when they are at hand: on `PATH`, or in the
directory `KEEL_WG_DIR` names (`apt-get download wireguard-tools` and
`dpkg-deb -x` give them without installing anything). `wg-quick` wants
root, so it runs in a network namespace of its own (`unshare -n` as root,
`unshare -rn`, or `sudo -n unshare -n`), and `wg-quick up` there also
needs the `wireguard` kernel module. Without the tools those tests skip,
except in CI, where the workflow installs `wireguard-tools`
(tests/wgtools.py).

`keel mesh` (decision 0048) is tested end to end by
`tests/test_mesh_netns.py`, which runs `tests/mesh_netns.py` as root in
a network namespace the same way, with two more namespaces joined to it
by veths, the real `wg-quick`, real TLS on the namespaces' addresses and
`ping` over the overlay; it needs the `wireguard` kernel module, and
skips without it outside CI. `tests/test_mesh_channel.py` serves the
real TLS listener on `[::1]`.

The one shell file the package ships, the firstboot hook
`firstboot.d/10keel-system`, is tested with bats in `tests/hook.bats`, with
`keel` replaced by a script on `PATH` that records its arguments and
answers with a chosen exit code. `tests/test_hook_bats.py` runs that suite
from pytest, so the repository keeps one required check and a broken hook
fails the same gate as a broken module. Without `bats` installed that test
skips, except in CI, where a silent skip would leave the hook untested.
