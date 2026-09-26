# Tests

The standard for code authored by the project is at least 95 percent line
and branch coverage, with every subcommand, exit code and error path
exercised (docs/decisions/0003-test-coverage-standard.md).

Run the suite from the repository root. It needs pytest, PyYAML,
coverage, the `tar` and `zstd` commands and the IPv6 loopback (the pull
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
