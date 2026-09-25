# Layers and `keel verify`

An appliance is assembled from layers (brief section 5.1): a `core`
rootfs, a stack layer such as `lamp` built on top of it, and the
application delta. Each layer is a deterministic tarball with a content
hash and a plain text manifest, both written by `bt-layer` in buildtasks.
`keel verify` reads those manifests on a running appliance and checks the
layers against them (brief section 5.4).

This page describes the manifest as `keel` consumes it, the checks, the
output and the exit codes. The library behind the command is
`keel.layers`; confconsole calls it directly.

## The manifest

One file per layer, `<name>.manifest`, plain text, one `key value` per
line, the value running to the end of the line. Blank lines are ignored.
Keys are lowercase, `[a-z][a-z0-9_]*`, and never repeat. The real `lamp`
manifest, as built:

```
layer lamp
type delta
parent core
parent_sha256 e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19
release debian/trixie
arch amd64
product_commit a295e3485ed560feac951fa7379671801d3a2894
common_commit b60dd2306b52591423aaeca2321cdd5322096ea1
fab_version 1.1.1
source_date_epoch 1700000000
common_overlays turnkey.d tkl-webcp confconsole-lamp apache php mysql adminer composer
common_conf turnkey.d tkl-webcp apache-cgi adminer-apache adminer-mysql apache-vhost apache-headers apache-security apache-ssl php mysql adminer
build_overlays turnkey.d/tkl-bashlib turnkey.d/systemd-chroot tkl-webcp confconsole-lamp apache php mysql adminer composer
build_conf turnkey.d/hostname turnkey.d/zz-ssl-ciphers tkl-webcp apache-cgi adminer-apache adminer-mysql apache-vhost apache-headers apache-security apache-ssl php mysql adminer
tarball lamp.tar.zst
sha256 237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae
size 79807121
```

Every key below is required; a manifest missing any of them is invalid.

| Key | Checked as | Meaning |
| --- | --- | --- |
| `layer` | `[a-z0-9][a-z0-9._-]*`, equal to the file name stem | Layer name |
| `type` | `rootfs` or `delta` | A full root file system, or the upper directories of a deck build on top of `parent` |
| `parent` | `none` for a rootfs; a layer name for a delta | The layer this one was built on |
| `parent_sha256` | `none` for a rootfs; 64 hex digits for a delta | The parent's `sha256` at build time |
| `release` | text | Debian release, `distro/codename` |
| `arch` | text | Debian architecture |
| `product_commit` | text | Git commit of the product that built the layer, `none` outside git |
| `common_commit` | text | Git commit of `common` |
| `fab_version` | text | `fab --version` |
| `source_date_epoch` | non negative integer | mtime of every tarball entry |
| `common_overlays` | text | `COMMON_OVERLAYS` of the product, the full list |
| `common_conf` | text | `COMMON_CONF` of the product, the full list |
| `build_overlays` | text | Overlays this layer applied (`default` for a rootfs) |
| `build_conf` | text | Conf scripts this layer ran (`default` for a rootfs) |
| `tarball` | a file name, no `/` | The layer tarball, next to the manifest |
| `sha256` | 64 lowercase hex digits | Digest of the tarball |
| `size` | non negative integer | Size of the tarball in bytes |

The `release`, `arch`, commit, version and overlay fields are recorded
and shown, not checked: nothing on a running appliance can be compared
with them yet.

Next to the tarball, `bt-layer` also writes `<tarball>.sha256`
(`sha256sum` format) and, when a signing key is set, `<tarball>.hash`:
a text file for a human with a `sha256sum` and a `sha512sum` line and,
once signed, a clear signature around it. `keel verify` reads the
`.hash` file when it is there and ignores the `.sha256` file, which
repeats what the manifest already says.

## What `keel verify` checks

```
keel verify [--layers-dir DIR] [--tarballs-dir DIR] [--non-interactive]
```

The manifests are read from `--layers-dir`, by default `$KEEL_LAYERS_DIR`
or `/var/lib/keel/layers`. Tarballs and `.hash` files are looked up in
`--tarballs-dir`, by default the same directory. Every `*.manifest` in
the directory is checked, in name order:

1. The manifest parses and validates as above, including the parent
   rule: a delta names a parent and its digest, a rootfs names neither.
2. The tarball exists and its size and sha256 equal the manifest.
3. The parent chain resolves: following `parent` reaches a rootfs
   through manifests that exist and are valid, without a loop, and at
   every step `parent_sha256` equals the parent's recorded `sha256`.
4. When `<tarball>.hash` exists: it carries a sha256 line, that digest
   equals the manifest, and the file name on the line is the tarball.
   The sha512 line is not recomputed. If the file is clear signed, the
   signature is detected and reported, and nothing more.

Then the command says that packages are not checked, because that half
of brief section 5.4 is not implemented yet, and exits accordingly.

### What it refuses to claim

- A signature is never reported as verified. The project has no trusted
  release key yet; until one is configured, a signed `.hash` file is
  reported as `signature present, not verified (no trusted key
  configured)` and an unsigned one as `hash file present, not signed`.
  Either way the layer is `unverified` and the exit code says so.
- Layers that all pass do not make `verify` exit 0. Packages are not
  checked, and the command never claims more than it checked, so it
  exits 9 after printing the layer results. When the packages check
  exists, 0 will mean what the brief says.
- An absent layers directory is not an error: the appliance has no
  layers, `verify` says so on stderr, checks nothing and moves on.

## Output

One line per layer on stdout, `name: status[: detail; detail]`, then a
summary line, so a caller can grep for `: mismatch` or `: invalid`
without parsing. Everything else goes to stderr.

```
# keel verify --layers-dir /var/lib/keel/layers
core: ok
lamp: mismatch: size 79807120, manifest says 79807121
layers: 2 checked, 1 ok, 0 unverified, 1 mismatch, 0 invalid
```

The statuses, worst first, and the exit code each one sets:

| Status | Exit | Meaning |
| --- | --- | --- |
| `invalid` | 6 `MANIFEST_INVALID` | The manifest cannot be read, or fails validation; every problem is listed |
| `mismatch` | 7 `LAYER_MISMATCH` | The tarball, the parent chain or the `.hash` digest does not match the manifest |
| `unverified` | 8 `SIGNATURE_UNVERIFIED` | Everything matches and a `.hash` file is present, but its signature was not (or cannot be) verified |
| `ok` | 0 | Everything matches and there is no `.hash` file to speak for |

The exit code of the command is the worst status of any layer; when
every layer is `ok`, it is 9 (`NOT_IMPLEMENTED`) for the packages half,
as explained above. A layers directory that exists but cannot be listed
is reported as one `invalid` line named after the directory.

## From confconsole

```python
from keel import exits, layers

report = layers.verify_layers("/var/lib/keel/layers")
for result in report.results:
    show_line(result.line())
show_line(report.summary())
if report.code != exits.OK:
    show_error(exits.DESCRIPTIONS[report.code])
```

`verify_layers()` never raises: an unreadable manifest or directory
becomes a result with `status == "invalid"`.

## Fixtures

`tests/fixtures/layers/` holds the real `core` and `lamp` manifests,
`.sha256` and `.hash` files from a build. The tarballs are not committed;
the tests write small stand ins and rewrite the digests and sizes to
match, so the suite runs without the build host.
