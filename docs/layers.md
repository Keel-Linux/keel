# Layers: `keel verify`, `keel pull` and `keel assemble`

An appliance is assembled from layers (brief section 5.1): a `core`
rootfs, a stack layer such as `lamp` built on top of it, and the
application delta. Each layer is a deterministic tarball with a content
hash and a plain text manifest, both written by `bt-layer` in buildtasks.
`keel verify` reads those manifests on a running appliance and checks the
layers against them (brief section 5.4). `keel pull` fetches the layers
an appliance needs and that the local cache does not have yet, and
`keel assemble` turns the cached chain into a rootfs directory and,
when asked, into the single tarball Proxmox expects (brief section 5.1).

This page describes the manifest as `keel` consumes it, the three
commands, their output and the exit codes. The library behind them is
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

## Verify from confconsole

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

## What `keel pull` fetches

```
keel pull LAYER --source URL-or-DIR [--cache-dir DIR] [--non-interactive]
```

`LAYER` is the top of the chain: the name of a layer as the source knows
it (`lamp`, `wordpress`), or the path of its manifest file when the
caller already has one. `--source` is where the manifests and tarballs
are served: a directory (`/mnt/builds/layers`, which is what `bt-layer`
writes today) or an http(s) URL such as
`http://[2001:db8:19::1]/layers`. IPv6 addresses go in brackets, as in
any URL. Only the standard library is used for the transfer; there is
no dependency on a download tool.

The command:

1. Reads `<LAYER>.manifest` from the source (or the given file) and
   validates it as described above.
2. Follows `parent` at the source, manifest by manifest, up to a rootfs
   layer. At every step the parent's recorded `sha256` must equal the
   child's `parent_sha256`: a source whose `core` has moved on since
   `lamp` was built is reported as a mismatch, never substituted.
3. For each layer, rootfs first: if `<name>-<sha256>.tar.zst` is in the
   cache with the recorded size and sha256, it is left alone and
   reported `cached`. Otherwise the tarball is streamed from the source
   into `<name>-<sha256>.tar.zst.part`, hashed on the way, and renamed
   into place only when its size and sha256 equal the manifest. A
   mismatch removes the partial file and fails with `LAYER_MISMATCH`;
   the transfer stops as soon as the manifest size is exceeded, so a
   wrong file is not downloaded whole. The manifest is stored next to
   the tarball as `<name>-<sha256>.manifest`.

A source may keep a tarball under either name: `<name>-<sha256>.tar.zst`
(what a layer host serves, decision 0005) or the `tarball` name in the
manifest (`lamp.tar.zst`, what `bt-layer` writes). Both are tried, in
that order.

Output, one line per layer on stdout, then a summary:

```
# keel pull lamp --source http://[2001:db8:19::1]/layers
core: cached (326418793 bytes)
lamp: fetched (79807121 bytes)
layers: 2 resolved, 1 fetched, 1 cached, 79807121 bytes transferred
```

A corrupted or truncated file in the cache is treated as absent and
fetched again. Layers are fetched rootfs first, so a failure part way
leaves the cache with a usable prefix of the chain.

## The cache

`--cache-dir`, by default `$KEEL_CACHE_DIR` or `/var/cache/keel/layers`,
holds:

```
/var/cache/keel/layers/
  core-e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19.tar.zst
  core-e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19.manifest
  lamp-237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae.tar.zst
  lamp-237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae.manifest
```

Everything is keyed by the sha256 the manifest records, so two versions
of a layer never collide, a `core` update is one new pair of files, and
`assemble` can resolve a chain exactly: the parent of a cached delta is
`<parent>-<parent_sha256>.manifest`, nothing else. A `.part` file is a
transfer in progress or one that failed; `pull` removes its own.

## What `keel assemble` produces

```
keel assemble LAYER --rootfs DIR [--template FILE] [--sha256 HEX]
              [--cache-dir DIR] [--non-interactive]
```

`LAYER` is a name in the cache. When more than one version of it is
cached, `--sha256` picks one; otherwise the command says which digests
it found and stops. The chain is resolved from the cached manifests
only; nothing is fetched. Before anything is extracted, every cached
tarball in the chain is checked against its manifest again, and
`--rootfs` must not exist or must be an empty directory.

The chain is then applied in order into the rootfs:

- the rootfs layer (`core`) is one tar of the whole tree and is
  extracted as is;
- a delta layer holds the two upper directories of the deck build,
  root.build then root.patched, each starting with its own `./` entry,
  and carries what overlayfs recorded there: a character device 0:0 is
  a whiteout, meaning the path from the layers below is removed; a
  directory with `trusted.overlay.opaque=y` replaces the directory
  below instead of merging with it.

For each of the two members, in order, the whiteout and opaque paths
are removed from the rootfs, then the member is extracted over it with
`tar --xattrs`, the whiteout nodes excluded and the `trusted.overlay.*`
attributes left out, so the result carries no trace of the overlay.
The order matters: a directory root.patched marked opaque must not keep
what root.build put in it. `tar` and `zstd` are run as subprocesses
with argument lists; the decompressed tar lives in a scratch directory
next to the rootfs for the duration and is removed whatever happens.
`trusted.overlay.redirect` (renamed directories) is not handled; the
deck builds do not produce it.

With `--template FILE`, the rootfs is then packed into `FILE`, a
`.tar.zst` that `pct create` and the Proxmox web UI take as a local
template (docs/proxmox-distribution.md), and `FILE.sha512` is written in
`sha512sum` format because that is the digest the pveam index carries.
The tar stream is deterministic in the same way the layers are (brief
section 5.4): entries sorted by name, numeric owners, every mtime set to
the top manifest's `source_date_epoch`, posix format without the
volatile pax fields, extended attributes kept. Two assemblies of the
same chain give the same tar; the compressed file is identical when the
same zstd version is used.

```
# keel assemble lamp --rootfs /var/lib/lxc/lamp/rootfs \
    --template /var/lib/vz/template/cache/debian-13-keel-lamp_19.0-1_amd64.tar.zst
core: extracted (1 members, 0 whiteouts, 0 opaque directories)
lamp: extracted (2 members, 31 whiteouts, 185 opaque directories)
rootfs: /var/lib/lxc/lamp/rootfs
template: /var/lib/vz/template/cache/debian-13-keel-lamp_19.0-1_amd64.tar.zst (417216340 bytes, sha512 ...)
```

### Root

Restoring owners, device nodes and extended attributes is only possible
as root, so `assemble` refuses to start as anyone else with
`ASSEMBLE_NEEDS_ROOT` (11) and a message saying so, rather than
producing a tree that looks right and is not. `pull` needs no
privileges beyond writing the cache.

## Exit codes of `pull` and `assemble`

| Code | Name | Raised when |
| --- | --- | --- |
| 0 | `OK` | Every layer resolved and is in the cache; the rootfs (and template) was written |
| 1 | `USAGE` | `--source` or `--rootfs` missing, unknown option |
| 6 | `MANIFEST_INVALID` | A manifest at the source, on disk or in the cache does not validate, or names another layer than the one asked for |
| 7 | `LAYER_MISMATCH` | A parent's sha256 differs from the child's `parent_sha256`, the chain loops, a download's size or sha256 differs from the manifest, or a cached tarball no longer matches at assembly time |
| 10 | `LAYER_UNAVAILABLE` | A manifest or tarball is not at the source or the transfer failed, the cache cannot be written, or `assemble` finds a layer of the chain missing from the cache |
| 11 | `ASSEMBLE_NEEDS_ROOT` | `assemble` was run by a user other than root |
| 12 | `ASSEMBLE_FAILED` | The rootfs is not empty or cannot be created, a member name would escape it, or tar or zstd exited non zero (a template path that cannot be written is reported here, after the rootfs is complete) |

## From confconsole

```python
from keel import exits, layers

try:
    report = layers.pull("lamp", "http://[2001:db8:19::1]/layers",
                         "/var/cache/keel/layers")
except layers.LayerError as e:
    show_error(f"{e} ({exits.DESCRIPTIONS[e.code]})")
else:
    for result in report.results:
        show_line(result.line())
    show_line(report.summary())
```

`layers.assemble(name, cache_dir, rootfs, template=None, sha256=None)`
has the same shape and returns a report whose `lines()` are what the
command prints. Both raise `LayerError` with the exit code in `code`.

## Fixtures

`tests/fixtures/layers/` holds the real `core` and `lamp` manifests,
`.sha256` and `.hash` files from a build. The tarballs are not committed;
the verify tests write small stand ins and rewrite the digests and sizes
to match. The pull and assemble tests build small real layers with the
`tarfile` module: a core tar and a delta whose whiteout is a character
device 0:0 and whose opaque directories carry the xattr in the pax
header, exactly as `tar --xattrs` stores them, so the overlay semantics
are exercised without overlayfs and without root. The http source is
served by `http.server` on `[::1]`.
