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
| `layer` | `[a-z0-9][a-z0-9._-]*`, the name in the file name (Layouts, below) | Layer name |
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

### Optional fields

A key that is not in the table above is kept as it was read and written
back unchanged, so `bt-layer` can record something new without this code
changing and without older manifests becoming unreadable. Nothing here
validates such a field; a reader that wants one has to check it itself.

These are the ones `bt-layer` writes today. Both are absent from every
manifest written before 2026-09-27, and absent means `none`.

| Key | Meaning |
| --- | --- |
| `units` | Every component the layer carries as a fab unit, as `name@version` sorted by name, or `none`. Cumulative: the parent's units merged with the ones this build added, so a child of this layer can subtract the whole stack |
| `build_units` | The units this build applied: `default` for a rootfs layer, else the ones the parent had not applied, or `none` |

A unit is a component `fab` applies from a directory under the product's
`UNIT_DIRS`: a plan, an overlay, a conf script and a removelist. A version
is the content of the unit's `version` file, or the commit of the unit's
own checkout, or `sha256-` and the first 16 digits of a digest of the
directory. `bt-layer` refuses to build a layer whose parent applied the
same unit at another version, because a conf script runs once.

Next to the tarball, `bt-layer` also writes `<tarball>.sha256`
(`sha256sum` format) and, when a signing key is set, `<tarball>.hash`:
a text file for a human with a `sha256sum` and a `sha512sum` line and,
once signed, a clear signature around it. `keel verify` reads the
`.hash` file when it is there and ignores the `.sha256` file, which
repeats what the manifest already says.

## Layouts

A directory of layers is named in one of two ways, and every command
reads both. The rule is written once, in `keel.layers.manifest`.

| Layout | Manifest | Tarball | Hash file | Written by |
| --- | --- | --- | --- | --- |
| build output | `lamp.manifest` | `lamp.tar.zst` (the `tarball` field) | `lamp.tar.zst.hash` | `bt-layer`, into the build directory a source serves |
| cache | `lamp-<sha256>.manifest` | `lamp-<sha256>.tar.zst` | `lamp-<sha256>.tar.zst.hash` | `keel pull`, into `--cache-dir` |

In both, `<layer>` is the `layer` field: a manifest file named after
another layer is `invalid`. In the cache layout `<sha256>` must be the
digest the manifest records; a file such as `lamp-ffff...manifest` whose
manifest says another sha256 is a `mismatch` (`file name sha256 ffff...,
manifest says ...`). The tarball and its `.hash` file are looked up next
to the manifest by the same rule, so `keel verify --layers-dir` on a
cache reports exactly what it reports on the build directory the cache
was pulled from. A layer name may contain `-`; only a trailing 64 hex
digit suffix counts as a digest, so `my-app.manifest` is the build
output layout of the layer `my-app`.

`keel verify` reads either layout, `keel pull` reads the build output
layout (or `<name>-<sha256>.tar.zst` at the source) and writes the cache
layout, and `keel assemble` reads the cache layout.

## What `keel verify` checks

```
keel verify [--layers-dir DIR] [--tarballs-dir DIR] [--non-interactive]
```

The manifests are read from `--layers-dir`, by default `$KEEL_LAYERS_DIR`
or `/var/lib/keel/layers`, in either layout. Tarballs and `.hash` files
are looked up in `--tarballs-dir`, by default the same directory, under
the name the layout gives them. Every `*.manifest` in the directory is
checked, in name order:

1. The manifest parses and validates as above, including the parent
   rule: a delta names a parent and its digest, a rootfs names neither.
   Its file name agrees with it: the layer name, and in the cache layout
   the sha256.
2. The tarball exists and its size and sha256 equal the manifest.
3. The parent chain resolves: following `parent` reaches a rootfs
   through manifests that exist and are valid, without a loop, and at
   every step `parent_sha256` equals the parent's recorded `sha256`.
   When a cache holds several versions of the parent, the one recording
   that `sha256` is the parent; every version is checked and reported.
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

## Layouts a mirror serves

Handbook decision 0016 made exactly one object in the mirror mutable,
and it is a signed pointer. `keel pull` reads all three layouts, and the
flat one it read before is still one of them.

```
layers/
  sha256/<digest>                   a layer tarball, named by its content:
                                    never overwritten, never deleted, shared
                                    by every release that installs it
  <release>/<rev>/<name>.manifest   one layer of one immutable release
                                    revision, referring to a blob by digest
  stable, testing                   the channel pointers: clear signed, with
                                    a timestamp and an expiry
  <name>.manifest, <name>.tar.zst   the flat layout, still served
```

The digest chain is what makes this worth the trouble, and it is
complete only when a channel is followed: the signature covers the
pointer, the pointer carries the sha256 of every manifest, and each
manifest carries the sha256 of its blob. Nothing along it is taken on
the mirror's word.

### The channel pointer

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

channel stable
release 2026-09-28
rev 1
signed_at 2026-09-28T04:11:09Z
expires_at 2026-10-05T04:11:09Z
layer core 5f3a...
layer lamp 9c1b...
-----BEGIN PGP SIGNATURE-----
...
```

| Key | Checked as | Meaning |
| --- | --- | --- |
| `channel` | `stable` or `testing`, and the name it was fetched under | Which channel this is; a pointer served as `stable` that says `testing` is refused |
| `release` | `YYYY-MM-DD` | The release revision it names |
| `rev` | a whole number above zero | Which revision of that release; revisions never overwrite each other |
| `signed_at` | `YYYY-MM-DDTHH:MM:SSZ` | When it was signed |
| `expires_at` | the same, after `signed_at`, and at most 30 days after it | When the client stops believing it |
| `layer` | a layer name and 64 lowercase hex digits, at least once, never twice for one layer | The sha256 of that layer's manifest in the release revision |

The pointer is one file and not a file beside a detached signature,
because two files are two mutable objects and a mirror could skew them
against each other.

**An expired pointer is an error, never a warning.** Without it, a
mirror that is stale, broken or hostile holds an appliance on an old and
vulnerable release simply by not updating, and the client cannot tell
that apart from "nothing new". The check is `now >= expires_at`, so the
moment of expiry is already expired.

**And an expiry has a ceiling, enforced here and not by the publisher.**
`expires_at - signed_at` may be at most 30 days. Unbounded, "until when"
is a permanent freeze: one signature from the online key pins an
appliance to an already published, known vulnerable revision for ever,
and the rollback refusal never fires because the revision does not go
backwards. That is the failure mode decision 0016 says the whole design
exists to prevent, so the bound cannot live in an environment variable on
the machine holding the key.

**The expiry is only as good as this machine's clock**, and nothing here
can check a clock. So both directions are handled as far as they can be.
A pointer signed more than an hour ahead of local time is refused, exit
17, rather than treated as fresh. And when a pointer has expired, the
message prints the expiry, the signature time **and** what this machine
thinks the time is, and names all three possibilities: a mirror that is
not being updated, a mirror holding this instance back, or a local clock
that is wrong. A clock that has run ahead expires every pointer there is,
and an operator told only about the mirror goes and looks at the mirror.

The keyring is `--channel-keyring`, by default `$KEEL_CHANNEL_KEYRING`
or `/usr/share/keyrings/keel-channel-keyring.gpg`. `gpgv` verifies,
because it refuses to do anything but verify: it cannot be talked into
importing a key, consulting a trust database or asking an agent. The
`keel` package depends on it and does not assume it, since on Debian 13
apt verifies with `sqv` and `gpgv` is a package of its own.

No repository ships that keyring yet, so `keel pull --channel` on a stock
appliance exits 18 naming the file it could not read. That fails closed,
which is the right way round, but the feature is not usable until the
keyring is packaged; `--channel-keyring` or `$KEEL_CHANNEL_KEYRING`
points at one in the meantime.

Four of gpgv's properties are load bearing, and all four were measured
rather than assumed:

* it **writes the plain text of a document whose signature it refused**,
  so `keel.layers.signature` reads that output only after every check
  below has passed;
* **its exit status does not mean the key is good, and neither does
  `VALIDSIG`.** A signature by a revoked primary, by a revoked signing
  subkey under a live primary, or by an expired key each give exit 0, a
  `VALIDSIG` line, and `Good signature from` on stderr. `GOODSIG` is the
  only line gpgv withholds, substituting `REVKEYSIG` or `EXPKEYSIG`. So a
  `GOODSIG` line is required and the retirement lines are refused
  outright. This matters more here than anywhere: the channel key is the
  one unattended online key in the design, the answer to its theft is to
  revoke it, and a verifier that accepts `VALIDSIG` makes revocation do
  nothing;
* it **reads a binary keyring only**, and an armored one gives
  `NO_PUBKEY`, the same message as a wrong key. An armored keyring is
  accepted here and dearmored in memory;
* it **accepts SHA-1** unless told otherwise, so `--weak-digest SHA1` is
  passed and a SHA-1 pointer is refused.

`--channel-signer FINGERPRINT`, repeatable, or `$KEEL_CHANNEL_SIGNER` as
a space separated list, narrows it further: only that key may move a
channel, whatever else the keyring holds. The fingerprint may be the
signing key's or its primary key's, so a subkey rotation needs no change
on the appliances, but that also means pinning a primary accepts a
revoked subkey of it, which is why the retirement refusal above is what
actually stops one. With neither set, any key in the keyring is accepted,
so a keyring holding the channel key alone is the other way to get the
separation decision 0016 argues for.

## What `keel pull` fetches

```
keel pull LAYER --source URL-or-DIR [--cache-dir DIR]
          [--channel stable|testing] [--channel-keyring FILE]
          [--channel-signer FINGERPRINT] [--channel-state FILE]
          [--release YYYY-MM-DD --rev N] [--allow-rollback]
          [--non-interactive]
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
4. When the source has the tarball's `.hash` file, under either tarball
   name, it is copied to `<name>-<sha256>.tar.zst.hash`, for a `cached`
   layer too, so `keel verify --layers-dir CACHE` reports the signature
   state the source publishes. A source without one is not an error.

A source may keep a tarball under any of three names, tried in this
order: `sha256/<digest>`, the blob of decision 0016, when a release
revision was resolved; `<name>-<sha256>.tar.zst`, what a layer host
serves; and the `tarball` name in the manifest (`lamp.tar.zst`, what
`bt-layer` writes). A mirror part way through the conversion therefore
serves both kinds of client.

### Following a channel

`--channel stable` fetches the pointer, verifies it, refuses it when it
has expired, and resolves `<release>/<rev>/<name>.manifest` for every
layer of the chain. Each manifest's bytes must hash to what the pointer
signed for that layer; a layer the pointer does not name is a mismatch,
because nothing signed then says which manifest it should have.

What was resolved is printed above the layer lines, always: a pull that
verified nothing says so, because otherwise it prints exactly what a
verified one prints:

```
# keel pull lamp --source /mnt/builds/layers
flat layout: no channel pointer was read, so nothing here is signed for. Pass --channel stable to follow a signed pointer
core: cached (326418793 bytes)
```

For a channel:

```
# keel pull lamp --source https://mirror.keellinux.org/layers --channel stable
channel stable: release 2026-09-28/1, signed 2026-09-28T04:11:09Z, expires 2026-10-05T04:11:09Z
core: cached (326418793 bytes)
lamp: fetched (79807121 bytes)
layers: 2 resolved, 1 fetched, 1 cached, 79807121 bytes transferred
```

The channel and revision are then recorded in `--channel-state`, by
default `$KEEL_CHANNEL_STATE` or `/var/lib/keel/channel`, which is what
`keel inspect` reads.

### Rollback

`--release 2026-09-28 --rev 1` names an immutable revision. It works for
every revision a channel has ever named, because a blob is never deleted:
every revision that was ever published can still be assembled.

**It is verified, and by the same chain.** A rollback is the operation an
operator performs after something has already gone wrong, against the
mirror they have the least reason to trust, so it is not the path that
skips the signature. Each revision keeps a copy of the first pointer that
was signed for it, written once by the publisher when it installs a channel
naming that revision (Keel-Linux/apt, `mirror_channel_script`), at
`layers/<release>/<rev>/revision`. A revision no channel ever named has
none, and is refused with exit 10. `--release/--rev` fetches that,
verifies it exactly as a channel pointer is verified, requires it to name
the revision it is filed under, and takes the manifest digests from it. A
mirror with no `revision` file gets exit 10; one with a rewritten manifest
gets exit 7. Before this, both were exit 0 with attacker bytes in the
cache.

The one check not applied is the expiry: an earlier revision is old on
purpose, and freshness is a question about a channel and not about a
revision. The output says so.

Given `--channel` as well, the state records
that the instance is on that revision of that channel, so `keel inspect`
says it is behind, which after a deliberate rollback is the truth.

A pointer that names an earlier revision than the one this instance is
on is refused with `CHANNEL_ROLLBACK`. A mirror does not move an
appliance backwards; an operator does, with `--allow-rollback` or by
naming the revision.

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
  core-e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19.tar.zst.hash
  core-e08e8224aeea1abb605b0e359d345f459d2e04d413e6a08c5e57f5b7858c9e19.manifest
  lamp-237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae.tar.zst
  lamp-237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae.tar.zst.hash
  lamp-237188ea3339caa72a6b7bcf36fc03bb4a40f654c643bb1ad0734d1b954102ae.manifest
```

This is the cache layout of the Layouts section; `keel verify
--layers-dir /var/cache/keel/layers` checks it as it checks a build
directory:

```
# keel verify --layers-dir /var/cache/keel/layers
core: unverified: hash file present, not signed
lamp: unverified: hash file present, not signed
layers: 2 checked, 0 ok, 2 unverified, 0 mismatch, 0 invalid
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
| 6 | `MANIFEST_INVALID` | A manifest at the source, on disk or in the cache does not validate, or names another layer than the one asked for or filed under |
| 7 | `LAYER_MISMATCH` | A parent's sha256 differs from the child's `parent_sha256`, the chain loops, a download's size or sha256 differs from the manifest, a cached manifest is filed under another sha256 than it records, or a cached tarball no longer matches at assembly time |
| 10 | `LAYER_UNAVAILABLE` | A manifest or tarball is not at the source or the transfer failed, the cache cannot be written, or `assemble` finds a layer of the chain missing from the cache |
| 17 | `CHANNEL_INVALID` | A channel pointer, or the record of the one this instance follows, does not parse or fails validation; also a pointer signed in the future, one claiming more than 30 days of life, and a revision pointer naming another revision |
| 18 | `CHANNEL_UNVERIFIED` | A channel pointer is not signed by a key that may move a channel, or no keyring was given to check it against |
| 19 | `CHANNEL_EXPIRED` | A channel pointer is past `expires_at`: the mirror is stale, broken or holding this instance back |
| 20 | `CHANNEL_ROLLBACK` | A channel pointer names an earlier revision than the one this instance is on |
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
