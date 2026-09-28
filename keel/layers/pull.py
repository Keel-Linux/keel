# Copyright (c) 2026 KeelLinux maintainers
"""Fetch the layers of an appliance that the cache does not have yet

Brief section 5.1: `keel pull` fetches only missing layers. Given the
top layer (a name looked up at the source, or a manifest file), the
parent chain is resolved through the manifests, every layer whose
tarball is already in the cache with the right digest is left alone,
and the others are downloaded, checked against the manifest and stored
under `<name>-<sha256>.tar.zst`, the cache layout of
keel.layers.manifest. The tarball's `.hash` file is copied next to it
when the source has one, so `keel verify` on the cache can report the
signature state.

Three ways to say which layers, and they are the three layouts of
handbook decision 0016:

* **nothing named** is the flat layout, `<name>.manifest` beside
  `<name>.tar.zst` at the root of the source. It is what every appliance
  published before the conversion follows, and it keeps working.
* **a channel** (`stable`, `testing`) fetches the pointer, verifies its
  clear signature and its expiry, and resolves the release revision it
  names. The digest chain is then complete: the signature covers the
  sha256 of every manifest, and each manifest covers the sha256 of its
  blob.
* **a release and a revision** name an immutable revision directly. That
  is how a rollback is asked for, and it needs no pointer, because the
  operator is the one choosing.
"""

import hashlib
import os
from dataclasses import dataclass, field

from keel import exits
from keel.layers import channel as channels
from keel.layers import layout, signature
from keel.layers import manifest as manifests
from keel.layers.cache import Cache
from keel.layers.constants import (
    HASH_SUFFIX,
    KIND_ROOTFS,
    MANIFEST_SUFFIX,
    PART_SUFFIX,
    READ_CHUNK,
    TARBALL_SUFFIX,
)
from keel.layers.errors import (
    ChannelError,
    LayerError,
    ManifestError,
    SignatureError,
)
from keel.layers.manifest import Manifest
from keel.layers.source import Source

STATUS_FETCHED = "fetched"
STATUS_CACHED = "cached"


@dataclass(frozen=True)
class Resolution:
    """How a pull was told to find the layers at the source

    Validated at construction, so a bad combination is a usage error
    before anything is fetched rather than a puzzling 404 afterwards.
    """

    channel: str | None = None
    release: str | None = None
    rev: int | None = None
    keyring: str | None = None
    signers: tuple[str, ...] = field(default_factory=tuple)
    state: str | None = None
    allow_rollback: bool = False

    def __post_init__(self):
        if self.channel is not None and not layout.is_channel(self.channel):
            raise ValueError(
                f"channel: {self.channel!r} is not one of"
                f" {', '.join(layout.CHANNELS)}"
            )
        if (self.release is None) != (self.rev is None):
            missing = "--rev" if self.rev is None else "--release"
            raise ValueError(
                "a release revision needs both --release and --rev;"
                f" {missing} is missing"
            )
        if self.release is None:
            return
        if not layout.is_release(self.release):
            raise ValueError(
                f"--release must be YYYY-MM-DD, got {self.release!r}"
            )
        if not layout.is_rev(str(self.rev)):
            raise ValueError(
                f"--rev must be a whole number above zero, got {self.rev!r}"
            )

    @property
    def by_release(self) -> bool:
        """An immutable revision was named, so no pointer is consulted"""
        return self.release is not None

    @property
    def by_channel(self) -> bool:
        return self.channel is not None and not self.by_release

    @property
    def flat(self) -> bool:
        return self.channel is None and not self.by_release


FLAT = Resolution()


@dataclass(frozen=True)
class PullResult:
    """One line of the report: what happened to one layer"""

    name: str
    sha256: str
    size: int
    status: str

    @property
    def transferred(self) -> int:
        return self.size if self.status == STATUS_FETCHED else 0

    def line(self) -> str:
        return f"{self.name}: {self.status} ({self.size} bytes)"


@dataclass(frozen=True)
class PullReport:
    cache_dir: str
    results: tuple[PullResult, ...]
    channel: channels.Channel | None = None
    revision: str | None = None

    @property
    def transferred(self) -> int:
        return sum(result.transferred for result in self.results)

    def count(self, status: str) -> int:
        return sum(1 for result in self.results if result.status == status)

    def summary(self) -> str:
        return (
            f"layers: {len(self.results)} resolved,"
            f" {self.count(STATUS_FETCHED)} fetched,"
            f" {self.count(STATUS_CACHED)} cached,"
            f" {self.transferred} bytes transferred"
        )

    def resolution_line(self) -> str | None:
        """What was resolved; None for the flat layout, which resolves none"""
        if self.channel is not None:
            return (
                f"channel {self.channel.name}:"
                f" release {self.channel.release}/{self.channel.rev},"
                f" signed {channels.format_stamp(self.channel.signed_at)},"
                f" expires {channels.format_stamp(self.channel.expires_at)}"
            )
        if self.revision is not None:
            return f"release {self.revision}, named on the command line"
        return None


@dataclass(frozen=True)
class Places:
    """Where one layout keeps the manifest and the tarball of a layer

    `digests` is the manifest sha256 the channel pointer signed, one per
    layer. Absent, there is nothing to compare a manifest against, which
    is the case for the flat layout and for a revision an operator named
    by hand: the signature that would have covered it was not consulted.
    """

    release: str | None = None
    rev: int | None = None
    digests: dict[str, str] | None = None

    def manifest_name(self, name: str) -> str:
        if self.release is None:
            return layout.flat_manifest_path(name)
        return layout.manifest_path(self.release, self.rev, name)

    def tarball_names(self, layer: Manifest) -> tuple[str, ...]:
        """Every name the source may keep the tarball under, best first"""
        names = (
            manifests.cache_stem(layer.name, layer.sha256) + TARBALL_SUFFIX,
            layer.tarball,
        )
        if self.release is None:
            return names
        return (layout.blob_path(layer.sha256), *names)

    def digest_problem(self, name: str, text: str) -> str | None:
        """The manifest is not the bytes the pointer signed for, or None"""
        if self.digests is None:
            return None
        signed = self.digests.get(name)
        if signed is None:
            return (
                f"the channel does not name layer {name!r}, so nothing"
                " signed says which manifest it should have"
            )
        found = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if found != signed:
            return (
                f"manifest sha256 {found}, the channel says {signed}"
            )
        return None


def load_source_manifest(
    source: Source, name: str, places: Places = Places()
) -> Manifest:
    """Fetch and validate the manifest of `name`, in the layout given"""
    filename = places.manifest_name(name)
    try:
        text = source.read_text(filename)
    except OSError as e:
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"{source.path(filename)}: {e}"
        ) from e
    problem = places.digest_problem(name, text)
    if problem is not None:
        raise LayerError(
            exits.LAYER_MISMATCH, f"{source.path(filename)}: {problem}"
        )
    return check_manifest(source.path(filename), text, name)


def check_manifest(path: str, text: str, name: str) -> Manifest:
    try:
        found = manifests.from_text(path, text)
    except ManifestError as e:
        raise LayerError(exits.MANIFEST_INVALID, str(e)) from e
    if found.name != name:
        raise LayerError(
            exits.MANIFEST_INVALID,
            f"{path}: manifest names {found.name!r}, asked for {name!r}",
        )
    return found


def load_top(
    layer: str, source: Source, places: Places = Places()
) -> Manifest:
    """The layer asked for: a manifest file on disk, or a name at the source"""
    if not (layer.endswith(MANIFEST_SUFFIX) or os.sep in layer):
        return load_source_manifest(source, layer, places)
    try:
        return manifests.load(layer)
    except ManifestError as e:
        raise LayerError(exits.MANIFEST_INVALID, str(e)) from e


def resolve_chain(
    top: Manifest, source: Source, places: Places = Places()
) -> list[Manifest]:
    """Walk the parents at the source up to a rootfs, rootfs first

    Every parent's recorded sha256 must equal the digest the child
    recorded at build time: a source that has moved on to a newer
    parent is a mismatch, not a silent substitution.
    """
    chain = [top]
    seen = {top.name}
    current = top
    while current.kind != KIND_ROOTFS:
        parent = load_source_manifest(source, current.parent, places)
        if parent.sha256 != current.parent_sha256:
            raise LayerError(
                exits.LAYER_MISMATCH,
                f"{current.name}: parent_sha256 {current.parent_sha256},"
                f" {parent.name} manifest at the source says {parent.sha256}",
            )
        if parent.name in seen:
            raise LayerError(
                exits.LAYER_MISMATCH,
                f"{current.name}: parent chain loops through {parent.name}",
            )
        seen.add(parent.name)
        chain.append(parent)
        current = parent
    chain.reverse()
    return chain


def tarball_names(
    layer: Manifest, places: Places = Places()
) -> tuple[str, ...]:
    """Where a source may keep the tarball, in the layout given"""
    return places.tarball_names(layer)


def open_tarball(source: Source, layer: Manifest, places: Places = Places()):
    """Open the first tarball name the source has, or raise LayerError"""
    problems = []
    for name in tarball_names(layer, places):
        try:
            return source.open(name)
        except OSError as e:
            problems.append(f"{source.path(name)}: {e}")
    raise LayerError(exits.LAYER_UNAVAILABLE, "; ".join(problems))


def download(
    source: Source, layer: Manifest, target: str, places: Places = Places()
) -> None:
    """Stream the tarball to `target`, hashing on the way

    The file lands as `<target>.part` and is renamed only when its size
    and sha256 equal the manifest, so the cache never holds a tarball
    under a digest it does not have. Reading stops as soon as the
    manifest size is exceeded, so a wrong file is not downloaded whole.
    """
    part = target + PART_SUFFIX
    digest = hashlib.sha256()
    size = 0
    try:
        with open_tarball(source, layer, places) as fob, \
                open(part, "wb") as out:
            while chunk := fob.read(READ_CHUNK):
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)
                if size > layer.size:
                    break
    except OSError as e:
        remove_quietly(part)
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"{layer.name}: transfer failed: {e}"
        ) from e
    if size != layer.size or digest.hexdigest() != layer.sha256:
        remove_quietly(part)
        raise LayerError(
            exits.LAYER_MISMATCH,
            f"{layer.name}: downloaded size {size} sha256"
            f" {digest.hexdigest()}, manifest says size {layer.size} sha256"
            f" {layer.sha256}",
        )
    os.replace(part, target)


def fetch_hash_file(
    source: Source, layer: Manifest, target: str, places: Places = Places()
) -> bool:
    """Copy the tarball's `.hash` file to `target` when the source has one

    Looked for under the same names as the tarball. A source without one
    is not an error: bt-layer writes the file only when a signing key is
    set. Returns whether a file was copied.
    """
    for name in tarball_names(layer, places):
        try:
            with source.open(name + HASH_SUFFIX) as fob:
                text = fob.read()
        except OSError:
            continue
        with open(target, "wb") as out:
            out.write(text)
        return True
    return False


def remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def fetch_channel(
    source: Source, resolution: Resolution
) -> channels.Channel:
    """The pointer, verified and fresh, or a LayerError saying which it is not

    The order matters and is the whole of the client half: fetch, verify
    the signature, read the fields, then refuse an expired pointer. A
    pointer that does not verify is never parsed, because the verifier
    writes the plain text of a document it refused and parsing it would
    be reading unsigned data.
    """
    name = resolution.channel
    if not resolution.keyring:
        raise LayerError(
            exits.CHANNEL_UNVERIFIED,
            f"{source.path(name)}: no keyring to verify the channel pointer"
            " against; a pointer nothing verifies is the mirror's word for"
            " itself",
        )
    try:
        with source.open(name) as fob:
            data = fob.read()
    except OSError as e:
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"{source.path(name)}: {e}"
        ) from e
    try:
        verified = signature.verify_bytes(
            source.path(name), data, resolution.keyring, resolution.signers
        )
    except SignatureError as e:
        raise LayerError(exits.CHANNEL_UNVERIFIED, str(e)) from e
    try:
        found = channels.from_text(name, verified.text, source.path(name))
    except ChannelError as e:
        raise LayerError(exits.CHANNEL_INVALID, str(e)) from e
    stale = found.staleness(channels.now())
    if stale is not None:
        raise LayerError(
            exits.CHANNEL_EXPIRED, f"{source.path(name)}: {stale}"
        )
    return found


def fetch_channel_at(
    source_location: str, name: str, keyring: str | None,
    signers: tuple[str, ...] = (),
) -> channels.Channel:
    """The pointer a mirror serves, for a caller that is not pulling

    `keel inspect --check-channel` asks the same question with the same
    refusals, so it asks it through the same code: an expired pointer is
    an error there too.
    """
    return fetch_channel(
        Source(source_location),
        Resolution(channel=name, keyring=keyring, signers=signers),
    )


def read_state(resolution: Resolution) -> channels.State | None:
    if not resolution.state:
        return None
    try:
        return channels.read_state(resolution.state)
    except ChannelError as e:
        raise LayerError(exits.CHANNEL_INVALID, str(e)) from e


def check_rollback(
    state: channels.State | None,
    found: channels.Channel,
    resolution: Resolution,
) -> None:
    """A pointer may not send an instance back to an older revision by itself

    Going back is a thing an operator asks for, by naming the release and
    the revision or by passing --allow-rollback. A mirror that serves a
    signed older pointer is doing the rollback half of the freeze attack.
    """
    if resolution.allow_rollback or not channels.is_rollback(state, found):
        return
    raise LayerError(
        exits.CHANNEL_ROLLBACK,
        f"{found.path}: {found.name} names {found.release}/{found.rev} and"
        f" this instance is on {state.release}/{state.rev}. A mirror does not"
        " move an appliance backwards: name the release and the revision, or"
        " pass --allow-rollback, if going back is what you mean",
    )


def resolve(
    source: Source, resolution: Resolution
) -> tuple[Places, channels.Channel | None, str | None]:
    """The layout to fetch from, the pointer followed and what to record"""
    if resolution.by_release:
        return (
            Places(resolution.release, resolution.rev),
            None,
            f"{resolution.release}/{resolution.rev}",
        )
    if not resolution.by_channel:
        return Places(), None, None
    state = read_state(resolution)
    found = fetch_channel(source, resolution)
    check_rollback(state, found, resolution)
    return (
        Places(found.release, found.rev, dict(found.layers)),
        found,
        f"{found.release}/{found.rev}",
    )


def record_state(
    resolution: Resolution, found: channels.Channel | None, source: str
) -> None:
    """Write down which channel and revision this instance now follows

    A revision named on the command line is recorded too, under the
    channel it was named with, because an operator who rolled back is
    behind that channel on purpose and `keel inspect` has to say so.
    """
    if not resolution.state or resolution.channel is None:
        return
    try:
        if found is not None:
            channels.record(resolution.state, found, source)
        else:
            channels.write_state(
                resolution.state, resolution.channel, resolution.release,
                resolution.rev, source,
            )
    except OSError as e:
        raise LayerError(
            exits.CONF_ERROR, f"{resolution.state}: cannot record: {e}"
        ) from e


def pull(
    layer: str, source_location: str, cache_dir: str,
    resolution: Resolution | None = None,
) -> PullReport:
    """Resolve the chain of `layer` and fetch what the cache lacks

    Raises LayerError with the exit code that names the failure. The
    layers are handled rootfs first, so a failure leaves the cache with
    a usable prefix of the chain. Nothing is fetched and nothing is
    recorded until the pointer, when there is one, has been verified and
    found fresh.
    """
    resolution = resolution or FLAT
    source = Source(source_location)
    places, found, revision = resolve(source, resolution)
    top = load_top(layer, source, places)
    chain = resolve_chain(top, source, places)
    cache = Cache(cache_dir)
    try:
        os.makedirs(cache_dir, exist_ok=True)
        results = tuple(
            pull_layer(source, cache, one, places) for one in chain
        )
    except OSError as e:
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"cache {cache_dir}: {e}"
        ) from e
    record_state(resolution, found, source_location)
    return PullReport(cache_dir, results, found, revision)


def pull_layer(
    source: Source, cache: Cache, layer: Manifest, places: Places = Places()
) -> PullResult:
    status = STATUS_CACHED
    if not cache.has(layer):
        download(
            source, layer, cache.tarball(layer.name, layer.sha256), places
        )
        status = STATUS_FETCHED
    cache.store_manifest(layer)
    fetch_hash_file(
        source, layer, cache.hash_file(layer.name, layer.sha256), places
    )
    return PullResult(layer.name, layer.sha256, layer.size, status)
