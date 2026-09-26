# Copyright (c) 2026 KeelLinux maintainers
"""Fetch the layers of an appliance that the cache does not have yet

Brief section 5.1: `keel pull` fetches only missing layers. Given the
top layer (a name looked up at the source, or a manifest file), the
parent chain is resolved through the manifests, every layer whose
tarball is already in the cache with the right digest is left alone,
and the others are downloaded, checked against the manifest and stored
under `<name>-<sha256>.tar.zst`.
"""

import hashlib
import os
from dataclasses import dataclass

from keel import exits
from keel.layers import manifest as manifests
from keel.layers.cache import Cache
from keel.layers.constants import (
    KIND_ROOTFS,
    MANIFEST_SUFFIX,
    PART_SUFFIX,
    READ_CHUNK,
    TARBALL_SUFFIX,
)
from keel.layers.errors import LayerError, ManifestError
from keel.layers.manifest import Manifest
from keel.layers.source import Source

STATUS_FETCHED = "fetched"
STATUS_CACHED = "cached"


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


def load_source_manifest(source: Source, name: str) -> Manifest:
    """Fetch and validate `<name>.manifest` from the source"""
    filename = name + MANIFEST_SUFFIX
    try:
        text = source.read_text(filename)
    except OSError as e:
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"{source.path(filename)}: {e}"
        ) from e
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


def load_top(layer: str, source: Source) -> Manifest:
    """The layer asked for: a manifest file on disk, or a name at the source"""
    if not (layer.endswith(MANIFEST_SUFFIX) or os.sep in layer):
        return load_source_manifest(source, layer)
    try:
        return manifests.load(layer)
    except ManifestError as e:
        raise LayerError(exits.MANIFEST_INVALID, str(e)) from e


def resolve_chain(top: Manifest, source: Source) -> list[Manifest]:
    """Walk the parents at the source up to a rootfs, rootfs first

    Every parent's recorded sha256 must equal the digest the child
    recorded at build time: a source that has moved on to a newer
    parent is a mismatch, not a silent substitution.
    """
    chain = [top]
    seen = {top.name}
    current = top
    while current.kind != KIND_ROOTFS:
        parent = load_source_manifest(source, current.parent)
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


def tarball_names(layer: Manifest) -> tuple[str, str]:
    """Where a source may keep the tarball: by hash, or as bt-layer wrote it"""
    return (f"{layer.name}-{layer.sha256}{TARBALL_SUFFIX}", layer.tarball)


def open_tarball(source: Source, layer: Manifest):
    """Open the first tarball name the source has, or raise LayerError"""
    problems = []
    for name in tarball_names(layer):
        try:
            return source.open(name)
        except OSError as e:
            problems.append(f"{source.path(name)}: {e}")
    raise LayerError(exits.LAYER_UNAVAILABLE, "; ".join(problems))


def download(source: Source, layer: Manifest, target: str) -> None:
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
        with open_tarball(source, layer) as fob, open(part, "wb") as out:
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


def remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def pull(layer: str, source_location: str, cache_dir: str) -> PullReport:
    """Resolve the chain of `layer` and fetch what the cache lacks

    Raises LayerError with the exit code that names the failure. The
    layers are handled rootfs first, so a failure leaves the cache with
    a usable prefix of the chain.
    """
    source = Source(source_location)
    top = load_top(layer, source)
    chain = resolve_chain(top, source)
    cache = Cache(cache_dir)
    try:
        os.makedirs(cache_dir, exist_ok=True)
        results = tuple(pull_layer(source, cache, found) for found in chain)
    except OSError as e:
        raise LayerError(
            exits.LAYER_UNAVAILABLE, f"cache {cache_dir}: {e}"
        ) from e
    return PullReport(cache_dir, results)


def pull_layer(source: Source, cache: Cache, layer: Manifest) -> PullResult:
    status = STATUS_CACHED
    if not cache.has(layer):
        download(source, layer, cache.tarball(layer.name, layer.sha256))
        status = STATUS_FETCHED
    cache.store_manifest(layer)
    return PullResult(layer.name, layer.sha256, layer.size, status)
