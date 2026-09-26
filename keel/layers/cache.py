# Copyright (c) 2026 KeelLinux maintainers
"""The layer cache: tarballs and manifests by name and content hash

Layout of the cache directory:

    <name>-<sha256>.tar.zst     the layer tarball, as built
    <name>-<sha256>.manifest    its manifest, as pulled

Both are keyed by the sha256 the manifest records, so two versions of
the same layer never collide and a file that is present with the right
digest never has to be fetched again.
"""

import glob
import os

from keel import exits
from keel.layers import manifest as manifests
from keel.layers.constants import (
    KIND_ROOTFS,
    MANIFEST_SUFFIX,
    TARBALL_SUFFIX,
)
from keel.layers.errors import LayerError, ManifestError
from keel.layers.manifest import Manifest
from keel.layers.verify import digest_and_size


class Cache:
    def __init__(self, path: str):
        self.path = path

    def tarball(self, name: str, sha256: str) -> str:
        return os.path.join(self.path, f"{name}-{sha256}{TARBALL_SUFFIX}")

    def manifest(self, name: str, sha256: str) -> str:
        return os.path.join(self.path, f"{name}-{sha256}{MANIFEST_SUFFIX}")

    def has(self, layer: Manifest) -> bool:
        """The tarball is present with the recorded size and sha256

        A file with another digest is treated as absent, so a truncated
        or corrupted download is replaced rather than trusted.
        """
        return not self.check(layer)

    def check(self, layer: Manifest) -> list[str]:
        """Problems with the cached tarball; an absent file is a problem"""
        path = self.tarball(layer.name, layer.sha256)
        try:
            sha256, size = digest_and_size(path)
        except OSError as e:
            return [f"{path}: {e.strerror or e}"]
        problems = []
        if size != layer.size:
            problems.append(f"size {size}, manifest says {layer.size}")
        if sha256 != layer.sha256:
            problems.append(f"sha256 {sha256}, manifest says {layer.sha256}")
        return problems

    def store_manifest(self, layer: Manifest) -> str:
        path = self.manifest(layer.name, layer.sha256)
        with open(path, "w", encoding="utf-8") as fob:
            fob.write(layer.text())
        return path

    def load(self, name: str, sha256: str) -> Manifest:
        """The cached manifest of one layer version, or LayerError"""
        path = self.manifest(name, sha256)
        try:
            return manifests.load(path)
        except ManifestError as e:
            code = exits.MANIFEST_INVALID
            if not os.path.exists(path):
                code = exits.LAYER_UNAVAILABLE
            raise LayerError(
                code, f"{name}: {e}; run keel pull first"
            ) from e

    def resolve(self, name: str, sha256: str | None) -> Manifest:
        """The cached manifest for a name, by sha256 when several exist"""
        if sha256 is not None:
            return self.load(name, sha256)
        pattern = os.path.join(
            self.path, glob.escape(f"{name}-") + "*" + MANIFEST_SUFFIX
        )
        found = sorted(glob.glob(pattern))
        if not found:
            raise LayerError(
                exits.LAYER_UNAVAILABLE,
                f"{name}: not in cache {self.path}; run keel pull first",
            )
        if len(found) > 1:
            digests = ", ".join(
                os.path.basename(path)[len(name) + 1: -len(MANIFEST_SUFFIX)]
                for path in found
            )
            raise LayerError(
                exits.LAYER_UNAVAILABLE,
                f"{name}: several versions in cache, pass --sha256 with one"
                f" of {digests}",
            )
        stem = os.path.basename(found[0])[: -len(MANIFEST_SUFFIX)]
        return self.load(name, stem[len(name) + 1:])

    def chain(self, top: Manifest) -> list[Manifest]:
        """The layers of `top`, rootfs first, every one from the cache

        Each parent is looked up by the name and digest the child
        records, so the chain is exact by construction.
        """
        chain = [top]
        current = top
        while current.kind != KIND_ROOTFS:
            current = self.load(current.parent, current.parent_sha256)
            chain.append(current)
        chain.reverse()
        return chain
