# Copyright (c) 2026 KeelLinux maintainers
"""Check a directory of layers against their manifests

For every `<name>.manifest` in the layers directory: the manifest must
parse and validate, the tarball it names must exist with the recorded
sha256 and size, the parent chain must resolve to a rootfs layer with
every parent_sha256 equal to the parent's recorded sha256, and a
`<tarball>.hash` file, when present, must name the same sha256.

A signature inside the hash file is detected and reported, never
verified: the project has no trusted key yet, and this code says so
rather than claiming a check it did not make.
"""

import hashlib
import os
from dataclasses import dataclass

from keel import exits
from keel.layers import hashfile, manifest as manifests
from keel.layers.constants import (
    HASH_SUFFIX,
    KIND_ROOTFS,
    MANIFEST_SUFFIX,
    READ_CHUNK,
)
from keel.layers.errors import ManifestError
from keel.layers.manifest import Manifest

STATUS_OK = "ok"
STATUS_INVALID = "invalid"
STATUS_MISMATCH = "mismatch"
STATUS_UNVERIFIED = "unverified"

STATUS_CODES = {
    STATUS_OK: exits.OK,
    STATUS_INVALID: exits.MANIFEST_INVALID,
    STATUS_MISMATCH: exits.LAYER_MISMATCH,
    STATUS_UNVERIFIED: exits.SIGNATURE_UNVERIFIED,
}
SEVERITY = (STATUS_OK, STATUS_UNVERIFIED, STATUS_MISMATCH, STATUS_INVALID)

SIGNATURE_PRESENT = (
    "signature present, not verified (no trusted key configured)"
)
SIGNATURE_ABSENT = "hash file present, not signed"


@dataclass(frozen=True)
class LayerResult:
    """One line of the report: what was found for one layer"""

    name: str
    status: str
    details: tuple[str, ...] = ()

    @property
    def code(self) -> int:
        return STATUS_CODES[self.status]

    def line(self) -> str:
        text = f"{self.name}: {self.status}"
        if self.details:
            text += ": " + "; ".join(self.details)
        return text


@dataclass(frozen=True)
class Report:
    layers_dir: str
    results: tuple[LayerResult, ...]

    @property
    def code(self) -> int:
        """The worst status of any layer decides the exit code"""
        if not self.results:
            return exits.OK
        worst = max(self.results, key=lambda r: SEVERITY.index(r.status))
        return worst.code

    def count(self, status: str) -> int:
        return sum(1 for result in self.results if result.status == status)

    def summary(self) -> str:
        counts = ", ".join(
            f"{self.count(status)} {status}" for status in SEVERITY
        )
        return f"layers: {len(self.results)} checked, {counts}"


def find_manifests(layers_dir: str) -> list[str]:
    """Manifest paths in the directory, sorted by name"""
    names = sorted(
        entry for entry in os.listdir(layers_dir)
        if entry.endswith(MANIFEST_SUFFIX)
    )
    return [os.path.join(layers_dir, name) for name in names]


def load_manifests(
    paths: list[str],
) -> tuple[dict[str, Manifest], list[LayerResult]]:
    """Load every manifest; the ones that fail become invalid results"""
    loaded: dict[str, Manifest] = {}
    failed: list[LayerResult] = []
    for path in paths:
        stem = os.path.basename(path)[: -len(MANIFEST_SUFFIX)]
        try:
            found = manifests.load(path)
        except ManifestError as e:
            failed.append(LayerResult(stem, STATUS_INVALID, tuple(e.errors)))
            continue
        if found.name != stem:
            failed.append(LayerResult(
                stem, STATUS_INVALID,
                (f"layer: manifest names {found.name!r}, file is {stem!r}",),
            ))
            continue
        loaded[found.name] = found
    return loaded, failed


def digest_and_size(path: str) -> tuple[str, int]:
    """sha256 and size of a file, read in chunks so a layer fits in memory"""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fob:
        while chunk := fob.read(READ_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def check_tarball(layer: Manifest, tarballs_dir: str) -> list[str]:
    """The tarball the manifest names exists with its sha256 and size"""
    path = os.path.join(tarballs_dir, layer.tarball)
    try:
        sha256, size = digest_and_size(path)
    except OSError as e:
        return [f"tarball {layer.tarball}: {e.strerror or e}"]
    problems = []
    if size != layer.size:
        problems.append(f"size {size}, manifest says {layer.size}")
    if sha256 != layer.sha256:
        problems.append(f"sha256 {sha256}, manifest says {layer.sha256}")
    return problems


def check_parent_chain(
    layer: Manifest, known: dict[str, Manifest]
) -> list[str]:
    """Walk parent links up to a rootfs, checking each recorded digest"""
    visited = {layer.name}
    current = layer
    while current.kind != KIND_ROOTFS:
        parent_name = current.parent
        parent = known.get(parent_name)
        if parent is None:
            return [f"parent {parent_name}: no valid manifest"]
        if current.parent_sha256 != parent.sha256:
            return [
                f"parent_sha256 {current.parent_sha256}, "
                f"{parent_name} manifest says {parent.sha256}"
            ]
        if parent_name in visited:
            return [f"parent chain loops through {parent_name}"]
        visited.add(parent_name)
        current = parent
    return []


def check_hash_file(
    layer: Manifest, tarballs_dir: str
) -> tuple[list[str], str | None]:
    """Problems with the hash file and, when it exists, its signature note

    The note is None when there is no hash file, so the layer can be
    fully ok; otherwise it says what was found about the signature, and
    the caller reports the layer as unverified.
    """
    path = os.path.join(tarballs_dir, layer.tarball + HASH_SUFFIX)
    if not os.path.exists(path):
        return [], None
    try:
        found = hashfile.load(path)
    except OSError as e:
        return [f"hash file: {e.strerror or e}"], SIGNATURE_ABSENT
    problems = []
    if found.sha256 is None:
        problems.append("hash file: no sha256 line")
    elif found.sha256 != layer.sha256:
        problems.append(
            f"hash file sha256 {found.sha256}, manifest says {layer.sha256}"
        )
    if found.filename is not None and found.filename != layer.tarball:
        problems.append(
            f"hash file names {found.filename}, manifest says {layer.tarball}"
        )
    note = SIGNATURE_PRESENT if found.signed else SIGNATURE_ABSENT
    return problems, note


def verify_layer(
    layer: Manifest, known: dict[str, Manifest], tarballs_dir: str
) -> LayerResult:
    problems = check_tarball(layer, tarballs_dir)
    problems += check_parent_chain(layer, known)
    hash_problems, note = check_hash_file(layer, tarballs_dir)
    problems += hash_problems
    if problems:
        return LayerResult(layer.name, STATUS_MISMATCH, tuple(problems))
    if note is not None:
        return LayerResult(layer.name, STATUS_UNVERIFIED, (note,))
    return LayerResult(layer.name, STATUS_OK)


def verify_layers(layers_dir: str, tarballs_dir: str | None = None) -> Report:
    """Verify every layer in the directory; never raises

    An absent directory holds no layers and gives an empty report, so an
    appliance built without layers verifies as today. A directory that
    exists but cannot be listed is reported as one invalid result named
    after the directory, so the report shape is the same for the caller.
    """
    tarballs_dir = tarballs_dir or layers_dir
    if not os.path.exists(layers_dir):
        return Report(layers_dir, ())
    try:
        paths = find_manifests(layers_dir)
    except OSError as e:
        result = LayerResult(
            layers_dir, STATUS_INVALID, (f"cannot list: {e.strerror or e}",)
        )
        return Report(layers_dir, (result,))
    known, failed = load_manifests(paths)
    checked = [
        verify_layer(layer, known, tarballs_dir)
        for layer in known.values()
    ]
    results = sorted(checked + failed, key=lambda result: result.name)
    return Report(layers_dir, tuple(results))
