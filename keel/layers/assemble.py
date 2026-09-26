# Copyright (c) 2026 KeelLinux maintainers
"""Assemble a rootfs from cached layers and, optionally, pack a template

Brief section 5.1: assembly produces the Proxmox LXC template. The chain
of the layer is resolved from the cached manifests, every cached tarball
is checked against its manifest before anything is extracted, the chain
is applied in order (keel.layers.extract) into an empty directory, and
when a template path is given the directory is packed (keel.layers.pack).

Extracting a rootfs restores owners, device nodes and extended
attributes, which only root can do, so the command refuses to start as
anyone else instead of producing a tree that looks right and is not.
"""

import os
import shutil
import tempfile
from dataclasses import dataclass

from keel import exits
from keel.layers.cache import Cache
from keel.layers.errors import LayerError
from keel.layers.extract import Applied, apply_layer
from keel.layers.manifest import Manifest
from keel.layers.pack import Packed, pack

WORK_PREFIX = ".keel-assemble-"


@dataclass(frozen=True)
class AssembleReport:
    rootfs: str
    applied: tuple[Applied, ...]
    packed: Packed | None

    def lines(self) -> list[str]:
        lines = [item.line() for item in self.applied]
        lines.append(f"rootfs: {self.rootfs}")
        if self.packed is not None:
            lines.append(self.packed.line())
        return lines


def require_root() -> None:
    euid = os.geteuid()
    if euid != 0:
        raise LayerError(
            exits.ASSEMBLE_NEEDS_ROOT,
            f"assemble must run as root: restoring owners, device nodes and"
            f" extended attributes is not possible as uid {euid}",
        )


def check_chain(cache: Cache, chain: list[Manifest]) -> None:
    """Every cached tarball matches its manifest before extraction starts"""
    for layer in chain:
        problems = cache.check(layer)
        if problems:
            raise LayerError(
                exits.LAYER_MISMATCH,
                f"{layer.name}: cached tarball: " + "; ".join(problems),
            )


def prepare(rootfs: str) -> str:
    """Make sure the rootfs exists and is empty; return a scratch directory

    The scratch directory for the decompressed tar is created next to
    the rootfs, so it is on the same file system as the tree it feeds.
    """
    try:
        os.makedirs(rootfs, exist_ok=True)
        if os.listdir(rootfs):
            raise LayerError(
                exits.ASSEMBLE_FAILED,
                f"{rootfs}: not empty, refusing to assemble",
            )
        return tempfile.mkdtemp(
            prefix=WORK_PREFIX, dir=os.path.dirname(os.path.abspath(rootfs))
        )
    except OSError as e:
        raise LayerError(exits.ASSEMBLE_FAILED, f"{rootfs}: {e}") from e


def assemble(
    layer: str,
    cache_dir: str,
    rootfs: str,
    template: str | None = None,
    sha256: str | None = None,
) -> AssembleReport:
    """Extract the chain of `layer` into `rootfs`; pack it when asked

    Raises LayerError with the exit code that names the failure. The
    scratch directory is removed whatever happens.
    """
    require_root()
    cache = Cache(cache_dir)
    top = cache.resolve(layer, sha256)
    chain = cache.chain(top)
    check_chain(cache, chain)
    work = prepare(rootfs)
    try:
        applied = tuple(
            apply_layer(
                found.name, cache.tarball(found.name, found.sha256), rootfs,
                work,
            )
            for found in chain
        )
    finally:
        shutil.rmtree(work)
    packed = None
    if template is not None:
        packed = pack(rootfs, template, top.source_date_epoch)
    return AssembleReport(rootfs, applied, packed)
