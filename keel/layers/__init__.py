# Copyright (c) 2026 KeelLinux maintainers
"""Layers: the manifest bt-layer writes, and verify, pull and assemble

Brief sections 5.1 and 5.4. This package is the only implementation; the
CLI and confconsole both call it.
"""

from keel.layers.assemble import AssembleReport, assemble
from keel.layers.constants import (
    CACHE_DEFAULT,
    CACHE_ENV,
    LAYERS_DEFAULT,
    LAYERS_ENV,
    REQUIRED_KEYS,
)
from keel.layers.errors import LayerError, ManifestError
from keel.layers.manifest import Manifest, load, parse, validate
from keel.layers.pull import PullReport, PullResult, pull
from keel.layers.verify import LayerResult, Report, verify_layers

__all__ = [
    "CACHE_DEFAULT",
    "CACHE_ENV",
    "LAYERS_DEFAULT",
    "LAYERS_ENV",
    "REQUIRED_KEYS",
    "AssembleReport",
    "LayerError",
    "LayerResult",
    "Manifest",
    "ManifestError",
    "PullReport",
    "PullResult",
    "Report",
    "assemble",
    "load",
    "parse",
    "pull",
    "validate",
    "verify_layers",
]
