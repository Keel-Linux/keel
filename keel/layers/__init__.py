# Copyright (c) 2026 KeelLinux maintainers
"""Layers: the manifest bt-layer writes and the checks keel verify runs

Brief section 5.4. This package is the only implementation; the CLI and
confconsole both call it.
"""

from keel.layers.constants import LAYERS_DEFAULT, LAYERS_ENV, REQUIRED_KEYS
from keel.layers.errors import ManifestError
from keel.layers.manifest import Manifest, load, parse, validate
from keel.layers.verify import LayerResult, Report, verify_layers

__all__ = [
    "LAYERS_DEFAULT",
    "LAYERS_ENV",
    "REQUIRED_KEYS",
    "LayerResult",
    "Manifest",
    "ManifestError",
    "Report",
    "load",
    "parse",
    "validate",
    "verify_layers",
]
