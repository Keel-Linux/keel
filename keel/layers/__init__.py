# Copyright (c) 2026 KeelLinux maintainers
"""Layers: the manifest bt-layer writes, and verify, pull and assemble

Brief sections 5.1 and 5.4. This package is the only implementation; the
CLI and confconsole both call it.
"""

from keel.layers.assemble import AssembleReport, assemble
from keel.layers.channel import Channel, State
from keel.layers.constants import (
    CACHE_DEFAULT,
    CACHE_ENV,
    KEYRING_DEFAULT,
    KEYRING_ENV,
    LAYERS_DEFAULT,
    LAYERS_ENV,
    REQUIRED_KEYS,
    STATE_DEFAULT,
    STATE_ENV,
)
from keel.layers.errors import (
    ChannelError,
    LayerError,
    ManifestError,
    SignatureError,
)
from keel.layers.layout import CHANNELS
from keel.layers.manifest import Manifest, load, parse, validate
from keel.layers.pull import (
    PullReport,
    PullResult,
    Resolution,
    fetch_channel_at,
    pull,
)
from keel.layers.verify import LayerResult, Report, verify_layers

__all__ = [
    "CACHE_DEFAULT",
    "CACHE_ENV",
    "CHANNELS",
    "KEYRING_DEFAULT",
    "KEYRING_ENV",
    "LAYERS_DEFAULT",
    "LAYERS_ENV",
    "REQUIRED_KEYS",
    "STATE_DEFAULT",
    "STATE_ENV",
    "AssembleReport",
    "Channel",
    "ChannelError",
    "LayerError",
    "LayerResult",
    "Manifest",
    "ManifestError",
    "PullReport",
    "PullResult",
    "Report",
    "Resolution",
    "SignatureError",
    "State",
    "assemble",
    "fetch_channel_at",
    "load",
    "parse",
    "pull",
    "validate",
    "verify_layers",
]
