# Copyright (c) 2026 KeelLinux maintainers
"""The appliance manifest, version 1 (decision 0041)

An overlay manifest says what an overlay runs; an appliance manifest
says what an appliance is built on, which overlays it adds with their
state in each installation mode, and what it runs itself. One schema
for both, versioned by an integer, with unknown keys refused at every
level. The format is docs/manifest-v1.md in the handbook; what keel
does with it is docs/manifest.md.

This is not the layer manifest of keel.layers, the key-value file
bt-layer writes beside a layer tarball: that one says how a layer was
built, this one what an appliance is.

Nothing else in keel reads it yet: `keel manifest validate` and `keel
manifest show` are its only clients.
"""

from keel.manifest.catalog import Catalog
from keel.manifest.constants import KINDS, MANIFEST_VERSION
from keel.manifest.load import ManifestError, load
from keel.manifest.report import Outcome, show, validate_target
from keel.manifest.resolve import Owned, OverlayState, Resolved, resolve
from keel.manifest.validate import validate

__all__ = [
    "KINDS", "MANIFEST_VERSION", "Catalog", "ManifestError", "Outcome",
    "Owned", "OverlayState", "Resolved", "load", "resolve", "show",
    "validate", "validate_target",
]
