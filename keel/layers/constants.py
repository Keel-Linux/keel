# Copyright (c) 2026 KeelLinux maintainers
"""Names, paths and key tables of the layer manifest

The manifest is written by bt-layer (buildtasks) as plain text, one
`key value` per line. Kept apart from the code that reads it so that the
format can be read without reading the parser.
"""

import re

LAYERS_DEFAULT = "/var/lib/keel/layers"
LAYERS_ENV = "KEEL_LAYERS_DIR"

MANIFEST_SUFFIX = ".manifest"
HASH_SUFFIX = ".hash"
NONE = "none"

KIND_ROOTFS = "rootfs"
KIND_DELTA = "delta"
KINDS = (KIND_ROOTFS, KIND_DELTA)

REQUIRED_KEYS = (
    "layer",
    "type",
    "parent",
    "parent_sha256",
    "release",
    "arch",
    "product_commit",
    "common_commit",
    "fab_version",
    "source_date_epoch",
    "common_overlays",
    "common_conf",
    "build_overlays",
    "build_conf",
    "tarball",
    "sha256",
    "size",
)

KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
INTEGER_RE = re.compile(r"^[0-9]+$")

SIGNED_MESSAGE_MARK = "-----BEGIN PGP SIGNED MESSAGE-----"
SIGNATURE_MARK = "-----BEGIN PGP SIGNATURE-----"

READ_CHUNK = 1 << 20
