# Copyright (c) 2026 KeelLinux maintainers
"""Names, paths and key tables of the layer manifest and channel pointer

The manifest is written by bt-layer (buildtasks) as plain text, one
`key value` per line. Kept apart from the code that reads it so that the
format can be read without reading the parser. The channel pointer of
handbook decision 0016 uses the same grammar, and its key table is here
for the same reason.
"""

import re

LAYERS_DEFAULT = "/var/lib/keel/layers"
LAYERS_ENV = "KEEL_LAYERS_DIR"
CACHE_DEFAULT = "/var/cache/keel/layers"
CACHE_ENV = "KEEL_CACHE_DIR"

# The record of the channel this instance follows, and the keyring a
# channel pointer is verified against. The keyring default is binary
# because that is the only form gpgv reads; an armored file is dearmored
# on the way in (keel.layers.signature).
STATE_DEFAULT = "/var/lib/keel/channel"
STATE_ENV = "KEEL_CHANNEL_STATE"
KEYRING_DEFAULT = "/usr/share/keyrings/keel-channel-keyring.gpg"
KEYRING_ENV = "KEEL_CHANNEL_KEYRING"

MANIFEST_SUFFIX = ".manifest"
HASH_SUFFIX = ".hash"
TARBALL_SUFFIX = ".tar.zst"
SHA512_SUFFIX = ".sha512"
PART_SUFFIX = ".part"
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

# The channel pointer. `layer` is the one key that repeats, once per
# layer of the release revision the pointer names.
LAYER_KEY = "layer"
TIMESTAMPS = ("signed_at", "expires_at")
CHANNEL_REQUIRED_KEYS = ("channel", "release", "rev", *TIMESTAMPS)
STATE_REQUIRED_KEYS = ("channel", "release", "rev", "source")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# What verifies a clear signature, and the status line that says a
# signature was good. gpgv names the signing key first and its primary
# key last, so configuring either fingerprint works and a subkey
# rotation needs no change on the appliances.
VERIFIER = ("gpgv",)
ARMOR_START = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = b"-----END PGP PUBLIC KEY BLOCK-----"
VALIDSIG_RE = re.compile(
    r"^\[GNUPG:\] VALIDSIG (?P<signer>[0-9A-Fa-f]{40})"
    r"(?:\s+\S+){8}\s+(?P<primary>[0-9A-Fa-f]{40})\s*$"
)

READ_CHUNK = 1 << 20

URL_SCHEMES = ("http", "https")
FETCH_TIMEOUT = 60

# What overlayfs leaves in an upper directory: a character device 0:0
# where a lower path was removed, and this xattr on a directory whose
# lower contents must not show through. Both are stored in the tarball by
# tar --xattrs as pax headers with this prefix.
PAX_XATTR_PREFIX = "SCHILY.xattr."
OVERLAY_XATTR_GLOB = "trusted.overlay.*"
OPAQUE_XATTR = PAX_XATTR_PREFIX + "trusted.overlay.opaque"
OPAQUE_VALUE = "y"
TAR_BLOCK = 512
TAR_END_OF_ARCHIVE = b"\0" * (2 * TAR_BLOCK)

ZSTD_LEVEL = 19
