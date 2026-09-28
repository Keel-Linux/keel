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
# Which key may move a channel, when an image wants to say so without
# passing --channel-signer on every call. Empty means every key in the
# keyring is accepted, so a keyring holding only the channel key is the
# other way to get the same separation.
SIGNER_ENV = "KEEL_CHANNEL_SIGNER"

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
# The longest a pointer may claim to be believable. Unbounded, "until
# when" is a permanent freeze: one signature from the online key pins an
# appliance to an already-staged, known-vulnerable revision for ever, and
# the rollback check never fires because the revision does not go
# backwards. Thirty days is a wide ceiling over the seven day default and
# still a bound.
MAX_TTL_DAYS = 30
# How far a pointer may be signed ahead of this machine's clock before it
# is refused. Small, because the only honest reasons for any gap at all
# are drift and the moment of signing.
MAX_FUTURE_SECONDS = 3600
# A `.hash` file is prose with two digest lines in it. Anything larger is
# not one, and the tarball path is already careful about unbounded reads.
HASH_FILE_MAX = 1 << 16
CHANNEL_REQUIRED_KEYS = ("channel", "release", "rev", *TIMESTAMPS)
STATE_REQUIRED_KEYS = ("channel", "release", "rev", "source")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# What verifies a clear signature, and the status lines that decide.
#
# GOODSIG and not VALIDSIG is the line that matters, and the difference is
# the whole of a key's retirement. Measured on gpgv 2.4.7: a signature by
# a revoked primary, by a revoked signing subkey under a live primary, or
# by an expired key each give **exit 0** and a VALIDSIG line, with stderr
# saying "Good signature from". GOODSIG is the only line gpgv withholds,
# substituting REVKEYSIG or EXPKEYSIG. A verifier that accepts VALIDSIG
# therefore makes revocation do nothing, which is the one answer there is
# to the theft of the online key that signs a channel.
#
# --weak-digest SHA1 because a SHA-1 clearsigned pointer otherwise
# verifies with a GOODSIG of its own (measured: exit 0; with the flag,
# exit 2 and ERRSIG).
VERIFIER = ("gpgv", "--weak-digest", "SHA1")
GOODSIG_RE = re.compile(r"^\[GNUPG:\] GOODSIG\b")
RETIRED_RE = re.compile(
    r"^\[GNUPG:\] (REVKEYSIG|EXPKEYSIG|KEYREVOKED|KEYEXPIRED)\b"
)
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
