# Copyright (c) 2026 KeelLinux maintainers
"""Values the CLI needs before it loads a package

The parser is built before a command is chosen, so reading these from
keel.layers, keel.spec and the rest would load each package for its
constants alone. The modules that own them import them from here, so
there is one source.
"""

import os

# KEEL_LIVE_ROOT stands in for / in the multi-node tests; never set on a
# machine (keel.inspect.constants documents it).
ROOT_DEFAULT = os.path.abspath(os.environ.get("KEEL_LIVE_ROOT") or "/")
SECRETS_DIR_DEFAULT = "/etc/keel/secrets"

LAYERS_DEFAULT = "/var/lib/keel/layers"
LAYERS_ENV = "KEEL_LAYERS_DIR"
CACHE_DEFAULT = "/var/cache/keel/layers"
CACHE_ENV = "KEEL_CACHE_DIR"

STATE_DEFAULT = "/var/lib/keel/channel"
STATE_ENV = "KEEL_CHANNEL_STATE"
KEYRING_DEFAULT = "/usr/share/keyrings/keel-channel-keyring.gpg"
KEYRING_ENV = "KEEL_CHANNEL_KEYRING"
SIGNER_ENV = "KEEL_CHANNEL_SIGNER"
IMAGE_KEYRINGS_DEFAULT = (
    "/usr/share/keyrings/keel-archive-keyring.gpg",
    "/usr/share/keyrings/keel-images-keyring.gpg",
)
IMAGE_KEYRINGS_ENV = "KEEL_IMAGE_KEYRINGS"

CHANNEL_STABLE = "stable"
CHANNEL_TESTING = "testing"
CHANNELS = (CHANNEL_STABLE, CHANNEL_TESTING)

MANIFEST_KINDS = ("overlay", "appliance")

SPEC_DEFAULT = "/etc/keel/instance.yaml"
CONF_DEFAULT = "/etc/inithooks.conf"
SPEC_ENV = "KEEL_SPEC"
CONF_ENV = "KEEL_CONF"

DEFAULT_WINDOW = 120
WIREGUARD_PORT = 51820
