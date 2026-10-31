# Copyright (c) 2026 KeelLinux maintainers
"""Parser constants: the values the CLI needs to build its argument parser

Every value here was in a heavier module before decision 0070 moved it.
The original modules import from here so their public names still resolve.
"""

import os

# -- keel.inspect.constants --------------------------------------------------
# The live system is /. KEEL_LIVE_ROOT names a tree that stands for it:
# the multi-node tests run several nodes in one container, each on a
# scratch root in a network namespace of its own, and keel there asks
# the servers, runs systemctl and writes under that root as it does on
# a machine (tests/mariadb_netns.py). Never set on a machine.
ROOT_DEFAULT = os.path.abspath(os.environ.get("KEEL_LIVE_ROOT") or "/")
SECRETS_DIR_DEFAULT = "/etc/keel/secrets"

# -- keel.spec.constants ------------------------------------------------------
SPEC_DEFAULT = "/etc/keel/instance.yaml"
CONF_DEFAULT = "/etc/inithooks.conf"
SPEC_ENV = "KEEL_SPEC"
CONF_ENV = "KEEL_CONF"

# -- keel.layers.constants ----------------------------------------------------
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

# -- keel.manifest.constants --------------------------------------------------
MANIFEST_KINDS = ("overlay", "appliance")

# -- keel.system.network ------------------------------------------------------
DEFAULT_WINDOW = 120

# -- keel.network.wireguard ---------------------------------------------------
WIREGUARD_PORT = 51820

# -- keel.layers.layout -------------------------------------------------------
CHANNEL_STABLE = "stable"
CHANNEL_TESTING = "testing"
CHANNELS = (CHANNEL_STABLE, CHANNEL_TESTING)
