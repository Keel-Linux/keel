# Copyright (c) 2026 KeelLinux maintainers
"""Keel: declarative management of a single appliance instance

Keel is compatible with TurnKey Linux appliances. The library is the only
place where logic lives; the CLI (keel.cli) and confconsole are both
clients of it.
"""

import importlib.metadata

# The version the package carries when it is not installed (a checkout,
# an image's tree read offline): debian/changelog's and pyproject.toml's,
# which tests/test_version.py keeps in step. Installed, the metadata
# dpkg put beside the package answers (keel#98).
FALLBACK_VERSION = "0.23.15"


def version() -> str:
    """The installed package's version, else the fallback"""
    try:
        return importlib.metadata.version("keel")
    except importlib.metadata.PackageNotFoundError:
        return FALLBACK_VERSION


__version__ = version()
