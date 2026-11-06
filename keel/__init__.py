# Copyright (c) 2026 KeelLinux maintainers
"""Keel: declarative management of a single appliance instance

Keel is compatible with TurnKey Linux appliances. The library is the only
place where logic lives; the CLI (keel.cli) and confconsole are both
clients of it.
"""

# The version the package carries when it is not installed (a checkout,
# an image's tree read offline): debian/changelog's and pyproject.toml's,
# which tests/test_version.py keeps in step. Installed, the metadata
# dpkg put beside the package answers (keel#98).
FALLBACK_VERSION = "0.23.87"


def version() -> str:
    """The installed package's version, else the fallback"""
    import importlib.metadata
    try:
        return importlib.metadata.version("keel")
    except importlib.metadata.PackageNotFoundError:
        return FALLBACK_VERSION


def __getattr__(name: str):
    """Lazy __version__: importlib.metadata is loaded only on first access

    Decision 0070.  __version__ is not a submodule, so the conflict that
    rule 7 prevents (a public function shadowed by a submodule of the same
    name) does not apply here.
    """
    if name == "__version__":
        v = version()
        globals()["__version__"] = v
        return v
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
