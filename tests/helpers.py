# Copyright (c) 2026 KeelLinux maintainers
"""Shared helpers for the spec tests"""

import os
import sys
import tempfile
from os.path import abspath, dirname

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from keel import spec  # noqa: E402


def doc(text: str) -> dict:
    """Load a YAML document from a string through spec.load()"""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False
    ) as fob:
        fob.write(text)
        path = fob.name
    try:
        return spec.load(path)
    finally:
        os.remove(path)


def env(text: str) -> dict:
    """Render a YAML document to a dict of exported variables"""
    document = doc(text)
    found = spec.validate(document)
    if found:
        raise AssertionError(f"unexpected errors: {found}")
    secrets = spec.resolve_secrets(document)
    rendered = spec.render_env(document, secrets)
    exported = {}
    for line in rendered.splitlines():
        if not line.startswith("export "):
            continue
        key, _, value = line[len("export "):].partition("=")
        exported[key] = value
    return exported


def errors(text: str) -> list[str]:
    return spec.validate(doc(text))
