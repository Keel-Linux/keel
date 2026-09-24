# Copyright (c) 2026 KeelLinux maintainers
"""Read a spec file into a plain dict

Parsing is deliberately kept in one function so that the file format can
be changed without touching anything else.
"""

import yaml

from keel.spec.errors import SpecError


def load(path: str) -> dict:
    """Parse the spec file, raise SpecError if it cannot be parsed"""
    try:
        with open(path) as fob:
            doc = yaml.safe_load(fob)
    except OSError as e:
        raise SpecError(f"{path}: {e}")
    except yaml.YAMLError as e:
        raise SpecError(f"{path}: not valid YAML: {e}")

    if doc is None:
        raise SpecError(f"{path}: file is empty")
    if not isinstance(doc, dict):
        raise SpecError(f"{path}: top level must be a mapping")
    return doc
