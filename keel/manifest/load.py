# Copyright (c) 2026 KeelLinux maintainers
"""Read a manifest file into a plain dict

PyYAML, as for the instance spec, with one difference: a key written
twice in one mapping is refused rather than the second silently
winning, since an overlay listed twice would otherwise lose its first
states without a word (docs/manifest.md, "Reading").
"""

import yaml


class ManifestError(Exception):
    """A manifest file cannot be read"""


class _Duplicate(yaml.YAMLError):
    pass


class _Loader(yaml.SafeLoader):
    """SafeLoader that refuses a key given twice in one mapping"""


def _mapping(loader: _Loader, node: yaml.MappingNode) -> dict:
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        try:
            duplicate = key in seen
        except TypeError:
            continue
        if duplicate:
            line = key_node.start_mark.line + 1
            raise _Duplicate(f"line {line}: {key} appears twice")
        seen.add(key)
    return loader.construct_mapping(node)


_Loader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load(path: str) -> dict:
    """Parse one manifest, raise ManifestError when it cannot be used"""
    try:
        with open(path) as fob:
            doc = yaml.load(fob, Loader=_Loader)  # noqa: S506 (a SafeLoader)
    except OSError as e:
        raise ManifestError(f"{path}: {e.strerror or e}")
    except _Duplicate as e:
        raise ManifestError(f"{path}: {e}")
    except yaml.YAMLError as e:
        raise ManifestError(f"{path}: not valid YAML: {e}")
    if doc is None:
        raise ManifestError(f"{path}: file is empty")
    if not isinstance(doc, dict):
        raise ManifestError(f"{path}: top level must be a mapping")
    return doc
