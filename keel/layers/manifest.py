# Copyright (c) 2026 KeelLinux maintainers
"""Parse and validate one layer manifest

A manifest is the plain text file bt-layer writes next to a layer
tarball: one `key value` per line, keys as in REQUIRED_KEYS. Parsing
never raises anything but ManifestError, and validation returns every
problem it finds rather than the first.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from keel.layers.constants import (
    INTEGER_RE,
    KEY_RE,
    KIND_DELTA,
    KIND_ROOTFS,
    KINDS,
    NAME_RE,
    NONE,
    REQUIRED_KEYS,
    SHA256_RE,
)
from keel.layers.errors import ManifestError


@dataclass(frozen=True)
class Manifest:
    """A validated manifest; the fields are read only"""

    path: str
    fields: Mapping[str, str]

    @property
    def name(self) -> str:
        return self.fields["layer"]

    @property
    def kind(self) -> str:
        return self.fields["type"]

    @property
    def parent(self) -> str | None:
        parent = self.fields["parent"]
        return None if parent == NONE else parent

    @property
    def parent_sha256(self) -> str | None:
        digest = self.fields["parent_sha256"]
        return None if digest == NONE else digest

    @property
    def tarball(self) -> str:
        return self.fields["tarball"]

    @property
    def sha256(self) -> str:
        return self.fields["sha256"]

    @property
    def size(self) -> int:
        return int(self.fields["size"])

    @property
    def source_date_epoch(self) -> int:
        return int(self.fields["source_date_epoch"])


def parse(text: str) -> dict[str, str]:
    """Split manifest text into fields

    Raises ManifestError on a line without a value, an invalid key or a
    repeated key. Blank lines are ignored so that a trailing newline or
    a hand edit does not break the file.
    """
    fields: dict[str, str] = {}
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        key, _, value = line.partition(" ")
        value = value.strip()
        if not KEY_RE.match(key):
            errors.append(f"line {number}: invalid key {key!r}")
        elif not value:
            errors.append(f"line {number}: {key}: missing value")
        elif key in fields:
            errors.append(f"line {number}: {key}: repeated key")
        else:
            fields[key] = value
    if errors:
        raise ManifestError("manifest", errors)
    return fields


def validate(fields: Mapping[str, str]) -> list[str]:
    """Return every problem with the fields, an empty list when valid"""
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        return [f"missing keys: {', '.join(missing)}"]
    errors = _validate_values(fields)
    errors.extend(_validate_parent(fields))
    return errors


def _validate_values(fields: Mapping[str, str]) -> list[str]:
    errors = []
    if not NAME_RE.match(fields["layer"]):
        errors.append(f"layer: invalid name {fields['layer']!r}")
    if fields["type"] not in KINDS:
        errors.append(f"type: must be one of {', '.join(KINDS)}")
    if not SHA256_RE.match(fields["sha256"]):
        errors.append("sha256: must be 64 lowercase hex digits")
    for key in ("size", "source_date_epoch"):
        if not INTEGER_RE.match(fields[key]):
            errors.append(f"{key}: must be a non negative integer")
    if "/" in fields["tarball"]:
        errors.append("tarball: must be a file name, not a path")
    return errors


def _validate_parent(fields: Mapping[str, str]) -> list[str]:
    """A delta names a parent and its digest; a rootfs names neither"""
    kind = fields["type"]
    parent = fields["parent"]
    digest = fields["parent_sha256"]
    if kind == KIND_ROOTFS:
        errors = []
        if parent != NONE:
            errors.append("parent: a rootfs layer must have parent none")
        if digest != NONE:
            errors.append(
                "parent_sha256: a rootfs layer must have parent_sha256 none"
            )
        return errors
    if kind != KIND_DELTA:
        return []
    errors = []
    if parent == NONE or not NAME_RE.match(parent):
        errors.append("parent: a delta layer must name its parent layer")
    elif parent == fields["layer"]:
        errors.append("parent: a layer cannot be its own parent")
    if not SHA256_RE.match(digest):
        errors.append(
            "parent_sha256: a delta layer must record the parent sha256"
        )
    return errors


def load(path: str) -> Manifest:
    """Read, parse and validate a manifest file

    Raises ManifestError, with every problem found, when the file cannot
    be read, is malformed or fails validation.
    """
    try:
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
    except (OSError, UnicodeDecodeError) as e:
        raise ManifestError(path, [f"cannot read: {e}"]) from e

    try:
        fields = parse(text)
    except ManifestError as e:
        raise ManifestError(path, e.errors) from e

    errors = validate(fields)
    if errors:
        raise ManifestError(path, errors)
    return Manifest(path=path, fields=MappingProxyType(dict(fields)))
