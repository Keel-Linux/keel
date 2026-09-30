# Copyright (c) 2026 KeelLinux maintainers
"""The manifests installed under a root

A machine has them at /usr/share/keel/overlays/<name>.yaml and
/usr/share/keel/appliances/<name>.yaml, from the packages that ship them
(decision 0041); a package build or a test has them under another root.
A name is looked up only when it has the shape of one, so no name can
climb out of the directory with `..`.
"""

import os

from keel.manifest.constants import DIRS, KINDS, NAME_RE, SHARE_DIR, SUFFIX
from keel.manifest.load import ManifestError, load
from keel.manifest.validate import validate


def stem_of(path: str) -> str:
    base = os.path.basename(path)
    return base[:-len(SUFFIX)] if base.endswith(SUFFIX) else base


def kind_of_directory(path: str) -> str | None:
    """The kind the directory of PATH holds, when it is one of the two"""
    parent = os.path.basename(os.path.dirname(os.path.abspath(path)))
    for kind in KINDS:
        if DIRS[kind] == parent:
            return kind
    return None


def kind_errors(doc: dict, directory: str | None,
                expected: str | None) -> list[str]:
    """The kind a file says against where it lies and what was asked"""
    kind = doc.get("kind")
    if kind not in KINDS:
        return []
    errors = []
    if expected and kind != expected:
        errors.append(f"kind: {kind}, but --kind says {expected}")
    if directory and kind != directory:
        errors.append(f"kind: {kind}, but the file is in {DIRS[directory]}/")
    return errors


class Catalog:
    """Reads and validates each installed manifest once"""

    def __init__(self, root: str):
        self.root = root
        self._docs: dict = {}
        self._usable: dict = {}

    def directory(self) -> str:
        return os.path.join(self.root, SHARE_DIR)

    def path(self, kind: str, name: str) -> str:
        return os.path.join(self.root, SHARE_DIR, DIRS[kind], name + SUFFIX)

    def names(self, kind: str) -> list[str]:
        try:
            entries = os.listdir(os.path.join(self.root, SHARE_DIR,
                                              DIRS[kind]))
        except OSError:
            return []
        return sorted(stem_of(entry) for entry in entries
                      if entry.endswith(SUFFIX))

    def exists(self, kind: str, name: str) -> bool:
        return bool(NAME_RE.match(name)) and os.path.isfile(
            self.path(kind, name))

    def read(self, kind: str, name: str) -> dict:
        """The parsed file; ManifestError when absent or unreadable"""
        key = (kind, name)
        if key not in self._docs:
            if not self.exists(kind, name):
                self._docs[key] = ManifestError(
                    f"no manifest named {name} under {self.directory()}")
            else:
                try:
                    self._docs[key] = load(self.path(kind, name))
                except ManifestError as e:
                    self._docs[key] = e
        found = self._docs[key]
        if isinstance(found, ManifestError):
            raise found
        return found

    def usable(self, kind: str, name: str) -> tuple[dict | None, str]:
        """The manifest when it is installed and valid, else why not"""
        key = (kind, name)
        if key not in self._usable:
            self._usable[key] = self._check(kind, name)
        return self._usable[key]

    def _check(self, kind: str, name: str) -> tuple[dict | None, str]:
        if not self.exists(kind, name):
            return None, ""
        try:
            doc = self.read(kind, name)
        except ManifestError as e:
            return None, str(e)
        errors = validate(doc, name, self) + kind_errors(doc, kind, None)
        if errors:
            return None, (f"{self.path(kind, name)} fails validation"
                          f" ({len(errors)} errors)")
        return doc, ""
