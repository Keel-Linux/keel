# Copyright (c) 2026 KeelLinux maintainers
"""What `keel manifest validate` and `keel manifest show` print

Each returns an Outcome: the text for standard output, the errors and
notes for standard error, and the exit code, with the codes of `keel
spec validate`: 2 when a file cannot be read, 3 when one fails
validation, and 1 for a question that cannot be answered as asked.
"""

from dataclasses import dataclass, field

from keel import exits
from keel.manifest.catalog import (
    Catalog,
    kind_errors,
    kind_of_directory,
    stem_of,
)
from keel.manifest.constants import APPLIANCE, KINDS, OVERLAY, SUFFIX
from keel.manifest.load import ManifestError, load
from keel.manifest.resolve import resolve
from keel.manifest.show import render
from keel.manifest.validate import validate


@dataclass
class Outcome:
    out: str = ""
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    unreadable: bool = False
    invalid: bool = False
    usage: bool = False

    @property
    def code(self) -> int:
        if self.usage:
            return exits.USAGE
        if self.unreadable:
            return exits.SPEC_UNREADABLE
        if self.invalid:
            return exits.SPEC_INVALID
        return exits.OK


def is_path(target: str) -> bool:
    """A target with a slash or a .yaml suffix is a file, else a name"""
    return "/" in target or target.endswith(SUFFIX)


def validate_target(root: str, target: str | None = None,
                    kind: str | None = None) -> Outcome:
    """Validate one file, the manifests of one name, or every installed one

    An appliance is also resolved along its chain, which is where most of
    what can go wrong between manifests shows.
    """
    catalog, outcome = Catalog(root), Outcome()
    if target is not None and is_path(target):
        _validate_file(catalog, outcome, target, kind_of_directory(target),
                       kind)
        return outcome
    kinds = [kind] if kind else list(KINDS)
    if target is None:
        files = [(each, name) for each in kinds
                 for name in catalog.names(each)]
        if not files:
            outcome.notes.append(f"no manifest installed under"
                                 f" {catalog.directory()}, nothing to do")
    else:
        files = [(each, target) for each in kinds
                 if catalog.exists(each, target)]
        if not files:
            outcome.errors.append(f"no manifest named {target} under"
                                  f" {catalog.directory()}")
            outcome.unreadable = True
    for each, name in files:
        _validate_file(catalog, outcome, catalog.path(each, name), each, None)
    return outcome


def _validate_file(catalog: Catalog, outcome: Outcome, path: str,
                   directory: str | None, expected: str | None) -> None:
    try:
        doc = load(path)
    except ManifestError as e:
        outcome.errors.append(str(e))
        outcome.unreadable = True
        return
    errors = (validate(doc, stem_of(path), catalog)
              + kind_errors(doc, directory, expected))
    resolved = None
    if not errors and doc["kind"] == APPLIANCE:
        resolved, errors = resolve(catalog, doc)
    if errors:
        outcome.errors.extend(f"{path}: {message}" for message in errors)
        outcome.invalid = True
        return
    outcome.out += f"{path}: ok\n"
    if resolved is not None:
        outcome.out += (f"{resolved.name}: resolved along"
                        f" {', '.join(resolved.chain)}\n")


def show(root: str, name: str, resolved: bool = False,
         kind: str | None = None) -> Outcome:
    """The manifest NAME as its file says it, or resolved along its chain

    A manifest that fails validation is not shown: what show prints is
    what a consumer would read, and none reads an invalid one.
    """
    catalog, outcome = Catalog(root), Outcome()
    found = [each for each in ([kind] if kind else KINDS)
             if catalog.exists(each, name)]
    if not found:
        outcome.errors.append(f"no manifest named {name} under"
                              f" {catalog.directory()}")
        outcome.unreadable = True
        return outcome
    if len(found) > 1:
        outcome.errors.append(f"both an overlay and an appliance are named"
                              f" {name}; say which with --kind")
        outcome.usage = True
        return outcome
    if resolved and found[0] == OVERLAY:
        outcome.errors.append(f"{name} is an overlay: only an appliance"
                              " resolves")
        outcome.usage = True
        return outcome
    path = catalog.path(found[0], name)
    checked = Outcome()
    _validate_file(catalog, checked, path, found[0], None)
    if checked.errors:
        return checked
    if resolved:
        outcome.out = render(resolve(catalog, catalog.read(APPLIANCE,
                                                           name))[0])
    else:
        with open(path) as fob:
            outcome.out = fob.read()
    return outcome
