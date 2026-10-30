# Copyright (c) 2026 KeelLinux maintainers
"""The packages half of keel verify (brief section 5.4, keel#239)

Each layer ships `<layer>.packages` next to its manifest: one
`name version arch` line per package of the image at that layer, and the
manifest records the line count (`packages`) and the file's sha256
(`packages_sha256`). Two checks:

- every list matches its manifest, so the list can be trusted;
- with a root, the packages dpkg records under it match the lists of the
  chain of the named layer, a higher layer replacing the entry of a lower
  one for the same package.

A manifest that declares no list is reported as not declared, and an
installed root is never checked unless one is named: the report says
what was checked, and no more.
"""

import hashlib
import os
import subprocess
from dataclasses import dataclass

from keel import exits
from keel.layers import manifest as manifests
from keel.layers.constants import KIND_ROOTFS
from keel.layers.manifest import Manifest
from keel.layers.verify import find_manifests, load_manifests

PACKAGES_SUFFIX = ".packages"
DPKG_FORMAT = "${Package} ${Version} ${Architecture}\n"

STATUS_OK = "ok"
STATUS_UNDECLARED = "not declared"
STATUS_MISMATCH = "mismatch"


@dataclass(frozen=True)
class ListResult:
    """One line: what was found for the package list of one layer"""

    name: str
    status: str
    details: tuple[str, ...] = ()

    def line(self) -> str:
        text = f"packages {self.name}: {self.status}"
        if self.details:
            text += ": " + "; ".join(self.details)
        return text


@dataclass(frozen=True)
class InstalledResult:
    """The comparison of a root's packages with the declared ones"""

    root: str
    layer: str
    problems: tuple[str, ...]
    declared: int
    installed: int

    def lines(self) -> list[str]:
        return list(self.problems) + [
            f"installed packages under {self.root}, against {self.layer}:"
            f" {self.declared} declared, {self.installed} installed,"
            f" {len(self.problems)} differ"]


def list_path(layer: Manifest) -> str:
    """The package list next to the manifest, under the manifest's stem"""
    directory = os.path.dirname(layer.path)
    return os.path.join(directory,
                        manifests.manifest_stem(layer.path) + PACKAGES_SUFFIX)


def parse(text: str) -> dict[str, tuple[str, str]]:
    """name -> (version, arch) of each `name version arch` line"""
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3:
            found[parts[0]] = (parts[1], parts[2])
    return found


def check_list(layer: Manifest) -> ListResult:
    """The list of LAYER exists with the count and sha256 it records"""
    declared = layer.fields.get("packages_sha256")
    if declared is None:
        return ListResult(layer.name, STATUS_UNDECLARED)
    path = list_path(layer)
    try:
        with open(path, "rb") as fob:
            data = fob.read()
    except OSError as e:
        return ListResult(layer.name, STATUS_MISMATCH,
                          (f"{os.path.basename(path)}: {e.strerror or e}",))
    problems = []
    digest = hashlib.sha256(data).hexdigest()
    if digest != declared:
        problems.append(f"sha256 {digest}, manifest says {declared}")
    count = len(data.decode("utf-8", "replace").splitlines())
    if str(count) != layer.fields.get("packages"):
        problems.append(f"{count} lines, manifest says"
                        f" {layer.fields.get('packages')}")
    if problems:
        return ListResult(layer.name, STATUS_MISMATCH, tuple(problems))
    return ListResult(layer.name, STATUS_OK, (f"{count} listed",))


def chain_of(known: dict[str, Manifest], name: str) -> list[Manifest] | None:
    """The layers from the rootfs up to NAME, or None when it breaks"""
    found = [layer for layer in known.values() if layer.name == name]
    if not found:
        return None
    chain = [found[0]]
    while chain[-1].kind != KIND_ROOTFS:
        parents = [layer for layer in known.values()
                   if layer.name == chain[-1].parent
                   and layer.sha256 == chain[-1].parent_sha256]
        if not parents or len(chain) > len(known):
            return None
        chain.append(parents[0])
    return list(reversed(chain))


def declared_packages(chain: list[Manifest]) -> dict[str, tuple[str, str]]:
    """The lists of the chain merged, a higher layer replacing a lower"""
    merged: dict[str, tuple[str, str]] = {}
    for layer in chain:
        with open(list_path(layer), encoding="utf-8") as fob:
            merged.update(parse(fob.read()))
    return merged


def installed_packages(root: str) -> dict[str, tuple[str, str]]:
    """What dpkg records under ROOT; raises OSError when it cannot tell"""
    admindir = os.path.join(root, "var", "lib", "dpkg")
    # dpkg-query prints nothing and exits 0 when there is no database.
    if not os.path.isfile(os.path.join(admindir, "status")):
        raise OSError(f"no dpkg database at {admindir}")
    result = subprocess.run(
        ["dpkg-query", f"--admindir={admindir}", "-W", "-f", DPKG_FORMAT],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or
                      f"dpkg-query exited {result.returncode}")
    return parse(result.stdout)


def compare(declared: dict, installed: dict) -> tuple[str, ...]:
    """One line per package that is missing, extra or different"""
    problems = []
    for name in sorted(set(declared) | set(installed)):
        want, have = declared.get(name), installed.get(name)
        if have is None:
            problems.append(f"missing {name} {want[0]} {want[1]}")
        elif want is None:
            problems.append(f"not declared {name} {have[0]} {have[1]}")
        elif want != have:
            problems.append(f"differs {name}: installed {have[0]} {have[1]},"
                            f" declared {want[0]} {want[1]}")
    return tuple(problems)


@dataclass(frozen=True)
class Report:
    lists: tuple[ListResult, ...]
    installed: InstalledResult | None
    problem: str | None = None

    @property
    def code(self) -> int:
        if self.problem is not None:
            return exits.PACKAGES_MISMATCH
        if any(result.status == STATUS_MISMATCH for result in self.lists):
            return exits.PACKAGES_MISMATCH
        if self.installed is not None and self.installed.problems:
            return exits.PACKAGES_MISMATCH
        return exits.OK

    def lines(self) -> list[str]:
        found = [result.line() for result in self.lists]
        if self.problem is not None:
            found.append(self.problem)
        elif self.installed is not None:
            found.extend(self.installed.lines())
        else:
            found.append("installed packages: not checked (no --root)")
        return found


def verify_packages_dir(layers_dir: str, root: str | None = None,
                        layer: str | None = None) -> Report:
    """verify_packages over the valid manifests of a layers directory"""
    try:
        paths = find_manifests(layers_dir)
    except OSError:
        paths = []
    known, _ = load_manifests(paths)
    return verify_packages(known, root, layer)


def verify_packages(known: dict[str, Manifest], root: str | None = None,
                    layer: str | None = None) -> Report:
    """Check every list; with ROOT and LAYER, the root's packages too"""
    lists = tuple(check_list(found) for found in
                  sorted(known.values(), key=lambda found: found.name))
    if root is None:
        return Report(lists, None)
    chain = chain_of(known, layer)
    if chain is None:
        return Report(lists, None, f"installed packages: {layer} has no"
                      " complete chain in the layers directory")
    unlisted = [found.name for found in chain
                if check_list(found).status != STATUS_OK]
    if unlisted:
        return Report(lists, None, "installed packages: not checked, the"
                      f" list of {', '.join(unlisted)} cannot be used")
    try:
        installed = installed_packages(root)
    except OSError as e:
        return Report(lists, None, f"installed packages under {root}:"
                      f" cannot be read: {e}")
    declared = declared_packages(chain)
    return Report(lists, InstalledResult(
        root, layer, compare(declared, installed), len(declared),
        len(installed)))
