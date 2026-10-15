# Copyright (c) 2026 KeelLinux maintainers
"""Check a release MANIFEST, its signature and the files it lists

keel-release writes `MANIFEST` and `MANIFEST.asc` for each release: a
header, then one `<size> <sha256> <path>` line for each file, with the
path relative to the directory of the MANIFEST. Decision 0055 moves its
signature to the images key. While the verifiers move, main and images
both sign it, in 1 `.asc`, and a signature by either key is good
(keel.layers.signature.verify_by_any).

The signature is checked first, and nothing in the MANIFEST is read
before it passes. Then each listed file that is present is checked for
its size and sha256. A file that is not present is reported and not
checked, because a release directory on a mirror and a MANIFEST fetched
alone are both normal.
"""

import os
import re
from dataclasses import dataclass

from keel import exits
from keel.layers.errors import SignatureError
from keel.layers.signature import verify_by_any
from keel.layers.verify import digest_and_size

ENTRY_START_RE = re.compile(r"^[0-9]+\s+[0-9a-f]{64}(\s|$)")
ENTRY_RE = re.compile(r"^([0-9]+)\s+([0-9a-f]{64})\s+(\S+)$")


@dataclass(frozen=True)
class ManifestReport:
    """What `keel verify --release-manifest` prints, and its exit code"""

    signature: str
    entries: tuple[str, ...] = ()
    code: int = exits.OK

    def lines(self) -> list[str]:
        return [self.signature, *self.entries]


def read_entries(text: str) -> tuple[list[tuple[int, str, str]], list[str]]:
    """The `size sha256 path` lines, and the problems with the others

    The same rule as keel-publish-mirror: a line that starts like an entry
    and does not have 3 fields is refused, and so is a path that is
    absolute or goes up out of the release directory.
    """
    entries: list[tuple[int, str, str]] = []
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not ENTRY_START_RE.match(line):
            continue
        found = ENTRY_RE.match(line)
        if not found:
            problems.append(f"line {number}: not '<size> <sha256> <path>'")
            continue
        size, sha256, path = found.groups()
        if os.path.isabs(path) or ".." in path.split("/"):
            problems.append(f"{path}: path leaves the release")
            continue
        entries.append((int(size), sha256, path))
    return entries, problems


def check_entry(root: str, size: int, sha256: str, path: str) -> str:
    """One report line for one listed file"""
    full = os.path.join(root, path)
    if not os.path.lexists(full):
        return f"{path}: not present, not checked"
    try:
        found_sha, found_size = digest_and_size(full)
    except OSError as e:
        return f"{path}: mismatch: {e.strerror or e}"
    problems = []
    if found_size != size:
        problems.append(f"size {found_size}, MANIFEST says {size}")
    if found_sha != sha256:
        problems.append(f"sha256 {found_sha}, MANIFEST says {sha256}")
    if problems:
        return f"{path}: mismatch: {'; '.join(problems)}"
    return f"{path}: ok"


def verify(path: str, keyrings: tuple[str, ...]) -> ManifestReport:
    """Verify MANIFEST against MANIFEST.asc, then the files; never raises"""
    try:
        with open(path, "rb") as fob:
            data = fob.read()
    except OSError as e:
        return ManifestReport(
            f"{path}: invalid: {e.strerror or e}",
            code=exits.MANIFEST_INVALID,
        )
    try:
        with open(path + ".asc", "rb") as fob:
            detached = fob.read()
    except OSError as e:
        return ManifestReport(
            f"{path}.asc: unverified: {e.strerror or e}",
            code=exits.SIGNATURE_UNVERIFIED,
        )
    try:
        verified = verify_by_any(path, data, keyrings, detached=detached)
    except SignatureError as e:
        return ManifestReport(
            f"unverified: {e}", code=exits.SIGNATURE_UNVERIFIED
        )
    head = f"{path}: signed by {', '.join(verified.fingerprints)}"
    entries, problems = read_entries(data.decode("utf-8", "replace"))
    if problems:
        return ManifestReport(
            head, tuple(problems), code=exits.MANIFEST_INVALID
        )
    root = os.path.dirname(os.path.abspath(path))
    lines = tuple(check_entry(root, *entry) for entry in entries)
    code = exits.OK
    if any(": mismatch" in line for line in lines):
        code = exits.LAYER_MISMATCH
    return ManifestReport(head, lines, code)
