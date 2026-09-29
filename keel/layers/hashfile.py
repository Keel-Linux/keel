# Copyright (c) 2026 KeelLinux maintainers
"""Read the `<tarball>.hash` file that generate-signature writes

The file is prose for a human with two digest lines in it, of the
sha256sum and sha512sum form, and may be wrapped in a clear signature.
Only the digest lines and the presence of a signature are read here.
Checking that signature needs the key it was made with, which is not the
channel keyring `keel pull` verifies a pointer against, and no caller
passes one, so nothing in this module claims to verify anything.
"""

import re
from dataclasses import dataclass

from keel.layers.constants import SIGNATURE_MARK, SIGNED_MESSAGE_MARK

DIGEST_LINE_RE = re.compile(r"^\s*([0-9a-f]{64}|[0-9a-f]{128})\s+(\S+)\s*$")
SHA256_LENGTH = 64


@dataclass(frozen=True)
class HashFile:
    path: str
    sha256: str | None
    sha512: str | None
    filename: str | None
    signed: bool


def parse(path: str, text: str) -> HashFile:
    """Pick the digest lines and the signature marks out of the text

    The first sha256 and the first sha512 line win; the file name is the
    one on the sha256 line, or the sha512 line when there is no sha256.
    """
    sha256 = sha512 = filename = None
    for line in text.splitlines():
        found = DIGEST_LINE_RE.match(line)
        if not found:
            continue
        digest, name = found.groups()
        if len(digest) == SHA256_LENGTH:
            if sha256 is None:
                sha256, filename = digest, name
        elif sha512 is None:
            sha512 = digest
            filename = filename or name
    signed = SIGNED_MESSAGE_MARK in text and SIGNATURE_MARK in text
    return HashFile(path, sha256, sha512, filename, signed)


def load(path: str) -> HashFile:
    """Read and parse a hash file; raises OSError when it cannot be read"""
    with open(path, encoding="utf-8", errors="replace") as fob:
        return parse(path, fob.read())
