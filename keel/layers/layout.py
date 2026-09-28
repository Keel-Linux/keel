# Copyright (c) 2026 KeelLinux maintainers
"""Where a mirror keeps a blob, a release manifest and a channel pointer

The mirror holds three kinds of object and exactly one of them is
mutable (handbook decision 0016):

    sha256/<digest>                 a layer tarball, named by its content;
                                    never overwritten, never deleted
    <release>/<rev>/<name>.manifest one layer of one immutable release
                                    revision, referring to a blob by digest
    stable, testing                 the channel pointers, clear signed and
                                    carrying a timestamp and an expiry

The flat layout that came before it, `<name>.manifest` beside
`<name>.tar.zst`, is still read: a client that could not read it would
strand every appliance published before the conversion. This module is
the only place either set of names is spelled.
"""

import posixpath
import re

BLOB_DIR = "sha256"
CHANNEL_STABLE = "stable"
CHANNEL_TESTING = "testing"
CHANNELS = (CHANNEL_STABLE, CHANNEL_TESTING)

RELEASE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
REV_RE = re.compile(r"^[1-9][0-9]*$")


def blob_path(digest: str) -> str:
    """Where the tarball with this sha256 lives, under the layers root"""
    return posixpath.join(BLOB_DIR, digest)


def release_dir(release: str, rev: int | str) -> str:
    """The directory of one immutable release revision"""
    return posixpath.join(str(release), str(rev))


def manifest_path(release: str, rev: int | str, name: str) -> str:
    """The manifest of one layer of one release revision"""
    return posixpath.join(release_dir(release, rev), name + ".manifest")


def flat_manifest_path(name: str) -> str:
    """The manifest of a layer in the flat layout, which is still served"""
    return name + ".manifest"


def is_release(value: str) -> bool:
    return bool(RELEASE_RE.match(value))


def is_rev(value: str) -> bool:
    return bool(REV_RE.match(value))


def is_channel(value: str) -> bool:
    return value in CHANNELS
