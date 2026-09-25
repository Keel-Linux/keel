# Copyright (c) 2026 KeelLinux maintainers
"""Shared helpers for the layer tests

The manifests, .sha256 and .hash files under tests/fixtures/layers are
the real ones bt-layer wrote for core and lamp. The tarballs are not
committed (hundreds of megabytes), so the helpers write small files in
their place and rewrite the digests and sizes in the manifests to match.
"""

import hashlib
import os
import sys
from os.path import abspath, dirname, join

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from keel.layers import manifest  # noqa: E402

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "layers")

CORE_BYTES = b"core layer stand in\n"
LAMP_BYTES = b"lamp layer stand in\n"

FAKE_SIGNATURE = (
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iQIzBAEBCgAdFiEE3ukNmXCuNdVbfGwtxtJUt2qdlDAFAmgAAAAACgkQxtJUt2qd\n"
    "lDAAAA==\n"
    "=AAAA\n"
    "-----END PGP SIGNATURE-----\n"
)


def read_fixture(name: str) -> str:
    with open(join(FIXTURES, name), encoding="utf-8") as fob:
        return fob.read()


def fixture_fields(name: str) -> dict[str, str]:
    return manifest.parse(read_fixture(f"{name}.manifest"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render(fields: dict[str, str]) -> str:
    return "".join(f"{key} {value}\n" for key, value in fields.items())


def write(path: str, content: str | bytes) -> str:
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fob:
        fob.write(content)
    return path


def write_manifest(root: str, fields: dict[str, str], name=None) -> str:
    return write(
        join(root, f"{name or fields['layer']}.manifest"), render(fields)
    )


def stand_in_fields(name: str, data: bytes, **overrides) -> dict[str, str]:
    """The real fixture manifest with the digest and size of `data`"""
    fields = dict(fixture_fields(name))
    fields.update(sha256=sha256(data), size=str(len(data)))
    fields.update(overrides)
    return fields


def hash_text(name: str, digest: str, signed: bool = False) -> str:
    """The real .hash file with its sha256 replaced by `digest`"""
    text = read_fixture(f"{name}.tar.zst.hash")
    real = fixture_fields(name)["sha256"]
    text = text.replace(real, digest)
    if signed:
        text = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
            + text + FAKE_SIGNATURE
        )
    return text


def build_tree(root: str) -> dict[str, dict[str, str]]:
    """Write core (rootfs) and lamp (delta on core) with matching tarballs

    Returns the fields written, so a test can alter one and rewrite it.
    """
    os.makedirs(root, exist_ok=True)
    core = stand_in_fields("core", CORE_BYTES)
    lamp = stand_in_fields("lamp", LAMP_BYTES, parent_sha256=core["sha256"])
    write(join(root, core["tarball"]), CORE_BYTES)
    write(join(root, lamp["tarball"]), LAMP_BYTES)
    write_manifest(root, core)
    write_manifest(root, lamp)
    return {"core": core, "lamp": lamp}
