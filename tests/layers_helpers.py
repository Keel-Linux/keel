# Copyright (c) 2026 KeelLinux maintainers
"""Shared helpers for the layer tests

The manifests, .sha256 and .hash files under tests/fixtures/layers are
the real ones bt-layer wrote for core and lamp. The tarballs are not
committed (hundreds of megabytes), so the helpers write small files in
their place and rewrite the digests and sizes in the manifests to match.
"""

import functools
import hashlib
import http.server
import io
import os
import socket
import subprocess
import sys
import tarfile
import threading
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


# Synthetic layers for pull and assemble: a small core rootfs and a lamp
# delta with the marks overlayfs leaves in an upper directory, written
# with the tarfile module, so the suite needs neither root nor overlayfs.

CORE_VERSION = b"turnkey-core-19.0-trixie-amd64\n"
LAMP_VERSION = b"turnkey-lamp-19.0-trixie-amd64\n"
TOOL_XATTR = ("SCHILY.xattr.user.keel", "tool")
OPAQUE = {"SCHILY.xattr.trusted.overlay.opaque": "y"}


def member(name: str, kind: str = "file", data: bytes = b"", mode=None,
           xattrs=None, linkname: str = "") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.mtime = 1700000000
    info.type = {
        "file": tarfile.REGTYPE,
        "dir": tarfile.DIRTYPE,
        "whiteout": tarfile.CHRTYPE,
        "link": tarfile.LNKTYPE,
    }[kind]
    default_mode = 0o755 if kind == "dir" else 0o644
    info.mode = default_mode if mode is None else mode
    info.size = len(data)
    info.linkname = linkname
    if xattrs:
        info.pax_headers = dict(xattrs)
    return info, data


def tar_bytes(members) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return buf.getvalue()


def zstd(data: bytes) -> bytes:
    return subprocess.run(
        ["zstd", "--quiet", "--stdout"], input=data, capture_output=True,
        check=True,
    ).stdout


def core_tar() -> bytes:
    return tar_bytes([
        member("./", "dir"),
        member("./etc", "dir"),
        member("./etc/apt", "dir"),
        member("./etc/apt/01proxy", data=b"Acquire::http::Proxy\n"),
        member("./etc/php", "dir"),
        member("./etc/php/old.ini", data=b"old\n"),
        member("./etc/turnkey_version", data=CORE_VERSION),
        member("./usr", "dir"),
        member("./usr/bin", "dir"),
        member("./usr/bin/tool", data=b"#!/bin/sh\n", mode=0o755,
               xattrs=dict([TOOL_XATTR])),
    ])


def lamp_tar() -> bytes:
    """Two upper directories: root.build, then root.patched

    root.build adds apache2 (opaque, new), removes the apt proxy, adds a
    file to php and one under var. root.patched makes php opaque with a
    new ini, so root.build's file must go too, replaces turnkey_version
    and removes the var file root.build created.
    """
    root_build = [
        member("./", "dir"),
        member("./etc", "dir"),
        member("./etc/apache2", "dir", xattrs=OPAQUE),
        member("./etc/apache2/apache2.conf", data=b"ServerRoot\n"),
        member("./etc/apt", "dir"),
        member("./etc/apt/01proxy", "whiteout"),
        member("./etc/php", "dir"),
        member("./etc/php/build.ini", data=b"build\n"),
        member("./var", "dir"),
        member("./var/lib", "dir"),
        member("./var/lib/x", data=b"x\n"),
    ]
    root_patched = [
        member("./", "dir"),
        member("./etc", "dir"),
        member("./etc/php", "dir", xattrs=OPAQUE),
        member("./etc/php/php.ini", data=b"php\n"),
        member("./etc/turnkey_version", data=LAMP_VERSION),
        member("./var", "dir"),
        member("./var/lib", "dir"),
        member("./var/lib/x", "whiteout"),
    ]
    return tar_bytes(root_build + root_patched)


def build_source(root: str, core_data=None, lamp_data=None) -> dict:
    """Write core and lamp tarballs and manifests the way bt-layer does

    The tarballs are real (small) tar.zst files, so the same tree serves
    pull (bytes and digests) and assemble (contents).
    """
    os.makedirs(root, exist_ok=True)
    core_data = zstd(core_tar()) if core_data is None else core_data
    lamp_data = zstd(lamp_tar()) if lamp_data is None else lamp_data
    core = stand_in_fields("core", core_data)
    lamp = stand_in_fields("lamp", lamp_data, parent_sha256=core["sha256"])
    write(join(root, core["tarball"]), core_data)
    write(join(root, lamp["tarball"]), lamp_data)
    write_manifest(root, core)
    write_manifest(root, lamp)
    return {"core": core, "lamp": lamp}


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    """Serve a directory over IPv6 loopback from a thread, for pull tests"""

    address_family = socket.AF_INET6

    def __init__(self, directory: str):
        super().__init__(
            ("::1", 0), functools.partial(Handler, directory=directory)
        )
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://[::1]:{self.server_address[1]}/"

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join()
