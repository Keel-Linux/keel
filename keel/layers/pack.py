# Copyright (c) 2026 KeelLinux maintainers
"""Pack an assembled rootfs into the single tarball Proxmox expects

The tar stream is deterministic in the same way the layers are (brief
section 5.4): entries sorted by name, numeric owners, every mtime set to
the manifest's source_date_epoch, posix format without the volatile pax
fields, extended attributes kept. It is compressed with zstd and a
`.sha512` file is written next to it, because that is the digest the
pveam index carries.
"""

import hashlib
import os
import subprocess
from dataclasses import dataclass

from keel import exits
from keel.layers.constants import READ_CHUNK, SHA512_SUFFIX, ZSTD_LEVEL
from keel.layers.errors import LayerError

TAR_CREATE = (
    "tar",
    "--create",
    "--file=-",
    "--sort=name",
    "--numeric-owner",
    "--format=posix",
    "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
    "--xattrs",
)
ZSTD_COMPRESS = ("zstd", "--quiet", "-T0", f"-{ZSTD_LEVEL}", "--force")


@dataclass(frozen=True)
class Packed:
    path: str
    size: int
    sha512: str
    sha512_path: str

    def line(self) -> str:
        return (
            f"template: {self.path} ({self.size} bytes, sha512 {self.sha512})"
        )


def sha512_of(path: str) -> str:
    digest = hashlib.sha512()
    with open(path, "rb") as fob:
        while chunk := fob.read(READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def pack(rootfs: str, template: str, epoch: int) -> Packed:
    """tar the rootfs into `template` through zstd and write its sha512"""
    tar_command = [
        *TAR_CREATE, f"--mtime=@{epoch}", f"--directory={rootfs}", "."
    ]
    zstd_command = [*ZSTD_COMPRESS, "-o", template]
    tar = subprocess.Popen(
        tar_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    zstd = subprocess.Popen(
        zstd_command, stdin=tar.stdout, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    tar.stdout.close()
    _, zstd_err = zstd.communicate()
    _, tar_err = tar.communicate()
    for name, proc, err in (("tar", tar, tar_err), ("zstd", zstd, zstd_err)):
        if proc.returncode != 0:
            raise LayerError(
                exits.ASSEMBLE_FAILED,
                f"{name} exited {proc.returncode}:"
                f" {err.decode(errors='replace').strip()}",
            )
    digest = sha512_of(template)
    sha512_path = template + SHA512_SUFFIX
    with open(sha512_path, "w", encoding="utf-8") as fob:
        fob.write(f"{digest}  {os.path.basename(template)}\n")
    return Packed(template, os.path.getsize(template), digest, sha512_path)
