# Copyright (c) 2026 KeelLinux maintainers
"""Apply one layer tarball to a rootfs directory, overlayfs semantics

A rootfs layer is one tar of the whole tree. A delta layer is the upper
directories of the deck build, two of them in one stream (root.build
then root.patched, each starting with its own `./` entry), and each
carries what overlayfs recorded:

- a character device 0:0 at a path is a whiteout: the path from the
  layers below is removed and nothing is put in its place;
- a directory with `trusted.overlay.opaque=y` replaces the directory
  below it instead of merging with it.

The tarball is decompressed once, the tar is scanned with tarfile for
the member groups and the whiteouts and opaque directories in each, and
then each group is fed to tar in order: the paths to remove are removed
first, the group is extracted over the rootfs with the whiteout nodes
excluded and the overlay xattrs left out, and the next group follows.
The order matters: a directory root.patched marked opaque must not keep
what root.build put in it.
"""

import os
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass, field

from keel import exits
from keel.layers.constants import (
    OPAQUE_VALUE,
    OPAQUE_XATTR,
    OVERLAY_XATTR_GLOB,
    READ_CHUNK,
    TAR_END_OF_ARCHIVE,
)
from keel.layers.errors import LayerError

ZSTD_DECOMPRESS = ("zstd", "--quiet", "--decompress", "--force")
TAR_EXTRACT = (
    "tar",
    "--extract",
    "--file=-",
    "--preserve-permissions",
    "--numeric-owner",
    "--xattrs",
    f"--xattrs-exclude={OVERLAY_XATTR_GLOB}",
    "--anchored",
    "--no-wildcards",
)


@dataclass
class Group:
    """One `-C dir .` member of the tarball: a byte range and its marks"""

    start: int
    end: int
    whiteouts: list[str] = field(default_factory=list)
    opaques: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Applied:
    """What applying one layer did, for the report"""

    name: str
    groups: int
    whiteouts: int
    opaques: int

    def line(self) -> str:
        return (
            f"{self.name}: extracted ({self.groups} members,"
            f" {self.whiteouts} whiteouts, {self.opaques} opaque directories)"
        )


def relative(name: str) -> str:
    """A member name as a path under the rootfs, or LayerError

    tar itself refuses names that escape the directory; this guards the
    removals this module does on its own.
    """
    rel = os.path.normpath(name)
    if rel == "." or rel == ".." or rel.startswith(("/", "../")):
        raise LayerError(
            exits.ASSEMBLE_FAILED, f"refusing to touch {name!r} in the rootfs"
        )
    return rel


def is_root(member: tarfile.TarInfo) -> bool:
    return os.path.normpath(member.name) == "."


def is_whiteout(member: tarfile.TarInfo) -> bool:
    return member.ischr() and member.devmajor == 0 and member.devminor == 0


def is_opaque(member: tarfile.TarInfo) -> bool:
    return (
        member.isdir()
        and member.pax_headers.get(OPAQUE_XATTR) == OPAQUE_VALUE
    )


def scan(plain: str) -> list[Group]:
    """Split the tar into groups at every `./` entry and collect the marks"""
    try:
        with tarfile.open(plain) as archive:
            members = archive.getmembers()
    except (tarfile.TarError, OSError) as e:
        raise LayerError(exits.ASSEMBLE_FAILED, f"{plain}: {e}") from e
    starts = [member.offset for member in members if is_root(member)]
    if not starts or starts[0] != 0:
        starts.insert(0, 0)
    ends = starts[1:] + [os.path.getsize(plain)]
    groups = [Group(start, end) for start, end in zip(starts, ends)]
    for member in members:
        group = next(g for g in groups if g.start <= member.offset < g.end)
        if is_whiteout(member):
            group.whiteouts.append(member.name)
        elif is_opaque(member):
            group.opaques.append(member.name)
    return groups


def remove_path(rootfs: str, name: str) -> None:
    """Remove whatever is at the path, a tree included; absent is fine"""
    target = os.path.join(rootfs, relative(name))
    try:
        found = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(found.st_mode):
        shutil.rmtree(target)
    else:
        os.remove(target)


def extract_group(plain: str, group: Group, rootfs: str) -> None:
    """Feed one byte range of the tar to tar, whiteout nodes excluded

    The range is a whole number of members, so appending an end of
    archive marker makes it a complete tar stream.
    """
    command = [*TAR_EXTRACT, f"--directory={rootfs}"]
    command += [f"--exclude={name}" for name in group.whiteouts]
    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        with open(plain, "rb") as fob:
            fob.seek(group.start)
            remaining = group.end - group.start
            while remaining:
                chunk = fob.read(min(READ_CHUNK, remaining))
                proc.stdin.write(chunk)
                remaining -= len(chunk)
            proc.stdin.write(TAR_END_OF_ARCHIVE)
    except BrokenPipeError:
        pass
    _, err = proc.communicate()
    if proc.returncode != 0:
        raise LayerError(
            exits.ASSEMBLE_FAILED,
            f"tar exited {proc.returncode}:"
            f" {err.decode(errors='replace').strip()}",
        )


def decompress(tarball: str, plain: str) -> None:
    proc = subprocess.run(
        [*ZSTD_DECOMPRESS, "-o", plain, tarball],
        stdin=subprocess.DEVNULL, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        raise LayerError(
            exits.ASSEMBLE_FAILED,
            f"zstd exited {proc.returncode}:"
            f" {proc.stderr.decode(errors='replace').strip()}",
        )


def apply_layer(name: str, tarball: str, rootfs: str, work: str) -> Applied:
    """Decompress, scan and extract one layer over the rootfs, in order"""
    plain = os.path.join(work, f"{name}.tar")
    decompress(tarball, plain)
    groups = scan(plain)
    for group in groups:
        for path in group.whiteouts + group.opaques:
            remove_path(rootfs, path)
        extract_group(plain, group, rootfs)
    os.remove(plain)
    return Applied(
        name,
        len(groups),
        sum(len(group.whiteouts) for group in groups),
        sum(len(group.opaques) for group in groups),
    )
