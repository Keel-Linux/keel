# Copyright (c) 2026 KeelLinux maintainers
"""Which mounted filesystems are real, read from /proc/self/mountinfo

monit has no wildcard, so apply writes one check per filesystem that
holds data (decision 0021) and a filesystem mounted later is watched
from the next apply. Left out, each for its reason:

- pseudo filesystems, which hold no data of the machine's (proc, sysfs,
  tmpfs, cgroup, the lxcfs files a container host provides);
- read only images and media (squashfs, erofs, iso9660, udf), full by
  design, and overlays, whose space is another filesystem's;
- network filesystems, whose space is another machine's to grow, and
  whose server can stall the check;
- anything under /proc, /sys, /dev and /run, which is the kernel's, the
  runtime's or, in a container, the host's;
- a bind mount of part of a filesystem, which is what a container host
  hands in for /etc/hostname and friends; btrfs is the exception,
  because a subvolume mounted as / shows the same way;
- a second mount of a device already listed, so a filesystem is watched
  once.
"""

import re
from dataclasses import dataclass

PSEUDO = frozenset((
    "autofs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs",
    "debugfs", "devpts", "devtmpfs", "efivarfs", "fuse.lxcfs",
    "fuse.gvfsd-fuse", "fuse.portal", "fusectl", "hugetlbfs", "mqueue",
    "nsfs", "overlay", "proc", "pstore", "ramfs", "rpc_pipefs",
    "securityfs", "selinuxfs", "squashfs", "sysfs", "tmpfs", "tracefs",
    "nfsd", "none",
    # read only media and images, always full by design
    "iso9660", "udf", "erofs", "cramfs", "romfs",
))
REMOTE = frozenset((
    "9p", "afs", "ceph", "cifs", "fuse.sshfs", "glusterfs", "nfs", "nfs4",
    "smb3", "smbfs", "virtiofs",
))
RUNTIME = ("/proc", "/sys", "/dev", "/run")
# What monit takes as an unquoted path, and its exec line and keel
# notify's argv carry as one word: measured with monit 5.34's parser,
# which refuses @, :, , and % in a path, besides spaces and quotes.
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_.+=~/-]*$")
ESCAPE = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class Mount:
    path: str
    fstype: str
    source: str


def unescape(field: str) -> str:
    """mountinfo writes a space as \\040, a tab as \\011 and so on"""
    return ESCAPE.sub(lambda found: chr(int(found.group(1), 8)), field)


def parse(mountinfo: str) -> list[tuple[str, str, Mount]]:
    """(device, root within it, mount) for every well formed line"""
    found = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if "-" not in fields[6:]:
            continue
        dash = fields.index("-", 6)
        if len(fields) < dash + 3:
            continue
        found.append((fields[2], unescape(fields[3]), Mount(
            path=unescape(fields[4]), fstype=fields[dash + 1],
            source=unescape(fields[dash + 2]),
        )))
    return found


def under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def real_filesystems(mountinfo: str) -> tuple[list[Mount], list[str]]:
    """The filesystems to watch, and the paths skipped for their name

    A mount point whose name monit's exec line cannot carry unquoted
    (a space, a quote) is named in the second list, so the plan says it
    is not watched rather than leaving it out in silence.
    """
    mounts, unsafe, devices = [], [], set()
    for device, root, mount in parse(mountinfo):
        if mount.fstype in PSEUDO or mount.fstype in REMOTE:
            continue
        if any(under(mount.path, prefix) for prefix in RUNTIME):
            continue
        if root != "/" and mount.fstype != "btrfs":
            continue
        if device in devices:
            continue
        devices.add(device)
        if not SAFE_PATH.match(mount.path):
            unsafe.append(mount.path)
            continue
        mounts.append(mount)
    return mounts, unsafe
