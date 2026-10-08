# Copyright (c) 2026 KeelLinux maintainers
"""A container template holds no kernel, initrd or bootloader

Decision 0052: every release ships a container template and a bootable
ISO from the same build. The packages only a virtual or a real machine
needs (the kernel, the initrd, firmware, GRUB, the installer) are in a
boot layer of their own, on top of the appliance layer and used by the
ISO alone; the layers a template is assembled from never carry them.

`check` is the guard: assemble refuses to pack a template whose dpkg
database records any of them, so a plan that pulls a kernel back into a
regular layer fails the release instead of shipping 190 MB an LXC
container never runs.
"""

import fnmatch
import os

from keel import exits
from keel.layers.errors import LayerError

# fnmatch patterns of package names, and why each has no use in an LXC
# container, which runs on the host's kernel and boots nothing itself
MACHINE_ONLY = (
    ("linux-image-*", "the kernel"),
    ("linux-headers-*", "headers of a kernel the container never runs"),
    ("linux-base", "kernel install hooks"),
    ("initramfs-tools*", "builds an initrd"),
    ("dracut*", "builds an initrd"),
    ("klibc-utils", "initrd early userspace"),
    ("libklibc", "initrd early userspace"),
    ("live-boot*", "boots the live ISO"),
    ("live-config*", "boots the live ISO"),
    ("live-tools", "boots the live ISO"),
    ("tkl-installer", "installs the live ISO onto a disk"),
    ("firmware-*", "device firmware, loaded by a machine's kernel"),
    ("*-microcode", "CPU microcode, loaded at boot"),
    ("grub*", "bootloader"),
    ("shim*", "UEFI Secure Boot loader"),
    ("efibootmgr", "UEFI boot entries"),
    ("mokutil", "UEFI Secure Boot keys"),
    ("efivar", "UEFI variables"),
    ("syslinux*", "bootloader of the ISO"),
    ("isolinux", "bootloader of the ISO"),
    ("extlinux", "bootloader"),
    ("os-prober", "finds other systems for the GRUB menu"),
    ("hdparm", "tunes physical disks"),
    ("qemu-guest-agent", "answers a QEMU host over virtio-serial"),
    ("acpi-support-base", "ACPI events come from a machine's firmware"),
    ("acpid", "ACPI events come from a machine's firmware"),
    ("jitterentropy-rngd", "feeds the entropy pool of the kernel, the"
     " host's in a container"),
)

STATUS = "var/lib/dpkg/status"


def installed(status: str) -> list[str]:
    """Names of the packages dpkg's status text records as present

    A package removed but not purged still has its conffiles, so it
    counts: only "not-installed" is absent.
    """
    names = []
    for stanza in status.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            key, sep, value = line.partition(":")
            if sep and not line[:1].isspace():
                fields[key] = value.strip()
        state = fields.get("Status", "").split()
        if "Package" in fields and state and state[-1] != "not-installed":
            names.append(fields["Package"])
    return sorted(names)


def machine_only(names: list[str]) -> list[str]:
    """The names that match a MACHINE_ONLY pattern"""
    return [
        name for name in names
        if any(fnmatch.fnmatchcase(name, pattern) for pattern, _ in MACHINE_ONLY)
    ]


def check(rootfs: str) -> None:
    """Refuse a rootfs to be packed as a container template

    Raises LayerError(ASSEMBLE_FAILED) when its dpkg database cannot be
    read or records a machine-only package.
    """
    path = os.path.join(rootfs, STATUS)
    try:
        with open(path, encoding="utf-8") as fob:
            status = fob.read()
    except (OSError, UnicodeDecodeError) as e:
        raise LayerError(
            exits.ASSEMBLE_FAILED, f"{path}: cannot read the dpkg database: {e}"
        ) from e
    present = machine_only(installed(status))
    if present:
        raise LayerError(
            exits.ASSEMBLE_FAILED,
            "not a container template: the rootfs has packages only a"
            " machine boots with (decision 0052): " + " ".join(present),
        )
