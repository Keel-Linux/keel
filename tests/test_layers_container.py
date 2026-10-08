# Copyright (c) 2026 KeelLinux maintainers
"""A container template never holds a kernel or a bootloader (decision 0052)

The package list of the published core 19.0-9 template (which still had
them) is the fixture of the patterns; the assemble tests use the
synthetic layers of tests/layers_helpers.py with a dpkg status file
added to the top layer.
"""

import os
import shutil
import tempfile
import unittest
from os.path import exists, join
from unittest import mock

from layers_helpers import (
    build_source,
    member,
    tar_bytes,
    zstd,
)

from keel import exits
from keel.layers import LayerError, assemble, pull
from keel.layers.container import (
    MACHINE_ONLY,
    check,
    installed,
    machine_only,
)

AS_ROOT = mock.patch("os.geteuid", return_value=0)

# What the core 19.0-9 template carried that a container never uses
CORE_19_0_9_MACHINE_ONLY = [
    "acpi-support-base", "acpid", "dracut-install", "efivar",
    "firmware-linux-free", "grub-common", "grub-pc", "grub-pc-bin",
    "grub2-common", "hdparm", "initramfs-tools", "initramfs-tools-bin",
    "initramfs-tools-core", "isolinux", "jitterentropy-rngd", "klibc-utils",
    "libklibc", "linux-base", "linux-image-6.12.111+deb13-amd64",
    "linux-image-amd64", "live-boot", "live-boot-initramfs-tools",
    "live-tools", "os-prober", "qemu-guest-agent", "syslinux",
    "syslinux-common", "tkl-installer",
]
# and packages of that template a container keeps, some of them close in
# name to a machine-only one
CORE_19_0_9_KEPT = [
    "base-files", "busybox", "dmsetup", "eject", "fdisk", "kmod",
    "libefiboot1t64", "libgrubby", "libudev1", "linux-libc-dev", "lvm2",
    "parted", "systemd", "systemd-sysv", "udev", "webmin-fdisk",
    "webmin-lvm", "zstd",
]


def stanza(name: str, status: str = "install ok installed") -> str:
    return f"Package: {name}\nStatus: {status}\nVersion: 1\n"


def status_of(*names: str) -> str:
    return "\n".join(stanza(name) for name in names)


class TestPatterns(unittest.TestCase):
    def test_every_pattern_says_why(self):
        for pattern, reason in MACHINE_ONLY:
            self.assertTrue(pattern and reason.strip(), pattern)

    def test_the_kernel_and_bootloader_of_core_19_0_9_are_machine_only(self):
        names = sorted(CORE_19_0_9_MACHINE_ONLY + CORE_19_0_9_KEPT)
        self.assertEqual(machine_only(names), CORE_19_0_9_MACHINE_ONLY)

    def test_future_kernel_and_uefi_packages_are_machine_only(self):
        names = [
            "linux-image-6.12.200+deb13-cloud-amd64", "linux-headers-amd64",
            "grub-efi-amd64-signed", "shim-signed", "efibootmgr", "mokutil",
            "firmware-misc-nonfree", "intel-microcode", "amd64-microcode",
            "dracut", "live-config-systemd", "extlinux",
        ]
        self.assertEqual(machine_only(names), names)


class TestInstalled(unittest.TestCase):
    def test_installed_half_configured_and_config_files_count(self):
        text = "\n".join([
            stanza("a"),
            stanza("b", "install ok half-configured"),
            stanza("c", "deinstall ok config-files"),
            stanza("d", "purge ok not-installed"),
        ])
        self.assertEqual(installed(text), ["a", "b", "c"])

    def test_continuation_lines_and_stanzas_without_a_status_are_skipped(self):
        text = (
            "Package: a\nStatus: install ok installed\nDescription: x\n"
            " Package: not-a-field\n\n"
            "Package: no-status\n\n"
            "Status: install ok installed\n\n\n"
        )
        self.assertEqual(installed(text), ["a"])


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.rootfs = tempfile.mkdtemp()
        os.makedirs(join(self.rootfs, "var/lib/dpkg"))

    def tearDown(self):
        shutil.rmtree(self.rootfs)

    def write_status(self, text: str) -> None:
        with open(join(self.rootfs, "var/lib/dpkg/status"), "w",
                  encoding="utf-8") as fob:
            fob.write(text)

    def test_a_rootfs_without_machine_only_packages_passes(self):
        self.write_status(status_of(*CORE_19_0_9_KEPT))
        check(self.rootfs)

    def test_a_rootfs_with_a_kernel_is_refused_and_named(self):
        self.write_status(status_of("base-files", "linux-image-amd64",
                                    "grub-pc"))
        with self.assertRaises(LayerError) as raised:
            check(self.rootfs)
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_FAILED)
        self.assertIn("grub-pc linux-image-amd64", str(raised.exception))
        self.assertIn("decision 0052", str(raised.exception))

    def test_a_kernel_removed_but_not_purged_is_refused(self):
        self.write_status(stanza("linux-image-amd64",
                                 "deinstall ok config-files"))
        with self.assertRaises(LayerError):
            check(self.rootfs)

    def test_a_rootfs_without_a_dpkg_database_is_refused(self):
        with self.assertRaises(LayerError) as raised:
            check(self.rootfs)
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_FAILED)
        self.assertIn("cannot read the dpkg database", str(raised.exception))

    def test_a_dpkg_database_that_is_not_text_is_refused(self):
        with open(join(self.rootfs, "var/lib/dpkg/status"), "wb") as fob:
            fob.write(b"\xff\xfe\x00")
        with self.assertRaises(LayerError):
            check(self.rootfs)


class TestAssembleRefusesAKernel(unittest.TestCase):
    """A chain whose rootfs has a kernel assembles, and packs no template"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.rootfs = join(self.tmpdir, "rootfs")
        self.template = join(self.tmpdir, "core.tar.zst")
        kernel = tar_bytes([
            member("./", "dir"),
            member("./var", "dir"),
            member("./var/lib", "dir"),
            member("./var/lib/dpkg", "dir"),
            member("./var/lib/dpkg/status",
                   data=status_of("base-files", "linux-image-amd64").encode()),
        ])
        build_source(self.source, core_data=zstd(kernel))
        pull("core", self.source, self.cache)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_the_template_is_refused_and_not_written(self):
        with AS_ROOT, self.assertRaises(LayerError) as raised:
            assemble("core", self.cache, self.rootfs, self.template)
        self.assertEqual(raised.exception.code, exits.ASSEMBLE_FAILED)
        self.assertIn("linux-image-amd64", str(raised.exception))
        self.assertFalse(exists(self.template))
        self.assertFalse(exists(self.template + ".sha512"))

    def test_the_rootfs_alone_is_assembled_for_the_iso(self):
        with AS_ROOT:
            report = assemble("core", self.cache, self.rootfs)
        self.assertIsNone(report.packed)
        with open(join(self.rootfs, "var/lib/dpkg/status"),
                  encoding="utf-8") as fob:
            self.assertIn("linux-image-amd64", fob.read())


if __name__ == "__main__":
    unittest.main()
