# Copyright (c) 2026 KeelLinux maintainers
"""What to do about an alert, from what the machine can see of itself

Every message says what to do, not only what happened (decision 0021).
The machine cannot know its VMID, its disk's name on the host, or even
that the host is Proxmox, so the host command carries placeholders and
names the hypervisor only as an example. The steps inside the machine
are chosen from what it can see: `systemd-detect-virt`, `findmnt` for the
filesystem's type and device, and the LVM layout. Nothing is run that
changes anything; growing a disk is the operator's act on the host.

The functions here are pure over the output of those commands; `Probe`
is how keel.monitor.notify runs them, with a timeout, and a test hands
in the outputs instead.
"""

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass

Probe = Callable[[tuple[str, ...]], str | None]
CONTAINERS = ("lxc", "lxc-libvirt", "systemd-nspawn", "openvz", "docker",
              "podman")
GROW = "+10G"
PARTITION_RES = (
    re.compile(r"^(/dev/(?:nvme\d+n\d+|mmcblk\d+|loop\d+))p(\d+)$"),
    re.compile(r"^(/dev/(?:[shvx]d[a-z]+))(\d+)$"),
)
# a directory listing is bounded: this many, from a du this deep, this fast
TOP = 3
DU_DEPTH = 2
DU_TIMEOUT = 20


@dataclass(frozen=True)
class Filesystem:
    target: str
    source: str
    fstype: str


def virtualisation(probe: Probe) -> str:
    """container, vm, none, or unknown when the machine cannot tell"""
    out = probe(("systemd-detect-virt",))
    if out is None:
        return "unknown"
    kind = out.strip()
    if kind == "none":
        return "none"
    return "container" if kind in CONTAINERS else "vm"


def filesystem(path: str, probe: Probe) -> Filesystem | None:
    out = probe(("findmnt", "-n", "-P", "-o", "TARGET,SOURCE,FSTYPE",
                 "-T", path))
    if not out:
        return None
    pairs = dict(re.findall(r'(\w+)="([^"]*)"', out.splitlines()[0]))
    if not pairs.get("TARGET"):
        return None
    return Filesystem(pairs["TARGET"], pairs.get("SOURCE", ""),
                      pairs.get("FSTYPE", ""))


def physical_volume(source: str, probe: Probe) -> str | None:
    """The PV under an LVM logical volume, or None when it is not one"""
    if not source.startswith("/dev/"):
        return None
    out = probe(("lvs", "--noheadings", "-o", "vg_name", source))
    if not out or not out.strip():
        return None
    group = out.split()[0]
    out = probe(("pvs", "--noheadings", "-o", "pv_name", "-S",
                 f"vg_name={group}"))
    names = (out or "").split()
    return names[0] if names else ""


def partition(device: str) -> tuple[str, str] | None:
    """(disk, number) for a partition such as /dev/sda3 or /dev/nvme0n1p2"""
    for pattern in PARTITION_RES:
        found = pattern.match(device)
        if found:
            return found.group(1), found.group(2)
    return None


def grow_here(fs: Filesystem, pv: str | None) -> list[str]:
    """The commands inside a VM or on bare metal, after the disk grew"""
    steps = []
    device = pv if pv else fs.source
    part = partition(device) if device else None
    if part:
        steps.append(f"growpart {part[0]} {part[1]}")
    if pv is not None:
        steps.append(f"pvresize {pv or '<physical volume>'}")
        steps.append(f"lvextend -r -l +100%FREE {fs.source}")
        return steps
    if fs.fstype in ("ext2", "ext3", "ext4"):
        steps.append(f"resize2fs {fs.source}")
    elif fs.fstype == "xfs":
        steps.append(f"xfs_growfs {fs.target}")
    elif fs.fstype == "btrfs":
        steps.append(f"btrfs filesystem resize max {fs.target}")
    else:
        steps.append(f"grow the {fs.fstype or 'unknown'} filesystem on"
                     f" {fs.source or fs.target} with its own tool")
    return steps


def volume(target: str) -> str:
    """How pct names the volume: rootfs for /, a mount point otherwise"""
    return "rootfs" if target == "/" else f"<mpN of {target}>"


def disk_steps(path: str, virt: str, fs: Filesystem | None,
               pv: str | None) -> list[str]:
    target = fs.target if fs else path
    if virt == "container":
        return [
            "Grow the disk on the host; the container sees the new size:",
            f"  host (for example Proxmox, container): pct resize <vmid>"
            f" {volume(target)} {GROW}",
            "  here: nothing more",
        ]
    here = "; ".join(grow_here(fs, pv)) if fs else (
        f"findmnt -T {path} names the device; grow its partition and"
        " filesystem")
    if virt == "vm":
        host = [f"  host (for example Proxmox, VM): qm resize <vmid> <disk>"
                f" {GROW}"]
    elif virt == "none":
        host = ["  this machine is not virtualised: grow or add the disk"]
    else:
        host = [f"  host (for example Proxmox): qm resize <vmid> <disk>"
                f" {GROW} for a VM, pct resize <vmid> {volume(target)}"
                f" {GROW} for a container, which needs nothing more here"]
    return ["Grow the disk on the host, then the filesystem here:", *host,
            f"  here: {here}"]


def inode_steps(path: str) -> list[str]:
    return [
        "Many small files have used the inodes up. Find where they are:",
        f"  du --inodes -x --max-depth={DU_DEPTH} {shlex.quote(path)}"
        " | sort -n | tail",
        "Remove what is not needed; an ext4 filesystem grown as below also"
        " gets more inodes.",
    ]


def resource_steps(check: str, virt: str) -> list[str]:
    """memory, swap, cpu and load: what to raise, on which host command"""
    memory = check in ("memory", "swap")
    what = {"memory": "the memory",
            "swap": "the swap, or the memory so less is swapped"}.get(
                check, "the cores")
    if virt == "container":
        setting = {"memory": "--memory <MiB>", "swap": "--swap <MiB>"}.get(
            check, "--cores <N>")
        return [f"Raise {what} on the host; a container gets it at once:",
                f"  host (for example Proxmox, container): pct set <vmid>"
                f" {setting}"]
    setting = "--memory <MiB>" if memory else "--cores <N>"
    return [f"Raise {what} on the host; a VM gets it at its next start,"
            " unless hotplug is on:",
            f"  host (for example Proxmox, VM): qm set <vmid> {setting}"]


def network_steps(check: str, iface: str, threshold: str) -> list[str]:
    if check == "link":
        return [f"The link of {iface} is down. Check the bridge or the cable"
                " it is attached to:",
                "  host (for example Proxmox): pct config <vmid> or"
                " qm config <vmid>, net lines",
                f"  here: ip link show {iface}"]
    return [f"{iface} has carried more than {threshold} Mbit/s for the"
            " declared time. See who sends it:",
            "  here: ss -tnpi, then raise max_mbit if the link is meant to"
            " carry it"]


def steps(check: str, target: str, threshold: str, probe: Probe) -> (
    list[str]
):
    """The advice lines for one alert, running only read only commands"""
    if check in ("link", "throughput"):
        return network_steps(check, target, threshold)
    virt = virtualisation(probe)
    if check in ("disk", "inodes"):
        fs = filesystem(target, probe)
        pv = physical_volume(fs.source, probe) if fs else None
        found = disk_steps(target, virt, fs, pv)
        return inode_steps(target) + found if check == "inodes" else found
    return resource_steps(check, virt)


def largest_directories(path: str, probe: Probe) -> str | None:
    """The TOP biggest directories DU_DEPTH down, or None, never slowly

    du's sizes include what is below, so the largest entries are taken
    in order and one that is inside, or holds, an entry already taken is
    passed over: /var 22G, and then not /var/lib, which /var counts. A
    directory with a large size of its own is listed as itself.
    """
    out = probe(("du", "-x", "-k", f"--max-depth={DU_DEPTH}", path))
    if not out:
        return None
    sizes = []
    for line in out.splitlines():
        size, _, name = line.partition("\t")
        if name and size.isdigit() and name != path:
            sizes.append((int(size), name))
    top: list[tuple[int, str]] = []
    for size, name in sorted(sizes, key=lambda pair: (-pair[0], pair[1])):
        if len(top) == TOP:
            break
        if not any(nested(name, taken) or nested(taken, name)
                   for _, taken in top):
            top.append((size, name))
    if not top:
        return None
    return ", ".join(f"{name} {human(size)}" for size, name in top)


def nested(inner: str, outer: str) -> bool:
    return inner.startswith(f"{outer.rstrip('/')}/")


def largest_processes(check: str, probe: Probe) -> str | None:
    """The TOP processes by memory or CPU, from ps"""
    column = "rss" if check in ("memory", "swap") else "pcpu"
    out = probe(("ps", "-eo", f"{column}=,comm=", f"--sort=-{column}"))
    if not out:
        return None
    found = []
    for line in out.splitlines()[:TOP]:
        value, _, name = line.strip().partition(" ")
        if not name:
            continue
        shown = human(int(value)) if column == "rss" and value.isdigit() \
            else f"{value}%"
        found.append(f"{name.strip()} {shown}")
    return ", ".join(found) or None


def human(kib: int) -> str:
    """A size as du -h prints it: 18G, 4.1G, 512K"""
    size, unit = float(kib), "K"
    for bigger in ("M", "G", "T"):
        if size < 1024:
            break
        size, unit = size / 1024, bigger
    return f"{size:.1f}{unit}" if size < 10 else f"{size:.0f}{unit}"
