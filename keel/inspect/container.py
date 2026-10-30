# Copyright (c) 2026 KeelLinux maintainers
"""Whether a root is an LXC container, whose host owns the interfaces"""

from keel.inspect import constants as paths
from keel.inspect.tree import Tree


def in_container(tree: Tree) -> bool:
    """The TurnKey marker, or systemd's own record of the container.

    A released Proxmox template has no marker (keel#238), but systemd
    writes run/systemd/container at boot. An offline tree has an empty
    run/, so there only the marker counts."""
    if tree.exists(paths.LXC_MARKER):
        return True
    return (tree.read(paths.SYSTEMD_CONTAINER).text or "").strip() == "lxc"
