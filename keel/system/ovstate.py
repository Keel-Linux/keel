# Copyright (c) 2026 KeelLinux maintainers
"""What the overlay plan looks at, read once from the root (decision 0020)"""

import os
from dataclasses import dataclass

from keel.inspect import constants as paths
from keel.inspect.tree import Tree
from keel.network import marker, wireguard
from keel.network.wireguard import MODULE
from keel.spec.secretstore import secret_file_error

WANTS = "etc/systemd/system/multi-user.target.wants/wg-quick@{iface}.service"


@dataclass(frozen=True)
class OverlayState:
    """`current` is the file now, None when there is none; `key_problem`
    why the existing key file is refused (owner, mode), live only;
    `module_loaded` None off the live system, where it means nothing"""

    iface: str
    key_path: str
    current: str | None
    rendered: str
    key_present: bool
    key_problem: str | None
    in_container: bool
    module_loaded: bool | None
    pending: bool
    enabled: bool
    addresses: tuple[str, ...] = ()


def overlay_of(doc: dict) -> dict | None:
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard")
    return overlay if isinstance(overlay, dict) else None


def observe_overlay(root: str, doc: dict) -> OverlayState | None:
    """None when the spec declares no overlay: nothing to plan"""
    overlay = overlay_of(doc)
    if overlay is None:
        return None
    tree = Tree(root)
    live = tree.root == paths.ROOT_DEFAULT
    iface = wireguard.interface(overlay)
    key = wireguard.key_path(overlay)
    key_file = tree.path(key.lstrip("/"))
    present = os.path.exists(key_file)
    return OverlayState(
        iface=iface,
        key_path=key,
        current=tree.read(wireguard.conf_path(iface)).text,
        rendered=wireguard.render(overlay),
        key_present=present,
        key_problem=secret_file_error(key_file) if present and live else None,
        in_container=tree.exists(paths.LXC_MARKER),
        module_loaded=tree.exists(MODULE) if live else None,
        pending=os.path.exists(tree.path(marker.PENDING)),
        enabled=tree.exists(WANTS.format(iface=iface)),
        addresses=tuple(one.split("/")[0]
                        for one in wireguard.addresses(overlay)),
    )
