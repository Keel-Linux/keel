# Copyright (c) 2026 KeelLinux maintainers
"""What the access network's plan looks at, read once (decision 0098)

The interface's file under /etc/keel/access, the key file, whether
`keel-access@<interface>` is enabled and the interface up, the peers the
interface holds now (`wg show <interface> allowed-ips`, which holds no
key of the node's), and keel's relay units. The peers and the link are
asked of the live system only.
"""

import os
import subprocess
from dataclasses import dataclass, field

from keel.inspect import constants as paths
from keel.inspect.dbengines import ENGINES
from keel.inspect.tree import Tree
from keel.network import access as acc
from keel.network import live
from keel.spec.secretstore import secret_file_error

RELAY_GLOB = f"{acc.RELAY_DIR}/keel-access-relay-*"
SOCKET_WANTS = "etc/systemd/system/sockets.target.wants/{unit}"


@dataclass(frozen=True)
class AccessState:
    """`declared` the spec's section; `rendered` what it renders, None
    when it declares none; `current` keel's file now, None when there is
    none; `held` the peers the live interface holds, None when not asked
    or not readable; `relays` keel's relay files now and `wanted` the
    ones the spec renders, by path"""

    iface: str
    declared: bool
    current: str | None
    rendered: str | None
    key_path: str = ""
    key_present: bool = False
    key_problem: str | None = None
    enabled: bool = False
    up: bool | None = None
    held: dict[str, str] | None = None
    wanted_peers: dict[str, str] = field(default_factory=dict)
    relays: dict[str, str | None] = field(default_factory=dict)
    wanted: dict[str, str] = field(default_factory=dict)
    sockets_enabled: frozenset[str] = frozenset()
    # the relay sockets that run now, on the live system
    sockets_active: frozenset[str] = frozenset()


def keel_file(text: str | None) -> bool:
    return bool(text) and text.startswith(acc.HEADER[0])


def written_iface(tree: Tree) -> str | None:
    """The interface of an access file keel wrote, when the spec has none
    now: what apply takes down and removes"""
    for name in tree.glob(f"{acc.CONF_DIR}/*.conf"):
        if keel_file(tree.read(name).text):
            return name.rsplit("/", 1)[-1][:-len(".conf")]
    return None


def held_peers(iface: str) -> dict[str, str] | None:
    try:
        out = subprocess.run(["wg", "show", iface, "allowed-ips"],
                             capture_output=True, text=True, check=False,
                             timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return acc.parse_allowed(out.stdout)


def active(unit: str) -> bool:
    try:
        out = subprocess.run(["systemctl", "is-active", unit],
                             capture_output=True, text=True, check=False,
                             timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out.stdout.strip() == "active"


def relay_files(tree: Tree) -> dict[str, str | None]:
    """keel's relay units now: the files of keel-access-relay-* that keel
    wrote (its header); another's file of that name is not keel's"""
    found = {}
    for name in tree.glob(RELAY_GLOB):
        text = tree.read(name).text
        if keel_file(text):
            found[name] = text
    return found


def installed_engine(tree: Tree) -> str | None:
    """The one database engine with a relay whose server binary is on
    the tree (keel.inspect.dbengines); None for none, and for two, where
    keel does not guess"""
    found = [engine.name for engine in ENGINES
             if engine.name in acc.RELAY_PORTS and engine.installed(tree.glob)]
    return found[0] if len(found) == 1 else None


def observe_access(root: str, doc: dict) -> AccessState | None:
    """None when the spec declares no access network and keel wrote none"""
    tree = Tree(root)
    is_live = tree.root == paths.ROOT_DEFAULT
    access = acc.section(doc)
    relays = relay_files(tree)
    if access is None:
        iface = written_iface(tree)
        if iface is None and not relays:
            return None
        iface = iface or acc.DEFAULT_INTERFACE
        return AccessState(
            iface=iface, declared=False,
            current=tree.read(acc.conf_path(iface)).text, rendered=None,
            enabled=tree.exists(acc.WANTS.format(iface=iface)),
            up=live.link_up(iface) if is_live else None, relays=relays)
    iface = acc.interface(access)
    key = acc.key_path(access)
    key_file = tree.path(key.lstrip("/"))
    present = os.path.exists(key_file)
    wanted = acc.relay_files(access, doc, installed_engine(tree))
    up = live.link_up(iface) if is_live else None
    return AccessState(
        iface=iface, declared=True,
        current=tree.read(acc.conf_path(iface)).text,
        rendered=acc.render(access),
        key_path=key, key_present=present,
        key_problem=(secret_file_error(key_file) if present and is_live
                     else None),
        enabled=tree.exists(acc.WANTS.format(iface=iface)),
        up=up,
        held=held_peers(iface) if up else None,
        wanted_peers=acc.wanted_peers(access),
        relays={**{path: tree.read(path).text for path in wanted},
                **relays},
        wanted=wanted,
        sockets_enabled=frozenset(
            unit for unit in acc.relay_socket_units(wanted)
            if tree.exists(SOCKET_WANTS.format(unit=unit))),
        sockets_active=frozenset(
            unit for unit in acc.relay_socket_units(wanted)
            if is_live and active(unit)),
    )
