# Copyright (c) 2026 KeelLinux maintainers
"""The access network, from the spec to its files; pure (decision 0098)

`network.access` declares a WireGuard interface of its own, apart from
the mesh's `wg0`, for the computers of the administrators. A computer
is an access peer: it is not in `network.overlay.wireguard.peers`, so
`--adopt` never makes it an operator root and `keel mesh sync` never
sends it to another node. It gets one /128 in the node's own random
unique local /64; the node is `::1` there.

The files are not under /etc/wireguard: inspect, the MTU converge and
the overlay's state read every `/etc/wireguard/*.conf` as the mesh's.
The interface's file is /etc/keel/access/<interface>.conf, which
`keel-access@<interface>.service` gives to `wg-quick up` by its path.
As for the mesh, the private key is not in the file: PostUp gives the
key file to `wg set`, so only `wg` and the kernel read it. No private
key of an administrator is ever on the node: the computer makes its own
key pair and the node gets the public key only.

The node has no endpoint for a computer and no keepalive: the computer
starts each handshake and keeps the path open, so a computer behind NAT
works with no change on the node. A peer's AllowedIPs is its /128 only.
"""

import ipaddress
import re

from keel.network.wireguard import KEY_PATH_RE, OVERLAY_MTU, POST_UP

DEFAULT_INTERFACE = "keel-access"
DEFAULT_PORT = 51822
DEFAULT_TOKEN_MINUTES = 15
MIN_TOKEN_MINUTES = 5
MAX_TOKEN_MINUTES = 60
CONF_DIR = "etc/keel/access"
UNIT = "keel-access@{iface}.service"
WANTS = "etc/systemd/system/multi-user.target.wants/" + UNIT
PREFIX_LENGTH = 64
# a name an administrator types for a computer, and a word of the list
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEADER = (
    "# Written by keel spec apply --system from network.access",
    "# (handbook decision 0098); edit the instance description, not this",
    "# file. The private key is not here: PostUp gives its file to wg.",
    "# Each peer is the computer of an administrator, never a mesh node.",
)
# the database relays of answer 5: the engine, its port on the loopback
RELAY_PORTS = {"mariadb": 3306, "postgresql": 5432}
RELAY_UNIT = "keel-access-relay-{port}"
RELAY_DIR = "etc/systemd/system"
PROXYD = "/usr/lib/systemd/systemd-socket-proxyd"
RELAY_TARGET = "127.0.0.1"


def section(doc: dict) -> dict | None:
    """The spec's network.access, None when it declares none"""
    found = (doc.get("network") or {}).get("access")
    return found if isinstance(found, dict) else None


def interface(access: dict) -> str:
    return str(access.get("interface") or DEFAULT_INTERFACE)


def port(access: dict) -> int:
    return int(access.get("listen_port") or DEFAULT_PORT)


def token_minutes(access: dict) -> int:
    return int(access.get("token_minutes") or DEFAULT_TOKEN_MINUTES)


def conf_path(iface: str) -> str:
    """The file keel-access@<iface> gives to wg-quick, under the root"""
    return f"{CONF_DIR}/{iface}.conf"


def key_path(access: dict) -> str:
    declared = (access.get("private_key") or {}).get("file")
    if declared:
        return str(declared)
    return f"/etc/wireguard/{interface(access)}.key"


def address(access: dict) -> ipaddress.IPv6Interface:
    return ipaddress.IPv6Interface(str(access["address"]))


def peers(access: dict) -> list[dict]:
    return [peer for peer in access.get("peers") or []
            if isinstance(peer, dict)]


def host(peer: dict) -> str:
    """A peer's address without its /128"""
    return str(ipaddress.IPv6Interface(str(peer["address"])).ip)


def render(access: dict) -> str:
    """The wg-quick file for the declared access network"""
    key = key_path(access)
    if not KEY_PATH_RE.match(key):
        raise ValueError(f"{key} is not a key path wg-quick may run")
    lines = list(HEADER) + [
        "[Interface]",
        f"Address = {address(access)}",
        f"ListenPort = {port(access)}",
        f"MTU = {OVERLAY_MTU}",
        f"PostUp = {POST_UP}{key}",
    ]
    for peer in peers(access):
        lines += ["", f"# {peer['name']}, enrolled {peer.get('enrolled')}",
                  "[Peer]", f"PublicKey = {peer['public_key']}",
                  f"AllowedIPs = {host(peer)}/128"]
    return "\n".join(lines) + "\n"


def interface_lines(text: str | None) -> tuple[str, ...]:
    """The [Interface] lines of a file: what a restart is needed for"""
    found, inside = [], False
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("["):
            inside = line.lower() == "[interface]"
            continue
        if inside and line:
            found.append(" ".join(line.split()))
    return tuple(found)


def wanted_peers(access: dict) -> dict[str, str]:
    """Each declared peer's public key and its /128"""
    return {str(peer["public_key"]): f"{host(peer)}/128"
            for peer in peers(access)}


def parse_allowed(text: str) -> dict[str, str]:
    """`wg show <iface> allowed-ips`: each peer's key and its prefixes,
    joined by a space in wg's order; a line with no prefix has none"""
    found = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        prefixes = [one for one in fields[1:] if one != "(none)"]
        found[fields[0]] = " ".join(prefixes)
    return found


def peer_changes(wanted: dict[str, str], held: dict[str, str]
                 ) -> tuple[list[tuple[str, str]], list[str]]:
    """What `wg set` must add or change, and remove, so the interface
    holds the declared peers and no other: (key, /128) to set, and the
    keys to remove, both sorted"""
    add = sorted((key, prefix) for key, prefix in wanted.items()
                 if held.get(key) != prefix)
    remove = sorted(key for key in held if key not in wanted)
    return add, remove


def relay_ports(doc: dict) -> tuple[int, ...]:
    """The database ports a relay serves on the access address: the
    engine database.server declares, MariaDB or PostgreSQL (answer 5)"""
    server = ((doc.get("database") or {}).get("server") or {})
    engine = server.get("engine") if isinstance(server, dict) else None
    found = RELAY_PORTS.get(str(engine)) if engine else None
    return (found,) if found else ()


def relay_files(access: dict, doc: dict) -> dict[str, str]:
    """The relay units, by path under the root: a socket on the access
    address and port, and a service that carries each connection to the
    loopback, so the database's binds and accounts do not change"""
    files = {}
    here = address(access).ip
    for number in relay_ports(doc):
        name = RELAY_UNIT.format(port=number)
        files[f"{RELAY_DIR}/{name}.socket"] = "\n".join((
            "# Written by keel spec apply --system from network.access",
            "# (handbook decision 0098, answer 5)",
            "[Unit]",
            f"Description=keel access relay of the database, port {number}",
            "",
            "[Socket]",
            f"ListenStream=[{here}]:{number}",
            "FreeBind=yes",
            "BindIPv6Only=ipv6-only",
            "",
            "[Install]",
            "WantedBy=sockets.target",
        )) + "\n"
        files[f"{RELAY_DIR}/{name}.service"] = "\n".join((
            "# Written by keel spec apply --system from network.access",
            "# (handbook decision 0098, answer 5)",
            "[Unit]",
            f"Description=keel access relay of the database, port {number}",
            f"Requires={name}.socket",
            f"After={name}.socket",
            "",
            "[Service]",
            f"ExecStart={PROXYD} {RELAY_TARGET}:{number}",
            "DynamicUser=yes",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "CapabilityBoundingSet=",
            "RestrictAddressFamilies=AF_INET AF_INET6",
            "SystemCallArchitectures=native",
        )) + "\n"
    return files


def relay_socket_units(files: dict[str, str]) -> tuple[str, ...]:
    return tuple(sorted(path.rsplit("/", 1)[-1] for path in files
                        if path.endswith(".socket")))


def addresses_of(doc: dict) -> frozenset[str]:
    """This node's access address, which only keel-access reaches under
    enforce; empty without network.access or with an address keel cannot
    read (validation names it)"""
    access = section(doc)
    try:
        return frozenset({str(address(access).ip)}) if access else \
            frozenset()
    except (KeyError, ValueError):
        return frozenset()


def suggest_address(global_id: bytes) -> str:
    """A random unique local /64 for the node, the node at ::1 (answer
    3); `global_id` is 5 random bytes, as for the mesh"""
    from keel.network.wireguard import suggest_address as mesh_suggest
    return mesh_suggest(global_id)


def free_address(access: dict, number: int) -> str:
    """The /128 `number` (1 < number < 2**64) in the node's /64"""
    network = address(access).network
    return f"{network.network_address + number}/128"
