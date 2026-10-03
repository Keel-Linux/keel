# Copyright (c) 2026 KeelLinux maintainers
"""The WireGuard overlay's file, from the spec and back (decision 0020)

`network.overlay.wireguard` declares this node's side of the private
network the nodes of a replicated appliance share: its address, the port
it listens on, where its private key is, and the peers it accepts.
`apply --system` renders it into /etc/wireguard/<interface>.conf, the file
wg-quick reads, and `keel inspect` reads that file back. Everything here
is pure: the key is made and read by keel.network.wgkeys.

The private key never enters the file. wg-quick would take it from a
PrivateKey line, which would put the secret in a file keel rewrites,
saves under /var/lib/keel/network for a revert and compares; instead a
PostUp line hands the key file to `wg set`, so only `wg` and the kernel
read it. wg-quick runs PostUp through bash's `eval`, which is why a key
path may only hold characters a shell gives no meaning (KEY_PATH_RE).
"""

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass

DEFAULT_INTERFACE = "wg0"
DEFAULT_PORT = 51820
CONF_DIR = "etc/wireguard"
# the link `systemctl enable wg-quick@<iface>` makes, which apply makes
# once a change of the overlay is confirmed (keel.system.overlay)
WANTS = "etc/systemd/system/multi-user.target.wants/wg-quick@{iface}.service"
# present while the module is loaded, in a container too: /sys/module
# there shows the host's modules, which are the only ones it has
MODULE = "sys/module/wireguard"
KEY_BYTES = 32
KEY_LENGTH = 44
# wg-quick's own rule for an interface name
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")
# a key path goes through bash's eval in PostUp: nothing a shell reads
KEY_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
POST_UP = "wg set %i private-key "
HEADER = (
    "# Written by keel spec apply --system from network.overlay.wireguard",
    "# (handbook decisions 0018 and 0020); edit the instance description,",
    "# not this file. The private key is not here: PostUp gives its file",
    "# to wg, so the key is read by wg alone.",
)
# The wg-quick keys the spec has a field for; any other is reported by
# inspect as a line the spec cannot hold, never silently dropped.
INTERFACE_KEYS = ("address", "listenport", "postup", "privatekey")
PEER_KEYS = ("publickey", "endpoint", "allowedips", "persistentkeepalive")
ULA_PREFIX = 0xFD
GLOBAL_ID_BYTES = 5


def interface(overlay: dict) -> str:
    return str(overlay.get("interface") or DEFAULT_INTERFACE)


def conf_path(iface: str) -> str:
    """The file wg-quick reads for `iface`, relative to the root"""
    return f"{CONF_DIR}/{iface}.conf"


def key_path(overlay: dict) -> str:
    """The private key file, absolute: declared, else beside the conf"""
    declared = (overlay.get("private_key") or {}).get("file")
    if declared:
        return str(declared)
    return f"/{CONF_DIR}/{interface(overlay)}.key"


def port(overlay: dict) -> int:
    return int(overlay.get("listen_port") or DEFAULT_PORT)


def addresses(overlay: dict) -> tuple[str, ...]:
    """This node's overlay addresses with their prefix, IPv6 first"""
    return tuple(
        str(ipaddress.ip_interface(str(overlay[name])))
        for name in ("address", "ipv4_address") if overlay.get(name)
    )


def is_key(text: str) -> bool:
    """A WireGuard key as wg prints it: 32 bytes in base64, 44 characters"""
    return key_bytes(text) is not None


def key_bytes(text: str) -> bytes | None:
    """The 32 bytes of a key written as wg prints it, or None

    The last character of the base64 carries two bits no byte uses.
    Python's decoder ignores them; wg refuses a key that sets them ("Key
    is not the correct length or format"), so such a spelling is no key
    here either. Keys are compared by these bytes (same_key), never as
    text.
    """
    if len(text) != KEY_LENGTH:
        return None
    try:
        found = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(found) != KEY_BYTES or base64.b64encode(found).decode() != text:
        return None
    return found


def same_key(one: str, other: str) -> bool:
    """Whether two spellings are the same WireGuard key"""
    found = key_bytes(one)
    return found is not None and found == key_bytes(other)


def split_endpoint(text: str) -> tuple[str, int]:
    """`[2001:db8::20]:51820` or `node2.example.org:51820` to host, port

    An IPv6 literal must be in brackets, as wg writes it: without them
    the last group of the address and the port cannot be told apart.
    Raises ValueError with the reason.
    """
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError("an IPv6 literal is written [address]:port")
        ipaddress.IPv6Address(host)
        return host, port_number(rest[1:])
    host, sep, digits = text.rpartition(":")
    if not sep or not host:
        raise ValueError("a port is required: host:port")
    if ":" in host:
        raise ValueError("an IPv6 literal is written in brackets:"
                         " [address]:port")
    return host, port_number(digits)


def port_number(digits: str) -> int:
    if not digits.isdigit() or not 1 <= int(digits) <= 65535:
        raise ValueError(f"{digits!r} is not a port number")
    return int(digits)


def canonical_endpoint(text: str) -> str:
    """One spelling per endpoint: an address compressed, a name lower case"""
    try:
        host, number = split_endpoint(text)
    except ValueError:
        return text
    try:
        value = ipaddress.ip_address(host)
    except ValueError:
        return f"{host.lower().rstrip('.')}:{number}"
    if value.version == 6:
        return f"[{value}]:{number}"
    return f"{value}:{number}"


def allowed(peer: dict) -> list[str]:
    return [str(ipaddress.ip_network(str(one), strict=False))
            for one in peer.get("allowed_ips") or []]


def render(overlay: dict) -> str:
    """The wg-quick file for the declared overlay"""
    lines = list(HEADER) + [
        "[Interface]",
        f"Address = {', '.join(addresses(overlay))}",
        f"ListenPort = {port(overlay)}",
        f"PostUp = {POST_UP}{key_path(overlay)}",
    ]
    for peer in overlay.get("peers") or []:
        lines += ["", "[Peer]", f"PublicKey = {peer['public_key']}"]
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append(f"AllowedIPs = {', '.join(allowed(peer))}")
        if peer.get("persistent_keepalive"):
            lines.append(
                f"PersistentKeepalive = {peer['persistent_keepalive']}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Parsed:
    """A wg-quick file read back into the spec's shape

    `inline_key` is a file that holds its private key in a PrivateKey
    line, which keel never writes; the parse does not keep the value, and
    only apply reads it, to move it into the key file
    (keel.network.wgkeys.adopt). `problems` are lines
    the spec cannot hold (DNS, MTU, a preshared key...), which inspect
    reports rather than dropping them in silence.
    """

    section: dict
    inline_key: bool
    problems: tuple[str, ...]


def parse(text: str) -> Parsed:
    iface: dict = {}
    peers: list[dict] = []
    problems: list[str] = []
    inline = False
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            current = {} if name == "peer" else None
            if current is not None:
                peers.append(current)
            elif name != "interface":
                problems.append(f"section {line} is not a wg-quick one")
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not sep:
            problems.append(f"line {line!r} is not key = value")
        elif current is None:
            inline = interface_line(iface, key, value, problems) or inline
        else:
            peer_line(current, key, value, problems)
    return Parsed(iface | ({"peers": peers} if peers else {}), inline,
                  tuple(problems))


def interface_line(iface: dict, key: str, value: str,
                   problems: list[str]) -> bool:
    """Read one line of [Interface]; True for an inline private key"""
    if key == "address":
        for one in split_list(value):
            place_address(iface, one, problems)
    elif key == "listenport" and value.isdigit():
        iface["listen_port"] = int(value)
    elif key == "postup" and value.startswith(POST_UP):
        iface["private_key"] = {"file": value[len(POST_UP):].strip()}
    elif key == "privatekey":
        return True
    else:
        problems.append(f"[Interface] {key} = {value}: not a field of the"
                        " spec")
    return False


def place_address(iface: dict, text: str, problems: list[str]) -> None:
    try:
        value = ipaddress.ip_interface(text)
    except ValueError:
        problems.append(f"Address {text} is not an address")
        return
    name = "address" if value.version == 6 else "ipv4_address"
    if name in iface:
        problems.append(f"Address {text}: the spec holds one address per"
                        " family")
        return
    iface[name] = str(value)


def peer_line(peer: dict, key: str, value: str, problems: list[str]) -> None:
    if key == "publickey":
        peer["public_key"] = value
    elif key == "endpoint":
        peer["endpoint"] = value
    elif key == "allowedips":
        peer["allowed_ips"] = split_list(value)
    elif key == "persistentkeepalive" and value.isdigit():
        peer["persistent_keepalive"] = int(value)
    else:
        problems.append(f"[Peer] {key}: not a field of the spec")


def split_list(value: str) -> list[str]:
    return [one.strip() for one in value.split(",") if one.strip()]


def suggest_address(global_id: bytes) -> str:
    """A unique local address (RFC 4193) for the first node of a set

    `global_id` is five random bytes, the 40 bit Global ID; the subnet is
    0 and this node is ::1 on its /64. The other nodes take ::2, ::3 on
    the same /64, so the one prefix is what an operator copies.
    """
    if len(global_id) != GLOBAL_ID_BYTES:
        raise ValueError(f"a Global ID is {GLOBAL_ID_BYTES} bytes")
    value = int.from_bytes(bytes([ULA_PREFIX]) + global_id, "big") << 80
    return str(ipaddress.IPv6Interface((value | 1, 64)))
