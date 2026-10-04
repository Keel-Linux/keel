# Copyright (c) 2026 KeelLinux maintainers
"""The address another node reaches this one at, found on the uplink

`keel mesh invite` puts this node's endpoint in the token, and `keel
mesh join` sends its own in the request. `--endpoint` gives it, and a
static address network.interfaces declares is taken next; a host whose
uplink is configured by DHCP or SLAAC declares none, so it is found
here, from what `ip` says the machine holds:

- on the uplink, the interfaces the default routes leave through (any
  interface when there is no default route), never a WireGuard one
  (`wg*`), whose addresses are the overlay's;
- a global IPv6 address that is not a unique local one (fc00::/7), not
  deprecated and not a SLAAC privacy address (`temporary`), a static
  one before a SLAAC or DHCPv6 one (`dynamic`): the order of keel-core's
  console banner (keel_banner_pick_ipv6) and confconsole;
- beside it, or instead of it, a public IPv4 address.

A privacy address changes within a day and an RFC 1918 or carrier NAT
one is reached from its own network only, so neither is ever taken: a
host that holds nothing better has no endpoint found, and the reason
says so and names `--endpoint` (`invite` refuses; `join` sends none, as
a node behind NAT does).
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

HELD = ("ip", "-o", "address", "show", "scope", "global")
ROUTES = (("ip", "-6", "route", "show", "default"),
          ("ip", "-4", "route", "show", "default"))
OVERLAY_PREFIX = "wg"
ULA = ipaddress.ip_network("fc00::/7")
# RFC 1918, and the shared space of RFC 6598 a carrier's NAT gives
PRIVATE4 = tuple(ipaddress.ip_network(one) for one in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
STATIC, DYNAMIC = 0, 1


@dataclass(frozen=True)
class Held:
    """An address an interface holds, and the flags `ip` gave it"""

    iface: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    flags: frozenset[str]


@dataclass(frozen=True)
class Choice:
    """The addresses chosen, IPv6 first, what to tell the operator, and,
    when none was, why"""

    addresses: tuple[str, ...]
    said: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()


def held(text: str) -> list[Held]:
    """`ip -o address show scope global` output, in its order"""
    found = []
    for line in text.splitlines():
        fields = line.replace("\\", " ").split()
        if len(fields) < 4 or fields[2] not in ("inet", "inet6"):
            continue
        try:
            address = ipaddress.ip_interface(fields[3]).ip
        except ValueError:
            continue
        found.append(Held(fields[1].split("@")[0], address,
                          frozenset(fields[4:])))
    return found


def uplinks(text: str) -> tuple[str, ...]:
    """`ip route show default` output: the interfaces, in order"""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if "dev" in fields and fields.index("dev") + 1 < len(fields):
            found.append(fields[fields.index("dev") + 1])
    return tuple(dict.fromkeys(found))


def candidates(found: list[Held], links: tuple[str, ...]) -> list[Held]:
    return [one for one in found
            if not one.iface.startswith(OVERLAY_PREFIX)
            and (not links or one.iface in links)
            and not (one.address.is_loopback or one.address.is_link_local
                     or one.address.is_multicast)]


def rank(one: Held) -> int:
    return DYNAMIC if "dynamic" in one.flags else STATIC


def pick(found: list[Held], links: tuple[str, ...]) -> Choice:
    """The endpoints among `found`, on the interfaces `links`"""
    usable = candidates(found, links)
    six = [one for one in usable if one.address.version == 6
           and one.address not in ULA and "deprecated" not in one.flags]
    stable = sorted((one for one in six if "temporary" not in one.flags),
                    key=rank)
    privacy = [one for one in six if "temporary" in one.flags]
    four = [one for one in usable if one.address.version == 4]
    public = [one for one in four
              if not any(one.address in net for net in PRIVATE4)]
    chosen = stable[:1] + public[:1]
    if chosen:
        said = [described(one) for one in chosen]
        if privacy and not stable:
            said.append(f"the SLAAC privacy address {privacy[0].address} was"
                        " left out: it changes within a day")
        return Choice(tuple(str(one.address) for one in chosen),
                      tuple(said))
    refused = []
    if privacy:
        refused.append(
            f"{privacy[0].address} is a SLAAC privacy address, the only"
            f" global IPv6 one {privacy[0].iface} holds: it changes within"
            " a day, and the other node's peer entry would then point"
            " nowhere")
    if four:
        refused.append(
            f"{four[0].address} is a private address (RFC 1918 or carrier"
            f" NAT), the only IPv4 one {four[0].iface} holds: a node outside"
            " its network reaches it only through a port forward")
    if not refused:
        refused.append("no global address on the uplink"
                       f" ({', '.join(links) or 'no default route'}) that"
                       " another node could reach")
    return Choice((), (), tuple(refused))


def described(one: Held) -> str:
    return (f"endpoint {one.address}, found on {one.iface}"
            " (--endpoint overrides it)")


def detect(output: Callable[[tuple[str, ...]], str | None]) -> Choice:
    """The endpoints of this machine, as `ip` shows it now"""
    routes = "".join(output(argv) or "" for argv in ROUTES)
    return pick(held(output(HELD) or ""), uplinks(routes))
