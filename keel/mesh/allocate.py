# Copyright (c) 2026 KeelLinux maintainers
"""The address an invite reserves for the new node (decisions 0048, 0051)

A random address of the inviter's **region**: the /112 of the overlay
its own address is in (0051, "How a region is declared": region k's
host n is `<prefix>::k:n`, the first region index 0). Free: not the
inviter's, not inside a peer's allowed_ips, not reserved by another
pending invite, and not in the VIP range. Random, from `secrets`, not
the lowest free one: two members of one region that invite at the same
time do not know each other's pending invites, so both would pick the
same lowest address, while two random draws in a /112 seldom meet. With
etcd, the invite also reserves the address there by a compare-and-swap
(keel.mesh.addrreserve), which catches the draws that meet.

Two regions cut off from each other never give out the same address,
since each allocates in its own range. A node keel placed before
regions, at a random address of the /64, allocates in the /112 its own
address is in: no node is renumbered (0051). Host 0 of a region is
never given: in the first region it is the subnet router anycast of
RFC 4291.

A draw that lands on a taken address is drawn again. When ATTEMPTS
draws in a row are taken the region is nearly full, and it is searched
from the last draw, wrapping around once, so a region with one address
left still gives it and a full one is refused.

The overlay's top /112, `<prefix>::ffff:n`, is the VIP range
(keel.mesh.vip): no region has that index and no invite allocates from
it; a node found there is not an inviter.
"""

import ipaddress
import secrets
from collections.abc import Callable, Iterable

from keel.mesh.vip import vip_range
from keel.network.wireguard import allowed

REGION_BITS = 112
ATTEMPTS = 16
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class AllocationError(ValueError):
    """No address left in the region, or no region to allocate in"""


def taken(overlay: dict) -> list[str]:
    """What the declared peers already route: every allowed_ips prefix"""
    return [one for peer in overlay.get("peers") or []
            for one in allowed(peer)]


def region_of(address: str) -> ipaddress.IPv6Network:
    """The /112 an overlay address is in, with or without its length

    An overlay no wider than a /112 is one region: itself.
    """
    mine = ipaddress.IPv6Interface(address)
    if "/" in address and mine.network.prefixlen >= REGION_BITS:
        return mine.network
    return ipaddress.IPv6Network((mine.ip, REGION_BITS), strict=False)


def free_address(own: str, used: Iterable[str],
                 randbelow: Callable[[int], int] | None = None) -> str:
    """A free address of `own`'s region, with the overlay's prefix length

    `own` is the inviter's overlay address with its length; `used` holds
    prefixes and bare addresses of either family (an address written
    with a length is that whole prefix), and what lies outside the
    region is ignored. `randbelow(n)` gives an integer in [0, n); tests
    pass their own (default: secrets.randbelow). Raises AllocationError
    when none is left, or when the inviter is in the VIP range.
    """
    randbelow = randbelow or secrets.randbelow
    mine = ipaddress.IPv6Interface(own)
    region = region_of(own)
    vips = vip_range(mine.network)
    if vips is not None and region == vips:
        raise AllocationError(
            f"this node's address {mine.ip} is in the VIP range {vips}:"
            " that range is for VIPs, and no node is invited from it."
            " Run keel mesh invite on a node outside that range")
    blocked = [network for network in (
        ipaddress.ip_network(str(one), strict=False) for one in used)
        if network.version == 6 and network.overlaps(region)]
    blocked.append(ipaddress.IPv6Network(mine.ip))
    found = drawn_free(int(region.network_address) + 1,
                       int(region.broadcast_address), blocked, randbelow)
    if found is None:
        raise AllocationError(
            f"no free address in {region}, this node's region: every one"
            " is this node's, a peer's or a pending invite's; wait for an"
            " invite to expire, or remove a peer")
    return f"{ipaddress.IPv6Address(found)}/{mine.network.prefixlen}"


def drawn_free(first: int, last: int, blocked: list[Network],
               randbelow: Callable[[int], int]) -> int | None:
    """A random free address in [first, last]; the search from the last
    draw, wrapping around once, after ATTEMPTS taken draws"""
    if last < first:
        return None
    for _ in range(ATTEMPTS):
        drawn = first + randbelow(last - first + 1)
        if first_free(drawn, drawn, blocked) is not None:
            return drawn
    found = first_free(drawn, last, blocked)
    if found is None:
        found = first_free(first, drawn, blocked)
    return found


def first_free(start: int, end: int, blocked: list[Network]) -> int | None:
    """The lowest address in [start, end] no blocked prefix covers"""
    candidate = start
    moved = True
    while moved and candidate <= end:
        moved = False
        for network in blocked:
            if int(network.network_address) <= candidate <= int(
                    network.broadcast_address):
                candidate = int(network.broadcast_address) + 1
                moved = True
    return candidate if candidate <= end else None
