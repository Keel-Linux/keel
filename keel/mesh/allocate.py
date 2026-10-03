# Copyright (c) 2026 KeelLinux maintainers
"""The address an invite reserves for the new node (decision 0048)

A random address of the inviter's overlay prefix that is not its own,
not inside a peer's allowed_ips and not reserved by another pending
invite. Random, from `secrets`, rather than the lowest free one: until
etcd exists no member knows what another member's pending invites hold,
so two members inviting at the same time would both pick ::2, while two
random draws in a /64 practically never meet. The prefix's own address,
the subnet router anycast of RFC 4291, is never given.

A draw that lands on a taken address is drawn again. When ATTEMPTS
draws in a row are taken the prefix is nearly full, and it is searched
from the last draw, wrapping around once, so a prefix with one address
left still gives it and a full one is refused.
"""

import ipaddress
import secrets
from collections.abc import Callable, Iterable

from keel.network.wireguard import allowed

ATTEMPTS = 16
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class AllocationError(ValueError):
    """No address left in the prefix"""


def taken(overlay: dict) -> list[str]:
    """What the declared peers already route: every allowed_ips prefix"""
    return [one for peer in overlay.get("peers") or []
            for one in allowed(peer)]


def free_address(own: str, used: Iterable[str],
                 randbelow: Callable[[int], int] | None = None) -> str:
    """A free address of `own`'s prefix, with its prefix length

    `own` is the inviter's overlay address with its length; `used` holds
    prefixes and bare addresses of either family (an address written
    with a length is that whole prefix), and what lies outside the
    prefix is ignored. `randbelow(n)` gives an integer in [0, n); tests
    pass their own (default: secrets.randbelow). Raises AllocationError
    when none is left.
    """
    randbelow = randbelow or secrets.randbelow
    mine = ipaddress.IPv6Interface(own)
    prefix = mine.network
    blocked = [network for network in (
        ipaddress.ip_network(str(one), strict=False) for one in used)
        if network.version == 6 and network.overlaps(prefix)]
    blocked.append(ipaddress.IPv6Network(mine.ip))
    first = int(prefix.network_address) + 1
    last = int(prefix.broadcast_address)
    found = None
    if last >= first:
        for _ in range(ATTEMPTS):
            drawn = first + randbelow(last - first + 1)
            if first_free(drawn, drawn, blocked) is not None:
                found = drawn
                break
        else:
            found = first_free(drawn, last, blocked)
            if found is None:
                found = first_free(first, drawn, blocked)
    if found is None:
        raise AllocationError(
            f"no free address in {prefix}: every one is this node's, a"
            " peer's or a pending invite's; wait for an invite to"
            " expire, or remove a peer")
    return f"{ipaddress.IPv6Address(found)}/{prefix.prefixlen}"


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
