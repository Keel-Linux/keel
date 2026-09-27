# Copyright (c) 2026 KeelLinux maintainers
"""An origin an authorization names, and the spellings that mean one thing

`database.server.replication.allowed_from` holds the origins a primary
allows to replicate from it. docs/spec.md says a prefix is the form to
prefer, because with IPv6 and no NAT the /64 a fleet lives on is stable
where a list of single addresses goes stale every time a container is
rebuilt. It also says MariaDB has no way to write that: a grant takes an
address and a netmask for IPv4 only, so authorizing an IPv6 /64 there can
only be spelled as the host pattern `2001:db8:1:%`.

So the same authorization has two spellings, one the operator should write
and one the server holds. This module is where they meet: `canonical` puts
both into the same form, so `keel diff` does not report drift on a
description that used the preferred form, and `host_pattern` produces the
engine's spelling, so `keel spec apply` can grant what the description
asked for.

A name is never resolved here. An authorization that names a host and a
server that holds an address are two different things, and calling them
the same is how a name that stopped resolving would pass unnoticed.

Nothing here reads a file or runs a command.
"""

import ipaddress

# A host pattern ends in a wildcard group: `2001:db8:1:%` for IPv6,
# `192.0.2.%` for IPv4. Only a group aligned one has a prefix that means
# exactly the same thing, which is why `2001:db8:1:5%` is left alone.
WILDCARD = "%"
GROUP_BITS = {":": 16, ".": 8}
FULL_LENGTH = {":": 128, ".": 32}
MAX_GROUP = {":": 0xFFFF, ".": 255}


def canonical(origin: str) -> str:
    """One origin in the form both spellings reduce to

    An address is compressed, a prefix is put in its network form, a group
    aligned host pattern becomes the prefix it authorizes, and anything
    else, a name or a pattern that matches no whole prefix, is lower cased
    and left as it stands.
    """
    text = str(origin).strip()
    if not text:
        return text
    prefix = as_prefix(text)
    if prefix is not None:
        return prefix
    address = _address(text)
    if address is not None:
        return address
    return text.lower().rstrip(".")


def is_name(origin: str) -> bool:
    """Whether an origin is a name rather than an address or a range

    A name is what docs/spec.md accepts and calls fragile, and the apply
    path has to know: MariaDB matches an account whose host is a name only
    while it resolves client addresses, so a description that holds one
    decides whether `skip_name_resolve` can be turned on.
    """
    text = str(origin).strip()
    if not text:
        return False
    return (
        as_prefix(text) is None
        and _address(text) is None
        and WILDCARD not in text
    )


def as_prefix(origin: str) -> str | None:
    """The prefix an origin authorizes, or None when it names no whole one

    Both spellings come through here: `2001:db8:1::/64` as written, and
    `2001:db8:1:%` counted out as four groups of sixteen bits.
    """
    text = str(origin).strip()
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return None
    return _pattern_prefix(text)


def host_pattern(origin: str) -> str | None:
    """The origin as MariaDB spells it, or None when it has no spelling

    A prefix that stops on a group boundary becomes the pattern for those
    groups; an address and a name are already what a grant holds, and come
    back unchanged. A prefix that stops inside a group (a /56, a /28) has
    no host pattern at all, and the caller says so rather than authorizing
    a wider or a narrower range than the description asked for.
    """
    text = str(origin).strip()
    if "/" not in text:
        return text or None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    separator = ":" if network.version == 6 else "."
    bits = GROUP_BITS[separator]
    length = network.prefixlen
    if length == FULL_LENGTH[separator]:
        return str(network.network_address)
    if length == 0 or length % bits:
        return None
    groups = _groups(network.network_address, separator)
    return separator.join(groups[: length // bits] + [WILDCARD])


def _groups(address: object, separator: str) -> list[str]:
    """Every group of an address, in the shortest spelling of each"""
    if separator == ".":
        return str(address).split(".")
    exploded = str(getattr(address, "exploded", address))
    return [format(int(group, 16), "x") for group in exploded.split(":")]


def _pattern_prefix(text: str) -> str | None:
    """A group aligned host pattern as its prefix, else None"""
    separator = ":" if ":" in text else "."
    parts = text.split(separator)
    if len(parts) < 2 or parts[-1] != WILDCARD:
        return None
    groups = parts[:-1]
    if WILDCARD in separator.join(groups) or not all(groups):
        return None
    bits = GROUP_BITS[separator] * len(groups)
    if bits >= FULL_LENGTH[separator]:
        return None
    filled = _fill(groups, separator)
    if filled is None:
        return None
    try:
        return str(ipaddress.ip_network(f"{filled}/{bits}", strict=False))
    except ValueError:
        return None


def _fill(groups: list[str], separator: str) -> str | None:
    """The groups as an address, the rest of it zero"""
    base = 16 if separator == ":" else 10
    for group in groups:
        try:
            value = int(group, base)
        except ValueError:
            return None
        if not 0 <= value <= MAX_GROUP[separator]:
            return None
    if separator == ":":
        return ":".join(groups) + "::"
    return ".".join(groups + ["0"] * (4 - len(groups)))


def _address(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None
