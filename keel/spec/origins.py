# Copyright (c) 2026 KeelLinux maintainers
"""An origin an authorization names, and the spellings that mean one thing

`database.server.replication.allowed_from` holds the origins a primary
allows to replicate from it. docs/spec.md says a prefix is the form to
prefer, because with IPv6 and no NAT the /64 a fleet lives on is stable
where a list of single addresses goes stale every time a container is
rebuilt. It also says MariaDB has no way to write that: a grant takes an
address and a netmask for IPv4 only, so authorizing an IPv6 /64 there can
only be spelled as the host pattern `2001:db8:1:%`. That pattern is matched
against the text of the client's address, which compresses zero groups, so
it holds a prefix exactly only when no group of the prefix can be
compressed away; fd3d:80b2:d0d7::/64, what `keel network wireguard
suggest-address` prints, has no pattern, and its replicas are authorized
by their addresses.

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

    MariaDB matches the host of a grant against the text of the client's
    address, the compressed form getnameinfo gives, and has a netmask for
    IPv4 only (MariaDB 11.8, Debian 13: an IPv6 CIDR or netmask host
    matches nothing). So an address is granted in that compressed form,
    and a prefix that stops on a group boundary becomes the pattern for
    those groups, when that pattern matches every address of the prefix
    and no other. A name comes back unchanged.

    A prefix that stops inside a group (a /56, a /28) has no host pattern
    at all, and neither does an IPv6 prefix a zero group of which the
    text can compress away (see `compressed_address`): the caller says so
    rather than authorizing a wider or a narrower range than the
    description asked for. A host pattern written as such is held to the
    same rule, as the prefix it names, and one with `::` has none: `::`
    stands for a number of zero groups no wildcard counts.
    """
    text = str(origin).strip()
    if "/" not in text:
        address = _address(text)
        if address is not None:
            return address
        if _elided_pattern(text):
            return None
        prefix = _pattern_prefix(text)
        if prefix is None:
            return text or None
        text = prefix
    network = _network(text)
    if network is None:
        return None
    separator = ":" if network.version == 6 else "."
    bits = GROUP_BITS[separator]
    length = network.prefixlen
    if length == FULL_LENGTH[separator]:
        return str(network.network_address)
    if length == 0 or length % bits:
        return None
    groups = _groups(network.network_address, separator)[: length // bits]
    if separator == ":" and not _always_written(groups):
        return None
    return separator.join(groups + [WILDCARD])


def compressed_address(origin: str) -> str | None:
    """An address of the prefix its host pattern would not match, or None

    The text of an IPv6 address writes its longest run of two zero groups
    or more as `::` (the first, if two are as long). When that run can
    take in a group of the prefix, the address's text no longer starts
    with the prefix's groups: in fd3d:80b2:d0d7::/64 the replica
    fd3d:80b2:d0d7::2 is not fd3d:80b2:d0d7:0:anything, and a grant to
    `fd3d:80b2:d0d7:0:%` refuses it. That happens exactly when the last
    group of the prefix is zero or two groups in a row are; this returns
    one such address, for the refusal to name, and None for any origin
    that is not a group aligned IPv6 prefix of that kind.

    A second pattern with the `::` does not fix it in general: after `::`
    nothing in `%` counts the groups the `::` stands for, so `2001::5:%`
    holds 2001::5:a:b, which is 2001:0:0:0:0:5:a:b and outside
    2001:0:0:5::/64.
    """
    text = str(origin).strip()
    network = _network(text if "/" in text else _pattern_prefix(text) or "")
    if network is None or network.version != 6:
        return None
    length = network.prefixlen
    if length in (0, FULL_LENGTH[":"]) or length % GROUP_BITS[":"]:
        return None
    count = length // GROUP_BITS[":"]
    groups = _groups(network.network_address, ":")[:count]
    if _always_written(groups):
        return None
    head = ":".join(groups) + ":"
    base = int(network.network_address)
    every_host_group = sum(
        1 << (GROUP_BITS[":"] * index) for index in range(8 - count)
    )
    # A last zero is compressed with the zero host groups after it in ::1
    # (or in the prefix address itself when one host group follows), and
    # a zero pair when no host group is zero, so one of these escapes.
    texts = (
        str(ipaddress.IPv6Address(base + offset))
        for offset in (1, 0, every_host_group)
    )
    return next((one for one in texts if not one.startswith(head)), None)


def mariadb_problem(origin: str) -> str | None:
    """Why a MariaDB grant cannot hold this origin exactly, or None

    One reason for the three places that meet it: validate refuses the
    description before apply writes anything, inspect does not write a
    grant it would refuse into one, and apply refuses rather than grant
    a wider or a narrower range than the description asked for.
    """
    if host_pattern(origin) is not None:
        return None
    text = str(origin).strip()
    address = compressed_address(text)
    if address is not None:
        return COMPRESSED.format(origin=text, address=address)
    if _elided_pattern(text):
        return ELIDED.format(origin=text)
    return NO_GROUP.format(origin=text)


NO_GROUP = (
    "{origin} names no whole group of the address, so MariaDB has no host"
    " pattern for it, and a wider or a narrower range than the description"
    " asked for is never granted. Write a prefix that stops on a group"
    " boundary, or each replica's address"
)
COMPRESSED = (
    "{origin} has no host pattern MariaDB can match: the server compares"
    " the text of a client's address, that text writes a run of zero"
    " groups as ::, and here the run can take in a group of the prefix,"
    " so a pattern of its groups would refuse {address}, which the prefix"
    " holds. MariaDB has no netmask for IPv6, and a wider or a narrower"
    " range than the description asked for is never granted. Write each"
    " replica's address instead (on an overlay, the address of each peer)"
)
ELIDED = (
    "{origin} is a host pattern with ::, which stands for a number of zero"
    " groups no wildcard counts, so it holds addresses outside any one"
    " prefix (2001::5:% holds 2001::5:a:b, which is 2001:0:0:0:0:5:a:b)."
    " Write the prefix, or each replica's address"
)


def _elided_pattern(text: str) -> bool:
    """A host pattern that writes zero groups as `::`"""
    return "::" in text and any(one in text for one in "%_")


def _always_written(groups: list[str]) -> bool:
    """Whether every address of the prefix writes each of these groups

    A lone zero group between two that are not zero is never compressed.
    A zero next to another zero, or a zero last, next to the host part,
    can be.
    """
    zero = [group == "0" for group in groups]
    if zero[-1]:
        return False
    return not any(one and two for one, two in zip(zero, zero[1:]))


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _network(text: str) -> Network | None:
    if "/" not in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


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
