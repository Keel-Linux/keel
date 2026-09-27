# Copyright (c) 2026 KeelLinux maintainers
"""Field level checks shared by the validators"""

import ipaddress
import re
from typing import Any

from keel.spec.constants import MAX_PORT

LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

MAX_DOMAIN_LENGTH = 253


def mapping_error(key: str, value: Any) -> str | None:
    """Every section of the spec is a mapping or absent"""
    if value is not None and not isinstance(value, dict):
        return f"{key}: must be a mapping"
    return None


def list_error(key: str, value: Any) -> str | None:
    """A field that holds several values is a list or absent

    A scalar is not read as a list of one: YAML makes it too easy to write
    `nameservers: 2001:db8::53`, and iterating a string would check it one
    character at a time.
    """
    if value is not None and not isinstance(value, list):
        return f"{key}: must be a list"
    return None


def domain_error(key: str, value: Any) -> str | None:
    """Reject anything that is not a bare domain name"""
    if not isinstance(value, str) or not value.strip():
        return f"{key}: must be a domain name"
    host = value.strip().rstrip(".")
    labels = host.split(".")
    if len(host) > MAX_DOMAIN_LENGTH:
        return f'{key}: domain "{value}" is invalid'
    if not all(LABEL_RE.match(label) for label in labels):
        return f'{key}: domain "{value}" is invalid'
    return None


def email_error(key: str, value: Any) -> str | None:
    if not EMAIL_RE.match(str(value)):
        return f"{key}: must be an email address"
    return None


def is_ipv4(value: str) -> bool:
    return _version(value) == 4


def is_ipv6(value: str) -> bool:
    return _version(value) == 6


def _version(value: str) -> int | None:
    """The address family of a string, or None when it is not an address"""
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def is_unicast(address: Any) -> bool:
    """Link local, loopback, multicast and :: are not instance addresses"""
    return not (
        address.is_link_local
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    )


LOCALHOST_NAMES = ("localhost", "ip6-localhost", "ip6-loopback")
LOCALHOST_REASON = (
    "Debian maps ::1 to ip6-localhost and never to localhost, so a resolver"
    " asked for localhost answers one family only; write ::1 and 127.0.0.1"
)


def literal_address_error(key: str, value: Any) -> str | None:
    """An address field holds a literal address, never a name

    docs/traps.md, "On Debian, localhost is not an IPv6 name": the
    PostgreSQL appliance shipped listening on IPv4 only because its
    configuration said localhost and looked right.
    """
    if not isinstance(value, str) or not value.strip():
        return f"{key}: must be an address"
    text = value.strip()
    if text.lower() in LOCALHOST_NAMES:
        return f'{key}: "{text}" is a name, not an address: {LOCALHOST_REASON}'
    if _version(text) is None:
        return f'{key}: "{text}" is not an address; addresses are literal'
    return None


def origin_error(key: str, value: Any) -> str | None:
    """An origin an authorization names: an address, a prefix or a name

    A prefix is the form to prefer, because with IPv6 and no NAT the /64 a
    fleet lives on is stable where a single address goes stale every time a
    container is rebuilt. A name is accepted and is fragile: see
    docs/spec.md.
    """
    if not isinstance(value, str) or not value.strip():
        return f"{key}: must be an address, a prefix or a name"
    text = value.strip()
    if text.lower() in LOCALHOST_NAMES:
        return f'{key}: "{text}" is ambiguous: {LOCALHOST_REASON}'
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError as e:
            return f"{key}: {text} is not a prefix ({e})"
        return None
    if _version(text) is not None:
        return None
    if domain_error(key, text) is not None:
        return (
            f'{key}: "{text}" is not an address, a prefix or a name'
        )
    return None


def port_error(key: str, value: Any) -> str | None:
    """A port is a whole number in range; a string that looks like one is not"""
    if isinstance(value, bool) or not isinstance(value, int):
        return f"{key}: must be a port number"
    if not 1 <= value <= MAX_PORT:
        return f"{key}: must be a port number between 1 and {MAX_PORT}"
    return None
