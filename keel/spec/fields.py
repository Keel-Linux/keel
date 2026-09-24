# Copyright (c) 2026 KeelLinux maintainers
"""Field level checks shared by the validators"""

import ipaddress
import re
from typing import Any

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
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def is_unicast(address: Any) -> bool:
    """Link local, loopback, multicast and :: are not instance addresses"""
    return not (
        address.is_link_local
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    )
