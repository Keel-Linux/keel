# Copyright (c) 2026 KeelLinux maintainers
"""The spec's firewall section (decisions 0041 and 0097)

The firewall is derived from the manifests: every `public` port of a
process whose overlay is enabled is opened on every interface, every
`mesh` port on the WireGuard interface only. Decision 0097 ends the
scope of 2026-09-30 (cloud advanced only): keel writes it in every mode.

- `state`: enforce (a drop policy), report (drops nothing, counts what
  enforce would drop) or off (no table of keel's).
- `enabled`: the spelling of keel 0.23.97 and before. `true` is
  enforce; `false` records no choice (keel inspect wrote it where it
  found no file), so it reads as an absent section.
- `allow`: the administrator's own ports, each `port`, `protocol` and an
  optional `from`, a list of prefixes; without `from`, every address.

With no word, the state is report, which an apply a person runs moves to
enforce when every listening socket belongs to the manifests (rule B,
keel.system.firewall).
"""

import ipaddress
from typing import Any

from keel.manifest.firewall import ENFORCE, OFF, STATES
from keel.spec.fields import mapping_error

KEY = "firewall"
KEYS = ("enabled", "state", "allow")
ALLOW_KEYS = ("port", "protocol", "from")
PROTOCOLS = ("tcp", "udp")
MAX_PORT = 65535


def state_word(value: Any) -> Any:
    """YAML 1.1 reads an unquoted `off` as false: that is the word off"""
    return OFF if value is False else value


def declared_state(doc: dict) -> str | None:
    """enforce, report or off as the spec says it; None when it says
    nothing that is a choice (no section, or `enabled: false`)"""
    firewall = doc.get(KEY)
    if not isinstance(firewall, dict):
        return None
    state = state_word(firewall.get("state"))
    if state in STATES:
        return state
    if firewall.get("enabled") is True:
        return ENFORCE
    return None


def validate_firewall(doc: dict) -> list[str]:
    firewall = doc.get(KEY)
    error = mapping_error(KEY, firewall)
    if error or not firewall:
        return [error] if error else []
    errors = [f"{KEY}.{name}: unknown key" for name in firewall
              if name not in KEYS]
    enabled = firewall.get("enabled")
    state = state_word(firewall.get("state"))
    if enabled is not None and not isinstance(enabled, bool):
        errors.append(f"{KEY}.enabled: must be true or false")
    if state is not None and state not in STATES:
        errors.append(f"{KEY}.state: must be one of {', '.join(STATES)}")
    if enabled is not None and state is not None:
        errors.append(f"{KEY}: say `state` or `enabled`, not both;"
                      " `enabled` is the old spelling (true is state:"
                      " enforce)")
    if "allow" in firewall:
        errors += _allow_errors(firewall["allow"])
    if errors:
        return errors
    if (enabled is True or state in ("enforce", "report")) and \
            not isinstance(doc.get("appliance"), dict):
        said = "enabled" if enabled is not None else "state"
        errors.append(f"{KEY}.{said}: needs appliance.name: the ports"
                      " come from its manifests")
    return errors


def _allow_errors(allow: Any) -> list[str]:
    if not isinstance(allow, list):
        return [f"{KEY}.allow: must be a list"]
    errors = []
    for index, item in enumerate(allow):
        errors += _item_errors(f"{KEY}.allow[{index}]", item)
    return errors


def _item_errors(where: str, item: Any) -> list[str]:
    if not isinstance(item, dict):
        return [f"{where}: must be a mapping"]
    errors = [f"{where}.{name}: unknown key" for name in item
              if name not in ALLOW_KEYS]
    port = item.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or \
            not 1 <= port <= MAX_PORT:
        errors.append(f"{where}.port: must be a port number, 1 to"
                      f" {MAX_PORT}")
    if item.get("protocol") not in PROTOCOLS:
        errors.append(f"{where}.protocol: must be tcp or udp")
    if "from" in item:
        errors += _from_errors(f"{where}.from", item["from"])
    return errors


def _from_errors(where: str, sources: Any) -> list[str]:
    if not isinstance(sources, list) or not sources:
        return [f"{where}: must be a list of prefixes"]
    return [problem for problem in (_prefix_problem(where, source)
                                    for source in sources) if problem]


def _prefix_problem(where: str, source: Any) -> str | None:
    try:
        ipaddress.ip_network(str(source), strict=True)
        return None
    except ValueError:
        pass
    try:
        ipaddress.ip_network(str(source), strict=False)
        why = "it has host bits set"
    except ValueError:
        why = "it does not appear to be an IPv4 or IPv6 network"
    return f"{where}: {source} is not a prefix: {why}"
