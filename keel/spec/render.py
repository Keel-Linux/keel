# Copyright (c) 2026 KeelLinux maintainers
"""Render a spec document as the inithooks conf the firstboot hooks read

Keel does not replace the existing hooks: it writes the variables they
already source, so an appliance gains a declarative front end without any
hook knowing that the spec exists.
"""

import ipaddress
import shlex
from typing import Any

from keel.spec.constants import KEYWORDS, MASK, MASKED_VARS, SECRET_VARS
from keel.spec.fields import is_ipv4, is_ipv6
from keel.spec.runtime import managed_by

MAX_NAMESERVERS = 2
# ifupdown has no SLAAC method of its own: `inet6 dhcp` is what the hook
# writes for both, and it keeps SLAAC on as confconsole does.
IP6_CONFIG = {"static": "static", "dhcp": "dhcp", "auto": "dhcp",
              "manual": "manual"}


def render_env(doc: dict, secrets: dict[str, str]) -> str:
    """Render the document and the resolved secrets as a shell conf file"""
    env: dict[str, str] = {}

    instance = doc.get("instance") or {}
    _set(env, "HOSTNAME", instance.get("hostname"))
    _set(env, "FQDN", instance.get("fqdn"))

    for var in SECRET_VARS.values():
        _set(env, var, secrets.get(var))

    app = doc.get("app") or {}
    _set(env, "APP_EMAIL", app.get("email"))
    _set(env, "APP_DOMAIN", app.get("domain"))
    for key, value in (app.get("options") or {}).items():
        _set(env, f"APP_{str(key).upper()}", value)

    hub = doc.get("hub") or {}
    api_key = hub.get("api_key")
    if isinstance(api_key, dict):
        api_key = secrets.get("HUB_APIKEY")
    _set(env, "HUB_APIKEY", _keyword(api_key))

    security = doc.get("security") or {}
    _set(env, "SEC_ALERTS", _keyword(security.get("alerts")))
    _set(env, "SEC_UPDATES", _keyword(security.get("updates")))

    if doc.get("first_login_wizard"):
        env["AUTO_RUN"] = "TRUE"

    env.update(network_env(doc.get("network")))

    for key, value in (doc.get("preseed") or {}).items():
        _set(env, str(key), value)

    lines = [
        f"export {key}={shlex.quote(value)}" for key, value in env.items()
    ]
    return "".join(f"{line}\n" for line in lines)


def mask(text: str) -> str:
    """Replace every secret value in a rendered conf with a placeholder"""
    masked = []
    for line in text.splitlines():
        key, _, value = line[len("export "):].partition("=")
        if key in MASKED_VARS and value not in KEYWORDS:
            line = f"export {key}={MASK}"
        masked.append(line)
    return "".join(f"{line}\n" for line in masked)


def masked_secrets(doc: dict) -> dict[str, str]:
    """Placeholders standing in for the secrets a render would resolve

    Rendering for display must never read or generate a secret, so the
    caller passes these instead of the real values.
    """
    declared = doc.get("secrets") or {}
    secrets = {
        var: MASK for name, var in SECRET_VARS.items() if name in declared
    }
    if isinstance((doc.get("hub") or {}).get("api_key"), dict):
        secrets["HUB_APIKEY"] = MASK
    return secrets


def network_env(network: Any) -> dict[str, str]:
    """Map the network section onto the IP_* and IP6_* variables of 01ipconfig

    Only the file managed case exports anything: when the host owns the
    interface configuration there is nothing for 01ipconfig to write. The
    IPv4 variables come first, exactly as before IPv6 was rendered, and the
    IP6_* variables only appear when an interface declares an ipv6 block,
    so a spec without one renders the same conf it always did.

    The hook configures one interface. When the spec declares several, the
    last ipv6 block wins as a whole, so an address is never exported next
    to another interface's method.
    """
    env: dict[str, str] = {}
    if not isinstance(network, dict) or managed_by(network) != "file":
        return env

    interfaces = network.get("interfaces") or {}
    nameservers = [str(server) for server in network.get("nameservers") or []]
    for iface in interfaces.values():
        env.update(_ipv4_env((iface or {}).get("ipv4") or {}))
    env.update(_dns_env("IP_DNS", filter(is_ipv4, nameservers)))
    ipv6_env: dict[str, str] = {}
    for iface in interfaces.values():
        ipv6_env = _ipv6_env((iface or {}).get("ipv6") or {}) or ipv6_env
    if ipv6_env:
        env.update(ipv6_env)
        env.update(_dns_env("IP6_DNS", filter(is_ipv6, nameservers)))
    return env


def _ipv4_env(ipv4: dict) -> dict[str, str]:
    method = str(ipv4.get("method") or "none")
    if method == "none":
        return {}
    env = {"IP_CONFIG": method}
    if method != "static":
        return env
    address = ipaddress.ip_interface(str(ipv4["address"]))
    env["IP_ADDRESS"] = str(address.ip)
    env["IP_NETMASK"] = str(address.netmask)
    _set(env, "IP_GW", ipv4.get("gateway"))
    return env


def _ipv6_env(ipv6: dict) -> dict[str, str]:
    """IP6_ADDRESS keeps its prefix length: an inet6 stanza has no netmask"""
    method = str(ipv6.get("method") or "none")
    if method == "none":
        return {}
    env = {"IP6_CONFIG": IP6_CONFIG[method]}
    if method != "static":
        return env
    env["IP6_ADDRESS"] = str(ipaddress.ip_interface(str(ipv6["address"])))
    _set(env, "IP6_GW", ipv6.get("gateway"))
    return env


def _dns_env(prefix: str, servers: Any) -> dict[str, str]:
    """The first two nameservers of one family, as PREFIX1 and PREFIX2"""
    return {
        f"{prefix}{index}": server
        for index, server in enumerate(
            list(servers)[:MAX_NAMESERVERS], start=1
        )
    }


def _set(env: dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        value = "TRUE" if value else "FALSE"
    env[key] = str(value)


def _keyword(value: Any) -> Any:
    """SKIP, FORCE and friends are compared upper case by the hooks"""
    if isinstance(value, str) and value.lower() in ("skip", "force"):
        return value.upper()
    return value
