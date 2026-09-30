# Copyright (c) 2026 KeelLinux maintainers
"""The spec's firewall section (decision 0041)

The firewall is derived from the manifests: every `public` port of a
process whose overlay is enabled is opened on every interface, every
`mesh` port on the WireGuard interface only. The maintainer scoped it on
2026-09-30: optional, and for cloud advanced installations only. So it
is off unless the spec says `enabled: true`, and `enabled: true` is
refused in the simple and cloud simple modes, where keel installs and
changes no firewall rule at all.
"""

from typing import Any

from keel.spec.fields import mapping_error

KEY = "firewall"
KEYS = ("enabled",)
MODE = "cloud_advanced"


def validate_firewall(doc: dict) -> list[str]:
    firewall = doc.get(KEY)
    error = mapping_error(KEY, firewall)
    if error or not firewall:
        return [error] if error else []
    errors = [f"{KEY}.{name}: unknown key" for name in firewall
              if name not in KEYS]
    enabled = firewall.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        return errors + [f"{KEY}.enabled: must be true or false"]
    if enabled:
        errors += _where_it_may_run(doc)
    return errors


def _where_it_may_run(doc: dict) -> list[str]:
    installation = doc.get("installation")
    mode: Any = (installation.get("mode") if isinstance(installation, dict)
                 else None)
    errors = []
    if mode != MODE:
        said = mode if mode is not None else "not declared"
        errors.append(
            f"{KEY}.enabled: the firewall derived from the manifests is for"
            f" cloud advanced installations only, and installation.mode is"
            f" {said}; in the other modes keel leaves the firewall alone")
    if not isinstance(doc.get("appliance"), dict):
        errors.append(f"{KEY}.enabled: needs appliance.name: the ports"
                      " come from its manifests")
    return errors
