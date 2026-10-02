# Copyright (c) 2026 KeelLinux maintainers
"""The appliance identity and the app section

/etc/turnkey_version names the appliance, its version, the Debian
release and the architecture. /etc/inithooks.conf, when it still exists
and the caller can read it (root only), holds the APP_* variables the
first boot used; otherwise app.domain falls back to the instance fqdn.
"""

from dataclasses import dataclass

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

# TurnKey's prefix, and the one a Keel image writes in the same file
# (keel-core-19.0-trixie-amd64): the fields after it are the same four
VERSION_PREFIXES = ("turnkey-", "keel-")
VERSION_FIELDS = 4
APP_PREFIX = "APP_"
APP_FIXED = {"APP_EMAIL": "email", "APP_DOMAIN": "domain"}
APP_SECRET = "APP_PASS"


@dataclass(frozen=True)
class Appliance:
    name: str
    version: str
    codename: str
    arch: str

    def __str__(self) -> str:
        return f"{self.name} {self.version} ({self.codename}, {self.arch})"


def probe_appliance(
    turnkey_version: File,
) -> tuple[Appliance | None, Finding]:
    """Parse turnkey-<name>-<version>-<codename>-<arch>, or keel-<name>-..."""
    lines = turnkey_version.lines()
    if not lines:
        reason = turnkey_version.problem or "file is empty"
        return None, missing("appliance", f"{turnkey_version.path} {reason}")
    text = lines[0]
    prefix = next((one for one in VERSION_PREFIXES if text.startswith(one)),
                  None)
    fields = text.removeprefix(prefix or "").rsplit("-", VERSION_FIELDS - 1)
    if prefix is None or len(fields) != VERSION_FIELDS:
        return None, missing(
            "appliance", f"{turnkey_version.path} holds {text!r}, not a"
            " TurnKey or Keel version string",
        )
    appliance = Appliance(*fields)
    return appliance, inferred("appliance", appliance, turnkey_version.path)


def probe_app(
    conf: File, fqdn: str | None
) -> tuple[dict | None, list[Finding]]:
    """Build the app section from inithooks.conf, else from the fqdn"""
    variables = conf.assignments() if conf.readable else {}
    app: dict = {}
    findings: list[Finding] = []

    for var, key in APP_FIXED.items():
        if var in variables:
            app[key] = variables[var]
            findings.append(inferred(f"app.{key}", variables[var], conf.path))
    if "domain" not in app and fqdn:
        app["domain"] = fqdn
        findings.append(
            inferred("app.domain", fqdn, "instance.fqdn, no APP_DOMAIN found")
        )
    for key in APP_FIXED.values():
        if key not in app:
            findings.append(missing(f"app.{key}", _conf_reason(conf)))

    options = {
        var[len(APP_PREFIX):].lower(): value
        for var, value in variables.items()
        if var.startswith(APP_PREFIX)
        and var not in APP_FIXED
        and var != APP_SECRET
    }
    if options:
        app["options"] = options
        for key, value in options.items():
            findings.append(inferred(f"app.options.{key}", value, conf.path))
    return (app or None), findings


def _conf_reason(conf: File) -> str:
    if conf.readable:
        return f"{conf.path} does not set it"
    return f"{conf.path} {conf.problem}"
