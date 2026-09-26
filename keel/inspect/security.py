# Copyright (c) 2026 KeelLinux maintainers
"""The security section: alerts and automatic security updates

The secalerts hook leaves two traces: a root alias in /etc/aliases and
MAILON=output in the cron-apt config. The secupdates hook installs
updates once at first boot; on a running machine the durable evidence of
the policy is cron-apt's install action, or unattended-upgrades.
"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

SKIP = "skip"
FORCE = "force"
UNATTENDED_ON = 'Unattended-Upgrade "1"'


def probe_security(
    conf: File,
    aliases: File,
    cron_apt_config: File,
    cron_apt_install: File,
    auto_upgrades: File,
) -> tuple[dict, list[Finding]]:
    variables = conf.assignments() if conf.readable else {}
    security: dict = {}
    findings: list[Finding] = []

    alerts, source = _alerts(variables, conf, aliases, cron_apt_config)
    if alerts is None:
        findings.append(missing("security.alerts", source))
    else:
        security["alerts"] = alerts
        findings.append(inferred("security.alerts", alerts, source))

    updates, source = _updates(
        variables, conf, cron_apt_config, cron_apt_install, auto_upgrades
    )
    security["updates"] = updates
    findings.append(inferred("security.updates", updates, source))
    return security, findings


def _alerts(
    variables: dict[str, str], conf: File, aliases: File, cron_apt: File
) -> tuple[str | None, str]:
    declared = variables.get("SEC_ALERTS")
    if declared:
        return declared.lower() if declared.upper() == "SKIP" else declared, \
            conf.path

    root_alias = _root_alias(aliases)
    if root_alias and "@" in root_alias:
        return root_alias, f"{aliases.path}, root alias"

    mailon = cron_apt.assignments().get("MAILON", "").lower()
    if mailon == "never":
        return SKIP, f"{cron_apt.path} sets MAILON=never"
    if aliases.readable:
        return SKIP, f"{aliases.path} has no external root alias"
    return None, (
        f"{aliases.path} {aliases.problem}; {cron_apt.path}"
        f" {cron_apt.problem or 'does not set MAILON=never'}"
    )


def _root_alias(aliases: File) -> str | None:
    for line in aliases.lines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "root":
            return value.strip().split(",")[0].strip()
    return None


def _updates(
    variables: dict[str, str],
    conf: File,
    cron_apt_config: File,
    cron_apt_install: File,
    auto_upgrades: File,
) -> tuple[str, str]:
    declared = variables.get("SEC_UPDATES", "").lower()
    if declared in (SKIP, FORCE):
        return declared, conf.path
    if any("upgrade" in line for line in cron_apt_install.lines()):
        return FORCE, f"{cron_apt_install.path} installs security updates"
    if any(UNATTENDED_ON in line for line in auto_upgrades.lines()):
        return FORCE, f"{auto_upgrades.path} enables unattended upgrades"
    if cron_apt_config.readable:
        return SKIP, f"{cron_apt_config.path} present but no install action"
    return SKIP, (
        f"neither {cron_apt_config.path} nor {auto_upgrades.path} is"
        " present"
    )
