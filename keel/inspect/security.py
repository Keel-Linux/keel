# Copyright (c) 2026 KeelLinux maintainers
"""The security section: alerts and the first boot security updates

The secalerts hook leaves two traces: a root alias in /etc/aliases and
MAILON=output in the cron-apt config.

updates_at_first_boot is different in kind. The 95secupdates hook reads
SEC_UPDATES once, or asks, and installs the pending security updates or
does not; the cron-apt install action and unattended-upgrades that a
running appliance carries are shipped with the image, not written by
that hook. So the value is read from inithooks.conf while it is still
there, then from the line the hook leaves of its answer
(/var/lib/inithooks/sec-updates, inithooks 2.3.6+keel16), and only on a
machine with neither inferred from the update posture, which is a proxy
and says so in the report: that proxy said force after an operator chose
Skip. `keel diff` does not compare the field (docs/diff.md).
"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

SKIP = "skip"
FORCE = "force"
UPDATES_FIELD = "updates_at_first_boot"
UNATTENDED_ON = 'Unattended-Upgrade "1"'
NO_TRACE = (
    "the first boot value itself leaves no trace, so this is the appliance's"
    " update posture"
)


def probe_security(
    conf: File,
    aliases: File,
    cron_apt_config: File,
    cron_apt_install: File,
    auto_upgrades: File,
    record: File,
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
        variables, conf, cron_apt_config, cron_apt_install, auto_upgrades,
        record,
    )
    security[UPDATES_FIELD] = updates
    findings.append(
        inferred(f"security.{UPDATES_FIELD}", updates, source)
    )
    return security, findings


def _alerts(
    variables: dict[str, str], conf: File, aliases: File, cron_apt: File
) -> tuple[str | None, str]:
    """The machine's own trace first, the first boot input only without one

    SEC_ALERTS in inithooks.conf is what the first boot was told; the
    root alias is what the machine does. A conf that 98finalize did not
    blank can be stale, and apply --system converges the alias (keel#35),
    so preferring the conf would report drift that apply cannot correct.
    """
    if aliases.readable:
        alias = root_alias(aliases)
        if alias and "@" in alias:
            return alias, f"{aliases.path}, root alias"
        if cron_apt.assignments().get("MAILON", "").lower() == "never":
            return SKIP, f"{cron_apt.path} sets MAILON=never"
        return SKIP, f"{aliases.path} has no external root alias"

    declared = variables.get("SEC_ALERTS")
    if declared:
        return declared.lower() if declared.upper() == "SKIP" else declared, \
            conf.path

    mailon = cron_apt.assignments().get("MAILON", "").lower()
    if mailon == "never":
        return SKIP, f"{cron_apt.path} sets MAILON=never"
    return None, (
        f"{aliases.path} {aliases.problem}; {cron_apt.path}"
        f" {cron_apt.problem or 'does not set MAILON=never'}"
    )


def root_alias(aliases: File) -> str | None:
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
    record: File,
) -> tuple[str, str]:
    declared = variables.get("SEC_UPDATES", "").lower()
    if declared in (SKIP, FORCE):
        return declared, conf.path
    chosen = (record.lines() or [""])[0].lower()
    if chosen in (SKIP, FORCE):
        return chosen, f"{record.path}, what the first boot chose"
    if any("upgrade" in line for line in cron_apt_install.lines()):
        return FORCE, (
            f"{cron_apt_install.path} installs security updates; {NO_TRACE}"
        )
    if any(UNATTENDED_ON in line for line in auto_upgrades.lines()):
        return FORCE, (
            f"{auto_upgrades.path} enables unattended upgrades; {NO_TRACE}"
        )
    if cron_apt_config.readable:
        return SKIP, (
            f"{cron_apt_config.path} present but no install action;"
            f" {NO_TRACE}"
        )
    return SKIP, (
        f"neither {cron_apt_config.path} nor {auto_upgrades.path} is"
        f" present; {NO_TRACE}"
    )
