# Copyright (c) 2026 KeelLinux maintainers
"""The locale section: timezone and language"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

ZONEINFO = "zoneinfo/"


def probe_locale(
    timezone: File, localtime_target: str | None, default_locale: File
) -> tuple[dict | None, list[Finding]]:
    """/etc/timezone, else the /etc/localtime symlink; LANG from the default"""
    locale: dict = {}
    findings: list[Finding] = []

    zone, source = current_timezone(timezone, localtime_target)
    if zone is None:
        findings.append(missing("locale.timezone", source))
    else:
        locale["timezone"] = zone
        findings.append(inferred("locale.timezone", zone, source))

    lang = default_locale.assignments().get("LANG")
    if lang:
        locale["lang"] = lang
        findings.append(inferred("locale.lang", lang, default_locale.path))
    else:
        reason = default_locale.problem or "does not set LANG"
        findings.append(
            missing("locale.lang", f"{default_locale.path} {reason}")
        )
    return (locale or None), findings


def current_timezone(
    timezone: File, localtime_target: str | None
) -> tuple[str | None, str]:
    """The zone and where it was read from, or None and why not"""
    lines = timezone.lines()
    if lines:
        return lines[0], timezone.path
    if localtime_target and ZONEINFO in localtime_target:
        zone = localtime_target.split(ZONEINFO, 1)[1]
        return zone, "the /etc/localtime symlink"
    reason = timezone.problem or "file is empty"
    return None, f"{timezone.path} {reason}; /etc/localtime is not a" \
        " zoneinfo symlink"
