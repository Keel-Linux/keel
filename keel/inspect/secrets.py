# Copyright (c) 2026 KeelLinux maintainers
"""The secrets and hub sections: placeholders only

inspect never reads a password, a hash or an API key, not even from an
inithooks.conf it can open. Every secret the appliance needs is declared
as a file reference under the secrets directory, and the report tells
the operator which files to create before apply.
"""

import os

from keel.inspect.report import Finding, inferred, missing, placeholder
from keel.inspect.tree import NOT_PRESENT, File

ROOT_PASSWORD = "root_password"
DB_PASSWORD = "db_password"
APP_PASSWORD = "app_password"
CONF_SECRETS = {"DB_PASS": DB_PASSWORD, "APP_PASS": APP_PASSWORD}
REASON = "values are never read; create the file (mode 0600) before apply"
HUB_REASON = (
    "API keys are never read, and the Hub is being decoupled (brief"
    " section 5.6)"
)


def probe_secrets(
    conf: File, secrets_dir: str, database_present: bool
) -> tuple[dict, list[Finding]]:
    """Declare root_password always, the others when the machine uses them"""
    names = [ROOT_PASSWORD]
    variables = conf.assignments() if conf.readable else {}
    for var, name in CONF_SECRETS.items():
        if var in variables:
            names.append(name)
    if database_present and DB_PASSWORD not in names:
        names.append(DB_PASSWORD)

    secrets: dict = {}
    findings: list[Finding] = []
    for name in names:
        path = os.path.join(secrets_dir, name)
        secrets[name] = {"file": path}
        findings.append(
            placeholder(f"secrets.{name}", f"file: {path}", REASON)
        )
    return secrets, findings


def probe_hub(registration: File) -> tuple[dict | None, list[Finding]]:
    """skip only when the machine is not registered with the Hub

    The key itself is never read, so a machine that is registered cannot
    tell a key from skip; it used to answer skip anyway, and diff called
    it the same as one that never registered. tklbam keeps the Hub
    registration in its registry; only whether that file is there is
    asked, never what it holds.
    """
    if registration.readable:
        return None, [missing(
            "hub.api_key",
            f"registered with the TurnKey Hub ({registration.path} is"
            f" present); {HUB_REASON}",
        )]
    if registration.problem != NOT_PRESENT:
        return None, [missing(
            "hub.api_key", f"{registration.path} {registration.problem}")]
    return {"api_key": "skip"}, [inferred(
        "hub.api_key", "skip",
        f"no Hub registration ({registration.path} not present)",
    )]
