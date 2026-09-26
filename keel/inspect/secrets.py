# Copyright (c) 2026 KeelLinux maintainers
"""The secrets and hub sections: placeholders only

inspect never reads a password, a hash or an API key, not even from an
inithooks.conf it can open. Every secret the appliance needs is declared
as a file reference under the secrets directory, and the report tells
the operator which files to create before apply.
"""

import os

from keel.inspect.report import Finding, inferred, placeholder
from keel.inspect.tree import File

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


def probe_hub() -> tuple[dict, list[Finding]]:
    return {"api_key": "skip"}, [inferred("hub.api_key", "skip", HUB_REASON)]
