# Copyright (c) 2026 KeelLinux maintainers
"""The tls section, from the dehydrated files confconsole writes

confconsole's Let's Encrypt plugin keeps its domains in
/etc/dehydrated/confconsole.domains.txt and the challenge type in
/etc/dehydrated/confconsole.config. A plain dehydrated install uses
domains.txt; both are read, the confconsole one first.
"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

CHALLENGES = ("http-01", "dns-01")
DEFAULT_CHALLENGE = "http-01"


def probe_tls(
    config: File, domain_files: list[File], dehydrated_present: bool
) -> tuple[dict, list[Finding]]:
    """Build the tls section; ACME is reported as configured or not"""
    if not dehydrated_present:
        return _disabled("/etc/dehydrated is not present, ACME not"
                         " configured")

    domains, source = _domains(domain_files)
    if not domains:
        return _disabled(f"no domains in {source}")

    challenge, challenge_source = _challenge(config)
    findings = [
        inferred("tls.acme.enabled", "true", source),
        inferred("tls.acme.domains", ", ".join(domains), source),
    ]
    acme: dict = {"enabled": True}
    if challenge is None:
        findings.append(missing("tls.acme.challenge", challenge_source))
    else:
        acme["challenge"] = challenge
        findings.append(
            inferred("tls.acme.challenge", challenge, challenge_source)
        )
    acme["domains"] = domains
    return {"acme": acme}, findings


def _disabled(reason: str) -> tuple[dict, list[Finding]]:
    return (
        {"acme": {"enabled": False}},
        [inferred("tls.acme.enabled", "false", reason)],
    )


def _domains(files: list[File]) -> tuple[list[str], str]:
    """Every name on every non comment line of the first file that has any"""
    for file in files:
        names = [name for line in file.lines() for name in line.split()]
        if names:
            return list(dict.fromkeys(names)), file.path
    return [], " or ".join(file.path for file in files)


def _challenge(config: File) -> tuple[str | None, str]:
    value = config.assignments().get("CHALLENGETYPE")
    if value is None:
        state = config.problem or "sets no CHALLENGETYPE"
        return DEFAULT_CHALLENGE, f"{config.path} {state}, dehydrated" \
            " defaults to http-01"
    if value not in CHALLENGES:
        return None, f"{config.path} sets CHALLENGETYPE={value!r}, which" \
            " the spec does not know"
    return value, config.path
