# Copyright (c) 2026 KeelLinux maintainers
"""The tls section, from the dehydrated files and the certificate in use

confconsole's Let's Encrypt plugin keeps its domains in
/etc/dehydrated/confconsole.domains.txt and the challenge type in
/etc/dehydrated/confconsole.config. A plain dehydrated install uses
domains.txt; both are read, the confconsole one first.

Those files say what was asked for. Whether ACME is on is a property of
what the machine serves: `enabled` is true only when the certificate in
/etc/ssl/private/cert.pem is not self-signed, has not expired and covers
every configured domain (keel#35). A domains file with a self-signed
certificate is a configuration that was never, or is no longer, carried
out, and reporting it as enabled made diff say same on a machine that
had no certificate. The domains and the challenge are still reported, so
the spec inspect writes keeps them, prepared, with enabled false.
"""

from datetime import datetime

from keel.inspect.certificate import covers, read_certificate
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import NOT_PRESENT, File

CHALLENGES = ("http-01", "dns-01")
DEFAULT_CHALLENGE = "http-01"


def probe_tls(
    config: File, domain_files: list[File], dehydrated_present: bool,
    cert: File, now: datetime,
) -> tuple[dict, list[Finding]]:
    """Build the tls section; ACME is on only when the certificate says so"""
    if not dehydrated_present:
        return _disabled("/etc/dehydrated is not present, ACME not"
                         " configured")

    domains, source = _domains(domain_files)
    if not domains:
        return _disabled(f"no domains in {source}")

    acme: dict = {}
    findings: list[Finding] = []
    enabled, why = _enabled(domains, cert, now)
    if enabled is None:
        findings.append(missing("tls.acme.enabled", why))
    else:
        acme["enabled"] = enabled
        findings.append(inferred("tls.acme.enabled", str(enabled).lower(),
                                 why))
    challenge, challenge_source = _challenge(config)
    findings.append(inferred("tls.acme.domains", ", ".join(domains), source))
    if challenge is None:
        findings.append(missing("tls.acme.challenge", challenge_source))
    else:
        acme["challenge"] = challenge
        findings.append(
            inferred("tls.acme.challenge", challenge, challenge_source)
        )
    acme["domains"] = domains
    return {"acme": acme}, findings


def _enabled(
    domains: list[str], cert: File, now: datetime
) -> tuple[bool | None, str]:
    """Whether the certificate in use carries out the configured domains"""
    asked = f"domains configured ({', '.join(domains)})"
    if not cert.readable:
        if cert.problem == NOT_PRESENT:
            return False, f"{asked} but {cert.path} {cert.problem}"
        return None, f"{cert.path} {cert.problem}"
    found, problem = read_certificate(cert.text or "")
    if found is None:
        return None, f"{cert.path}: {problem}"
    if found.self_signed:
        return False, (f"{asked} but {cert.path} is self-signed"
                       f" ({found.subject})")
    if found.not_after <= now:
        return False, (f"{asked} but {cert.path} expired on"
                       f" {found.not_after.date().isoformat()}")
    uncovered = [d for d in domains if not covers(found, d)]
    if uncovered:
        return False, (f"{asked} but {cert.path} does not cover"
                       f" {', '.join(uncovered)}")
    return True, (f"{cert.path}, issued by {found.issuer}, covers every"
                  f" configured domain until"
                  f" {found.not_after.date().isoformat()}")


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
