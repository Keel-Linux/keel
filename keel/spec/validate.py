# Copyright (c) 2026 KeelLinux maintainers
"""Validation of a loaded spec document

validate() returns every error it finds instead of raising on the first
one, so that an operator fixes the whole file in one pass.

Secret references are checked in two layers: their structure (exactly one
known backend, a path that is a string) always, and the file behind a
`file:` reference (present, root owned, mode 0600 or stricter) only when
`check_secret_files` is true. apply and render keep the default and need
the files; diff and a structure only `spec validate` do not, because a
secret is a reference and the machine being checked may not hold the
value.
"""

from typing import Any

from keel.spec.compat import canonical
from keel.spec.constants import (
    SCHEMA_VERSION,
    TOP_LEVEL_KEYS,
    WIZARD_ONLY_GENERATE,
)
from keel.spec.fields import (
    NAME_RE,
    domain_error,
    email_error,
    list_error,
    mapping_error,
)
from keel.spec.validate_appliance import (
    ManifestFacts,
    against_manifests,
    allowed_secret,
    unknown_secret,
    validate_appliance,
)
from keel.spec.validate_database import validate_database
from keel.spec.validate_firewall import validate_firewall
from keel.spec.validate_extras import validate_locale, validate_users
from keel.spec.validate_monitor import validate_monitor
from keel.spec.validate_network import validate_network
from keel.spec.validate_secret import validate_secret


def validate(doc: dict, *, check_secret_files: bool = True,
             facts: ManifestFacts | None = None) -> list[str]:
    """Return a list of error messages, empty when the document is valid

    With `check_secret_files` false, a `file:` secret reference is still
    checked for structure, but the file itself is not looked at.

    `facts` are what the manifests of the spec's appliance declare
    (keel.manifest.facts), which a caller that knows the root gathers:
    with them the spec is also held against the manifests, rules 25 to
    27 of the format, and a secret a manifest declares is a known name.
    Without them only the structure of the three sections is checked.

    The document is canonicalised first (keel.spec.compat), so a spec
    that still uses a deprecated field name is validated under the name
    it means, not rejected as unknown. The warning about the old name is
    printed by the caller, which is keel.commands.read_spec.
    """
    doc = canonical(doc)
    errors: list[str] = []

    if doc.get("version") != SCHEMA_VERSION:
        errors.append(f"version: must be {SCHEMA_VERSION}")
    for key in doc:
        if key not in TOP_LEVEL_KEYS:
            errors.append(f"{key}: unknown top level key")

    errors.extend(_validate_instance(doc.get("instance")))
    errors.extend(_validate_secrets(doc, check_secret_files, facts))
    errors.extend(_validate_app(doc.get("app")))
    errors.extend(_validate_hub(doc.get("hub"), check_secret_files))
    errors.extend(_validate_security(doc.get("security")))
    errors.extend(_validate_wizard(doc.get("first_login_wizard")))
    errors.extend(validate_network(doc.get("network"), check_secret_files))
    errors.extend(_validate_tls(doc.get("tls")))
    errors.extend(_validate_preseed(doc.get("preseed")))
    errors.extend(validate_users(doc.get("users")))
    errors.extend(validate_locale(doc.get("locale")))
    errors.extend(
        validate_database(doc.get("database"), check_secret_files,
                          paired=bool(isinstance(doc.get("appliance"), dict)
                                      and doc["appliance"].get("vip")))
    )
    errors.extend(validate_monitor(
        doc.get("monitor"), doc.get("security"), check_secret_files
    ))
    errors.extend(validate_appliance(doc))
    errors.extend(against_manifests(doc, facts))
    errors.extend(validate_firewall(doc))
    return errors


def _validate_instance(instance: Any) -> list[str]:
    error = mapping_error("instance", instance)
    if error or not instance:
        return [error] if error else []

    errors = []
    for key in instance:
        if key not in ("hostname", "fqdn"):
            errors.append(f"instance.{key}: unknown key")
    for key in ("hostname", "fqdn"):
        if key in instance:
            error = domain_error(f"instance.{key}", instance[key])
            if error:
                errors.append(error)
    return errors


def _validate_secrets(doc: dict, check_secret_files: bool,
                      facts: ManifestFacts | None) -> list[str]:
    declared = doc.get("secrets")
    error = mapping_error("secrets", declared)
    if error or not declared:
        return [error] if error else []

    wizard = bool(doc.get("first_login_wizard"))
    errors = []
    for name, spec in declared.items():
        key = f"secrets.{name}"
        if not allowed_secret(name, facts):
            errors.append(unknown_secret(key, facts))
            continue
        errors.extend(validate_secret(key, spec, check_secret_files))
        if not isinstance(spec, dict):
            continue
        if (
            spec.get("generate")
            and name in WIZARD_ONLY_GENERATE
            and not wizard
        ):
            errors.append(
                f"{key}: generate needs first_login_wizard, otherwise"
                " nobody can log in with the generated value"
            )
    return errors


def _validate_app(app: Any) -> list[str]:
    error = mapping_error("app", app)
    if error or not app:
        return [error] if error else []

    errors = []
    for key in app:
        if key not in ("email", "domain", "options"):
            errors.append(f"app.{key}: unknown key")
    if "email" in app:
        error = email_error("app.email", app["email"])
        if error:
            errors.append(error)
    if "domain" in app:
        error = domain_error("app.domain", app["domain"])
        if error:
            errors.append(error)

    options = app.get("options")
    error = mapping_error("app.options", options)
    if error:
        return errors + [error]
    for key in options or {}:
        if not NAME_RE.match(str(key)):
            errors.append(f"app.options.{key}: not a valid variable name")
    return errors


def _validate_hub(hub: Any, check_secret_files: bool) -> list[str]:
    error = mapping_error("hub", hub)
    if error or not hub:
        return [error] if error else []

    errors = []
    for key in hub:
        if key != "api_key":
            errors.append(f"hub.{key}: unknown key")
    api_key = hub.get("api_key")
    if isinstance(api_key, dict):
        errors.extend(
            validate_secret("hub.api_key", api_key, check_secret_files)
        )
    elif api_key is not None and str(api_key).lower() != "skip":
        errors.append("hub.api_key: must be 'skip' or a secret mapping")
    return errors


def _validate_security(security: Any) -> list[str]:
    error = mapping_error("security", security)
    if error or not security:
        return [error] if error else []

    errors = []
    for key in security:
        if key not in ("alerts", "updates_at_first_boot"):
            errors.append(f"security.{key}: unknown key")

    alerts = security.get("alerts")
    if alerts is not None and str(alerts).lower() != "skip":
        if email_error("security.alerts", alerts):
            errors.append(
                "security.alerts: must be 'skip' or an email address"
            )

    updates = security.get("updates_at_first_boot")
    if updates is not None and str(updates).lower() not in ("skip", "force"):
        errors.append(
            "security.updates_at_first_boot: must be 'skip' or 'force'"
        )
    return errors


def _validate_wizard(wizard: Any) -> list[str]:
    if wizard is not None and not isinstance(wizard, bool):
        return ["first_login_wizard: must be true or false"]
    return []


def _validate_tls(tls: Any) -> list[str]:
    error = mapping_error("tls", tls)
    if error or not tls:
        return [error] if error else []

    errors = []
    for key in tls:
        if key != "acme":
            errors.append(f"tls.{key}: unknown key")

    acme = tls.get("acme")
    error = mapping_error("tls.acme", acme)
    if error or not acme:
        return errors + ([error] if error else [])

    for key in acme:
        if key not in ("enabled", "challenge", "domains", "agree_tos"):
            errors.append(f"tls.acme.{key}: unknown key")
    for key in ("enabled", "agree_tos"):
        value = acme.get(key)
        if value is not None and not isinstance(value, bool):
            errors.append(f"tls.acme.{key}: must be true or false")
    if acme.get("challenge") not in (None, "http-01", "dns-01"):
        errors.append("tls.acme.challenge: must be http-01 or dns-01")
    domains = acme.get("domains")
    error = list_error("tls.acme.domains", domains)
    if error:
        return errors + [error]
    for domain in domains or []:
        error = domain_error("tls.acme.domains", domain)
        if error:
            errors.append(error)
    return errors


def _validate_preseed(preseed: Any) -> list[str]:
    error = mapping_error("preseed", preseed)
    if error or not preseed:
        return [error] if error else []
    return [
        f"preseed.{key}: not a valid variable name"
        for key in preseed
        if not NAME_RE.match(str(key))
    ]
