# Copyright (c) 2026 KeelLinux maintainers
"""Validation of a loaded spec document

validate() returns every error it finds instead of raising on the first
one, so that an operator fixes the whole file in one pass.
"""

from typing import Any

from keel.spec.constants import (
    SCHEMA_VERSION,
    SECRET_BACKENDS,
    SECRET_VARS,
    TOP_LEVEL_KEYS,
    WIZARD_ONLY_GENERATE,
)
from keel.spec.fields import (
    NAME_RE,
    domain_error,
    email_error,
    mapping_error,
)
from keel.spec.secretstore import secret_file_error
from keel.spec.validate_network import validate_network


def validate(doc: dict) -> list[str]:
    """Return a list of error messages, empty when the document is valid"""
    errors: list[str] = []

    if doc.get("version") != SCHEMA_VERSION:
        errors.append(f"version: must be {SCHEMA_VERSION}")
    for key in doc:
        if key not in TOP_LEVEL_KEYS:
            errors.append(f"{key}: unknown top level key")

    errors.extend(_validate_instance(doc.get("instance")))
    errors.extend(_validate_secrets(doc))
    errors.extend(_validate_app(doc.get("app")))
    errors.extend(_validate_hub(doc.get("hub")))
    errors.extend(_validate_security(doc.get("security")))
    errors.extend(_validate_wizard(doc.get("first_login_wizard")))
    errors.extend(validate_network(doc.get("network")))
    errors.extend(_validate_tls(doc.get("tls")))
    errors.extend(_validate_preseed(doc.get("preseed")))
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


def _validate_secrets(doc: dict) -> list[str]:
    declared = doc.get("secrets")
    error = mapping_error("secrets", declared)
    if error or not declared:
        return [error] if error else []

    wizard = bool(doc.get("first_login_wizard"))
    errors = []
    for name, spec in declared.items():
        key = f"secrets.{name}"
        if name not in SECRET_VARS:
            errors.append(f"{key}: unknown secret")
            continue
        errors.extend(validate_secret(key, spec))
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


def validate_secret(key: str, spec: Any) -> list[str]:
    """Check one secret reference: exactly one backend, and it works"""
    if not isinstance(spec, dict):
        return [f"{key}: must be a mapping"]

    backends = [name for name in SECRET_BACKENDS if name in spec]
    unknown = [name for name in spec if name not in SECRET_BACKENDS]
    errors = [f"{key}.{name}: unknown secret backend" for name in unknown]
    if len(backends) != 1:
        errors.append(
            f"{key}: exactly one of {', '.join(SECRET_BACKENDS)} is required"
        )
        return errors
    if "file" in spec:
        error = secret_file_error(str(spec["file"]))
        if error:
            errors.append(f"{key}: {error}")
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


def _validate_hub(hub: Any) -> list[str]:
    error = mapping_error("hub", hub)
    if error or not hub:
        return [error] if error else []

    errors = []
    for key in hub:
        if key != "api_key":
            errors.append(f"hub.{key}: unknown key")
    api_key = hub.get("api_key")
    if isinstance(api_key, dict):
        errors.extend(validate_secret("hub.api_key", api_key))
    elif api_key is not None and str(api_key).lower() != "skip":
        errors.append("hub.api_key: must be 'skip' or a secret mapping")
    return errors


def _validate_security(security: Any) -> list[str]:
    error = mapping_error("security", security)
    if error or not security:
        return [error] if error else []

    errors = []
    for key in security:
        if key not in ("alerts", "updates"):
            errors.append(f"security.{key}: unknown key")

    alerts = security.get("alerts")
    if alerts is not None and str(alerts).lower() != "skip":
        if email_error("security.alerts", alerts):
            errors.append(
                "security.alerts: must be 'skip' or an email address"
            )

    updates = security.get("updates")
    if updates is not None and str(updates).lower() not in ("skip", "force"):
        errors.append("security.updates: must be 'skip' or 'force'")
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
        if key not in ("enabled", "challenge", "domains"):
            errors.append(f"tls.acme.{key}: unknown key")
    if acme.get("challenge") not in (None, "http-01", "dns-01"):
        errors.append("tls.acme.challenge: must be http-01 or dns-01")
    for domain in acme.get("domains") or []:
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
