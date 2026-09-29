# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the monitor section (decision 0021)

Two rules that are about more than one field, because a monitor with
nobody to tell is worse than none: it looks like one.

- `enabled: true` needs a working channel under `notify`.
- `email: true` needs `security.alerts` to be an address, since that is
  where the mail goes; `skip`, or no alerts at all, leaves nowhere.

monit holds a condition for at most 64 cycles, and the cycle is the
machine's, so whether a duration fits is decided by the plan, which reads
it; validation only refuses what could fit no machine.
"""

import math
import re
from typing import Any
from urllib.parse import urlsplit

from keel.monitor.render import slug
from keel.monitor.settings import (
    CHECKS,
    DEFAULTS,
    MAX_CYCLES,
    NETWORK_KEYS,
    NOTIFY_KEYS,
)
from keel.spec.fields import email_error, mapping_error
from keel.spec.validate_secret import validate_secret

# A kernel interface name as monit's parser takes it: no colon, which
# only an address label such as eth0:1 carries, and at most 15 characters
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
CHAT_ID_RE = re.compile(r"^(-?[0-9]+|@[A-Za-z0-9_]{5,})$")
PERCENT_KEYS = ("warn", "critical")
# A cycle of an hour is already a monitor that looks once an hour; 64 of
# them is the longest duration any machine could hold.
LONGEST_CYCLE = 3600
LONGEST_MINUTES = MAX_CYCLES * LONGEST_CYCLE // 60
NO_CHANNEL = (
    "monitor.enabled: true needs a working channel in monitor.notify"
    " (email, telegram, ntfy or webhook): a monitor with nobody to tell"
    " looks like one and is not"
)


def validate_monitor(
    monitor: Any, security: Any, check_secret_files: bool = True
) -> list[str]:
    error = mapping_error("monitor", monitor)
    if error or not monitor:
        return [error] if error else []

    errors = [
        f"monitor.{key}: unknown key" for key in monitor
        if key not in ("enabled", "checks", "notify")
    ]
    enabled = monitor.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        errors.append("monitor.enabled: must be true or false")
    errors.extend(_validate_checks(monitor.get("checks")))
    notify = monitor.get("notify")
    errors.extend(
        _validate_notify(notify, alerts_address(security),
                         check_secret_files)
    )
    if enabled is True and not working_channels(notify, security):
        errors.append(NO_CHANNEL)
    return errors


def alerts_address(security: Any) -> str | None:
    """security.alerts when it is an address, which is where mail goes"""
    if not isinstance(security, dict):
        return None
    alerts = security.get("alerts")
    if alerts is None or str(alerts).lower() == "skip":
        return None
    if email_error("security.alerts", alerts):
        return None
    return str(alerts)


def working_channels(notify: Any, security: Any) -> list[str]:
    """The channels a message can reach, by name, in declaration order

    Only the shape is looked at here; each channel's own errors are
    reported on its fields.
    """
    if not isinstance(notify, dict):
        return []
    found = []
    if notify.get("email") is True and alerts_address(security):
        found.append("email")
    for name in ("telegram", "ntfy", "webhook"):
        if isinstance(notify.get(name), dict) and notify[name]:
            found.append(name)
    return found


def _validate_checks(checks: Any) -> list[str]:
    error = mapping_error("monitor.checks", checks)
    if error or not checks:
        return [error] if error else []

    errors = []
    for name in checks:
        if name not in CHECKS:
            errors.append(f"monitor.checks.{name}: unknown check")
    for name, defaults in DEFAULTS.items():
        errors.extend(_validate_check(name, checks.get(name), defaults))
    if not errors:
        disk = {**DEFAULTS["disk"], **(checks.get("disk") or {})}
        if float(disk["warn"]) >= float(disk["critical"]):
            errors.append(
                f"monitor.checks.disk: warn ({disk['warn']}) must be below"
                f" critical ({disk['critical']})"
            )
    errors.extend(_validate_network(checks.get("network")))
    return errors


def _validate_check(name: str, check: Any, defaults: dict) -> list[str]:
    key = f"monitor.checks.{name}"
    error = mapping_error(key, check)
    if error or not check:
        return [error] if error else []

    errors = [
        f"{key}.{field}: unknown key" for field in check
        if field not in defaults
    ]
    for field in PERCENT_KEYS:
        if field in check and field in defaults:
            errors.extend(_threshold_errors(f"{key}.{field}", check[field],
                                            name != "load_per_core"))
    if "for_minutes" in check and "for_minutes" in defaults:
        errors.extend(_minutes_errors(f"{key}.for_minutes",
                                      check["for_minutes"]))
    return errors


def _validate_network(network: Any) -> list[str]:
    error = mapping_error("monitor.checks.network", network)
    if error or not network:
        return [error] if error else []

    errors = []
    services: dict[str, str] = {}
    for iface, check in network.items():
        key = f"monitor.checks.network.{iface}"
        if not IFACE_RE.match(str(iface)):
            errors.append(f"{key}: not an interface name")
        name = slug(str(iface))
        if name in services:
            errors.append(f"{key}: monit's service for it would have the"
                          f" name of {services[name]}'s; watch one of them")
        services.setdefault(name, str(iface))
        error = mapping_error(key, check)
        if error:
            errors.append(error)
            continue
        check = check or {}
        errors.extend(f"{key}.{field}: unknown key" for field in check
                      if field not in NETWORK_KEYS)
        link = check.get("link")
        if link is not None and not isinstance(link, bool):
            errors.append(f"{key}.link: must be true or false")
        if "max_mbit" in check:
            errors.extend(_positive_errors(f"{key}.max_mbit",
                                           check["max_mbit"]))
        if "for_minutes" in check:
            errors.extend(_minutes_errors(f"{key}.for_minutes",
                                          check["for_minutes"]))
        if link is not True and "max_mbit" not in check:
            errors.append(f"{key}: nothing to watch; declare link: true,"
                          " max_mbit, or both")
    return errors


def _is_number(value: Any) -> bool:
    """A finite number; YAML's .inf and .nan would reach monit otherwise"""
    return isinstance(value, int | float) and not isinstance(value, bool) \
        and math.isfinite(value)


def _threshold_errors(key: str, value: Any, percent: bool) -> list[str]:
    if not percent:
        return _positive_errors(key, value)
    if not _is_number(value) or not 0 < value < 100:
        return [f"{key}: must be a percentage above 0 and below 100"]
    return []


def _positive_errors(key: str, value: Any) -> list[str]:
    if not _is_number(value) or value <= 0:
        return [f"{key}: must be a number above 0"]
    return []


def _minutes_errors(key: str, value: Any) -> list[str]:
    """A whole number of minutes that monit could hold at some cycle

    Whether it fits monit's 64 cycles depends on the cycle of the machine
    it is applied to, so the plan checks that; here it is bounded by the
    longest cycle keel accepts reading, which no machine exceeds.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return [f"{key}: must be a whole number of minutes, at least 1"]
    if value > LONGEST_MINUTES:
        return [f"{key}: at most {LONGEST_MINUTES}: monit holds a condition"
                f" for at most {MAX_CYCLES} cycles, which is"
                f" {LONGEST_MINUTES} minutes even at a cycle of"
                f" {LONGEST_CYCLE} s"]
    return []


def _validate_notify(
    notify: Any, address: str | None, check_secret_files: bool
) -> list[str]:
    error = mapping_error("monitor.notify", notify)
    if error or not notify:
        return [error] if error else []

    errors = [
        f"monitor.notify.{key}: unknown key" for key in notify
        if key not in NOTIFY_KEYS
    ]
    for key in ("email", "details"):
        value = notify.get(key)
        if value is not None and not isinstance(value, bool):
            errors.append(f"monitor.notify.{key}: must be true or false")
    if notify.get("email") is True and address is None:
        errors.append(
            "monitor.notify.email: security.alerts is skip or absent, so"
            " there is no address to mail; set security.alerts to an"
            " address, or email to false"
        )
    errors.extend(_validate_telegram(notify.get("telegram"),
                                     check_secret_files))
    errors.extend(_validate_ntfy(notify.get("ntfy"), check_secret_files))
    errors.extend(_validate_webhook(notify.get("webhook"),
                                    check_secret_files))
    return errors


def _validate_telegram(telegram: Any, check_secret_files: bool) -> list[str]:
    key = "monitor.notify.telegram"
    error = mapping_error(key, telegram)
    if error or telegram is None:
        return [error] if error else []

    errors = _unknown(key, telegram, ("chat_id", "token"))
    chat_id = telegram.get("chat_id")
    if chat_id is None or isinstance(chat_id, bool) \
            or not CHAT_ID_RE.match(str(chat_id)):
        errors.append(f"{key}.chat_id: must be a chat id such as"
                      " -1001234567890, or a channel name such as @keel_ops")
    if "token" not in telegram:
        errors.append(f"{key}.token: required, as a secret reference")
    else:
        errors.extend(_token_errors(f"{key}.token", telegram["token"],
                                    check_secret_files))
    return errors


def _token_errors(key: str, spec: Any, check_secret_files: bool) -> (
    list[str]
):
    """A token is issued by the service, so it is a file, never generated"""
    if isinstance(spec, dict) and "generate" in spec:
        return [f"{key}: a token is issued by the service, so it is a"
                " file reference; a generated value is one nobody else"
                " knows"]
    return validate_secret(key, spec, check_secret_files)


def _validate_ntfy(ntfy: Any, check_secret_files: bool) -> list[str]:
    key = "monitor.notify.ntfy"
    error = mapping_error(key, ntfy)
    if error or ntfy is None:
        return [error] if error else []

    errors = _unknown(key, ntfy, ("url", "token"))
    errors.extend(_url_errors(f"{key}.url", ntfy.get("url"),
                              check_secret_files))
    if "token" in ntfy:
        errors.extend(_token_errors(f"{key}.token", ntfy["token"],
                                    check_secret_files))
    return errors


def _validate_webhook(webhook: Any, check_secret_files: bool) -> list[str]:
    key = "monitor.notify.webhook"
    error = mapping_error(key, webhook)
    if error or webhook is None:
        return [error] if error else []
    return _unknown(key, webhook, ("url",)) + _url_errors(
        f"{key}.url", webhook.get("url"), check_secret_files)


def _unknown(key: str, mapping: dict, known: tuple[str, ...]) -> list[str]:
    return [f"{key}.{field}: unknown key" for field in mapping
            if field not in known]


def _url_errors(key: str, url: Any, check_secret_files: bool) -> list[str]:
    """A literal https URL, or a secret reference to a file holding one

    A Slack or Discord webhook URL, and a public ntfy topic, is itself
    the credential, so it may live in a secret file like a token. No
    message ever repeats the value: a validation error is printed.
    """
    if url is None:
        return [f"{key}: required, an https URL or a secret reference"]
    if isinstance(url, dict):
        return _token_errors(key, url, check_secret_files)
    problem = url_problem(url)
    return [f"{key}: {problem}"] if problem else []


def url_problem(url: Any) -> str | None:
    """Why a value is not an https URL keel posts to, never quoting it

    Plain http would carry the message, and any token in the request,
    in the clear. A user and password in the URL would put a secret in
    the spec, which holds references only. keel notify asks the same of
    a URL it reads from a secret file.
    """
    if not isinstance(url, str) or not url.strip():
        return "must be an https URL"
    if any(char.isspace() for char in url):
        return "must not contain spaces"
    try:
        parts = urlsplit(url)
        # a port that is not a number raises here, not at alert time
        host, _ = parts.hostname, parts.port
    except ValueError:
        return "not a URL"
    if parts.scheme != "https" or not host:
        return "not an https URL with a host"
    if parts.username is not None or parts.password is not None:
        return ("must not carry credentials; a token is a secret reference"
                " of its own")
    return None
