# Copyright (c) 2026 KeelLinux maintainers
"""/etc/keel/monitor.json: all keel notify reads, written at apply

keel notify runs as root whenever monit alerts, so what it reads decides
where root sends things. It does not read the spec: a spec can move, be
deleted, sit in a temporary path, fail validation for a field that has
nothing to do with alerts, or belong to a user who could later point a
token file at /etc/keel/secrets/root_password and the URL at a server of
their own. Apply resolves the channels from the spec once, as root, into
this file, mode 0600, and notify refuses it unless root owns it and
nobody else can write it, the rule every secret file follows.

The file holds the channels (a literal URL, or the path of the secret
file holding it; a chat id), the paths of the token files and never a
token, the alerts address, the details switch and the host's name and
address for the message.
"""

import json

from keel.spec.errors import SpecError
from keel.spec.secretstore import secret_file_error
from keel.spec.validate_monitor import alerts_address, working_channels

PATH = "/etc/keel/monitor.json"
WRITTEN_BY = "keel spec apply --system, from the monitor section (0021)"
# the most of the file notify reads; it is a few hundred bytes
MAX_BYTES = 65536


def address_of(doc: dict) -> str:
    """The first static address the spec declares, IPv6 first"""
    interfaces = (doc.get("network") or {}).get("interfaces") or {}
    for family in ("ipv6", "ipv4"):
        for iface in interfaces.values():
            declared = (iface or {}).get(family) or {}
            if declared.get("method") == "static" and declared.get("address"):
                return str(declared["address"]).split("/")[0]
    return ""


def reference(value, name: str) -> dict:
    """A literal value, or the path of the secret file that holds it"""
    if isinstance(value, dict):
        return {f"{name}_file": str(value["file"])}
    return {name: str(value)}


def build(doc: dict) -> dict:
    """The file's content, from a spec that has passed validation"""
    notify = (doc.get("monitor") or {}).get("notify") or {}
    channels = working_channels(notify, doc.get("security"))
    found: dict = {
        "written_by": WRITTEN_BY,
        "host": str((doc.get("instance") or {}).get("hostname") or ""),
        "address": address_of(doc),
        "details": notify.get("details") is True,
    }
    if "email" in channels:
        found["email"] = alerts_address(doc.get("security"))
    if "telegram" in channels:
        telegram = notify["telegram"]
        found["telegram"] = {"chat_id": str(telegram["chat_id"]),
                             "token_file": str(telegram["token"]["file"])}
    if "ntfy" in channels:
        ntfy = notify["ntfy"]
        found["ntfy"] = reference(ntfy["url"], "url")
        if ntfy.get("token"):
            found["ntfy"]["token_file"] = str(ntfy["token"]["file"])
    if "webhook" in channels:
        found["webhook"] = reference(notify["webhook"]["url"], "url")
    return found


def render(doc: dict) -> str:
    return json.dumps(build(doc), indent=2, sort_keys=True) + "\n"


def secret_paths(settings: dict) -> list[str]:
    """Every secret file the channels name, in channel order"""
    return [
        str(channel[key])
        for name in ("telegram", "ntfy", "webhook")
        for channel in [settings.get(name) or {}]
        for key in ("url_file", "token_file") if channel.get(key)
    ]


def written_by_keel(text: str | None) -> bool:
    try:
        found = json.loads(text or "")
    except ValueError:
        return False
    return isinstance(found, dict) and found.get("written_by") == WRITTEN_BY


def load(path: str = PATH) -> dict:
    """The settings, from a file root owns and nobody else can write

    Raises SpecError, whose text names the file and never its content.
    """
    problem = secret_file_error(path)
    if problem:
        raise SpecError(problem)
    try:
        with open(path, "rb") as fob:
            found = json.loads(fob.read(MAX_BYTES))
    except (OSError, ValueError):
        raise SpecError(f"{path}: not readable as keel's monitor settings")
    if not isinstance(found, dict) or found.get("written_by") != WRITTEN_BY:
        raise SpecError(f"{path}: not keel's monitor settings")
    return found
