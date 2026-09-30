# Copyright (c) 2026 KeelLinux maintainers
"""`keel manifest show NAME --resolved`: the resolved chain as tables

The first two tables are the format's own (docs/manifest-v1.md, "Worked
example: Keel Web", "Resolved"), row for row: the overlays with their
state in each mode, and the ports grouped by process and exposure. The
others say what the chain runs and needs: processes with their restart
limit, checks, secrets with their policy, options, first boot hooks and
the application sections. States are printed as the words they are,
never as YAML booleans.
"""

import yaml

from keel.manifest.constants import (
    DEFAULT_EVERY,
    DEFAULT_RESTART,
    MODE_TITLES,
    MODES,
    NEVER,
)
from keel.manifest.resolve import Owned, Resolved

NONE = "none"
FAMILY = {"127.0.0.1": "IPv4", "::1": "IPv6"}


def render(resolved: Resolved) -> str:
    """Every table of the resolved appliance, as show prints them"""
    head = (f"{resolved.title} ({resolved.name}), resolved along"
            f" {', '.join(resolved.chain)}")
    sections = [
        ("Overlays", _overlays(resolved)),
        ("Ports", _ports(resolved)),
        ("Processes", _processes(resolved)),
        ("Checks", _checks(resolved)),
        ("Secrets", _secrets(resolved)),
        ("Options", _options(resolved)),
        ("First boot hooks", _hooks(resolved)),
    ]
    parts = [head] + [f"{title}\n{body}" for title, body in sections]
    parts.append(_application(resolved.application))
    return "\n\n".join(parts) + "\n"


def table(header: tuple[str, ...], rows: list[tuple]) -> str:
    """A Markdown table, as the format writes them; `none` when empty"""
    if not rows:
        return NONE
    lines = [_row(header), _row(tuple("---" for _ in header))]
    lines.extend(_row(row) for row in rows)
    return "\n".join(lines)


def _row(cells: tuple) -> str:
    return "| " + " | ".join(str(cell).replace("|", "\\|")
                             for cell in cells) + " |"


def _overlays(resolved: Resolved) -> str:
    header = ("Overlay", "From") + tuple(MODE_TITLES[mode] for mode in MODES)
    return table(header, [
        (state.name, state.appliance) + tuple(state.states[mode]
                                              for mode in MODES)
        for state in resolved.overlays
    ])


def _ports(resolved: Resolved) -> str:
    """One row per process and exposure, in the order of the lowest port"""
    groups: dict = {}
    for owned in resolved.processes:
        for listen in owned.item.get("listen") or []:
            address = listen.get("address")
            key = (owned.item["name"], owned.origin, listen["expose"],
                   address)
            groups.setdefault(key, []).append(
                (listen["port"], listen["protocol"]))
    rows = []
    for (name, origin, expose, address), ports in groups.items():
        ports.sort()
        exposure = f"{expose}, {FAMILY[address]}" if address else expose
        rows.append((ports[0], name, (
            ", ".join(f"{port}/{protocol}" for port, protocol in ports),
            name, origin, exposure)))
    rows.sort(key=lambda row: (row[0], row[1]))
    return table(("Port", "Process", "From", "Exposure"),
                 [row[2] for row in rows])


def _restart(item: dict) -> str:
    restart = item.get("restart", DEFAULT_RESTART)
    if restart == NEVER:
        return NEVER
    return (f"{restart['attempts']} restarts within"
            f" {restart['within_cycles']} cycles")


def _processes(resolved: Resolved) -> str:
    return table(("Process", "Unit", "From", "Restart"), [
        (owned.item["name"], owned.item["unit"], owned.origin,
         _restart(owned.item))
        for owned in resolved.processes
    ])


def probe(check: dict) -> str:
    """What a check asks, in one phrase"""
    kind = check["type"]
    if kind == "command":
        return "command " + " ".join(check["command"])
    where = f"{check['address']} port {check['port']}"
    if kind == "http":
        scheme = "https" if check.get("tls") else "http"
        return f"{scheme} {where} {check['path']}, expects {check['expect']}"
    if kind == "protocol":
        return f"{check['protocol']} {where}"
    return f"tcp {where}"


def _every(check: dict) -> str:
    every = check.get("every_cycles", DEFAULT_EVERY)
    return "1 cycle" if every == 1 else f"{every} cycles"


def _checks(resolved: Resolved) -> str:
    return table(
        ("Check", "Process", "From", "Probe", "On failure", "Every"), [
            (owned.item["name"], owned.item.get("process", NONE),
             owned.origin, probe(owned.item), owned.item["on_failure"],
             _every(owned.item))
            for owned in resolved.checks
        ])


def _secrets(resolved: Resolved) -> str:
    return table(("Secret", "From", "Generate", "Shared", "Description"), [
        (owned.item["name"], owned.origin, owned.item["generate"],
         "yes" if owned.item.get("shared") else "no",
         owned.item["description"])
        for owned in resolved.secrets
    ])


def _default(item: dict) -> str:
    if "default" not in item:
        return "none: required"
    value = item["default"]
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _options(resolved: Resolved) -> str:
    rows = []
    for owned in resolved.options:
        kind = owned.item["type"]
        if kind == "enum":
            kind = f"enum: {', '.join(owned.item['values'])}"
        rows.append((owned.item["name"], owned.origin, kind,
                     _default(owned.item)))
    return table(("Option", "From", "Type", "Default"), rows)


def _hooks(resolved: Resolved) -> str:
    return table(("Hook", "From"), [
        (owned.item, owned.origin) for owned in resolved.hooks
    ])


def _application(application: Owned | None) -> str:
    if application is None:
        return f"Application\n{NONE}"
    text = yaml.safe_dump(application.item, sort_keys=False,
                          default_flow_style=False)
    return f"Application, from {application.origin}\n{text.rstrip()}"
