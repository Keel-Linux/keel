# Copyright (c) 2026 KeelLinux maintainers
"""Monit's checks, derived from the resolved manifests; pure

docs/manifest-v1.md, "What is derived, and how": every process and every
check of the appliance itself and of each overlay the spec has
`enabled`, and nothing of an overlay that is `disabled`. So turning an
overlay on or off adds or removes exactly its checks.

- A process is a `check program` on its unit, with the unit's own start
  and restart commands: Monit restarts through systemd, never around it
  (decision 0041, 5). Its restart limit is the manifest's, and reaching
  it stops the restarts and says so (0040, "Resolved"): a loop is
  reported, not hidden.
- A check is a `check host` (http, tcp, a Monit protocol) or a `check
  program` (an argv command). `on_failure: restart` restarts the unit of
  its process; `alert` only tells.
- Every failure, every recovery and a restart limit reached run keel
  notify, as the checks of decision 0021 do, so the operator hears of it
  on the channels of the spec's monitor section.

Names are `keel-unit-<process>` and `keel-check-<check>`: a process and a
check may share a name (Core's sshd), and Monit refuses two services of
one name. The file is keel.system's to write and include; nothing here
reads a file.
"""

from dataclasses import dataclass

from keel.manifest.constants import DEFAULT_EVERY, DEFAULT_RESTART, NEVER
from keel.manifest.resolve import Owned, Resolved
from keel.monitor.settings import reminder

# where apply writes the file, and the link in monit's include directory
# that exists only while the spec's monitor is enabled (0041, "Resolved")
PATH = "etc/keel/monit/keel-manifest.conf"
LINK = "etc/monit/conf.d/keel-manifest.conf"
HEADER = (
    "# written by keel spec apply --system from the appliance manifests\n"
    "# (handbook decisions 0040 and 0041); a change made here is"
    " overwritten"
)
SYSTEMCTL = "/usr/bin/systemctl"
INDENT = "    "
HOLD = "for 2 cycles"
LOOPBACK = "::1"
ENABLED = "enabled"
# a character Monit's quoted program string cannot carry inside one
# argument: it splits the string at spaces and has no escape
UNQUOTABLE = (" ", "\t", "\n", '"', "'")


@dataclass(frozen=True)
class Rendered:
    text: str
    services: tuple[str, ...]
    notes: tuple[str, ...]


def unit_service(process: str) -> str:
    return f"keel-unit-{process}"


def check_service(check: str) -> str:
    return f"keel-check-{check}"


def watched(owned: Owned, states: dict) -> bool:
    """The appliance's own, or an overlay's that the spec has enabled"""
    return owned.overlay is None or states.get(owned.overlay) == ENABLED


def render(resolved: Resolved, states: dict, mesh: str | None,
           notify: tuple[str, ...], cycle: int) -> Rendered:
    """The file, what it watches, and what it could not watch and why

    `states` are the spec's overlays; `mesh` the overlay address of
    network.overlay.wireguard, with or without its prefix; `notify` the
    argv prefix of keel notify; `cycle` monit's, in seconds, which the
    reminders count in.
    """
    writer = _Writer(notify, reminder(cycle))
    processes = {owned.item["name"]: owned.item
                 for owned in resolved.processes if watched(owned, states)}
    owners = {owned.item["name"]: owned.overlay
              for owned in resolved.processes}
    blocks, services, notes = [HEADER + "\n"], [], []
    for process in processes.values():
        blocks.append(writer.process(process))
        services.append(unit_service(process["name"]))
    address = mesh.split("/")[0] if mesh else None
    for owned in resolved.checks:
        if not watched(owned, states):
            continue
        check = owned.item
        process = check.get("process")
        if process is not None and process not in processes:
            # a check of the appliance's own on an overlay's process:
            # depending on a service the file does not hold would make
            # monit refuse the whole file
            notes.append(f"{check['name']} not watched: its process"
                         f" {process} belongs to the overlay"
                         f" {owners[process]}, which is disabled")
            continue
        block, why = writer.check(check, processes, resolved, address)
        if block is None:
            notes.append(f"{check['name']} not watched: {why}")
            continue
        blocks.append(block)
        services.append(check_service(check["name"]))
    return Rendered("\n".join(blocks), tuple(services), tuple(notes))


def limit(process: dict) -> dict | None:
    """The restart limit of a process, None for `restart: never`"""
    restart = process.get("restart", DEFAULT_RESTART)
    return None if restart == NEVER else restart


def loopback_address(port: int, resolved: Resolved) -> str:
    """`::1`, or the literal a process binds that port on (rule 6)"""
    for owned in resolved.processes:
        for listen in owned.item.get("listen") or []:
            if listen["port"] == port and listen.get("address"):
                return listen["address"]
    return LOOPBACK


def probe(check: dict) -> str:
    """The Monit test of an http, tcp or protocol check"""
    port = f"port {check['port']}"
    kind = check["type"]
    if kind == "http":
        scheme = "https" if check.get("tls") else "http"
        return (f'{port} protocol {scheme} request "{check["path"]}"'
                f" status = {check['expect']}")
    if kind == "protocol":
        return f"{port} protocol {check['protocol']}"
    return f"{port} type tcp"


class _Writer:
    def __init__(self, notify: tuple[str, ...], every: int):
        self.prefix = " ".join(notify)
        self.every = every

    def notify(self, level: str, check: str, name: str,
               unit: str | None) -> str:
        words = [self.prefix, "--level", level, "--check", check,
                 "--name", name]
        if unit:
            words += ["--unit", unit]
        return f'exec "{" ".join(words)}"'

    def told(self, test: str, name: str, unit: str | None) -> list[str]:
        """The alert of a failed test, its reminder and its recovery"""
        return [
            f"{INDENT}if {test} {HOLD} then"
            f" {self.notify('critical', 'service', name, unit)}",
            f"{INDENT}{INDENT}repeat every {self.every} cycles",
            f"{INDENT}else if succeeded then"
            f" {self.notify('recovery', 'service', name, unit)}",
        ]

    def restarted(self, test: str, name: str, unit: str, restart: dict,
                  depends: list[str]) -> list[str]:
        """Restart through systemd, tell, and stop at the limit"""
        loop = (f"{restart['attempts']} restarts within"
                f" {restart['within_cycles']} cycles")
        return [
            f'{INDENT}start program = "{SYSTEMCTL} start {unit}"',
            f'{INDENT}restart program = "{SYSTEMCTL} restart {unit}"',
            *depends,
            f"{INDENT}if {test} {HOLD} then restart",
            *self.told(test, name, unit),
            f"{INDENT}if {loop} then unmonitor",
            f"{INDENT}if {loop} then"
            f" {self.notify('critical', 'restarts', name, unit)}",
        ]

    def process(self, process: dict) -> str:
        unit, name = process["unit"], process["name"]
        head = (f'check program {unit_service(name)} with path'
                f' "{SYSTEMCTL} is-active --quiet {unit}"')
        restart = limit(process)
        if restart is None:
            lines = self.told("status != 0", name, unit)
        else:
            lines = self.restarted("status != 0", name, unit, restart, [])
        return _block(head, lines)

    def check(self, check: dict, processes: dict, resolved: Resolved,
              mesh: str | None) -> tuple[str | None, str]:
        name = check["name"]
        if check["type"] == "command":
            if any(char in part for part in check["command"]
                   for char in UNQUOTABLE):
                return None, ("monit splits its command at spaces, and an"
                              " argument holds a space or a quote")
            head = (f"check program {check_service(name)} with path"
                    f' "{" ".join(check["command"])}"')
            test = "status != 0"
        else:
            if check["address"] == "loopback":
                address = loopback_address(check["port"], resolved)
            elif mesh:
                address = mesh
            else:
                return None, ("its address is the mesh, and the spec"
                              " declares no"
                              " network.overlay.wireguard.address")
            head = f"check host {check_service(name)} with address {address}"
            test = f"failed {probe(check)}"
        lines = []
        every = check.get("every_cycles", DEFAULT_EVERY)
        if every != DEFAULT_EVERY:
            lines.append(f"{INDENT}every {every} cycles")
        process = processes.get(check.get("process"))
        depends = ([f"{INDENT}depends on {unit_service(process['name'])}"]
                   if process else [])
        restart = limit(process) if process else None
        if check["on_failure"] == "restart" and restart is not None:
            return _block(head, lines + self.restarted(
                test, name, process["unit"], restart, depends)), ""
        unit = process["unit"] if process else None
        return _block(head, lines + depends
                      + self.told(test, name, unit)), ""


def _block(head: str, lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in [head, *lines])
