# Copyright (c) 2026 KeelLinux maintainers
"""Plan the firewall derived from the manifests (decision 0041)

Optional, and for cloud advanced installations only (the maintainer,
2026-09-30): the spec's `firewall.enabled: true`, which validation
refuses in the other modes, writes /etc/keel/firewall/keel-manifest.nft
(keel.manifest.firewall) and loads it; `false` removes keel's file and
table; a spec that says nothing leaves both as they are, as it leaves
the monitor.

A firewall that cuts SSH on a VM is a lockout, so every guard is here,
before anything is written:

- the ruleset lets in the loopback, established and related traffic
  (the session that runs apply lives through the change), ICMPv6 and
  the DHCP client replies, whatever the manifests say;
- every port sshd is configured to listen on must be one the ruleset
  opens on every interface, or the step is refused and nothing moves;
- nothing moves while a network change waits for `keel network
  confirm` (decision 0018): the confirmation comes over a new session,
  and a ruleset changed in the window could be what refuses it;
- `nft -c` checks the file before `nft -f` loads it, and the load is
  one transaction, so a file nft refuses leaves the table as it was;
- a file at that path keel did not write is never replaced.

keel-firewall.service loads the file at boot, so the table survives a
reboot; nothing but keel's own `inet keel` table is ever touched.
"""

from keel.manifest.firewall import HEADER, PATH, Ruleset, render
from keel.manifest.resolve import Resolved
from keel.network import wireguard
from keel.system.actions import (
    Action,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Step,
    WriteFile,
)
from keel.system.fwstate import FirewallState

FIELD = "derived.firewall"
MODE = 0o600
TABLE_ARGS = ("inet", "keel")


def written_by_keel(state: FirewallState) -> bool:
    return (state.file.text or "").startswith(HEADER)


def plan_firewall(doc: dict, resolved: Resolved | None,
                  state: FirewallState | None, live: bool,
                  available: frozenset[str]) -> list[Step]:
    if resolved is None or state is None:
        return []
    firewall = doc.get("firewall")
    if firewall is None:
        if not written_by_keel(state):
            return []
        return [Step(FIELD, (Note(
            "not declared: the firewall keel set up earlier is left as it"
            " is; `firewall.enabled: false` removes it"),))]
    if firewall.get("enabled") is not True:
        return [Step(FIELD, off(state, live, available))]
    return [Step(FIELD, on(doc, resolved, state, live, available))]


def off(state: FirewallState, live: bool,
        available: frozenset[str]) -> tuple[Action, ...]:
    actions: list[Action] = []
    if written_by_keel(state):
        actions.append(RemoveFile(PATH, f"remove /{PATH}, which keel wrote:"
                                  " the firewall is off in the spec"))
    if live and state.loaded is not None and "nft" in available:
        actions.append(Run(("nft", "delete", "table", *TABLE_ARGS),
                           "remove keel's table: the firewall is off in"
                           " the spec"))
    return tuple(actions) or (Note("unchanged (off)"),)


def on(doc: dict, resolved: Resolved, state: FirewallState, live: bool,
       available: frozenset[str]) -> tuple[Action, ...]:
    wg = ((doc.get("network") or {}).get("overlay") or {}).get("wireguard")
    ruleset = render(resolved, doc.get("overlays") or {},
                     wg if isinstance(wg, dict) else None)
    refusal = guard(ruleset, state, live, available)
    if refusal is not None:
        return (refusal,)
    if state.pending:
        return (Note(
            "a network change waits for keel network confirm (decision"
            " 0018): the firewall is left as it is until it is confirmed"
            " or reverted, so it cannot refuse the session that confirms;"
            " apply again then"),)
    actions: list[Action] = [Note(note) for note in ruleset.notes]
    written = state.file.text != ruleset.text
    if written:
        actions.append(WriteFile(PATH, ruleset.text, MODE, None,
                                 f"write /{PATH}: {opened(ruleset, wg)}"))
    if not live:
        actions.append(Note("not loaded: not the live system;"
                            " keel-firewall.service loads it at boot"))
    elif written or state.loaded != ruleset.digest:
        actions += [
            Run(("nft", "-c", "-f", f"/{PATH}"),
                "check the ruleset; a file nft refuses changes nothing"),
            Run(("nft", "-f", f"/{PATH}"),
                "load it in one transaction, replacing table inet keel"
                " only"),
        ]
    if all(isinstance(action, Note) for action in actions):
        actions.append(Note(f"unchanged (/{PATH}, loaded as table inet"
                            " keel)"))
    return tuple(actions)


def guard(ruleset: Ruleset, state: FirewallState, live: bool,
          available: frozenset[str]) -> Refuse | None:
    """Why nothing may be written or loaded, or None"""
    closed = [port for port in state.ssh_ports
              if (port, "tcp") not in ruleset.public]
    if closed:
        ports = ", ".join(f"{port}/tcp" for port in closed)
        return Refuse(
            f"the ruleset would close SSH: sshd listens on {ports}"
            f" ({state.ssh_source}), and no enabled process of the"
            " manifests opens it; nothing is written or loaded")
    if state.file.readable and not written_by_keel(state):
        return Refuse(
            f"/{PATH} is there and keel did not write it: it is not"
            " replaced; move it away and apply again")
    if live and "nft" not in available:
        return Refuse("nft not found: install nftables (apt install"
                      " nftables), and keel installs no package")
    return None


def opened(ruleset: Ruleset, wg) -> str:
    """What the ruleset opens, in one phrase"""
    def ports(found, protocol):
        return ", ".join(str(port) for port, proto in found
                         if proto == protocol)
    public = " and ".join(f"{protocol} {ports(ruleset.public, protocol)}"
                          for protocol in ("tcp", "udp")
                          if ports(ruleset.public, protocol))
    phrase = f"public {public}"
    if ruleset.mesh:
        iface = (wg or {}).get("interface") or wireguard.DEFAULT_INTERFACE
        mesh = " and ".join(f"{protocol} {ports(ruleset.mesh, protocol)}"
                            for protocol in ("tcp", "udp")
                            if ports(ruleset.mesh, protocol))
        phrase += f", mesh {mesh} on {iface}"
    return phrase
