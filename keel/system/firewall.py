# Copyright (c) 2026 KeelLinux maintainers
"""Plan the firewall derived from the manifests (decisions 0041, 0097)

Decision 0097: keel writes /etc/keel/firewall/keel-manifest.nft
(keel.manifest.firewall) in every mode, and loads it, in one of the
states of the spec's `firewall.state`:

- `enforce`: a drop policy;
- `report`: the same rules, which drop nothing and count what enforce
  would drop;
- `off`: keel's file and table are removed, and the plan warns.

`enabled: true` is enforce. With no word (no section, or `enabled:
false`), the node is in report, and rule B, the maintainer's answer of
2026-11-23, decides when it goes to enforce: only at an apply a person
runs (`attended`, which keel spec apply passes and keel mesh never
does), and only when each socket on an address that is not a loopback
belongs to a unit of the manifests (keel.system.listeners). Else it
stays in report and the plan says which sockets keep it there. Once
keel's file is in enforce, that file is the record: no apply without a
word moves it back. keel mesh applies the whole spec every 15 minutes
with no person, so it never begins enforcement, not even where the spec
says enforce: it keeps report until a person applies.

A firewall that cuts SSH on a VM is a lockout, so every guard is here,
before anything is written:

- the ruleset lets in the loopback, established and related traffic
  (the session that runs apply lives through the change), ICMPv6 and
  the DHCP client replies, whatever the manifests say;
- every port sshd listens on is opened, and named where the manifests
  do not open it; when those ports cannot be determined, the step is
  refused and nothing moves;
- nothing moves while a network change waits for `keel network
  confirm` (decision 0018): the confirmation comes over a new session,
  and a ruleset changed in the window could be what refuses it;
- `nft -c` checks the file before `nft -f` loads it, and the load is
  one transaction, so a file nft refuses leaves the table as it was;
- a file at that path keel did not write is never replaced.

keel-firewall.service loads the file at boot, so the table survives a
reboot; nothing but keel's own `inet keel` table is ever touched.
"""

from keel.manifest.firewall import (
    ENFORCE,
    HEADER,
    OFF,
    PATH,
    REPORT,
    Allow,
    Ruleset,
    exposed,
    file_state,
    render,
)
from keel.manifest.resolve import Resolved
from keel.network import wireguard
from keel.spec.validate_firewall import declared_state
from keel.system.actions import (
    Action,
    InstallRuleset,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Step,
    WriteFile,
)
from keel.system.fwstate import FirewallState
from keel.system.listeners import classify, declared_units, unopened

FIELD = "derived.firewall"
MODE = 0o600
TABLE_ARGS = ("inet", "keel")
OFF_WARNING = ("off in the spec: no inbound rule of keel's protects this"
               " node; `firewall.state: enforce` closes it")
UNATTENDED = ("report: only an apply a person runs (keel spec apply"
              " --system) moves this node to enforce")
UNATTENDED_DECLARED = ("report until an apply a person runs: the spec says"
                       " enforce, and keel mesh never begins enforcement"
                       " (decision 0097)")
KEPT = ("enforce, as keel's file already says; `firewall.state: report`"
        " goes back")
PROMOTED = ("enforce: each socket on an address that is not a loopback"
            " belongs to a unit of the manifests (decision 0097, B)")


def written_by_keel(state: FirewallState) -> bool:
    return (state.file.text or "").startswith(HEADER)


def waiting_notice(sockets: list[str]) -> str:
    """What the administrator is told when rule B keeps a node in report

    The plan says it. When the ntfy notice of decision 0085 is built,
    this is the text it sends for a node that waits in report (decision
    0097, work item 15); keel has no such sender today.
    """
    return ("report: enforce waits, because these sockets belong to no"
            f" unit of the manifests: {'; '.join(sockets)}. Declare each in"
            " firewall.allow, or stop it, or set firewall.state: enforce;"
            " then run keel spec apply --system")


def plan_firewall(doc: dict, resolved: Resolved | None,
                  state: FirewallState | None, live: bool,
                  available: frozenset[str],
                  attended: bool = False) -> list[Step]:
    if resolved is None or state is None:
        return []
    declared = declared_state(doc)
    if declared == OFF:
        return [Step(FIELD, (Note(OFF_WARNING),)
                     + off(state, live, available))]
    return [Step(FIELD, on(doc, resolved, state, live, available,
                           declared, attended))]


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


def overlay_of(doc: dict) -> dict | None:
    found = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard")
    return found if isinstance(found, dict) else None


def allow_of(doc: dict) -> tuple[Allow, ...]:
    """The spec's firewall.allow, validated before apply reads it"""
    firewall = doc.get("firewall")
    items = firewall.get("allow") if isinstance(firewall, dict) else None
    return tuple(Allow(item["port"], item["protocol"],
                       tuple(str(source) for source in item.get("from")
                             or ()))
                 for item in items or ())


def build(doc: dict, resolved: Resolved, state: FirewallState,
          target: str) -> Ruleset:
    return render(resolved, doc.get("overlays") or {}, overlay_of(doc),
                  state.bridges, state=target, ssh=state.ssh_ports,
                  allow=allow_of(doc), fence=state.fence)


def opened_ports(ruleset: Ruleset, doc: dict) -> frozenset:
    """What the ruleset opens to someone: public, the mesh on the
    overlay, and the administrator's ports"""
    return frozenset(ruleset.public) | frozenset(ruleset.mesh) | {
        (item.port, item.protocol) for item in allow_of(doc)}


def choose(doc: dict, resolved: Resolved, state: FirewallState,
           declared: str | None, attended: bool) -> tuple[str, list[str]]:
    """The state to write, and what the plan says about it"""
    current = file_state(state.file.text)
    if declared == ENFORCE:
        if attended or current == ENFORCE:
            return ENFORCE, []
        return REPORT, [UNATTENDED_DECLARED]
    if declared == REPORT:
        return REPORT, []
    if current == ENFORCE:
        return ENFORCE, [KEPT]
    if not attended:
        return REPORT, [UNATTENDED]
    if state.listeners is None:
        return REPORT, [f"report: the sockets cannot be listed"
                        f" ({state.listeners_source}), so enforce waits;"
                        " `firewall.state: enforce` enforces anyway"]
    found = sorting(doc, resolved, state)
    if found.undeclared:
        return REPORT, [waiting_notice([item.describe()
                                        for item in found.undeclared])]
    return ENFORCE, [PROMOTED]


def sorting(doc: dict, resolved: Resolved, state: FirewallState):
    """The sockets, sorted by rule B against the enforce ruleset"""
    enforcing = build(doc, resolved, state, ENFORCE)
    overlay = overlay_of(doc)
    return classify(
        state.listeners or (),
        declared_units(resolved, doc.get("overlays") or {}),
        ssh=state.ssh_ports,
        allow=frozenset((item.port, item.protocol)
                        for item in allow_of(doc)),
        opened=opened_ports(enforcing, doc),
        overlay=None if overlay is None else (
            overlay.get("interface") or wireguard.DEFAULT_INTERFACE,
            overlay.get("listen_port") or wireguard.DEFAULT_PORT))


def told(doc: dict, resolved: Resolved, state: FirewallState,
         ruleset: Ruleset) -> list[str]:
    """What enforce closes, or would close, of the sockets seen"""
    if state.listeners is None:
        return []
    if ruleset.state == ENFORCE:
        return [f"closes {item.describe()}: the manifests declare its"
                " process, not this port"
                for item in sorting(doc, resolved, state).closed]
    overlay = overlay_of(doc)
    device = None if overlay is None else (
        overlay.get("interface") or wireguard.DEFAULT_INTERFACE)
    return [f"enforce would close {item.describe()}" for item in unopened(
        state.listeners, opened_ports(ruleset, doc), device)]


def ssh_said(resolved: Resolved, doc: dict, state: FirewallState
             ) -> list[str]:
    """Name sshd's ports where the manifests do not open them all"""
    public, _ = exposed(resolved, doc.get("overlays") or {})
    if all((port, "tcp") in public for port in state.ssh_ports):
        return []
    ports = ", ".join(str(port) for port in state.ssh_ports)
    return [f"SSH stays open: tcp {ports}, the ports sshd listens on"
            f" ({state.ssh_source})"]


def on(doc: dict, resolved: Resolved, state: FirewallState, live: bool,
       available: frozenset[str], declared: str | None,
       attended: bool) -> tuple[Action, ...]:
    refusal = guard(state, live, available)
    if refusal is not None:
        return (refusal,)
    if state.pending:
        return (Note(
            "a network change waits for keel network confirm (decision"
            " 0018): the firewall is left as it is until it is confirmed"
            " or reverted, so it cannot refuse the session that confirms;"
            " apply again then"),)
    target, said = choose(doc, resolved, state, declared, attended)
    ruleset = build(doc, resolved, state, target)
    said += told(doc, resolved, state, ruleset)
    said += ssh_said(resolved, doc, state)
    said += [state.fence_note] if state.fence_note else []
    actions: list[Action] = [Note(note) for note in
                             said + list(ruleset.notes)]
    return tuple(actions + load(ruleset, state, live, overlay_of(doc)))


def load(ruleset: Ruleset, state: FirewallState, live: bool,
         wg: dict | None) -> list[Action]:
    """Write and load the ruleset where it differs from what is there"""
    actions: list[Action] = []
    written = state.file.text != ruleset.text
    summary = (f"write /{PATH} ({ruleset.state}):"
               f" {opened(ruleset, wg, state.bridges)}")
    nft_load = Run(("nft", "-f", f"/{PATH}"),
                   "load it in one transaction, replacing table inet keel"
                   " only")
    if not live:
        if written:
            actions.append(WriteFile(PATH, ruleset.text, MODE, None,
                                     summary))
        actions.append(Note("not loaded: not the live system;"
                            " keel-firewall.service loads it at boot"))
        if not written:
            actions.append(Note(f"unchanged (/{PATH})"))
    elif written:
        actions += [InstallRuleset(PATH, ruleset.text, summary), nft_load]
    elif state.loaded != ruleset.digest:
        actions += [
            Run(("nft", "-c", "-f", f"/{PATH}"),
                "check the ruleset; a file nft refuses changes nothing"),
            nft_load,
        ]
    else:
        actions.append(Note(f"unchanged (/{PATH}, loaded as table inet"
                            " keel)"))
    return actions


def guard(state: FirewallState, live: bool,
          available: frozenset[str]) -> Refuse | None:
    """Why nothing may be written or loaded, or None"""
    if not state.ssh_ports:
        return Refuse(
            f"the ports sshd listens on cannot be determined"
            f" ({state.ssh_source}): no firewall is applied, since one"
            " could close SSH; nothing is written or loaded")
    if state.file.readable and not written_by_keel(state):
        return Refuse(
            f"/{PATH} is there and keel did not write it: it is not"
            " replaced; move it away and apply again")
    if live and "nft" not in available:
        return Refuse("nft not found: install nftables (apt install"
                      " nftables), and keel installs no package")
    return None


def opened(ruleset: Ruleset, wg, bridges: tuple[str, ...] = ()) -> str:
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
    if bridges:
        phrase += f", DHCP and DNS for the guests of {', '.join(bridges)}"
    return phrase
