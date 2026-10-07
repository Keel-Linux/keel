# Copyright (c) 2026 KeelLinux maintainers
"""The appliance, its installation mode and its overlays (0041)

docs/manifest-v1.md, "The instance spec side":

- `appliance.name` is the one installed appliance manifest that no
  other one has as its base, the top of the chain;
- `installation.mode` is chosen once and nothing on the machine records
  it, so it is read from the spec the installer emitted, and reported
  as not inferred otherwise;
- `overlays.<name>` is read from systemd for an overlay that owns units
  (keel.inspect.units). WireGuard owns none in its manifest, since the
  interface is the spec's: its state is read the way apply leaves it,
  from wg-quick@<iface> of the /etc/wireguard file and, on the live
  system, the interface. An overlay with nothing on the machine to say
  (the installer, WireGuard with no file) is given by the emitted spec,
  or not inferred.

Nothing is written for a machine with no appliance manifest, which is
every machine of before 0041.
"""

from collections.abc import Callable

import yaml

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import Tree
from keel.inspect.units import overlay_state, read_units
from keel.manifest import firewall
from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.facts import gather
from keel.manifest.load import ManifestError
from keel.manifest.resolve import overlay_units
from keel.network import live as live_link
from keel.network import wireguard
from keel.spec.constants import INSTALLATION_MODES, OVERLAY_STATES

EMITTED = "etc/keel/instance.yaml"
LIVE_ROOT = "/"
# the overlay whose state is its interface's (decisions 0020, 0024)
WIREGUARD = "wireguard"
CONF_SUFFIX = ".conf"
LinkUp = Callable[[str], bool]


def probe_appliance_sections(tree: Tree) -> tuple[dict, list[Finding]]:
    """The three sections, each only when something was found"""
    catalog = Catalog(tree.root)
    names = catalog.names(APPLIANCE)
    if not names:
        return {}, []
    tops = top_of(catalog, names)
    key = "appliance.name"
    if len(tops) != 1:
        return {}, [missing(key, (
            f"{' and '.join(tops)} are installed, and neither is built on"
            " the other") if tops else "every installed appliance is the"
            " base of another, which no chain allows")]
    name = tops[0]
    sections: dict = {"appliance": {"name": name}}
    findings = [inferred(key, name, (
        f"the one appliance manifest under {catalog.directory()}/appliances"
        " that no other is built on"))]
    facts = gather(tree.root, name)
    if facts.resolved is None:
        return sections, findings + [missing(
            "overlays", "; ".join(facts.problems))]
    emitted, where = read_emitted(tree)
    vip = (emitted.get("appliance") or {}).get("vip")
    if vip is not None:
        # the pair's VIP is chosen at installation, and nothing on the
        # machine says it is this node's rather than another pair's it
        # routes (decision 0049): the emitted spec says it
        sections["appliance"]["vip"] = vip
        findings.append(inferred("appliance.vip", vip, where))
    mode = (emitted.get("installation") or {}).get("mode")
    if mode in INSTALLATION_MODES:
        sections["installation"] = {"mode": mode}
        findings.append(inferred("installation.mode", mode, where))
    else:
        findings.append(missing("installation.mode", (
            "a machine's units do not say which mode chose them, and no"
            f" spec the installer emitted says it at {where}")))
    sections["overlays"], found = overlay_states(tree, facts.resolved,
                                                 emitted, where)
    ruleset = tree.read(firewall.PATH)
    enabled = (ruleset.text or "").startswith(firewall.HEADER)
    sections["firewall"] = {"enabled": enabled}
    found.append(inferred("firewall.enabled", str(enabled).lower(), (
        f"{ruleset.path}, keel's ruleset" if enabled
        else f"{ruleset.path}: no ruleset of keel's")))
    return sections, findings + found


def top_of(catalog: Catalog, names: list[str]) -> list[str]:
    bases = set()
    for name in names:
        try:
            bases.add(catalog.read(APPLIANCE, name).get("base"))
        except ManifestError:
            continue
    return [name for name in names if name not in bases]


def read_emitted(tree: Tree) -> tuple[dict, str]:
    """The spec at /etc/keel/instance.yaml, when it can be read as one"""
    file = tree.read(EMITTED)
    try:
        doc = yaml.safe_load(file.text or "") if file.readable else None
    except yaml.YAMLError:
        doc = None
    return (doc if isinstance(doc, dict) else {}), file.path


def wireguard_state(tree: Tree, live: bool,
                    link_up: LinkUp) -> tuple[str | None, str] | None:
    """overlays.wireguard as apply leaves it, and what said so

    apply writes /etc/wireguard/<iface>.conf and enables wg-quick@<iface>
    once the change is confirmed (keel.system.overlay): enabled is that
    unit enabled and, on the live system, the interface up; disabled is
    neither. The default interface's file is read when there are several,
    as for network.overlay. Up and not enabled (a change waiting for its
    confirmation) or enabled and down (drift apply restarts) is None.
    None alone when there is no file: then nothing on the machine says.
    """
    names = [path.rsplit("/", 1)[-1][:-len(CONF_SUFFIX)] for path in
             tree.glob(f"{wireguard.CONF_DIR}/*{CONF_SUFFIX}")]
    if not names:
        return None
    iface = (wireguard.DEFAULT_INTERFACE
             if wireguard.DEFAULT_INTERFACE in names else names[0])
    enabled = tree.exists(wireguard.WANTS.format(iface=iface))
    said = f"wg-quick@{iface}.service {'enabled' if enabled else 'disabled'}"
    up = None
    if live:
        up = link_up(iface)
        said += f", {iface} {'up' if up else 'down'}"
    if enabled and up is not False:
        return "enabled", said
    if not enabled and not up:
        return "disabled", said
    return None, said


def overlay_states(tree: Tree, resolved, emitted: dict, where: str,
                   link_up: LinkUp = live_link.link_up) -> (
    tuple[dict, list[Finding]]
):
    live = tree.root == LIVE_ROOT
    wanted = [unit for state in resolved.overlays
              for unit in overlay_units(resolved, state.name)]
    units = read_units(tree, wanted, live)
    declared = emitted.get("overlays") or {}
    overlays: dict = {}
    findings = []
    for state in resolved.overlays:
        key = f"overlays.{state.name}"
        names = overlay_units(resolved, state.name)
        found = (wireguard_state(tree, live, link_up)
                 if not names and state.name == WIREGUARD else None)
        emitted_value = declared.get(state.name) if isinstance(
            declared, dict) else None
        if found is not None:
            value, why = found
            if value is not None:
                overlays[state.name] = value
                findings.append(inferred(key, value, why))
            elif emitted_value in OVERLAY_STATES:
                # inside a 0018 window, say: the machine is between two
                # states, so the spec the installer emitted still gives
                # the key, and the spec inspect writes keeps it
                overlays[state.name] = emitted_value
                findings.append(inferred(key, emitted_value, (
                    f"{where}; its interface and its unit disagree:"
                    f" {why}")))
            else:
                findings.append(missing(key, (
                    f"its interface and its unit disagree: {why}, and no"
                    f" spec the installer emitted says it at {where}")))
            continue
        if not names:
            value = emitted_value
            if value in OVERLAY_STATES:
                overlays[state.name] = value
                findings.append(inferred(key, value,
                                         f"{where}; it runs no unit"))
            else:
                findings.append(missing(key, (
                    "runs no unit, so systemd does not say whether it is"
                    f" on, and no spec the installer emitted says it at"
                    f" {where}")))
            continue
        value, why = overlay_state([units[unit] for unit in names])
        if value is None:
            findings.append(missing(key, f"its units disagree: {why}"))
            continue
        overlays[state.name] = value
        findings.append(inferred(key, value, "systemd: " + ", ".join(
            units[unit].describe() for unit in names)))
    return overlays, findings
