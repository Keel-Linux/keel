# Copyright (c) 2026 KeelLinux maintainers
"""The appliance, its installation mode and its overlays (0041)

docs/manifest-v1.md, "The instance spec side":

- `appliance.name` is the one installed appliance manifest that no
  other one has as its base, the top of the chain;
- `installation.mode` is chosen once and nothing on the machine records
  it, so it is read from the spec the installer emitted, and reported
  as not inferred otherwise;
- `overlays.<name>` is read from systemd for an overlay that owns units
  (keel.inspect.units). An overlay that owns none (the installer,
  WireGuard) has no state in systemd; the emitted spec gives it, or it
  is not inferred.

Nothing is written for a machine with no appliance manifest, which is
every machine of before 0041.
"""

import yaml

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import Tree
from keel.inspect.units import overlay_state, read_units
from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.facts import gather
from keel.manifest.load import ManifestError
from keel.manifest.resolve import overlay_units
from keel.spec.constants import INSTALLATION_MODES, OVERLAY_STATES

EMITTED = "etc/keel/instance.yaml"
LIVE_ROOT = "/"


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


def overlay_states(tree: Tree, resolved, emitted: dict,
                   where: str) -> tuple[dict, list[Finding]]:
    wanted = [unit for state in resolved.overlays
              for unit in overlay_units(resolved, state.name)]
    units = read_units(tree, wanted, tree.root == LIVE_ROOT)
    declared = emitted.get("overlays") or {}
    overlays: dict = {}
    findings = []
    for state in resolved.overlays:
        key = f"overlays.{state.name}"
        names = overlay_units(resolved, state.name)
        if not names:
            value = declared.get(state.name) if isinstance(
                declared, dict) else None
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
