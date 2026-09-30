# Copyright (c) 2026 KeelLinux maintainers
"""Drift of the overlays and of Monit's derived file (decision 0041)

docs/manifest-v1.md, "Who reads it": diff compares the states with
systemd, and the derived Monit file with what is on disk, so a hand edit
of either is drift. The states are read the way apply reads them
(keel.inspect.units); the file is rendered by the code apply writes it
with (keel.manifest.monit) and compared whole. An overlay that runs no
unit has nothing in systemd to compare, and says so.
"""

from keel.diff.report import DRIFT, NOT_COMPARED, SAME, UNKNOWN, FieldDiff
from keel.inspect.monitor import monit_cycle
from keel.inspect.tree import Tree
from keel.inspect.units import overlay_state, read_units
from keel.manifest import firewall as fw
from keel.manifest import monit
from keel.manifest.facts import gather
from keel.manifest.resolve import overlay_units
from keel.system.fwstate import table_digest
from keel.system.monitor import NOTIFY

LIVE_ROOT = "/"
RENDERED = "the file apply renders from the manifests"
DIFFERS = "a file that differs from it"
NO_UNIT = "runs no unit, so nothing in systemd says whether it is on"
NO_MONITOR = ("no monitor section: the include is left as an earlier apply"
              " set it")
RULESET = "the ruleset apply renders from the manifests"
KEEL_RULESET = "keel's ruleset"
NOT_LIVE = ("the table the kernel holds is asked of nft on the live system"
            " only")


def appliance_fields(declared: dict, root: str) -> list[FieldDiff]:
    """overlays.<name>, derived.monit and derived.monit.included"""
    appliance = declared.get("appliance")
    if not isinstance(appliance, dict):
        return []
    facts = gather(root, str(appliance.get("name")))
    resolved = facts.resolved
    if resolved is None:
        return [FieldDiff("overlays", UNKNOWN, reason="; ".join(
            facts.problems))]
    tree = Tree(root)
    states = declared.get("overlays") or {}
    names = [unit for state in resolved.overlays
             for unit in overlay_units(resolved, state.name)]
    units = read_units(tree, names, tree.root == LIVE_ROOT)
    fields = []
    for name, wanted in states.items():
        key = f"overlays.{name}"
        owned = overlay_units(resolved, name)
        if not owned:
            fields.append(FieldDiff(key, NOT_COMPARED, wanted, None,
                                    NO_UNIT))
            continue
        value, why = overlay_state([units[unit] for unit in owned])
        status = SAME if value == wanted else DRIFT
        fields.append(FieldDiff(key, status, wanted, value or why))
    return (fields + monit_fields(declared, resolved, states, tree)
            + firewall_fields(declared, resolved, states, tree))


def firewall_fields(declared: dict, resolved, states: dict,
                    tree: Tree) -> list[FieldDiff]:
    """The ruleset file whole, and on the live system the kernel's table
    by the digest in its comment; nothing when the spec has no firewall"""
    firewall = declared.get("firewall")
    if not isinstance(firewall, dict):
        return []
    file = tree.read(fw.PATH)
    keel_s = (file.text or "").startswith(fw.HEADER)
    if firewall.get("enabled") is not True:
        return [FieldDiff("derived.firewall", DRIFT if keel_s else SAME,
                          None, KEEL_RULESET if keel_s else None)]
    wg = ((declared.get("network") or {}).get("overlay") or {}).get(
        "wireguard")
    ruleset = fw.render(resolved, states, wg if isinstance(wg, dict)
                        else None)
    if file.text == ruleset.text:
        fields = [FieldDiff("derived.firewall", SAME, RULESET, RULESET)]
    else:
        fields = [FieldDiff("derived.firewall", DRIFT, RULESET,
                            DIFFERS if file.readable else None)]
    key = "derived.firewall.loaded"
    if tree.root != LIVE_ROOT:
        return fields + [FieldDiff(key, NOT_COMPARED, None, None,
                                   NOT_LIVE)]
    held = table_digest()
    return fields + [FieldDiff(key, SAME if held == ruleset.digest
                               else DRIFT, ruleset.digest, held)]


def monit_fields(declared: dict, resolved, states: dict,
                 tree: Tree) -> list[FieldDiff]:
    wg = ((declared.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    rendered = monit.render(resolved, states, wg.get("address"), NOTIFY,
                            monit_cycle(tree).seconds)
    file = tree.read(monit.PATH)
    if file.text == rendered.text:
        fields = [FieldDiff("derived.monit", SAME, RENDERED, RENDERED)]
    else:
        fields = [FieldDiff("derived.monit", DRIFT, RENDERED,
                            DIFFERS if file.readable else None)]
    included = tree.readlink(monit.LINK) == "/" + monit.PATH
    monitor = declared.get("monitor")
    key = "derived.monit.included"
    if monitor is None:
        return fields + [FieldDiff(key, NOT_COMPARED, None, included,
                                   NO_MONITOR)]
    wanted = isinstance(monitor, dict) and monitor.get("enabled") is True
    return fields + [FieldDiff(key, SAME if wanted == included else DRIFT,
                               wanted, included)]
