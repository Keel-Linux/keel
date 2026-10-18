# Copyright (c) 2026 KeelLinux maintainers
"""What the appliance plan looks at, read once from the root (0041)

The resolved chain of the spec's appliance, what systemd says about
every unit an overlay of it owns, Monit's derived file and its include
as keel last wrote them, monit's cycle, which parts of CrowdSec's
identity exist, and each overlay's state hooks with what was recorded
after they last ran (keel.system.hooks). Nothing is read when the spec
names no appliance: a spec of before decision 0041 plans exactly what it
planned before.
"""

from dataclasses import dataclass, field

from keel.inspect.constants import ROOT_DEFAULT
from keel.inspect.monitor import Cycle, monit_cycle
from keel.inspect.tree import File, Tree
from keel.inspect.units import UnitState, read_units
from keel.manifest import monit
from keel.manifest.facts import gather
from keel.manifest.resolve import Resolved, overlay_units
from keel.mesh.etcdstate import CLUSTER
from keel.system import anubiskey
from keel.system.anubiskey import AnubisKey
from keel.system.crowdsec import CrowdsecState, observe_crowdsec
from keel.system.etcd import EtcdState, observe_etcd
from keel.system.fwstate import FirewallState, observe_firewall
from keel.system.hooks import OverlayHooks, observe_hooks

MANIFEST_MONIT = monit.PATH
MONIT_LINK = monit.LINK

__all__ = ["ApplianceState", "CrowdsecState", "OverlayHooks",
           "observe_appliance", "overlay_units"]


@dataclass(frozen=True)
class ApplianceState:
    resolved: Resolved | None
    problems: tuple[str, ...]
    units: dict[str, UnitState]
    monit_file: File
    # where the include in /etc/monit/conf.d points, and whether anything
    # at all is at that path (a file keel did not make is not replaced)
    monit_link: str | None
    monit_link_present: bool
    cycle: Cycle
    crowdsec: CrowdsecState
    root: str
    firewall: FirewallState | None = None
    # each overlay's state hooks (keel.system.hooks), only those that
    # have any, with what was recorded after they last passed
    hooks: dict[str, OverlayHooks] = field(default_factory=dict)
    # etcd's state and files (keel.system.etcd), when the chain has it
    etcd: EtcdState | None = None
    # the pair's Anubis key, asked of the other member, when this node
    # has to ask for it (keel.system.anubiskey, Keel-Linux/common#56)
    anubis_key: AnubisKey | None = None
    # the VIP overlay waits for etcd's cluster: its unit's start
    # condition is cluster.json (keel#106)
    vip_waits: bool = False


def observe_appliance(root: str, doc: dict, start: bool = False,
                      spec: str | None = None) -> ApplianceState | None:
    """None when the spec names no appliance

    `start` is whether this run may change the machine: only such a run
    asks the other member of a pair for Anubis's key, over the members'
    channel, with the spec at `spec` (keel.system.anubiskey)."""
    appliance = doc.get("appliance")
    if not isinstance(appliance, dict):
        return None
    tree = Tree(root)
    facts = gather(root, str(appliance.get("name")))
    units: dict[str, UnitState] = {}
    hooks: dict[str, OverlayHooks] = {}
    etcd = None
    anubis_key = None
    vip_waits = False
    if facts.resolved is not None:
        names = [unit for state in facts.resolved.overlays
                 for unit in overlay_units(facts.resolved, state.name)]
        units = read_units(tree, names, tree.root == ROOT_DEFAULT)
        hooks = {state.name: found for state in facts.resolved.overlays
                 if (found := observe_hooks(tree.root, state.name,
                                            state.manifest))}
        names = {state.name for state in facts.resolved.overlays}
        vip_waits = "vip" in names and not tree.exists(CLUSTER)
        if "etcd" in names:
            etcd = observe_etcd(tree, doc)
        if anubiskey.OVERLAY in names and tree.root == ROOT_DEFAULT:
            anubis_key = anubiskey.observe(
                tree.root, doc, start,
                spec or tree.path("etc/keel/instance.yaml"))
    return ApplianceState(
        resolved=facts.resolved,
        problems=facts.problems,
        units=units,
        monit_file=tree.read(MANIFEST_MONIT),
        monit_link=tree.readlink(MONIT_LINK),
        monit_link_present=tree.exists(MONIT_LINK),
        cycle=monit_cycle(tree),
        crowdsec=observe_crowdsec(tree),
        root=tree.root,
        # nft is asked only when the spec speaks of the firewall
        firewall=observe_firewall(tree, tree.root == ROOT_DEFAULT
                                  and doc.get("firewall") is not None),
        hooks=hooks,
        etcd=etcd,
        anubis_key=anubis_key,
        vip_waits=vip_waits,
    )
