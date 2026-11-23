# Copyright (c) 2026 KeelLinux maintainers
"""Drift of the overlays and of Monit's derived file (decision 0041)

docs/manifest-v1.md, "Who reads it": diff compares the states with
systemd, and the derived Monit file with what is on disk, so a hand edit
of either is drift. The states are read the way apply reads them
(keel.inspect.units); the file is rendered by the code apply writes it
with (keel.manifest.monit) and compared whole. An overlay that runs no
unit has nothing in systemd to compare, and says so; nor has etcd while
it waits for its cluster, which apply leaves stopped (keel.system.etcd).
An overlay the chain gained since the spec was last applied is compared
with the default apply converges it to, and said to be not declared.
"""

import ipaddress
from datetime import datetime, timezone

from keel.diff.report import (
    DRIFT,
    NOT_COMPARED,
    NOT_DECLARED,
    SAME,
    UNKNOWN,
    FieldDiff,
)
from keel.inspect.monitor import monit_cycle
from keel.inspect.tree import Tree
from keel.inspect.units import overlay_state, read_units, waiting
from keel.manifest import firewall as fw
from keel.manifest import monit
from keel.manifest.facts import gather
from keel.manifest.resolve import overlay_units
from keel.mesh import etcdstate
from keel.spec import overlayrecord
from keel.spec.validate_appliance import with_defaults
from keel.network import wireguard
from keel.spec.validate_firewall import declared_state
from keel.system.firewall import (
    allow_of,
    mesh_context,
    opened_ports,
    overlay_of,
)
from keel.system.fwstate import (
    bridges_of,
    fence_ports,
    recorded_state,
    ssh_ports,
    table_digest,
)
from keel.system.listeners import observe_listeners, unopened
from keel.system.monitor import NOTIFY

RENEWED = "renewed by keel mesh etcd tend"
LIVE_ROOT = "/"
RENDERED = "the file apply renders from the manifests"
DIFFERS = "a file that differs from it"
NO_UNIT = "runs no unit, so nothing in systemd says whether it is on"
NO_CLUSTER = ("waits for its cluster (the third cloud advanced member's"
              " join, or keel mesh etcd form): apply starts nothing before")
NO_VIP_CLUSTER = (
    "keel-vip.service starts with etcd's cluster (cluster.json), and"
    " apply starts nothing before; without etcd, keel vip check"
    " (keel-vip-check.timer) does its work (keel#106)"
)
NO_MONITOR = ("no monitor section: the include is left as an earlier apply"
              " set it")
RULESET = "the ruleset apply renders from the manifests"
KEEL_RULESET = "keel's ruleset"
OFF_WARNING = ("warning: off in the spec, no inbound rule of keel's"
               " protects this node")
LEGACY_RULES = ("etc/iptables/rules.v4", "etc/iptables/rules.v6")
# MariaDB, PostgreSQL and Redis: a `firewall.allow` item with no `from`
# opens them to the world (decision 0097, section 2)
DATABASE_PORTS = frozenset({(3306, "tcp"), (5432, "tcp"), (6379, "tcp")})
DEFAULT_NOTE = "not declared: the manifest's default"
LEGACY_VIP = (
    "{vip} is outside the VIP range{range}. It was paired before the"
    " range (0.23.3), and the signed pair record on this node keeps it"
    " valid. A new VIP is in the range. To move this one, declare a VIP"
    " of the range on both members and run keel vip pair again"
)
NOT_LIVE = ("the table the kernel holds is asked of nft on the live system"
            " only")
NOT_APPLIED = (
    f"no successful apply is recorded (/{overlayrecord.RECORD}):"
    " apply has not converged this appliance; see the [10keel-system]"
    " lines in /var/log/inithooks.log, or run"
    " keel spec apply --system --dry-run"
)


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
    declared, defaulted = with_defaults(declared, facts)
    states = declared.get("overlays") or {}
    names = [unit for state in resolved.overlays
             for unit in overlay_units(resolved, state.name)]
    units = read_units(tree, names, tree.root == LIVE_ROOT)
    fields = []
    for name, wanted in states.items():
        key = f"overlays.{name}"
        owned = overlay_units(resolved, name)
        if not owned:
            given = (f"not declared (default: {wanted}); "
                     if name in defaulted else "")
            fields.append(FieldDiff(key, NOT_COMPARED, wanted, None,
                                    given + NO_UNIT))
            continue
        if name == "etcd" and wanted == "enabled" and \
                not tree.exists(etcdstate.CLUSTER):
            fields.append(FieldDiff(key, NOT_COMPARED, wanted, None,
                                    NO_CLUSTER))
            continue
        if name == "vip" and wanted == "enabled" and \
                not tree.exists(etcdstate.CLUSTER):
            fields.append(vip_waiting(key, [units[unit] for unit in owned]))
            continue
        value, why = overlay_state([units[unit] for unit in owned])
        if name in defaulted:
            fields.append(defaulted_field(key, wanted, value or why,
                                          value == wanted))
            continue
        status = SAME if value == wanted else DRIFT
        fields.append(FieldDiff(key, status, wanted, value or why))
    applied = facts.recorded is not None
    return (fields + monit_fields(declared, resolved, states, tree, applied)
            + firewall_fields(declared, resolved, states, tree)
            + etcd_fields(states, tree))


def vip_waiting(key: str, units: list) -> FieldDiff:
    """The VIP overlay before etcd's cluster exists: enabled is every
    unit enabled, running or not, since its start condition holds it"""
    if all(unit.is_enabled or unit.is_fixed for unit in units):
        return FieldDiff(key, SAME, "enabled", "enabled", NO_VIP_CLUSTER)
    return FieldDiff(key, DRIFT, "enabled", ", ".join(
        unit.describe() for unit in units), NO_VIP_CLUSTER)


def vip_fields(declared: dict, root: str) -> list[FieldDiff]:
    """appliance.vip.range: information when the VIP was paired before
    the VIP range and lies outside it (keel.mesh.vip.before_range);
    nothing for a VIP in the range"""
    from keel.mesh import vip as vipstate
    from keel.mesh.vippair import kept_vips
    from keel.system.ovstate import overlay_of
    appliance = declared.get("appliance")
    overlay = overlay_of(declared) or {}
    try:
        vip = vipstate.declared(declared) if isinstance(
            appliance, dict) else None
        prefix = ipaddress.IPv6Interface(str(overlay.get("address"))).network
    except ValueError:
        return []
    vips = vipstate.vip_range(prefix)
    if vip is None or not vipstate.before_range(vip, prefix) or \
            vip not in kept_vips(root):
        return []
    return [FieldDiff("appliance.vip.range", NOT_COMPARED, vip, None,
                      LEGACY_VIP.format(
                          vip=vip, range=f" {vips}" if vips else ""))]


def defaulted_field(key: str, default: str, observed: object,
                    same: bool) -> FieldDiff:
    """An overlay the spec does not declare and that takes its default:
    not declared while the machine has the default, else drift"""
    if same:
        return FieldDiff(key, NOT_DECLARED, None, observed,
                         f"default: {default}")
    return FieldDiff(key, DRIFT, default, observed, note=DEFAULT_NOTE)


def etcd_fields(states: dict, tree: Tree,
                now: datetime | None = None) -> list[FieldDiff]:
    """etcd.certificates: renewed by keel mesh etcd tend, or drift, with
    why: its last renewal failed, or the certificate expires within seven
    days (keel.mesh.etcdcare)"""
    from keel.mesh import etcdcare
    if states.get("etcd") != "enabled" or \
            not tree.exists(etcdstate.CLUSTER):
        return []
    now = now or datetime.now(timezone.utc)
    problem = etcdcare.renewal_problem(tree.root)
    ends = etcdstate.expires(tree.root)
    if problem is None and ends is not None and \
            ends - now < etcdcare.WARN_BEFORE:
        problem = f"expires {ends:%Y-%m-%d %H:%M} UTC, within 7 days"
    if problem is None and ends is None:
        problem = "no member certificate"
    if problem:
        return [FieldDiff("etcd.certificates", DRIFT, RENEWED, None,
                          problem)]
    return [FieldDiff("etcd.certificates", SAME, RENEWED, RENEWED)]


def firewall_fields(declared: dict, resolved, states: dict,
                    tree: Tree) -> list[FieldDiff]:
    """The ruleset file whole, and on the live system the kernel's table
    by the digest in its comment and the sockets enforce closes or would
    close; and the warnings of decision 0097"""
    warnings = firewall_warnings(declared, tree)
    file = tree.read(fw.PATH)
    said = declared_state(declared)
    if said == fw.OFF:
        keel_s = file.readable and fw.keel_owns(file.text)
        return [FieldDiff("derived.firewall", DRIFT if keel_s else SAME,
                          None, KEEL_RULESET if keel_s else None),
                FieldDiff("derived.firewall.state", NOT_COMPARED,
                          reason=OFF_WARNING)] + warnings
    expected = expected_state(said, fw.file_state(file.text)
                              or recorded_state(tree))
    wanted = f"{RULESET}, {expected}"
    live = tree.root == LIVE_ROOT
    ssh, source = ssh_ports(tree, live)
    if not ssh:
        return [FieldDiff("derived.firewall", UNKNOWN, wanted, None,
                          "the ports sshd listens on cannot be determined"
                          f" ({source})")] + warnings
    fence, _ = fence_ports(tree)
    wg = overlay_of(declared)
    ruleset = fw.render(resolved, states, wg, bridges_of(tree),
                        state=expected, ssh=ssh, allow=allow_of(declared),
                        fence=fence)
    if file.text == ruleset.text:
        fields = [FieldDiff("derived.firewall", SAME, wanted, wanted)]
    else:
        fields = [FieldDiff("derived.firewall", DRIFT, wanted,
                            DIFFERS if file.readable else None)]
    key = "derived.firewall.loaded"
    if not live:
        return fields + [FieldDiff(key, NOT_COMPARED, None, None,
                                   NOT_LIVE)] + warnings
    held = table_digest()
    fields.append(FieldDiff(key, SAME if held == ruleset.digest
                            else DRIFT, ruleset.digest, held))
    return fields + [listener_field(declared, resolved, ruleset, tree)] \
        + warnings


def expected_state(said: str | None, current: str | None) -> str:
    """What apply writes with no person: diff never promotes (rule B)"""
    if said in (fw.ENFORCE, fw.REPORT):
        return said
    return fw.ENFORCE if current == fw.ENFORCE else fw.REPORT


def listener_field(declared: dict, resolved, ruleset,
                   tree: Tree) -> FieldDiff:
    """The sockets on an address that is not a loopback whose port the
    ruleset does not open"""
    key = "derived.firewall.listeners"
    found, why = observe_listeners(tree, True)
    if found is None:
        return FieldDiff(key, NOT_COMPARED, reason=why)
    wg = overlay_of(declared)
    device = (wg.get("interface") or wireguard.DEFAULT_INTERFACE
              if wg else None)
    mesh, addresses = mesh_context(declared, resolved)
    closed = unopened(found, opened_ports(ruleset, declared), device, mesh,
                      addresses)
    verb = ("enforce would close" if ruleset.state == fw.REPORT
            else "enforce closes")
    named = "; ".join(item.describe() for item in closed) or "nothing"
    return FieldDiff(key, NOT_COMPARED, reason=f"{ruleset.state}: {verb}"
                     f" {named}")


def firewall_warnings(declared: dict, tree: Tree) -> list[FieldDiff]:
    """rules.v4 and rules.v6 of TurnKey, and a database port the spec's
    allow opens to every address (decision 0097, sections 1 and 2)"""
    fields = []
    legacy = [f"/{path}" for path in LEGACY_RULES if tree.exists(path)]
    if legacy:
        there = " and ".join(legacy) + (" is" if len(legacy) == 1
                                        else " are")
        fields.append(FieldDiff(
            "derived.firewall.legacy", NOT_COMPARED,
            reason=f"warning: {there} there: do not install"
            " iptables-persistent, its rules have no WireGuard port"))
    open_databases = [f"{item.port}/{item.protocol}"
                      for item in allow_of(declared)
                      if not item.sources and
                      (item.port, item.protocol) in DATABASE_PORTS]
    if open_databases:
        fields.append(FieldDiff(
            "firewall.allow", NOT_COMPARED,
            reason="warning: " + "; ".join(
                f"{port} opens a database port to every address: give it"
                " `from`" for port in open_databases)))
    return fields


def monit_fields(declared: dict, resolved, states: dict,
                 tree: Tree, applied: bool = True) -> list[FieldDiff]:
    wg = ((declared.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    rendered = monit.render(resolved, states, wg.get("address"), NOTIFY,
                            monit_cycle(tree).seconds,
                            waiting(tree, [owned.item["unit"] for owned
                                           in resolved.processes]),
                            firewall=declared_state(declared) != fw.OFF)
    file = tree.read(monit.PATH)
    if file.text == rendered.text:
        fields = [FieldDiff("derived.monit", SAME, RENDERED, RENDERED)]
    elif not file.readable and not applied:
        fields = [FieldDiff("derived.monit", DRIFT, RENDERED, None,
                            note=NOT_APPLIED)]
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
