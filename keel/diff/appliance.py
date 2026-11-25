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
import shutil
from dataclasses import replace
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
from keel.spec.validate_firewall import declared_state
from keel.system.firewall import allow_of, foretell, guard, settled
from keel.system.fwstate import observe_firewall, table_digest
from keel.system.listeners import sees_every_process
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
# keel#318: diff speaks for the apply a person runs, the only one rule B
# lets begin enforcement
PERSON = "an apply a person runs (keel spec apply --system) writes"
MESH_KEEPS = ("; keel mesh, which runs with no person, writes report until"
              " then: it never begins enforcement (decision 0097)")
FROM_SPEC = {
    fw.ENFORCE: "the spec says enforce",
    fw.REPORT: "the spec says firewall.state: report, so rule B never"
               " moves it",
}
PERSON_HOLDS = ("an apply a person runs (keel spec apply --system) changes"
                " no rule")
PENDING = "a network change waits for keel network confirm (decision 0018)"
AS_ROOT = ("ss shows the process of each socket to root only: run keel"
           " diff as root")
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
    live = tree.root == LIVE_ROOT
    state = observe_firewall(tree, live)
    if live and not sees_every_process():
        state = replace(state, listeners=None, listeners_source=AS_ROOT)
        if settled(state, said, True) is None:
            return [FieldDiff("derived.firewall", UNKNOWN, RULESET, None,
                              "rule B needs the process of each socket,"
                              " and ss shows it to root only: run keel"
                              " diff as root")] + warnings
    if not state.ssh_ports:
        decided = settled(state, said, True)
        wanted = f"{RULESET}, {decided[0]}" if decided else RULESET
        return [FieldDiff("derived.firewall", UNKNOWN, wanted, None,
                          "the ports sshd listens on cannot be determined"
                          f" ({state.ssh_source})")] + warnings
    foretold = foretell(declared, resolved, state, said, True)
    ruleset = foretold.ruleset
    wanted = f"{RULESET}, {ruleset.state}"
    if file.text == ruleset.text:
        fields = [FieldDiff("derived.firewall", SAME, wanted, wanted)]
    else:
        fields = [FieldDiff("derived.firewall", DRIFT, wanted,
                            DIFFERS if file.readable else None)]
    withheld = withheld_by(state, live)
    fields.append(FieldDiff("derived.firewall.state", NOT_COMPARED,
                            reason=f"{PERSON_HOLDS}: {withheld}")
                  if withheld else state_field(said, state, foretold))
    key = "derived.firewall.loaded"
    if not live:
        return fields + [FieldDiff(key, NOT_COMPARED, None, None,
                                   NOT_LIVE)] + warnings
    held = table_digest()
    fields.append(FieldDiff(key, SAME if held == ruleset.digest
                            else DRIFT, ruleset.digest, held))
    listeners = (FieldDiff("derived.firewall.listeners", NOT_COMPARED,
                           reason=f"{PERSON_HOLDS}, so it closes nothing")
                 if withheld else listener_field(state, foretold))
    return fields + [listeners] + warnings


def withheld_by(state, live: bool) -> str:
    """Why the apply a person runs leaves the firewall as it is: the
    guards of its plan (keel.system.firewall.guard), and a network
    change that waits for keel network confirm; empty when it writes"""
    available = frozenset({"nft"}) if live and shutil.which("nft") \
        else frozenset()
    refusal = guard(state, live, available)
    if refusal is not None:
        return refusal.summary
    return PENDING if state.pending else ""


def state_field(said: str | None, state, foretold) -> FieldDiff:
    """What an apply a person runs writes, and why, in the words of its
    plan; and where keel mesh, which runs with no person, writes report"""
    target = foretold.ruleset.state
    reasons = foretold.reasons or [FROM_SPEC[target]]
    text = "; ".join(reason.removeprefix(f"{target}: ").removeprefix(
        f"{target}, ") for reason in reasons)
    joiner = ", " if text.startswith("as ") else ": "
    mesh = settled(state, said, False)
    tail = MESH_KEEPS if target == fw.ENFORCE and mesh is not None and \
        mesh[0] == fw.REPORT else ""
    return FieldDiff("derived.firewall.state", NOT_COMPARED,
                     reason=f"{PERSON} {target}{joiner}{text}{tail}")


def listener_field(state, foretold) -> FieldDiff:
    """The sockets on an address that is not a loopback that the apply
    closes, or that enforce would close, as its plan names them"""
    key = "derived.firewall.listeners"
    if state.listeners is None:
        return FieldDiff(key, NOT_COMPARED, reason=state.listeners_source)
    target = foretold.ruleset.state
    named = "; ".join(foretold.closes) or (
        "closes nothing" if target == fw.ENFORCE
        else "enforce would close nothing")
    return FieldDiff(key, NOT_COMPARED, reason=f"{target}: {named}")


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
