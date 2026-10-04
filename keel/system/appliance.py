# Copyright (c) 2026 KeelLinux maintainers
"""Plan the appliance: the overlays' units and Monit's file (0041)

The spec's `overlays` says which overlays run; each one's processes
name the units. `enabled` enables and starts them, `disabled` stops and
disables them, in the order `requires` gives: what an overlay requires
comes up before it and goes down after it. Nothing is ever masked or
unmasked, so what `systemctl enable` undoes stays what an operator,
Webmin and keel all expect (Keel-Linux/common, packages/README.md).
CrowdSec's identity is made on its first enable (keel.system.crowdsec).
etcd's configuration is rendered from the mesh's state, and etcd waits
for its cluster before anything is started (keel.system.etcd).
An overlay's state hooks, Coraza's for one, which has no unit, run after
its units come up and before they go down (keel.system.hooks).

Monit's file, /etc/keel/monit/keel-manifest.conf, is always written
(0041, "Resolved"): the appliance's own processes and checks, and those
of every enabled overlay (keel.manifest.monit). It is included from
/etc/monit/conf.d/ by a link, present only while `monitor.enabled` is
true, so turning the monitor on activates checks that already exist. A
spec without a monitor section leaves the link as it is, as the monitor
step leaves keel.conf (keel#46).

Monit's step comes first: turning an overlay off removes its checks
before its units stop, so Monit never restarts what the spec just
stopped; turning one on adds checks Monit holds for two cycles, by
which time the units have started.
"""

from keel.manifest.monit import render
from keel.manifest.resolve import Resolved
from keel.system.actions import (
    Action,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Step,
    Symlink,
    WriteFile,
)
from keel.system.appstate import (
    MANIFEST_MONIT,
    MONIT_LINK,
    ApplianceState,
    overlay_units,
)
from keel.system.crowdsec import OVERLAY as CROWDSEC
from keel.system.crowdsec import plan_identity
from keel.system.etcd import OVERLAY as ETCD
from keel.system.etcd import plan_etcd, waiting
from keel.system.hooks import plan_hooks
from keel.system.monitor import NOTIFY, reload

MONIT_FIELD = "derived.monit"
MODE = 0o600
ENABLED = "enabled"
DISABLED = "disabled"

__all__ = ["MANIFEST_MONIT", "MONIT_LINK", "plan_appliance"]


def plan_appliance(doc: dict, state: ApplianceState | None, live: bool,
                   available: frozenset[str]) -> list[Step]:
    if state is None:
        return []
    if state.resolved is None:
        return [Step("appliance", tuple(
            Refuse(problem) for problem in state.problems))]
    states = doc.get("overlays") or {}
    steps = [plan_monit(doc, states, state, live, available)]
    for name in converge_order(state.resolved, states):
        units = overlay_units(state.resolved, name)
        if units or state.hooks.get(name):
            steps.append(plan_overlay(name, states.get(name), units, state,
                                      live, available))
    return steps


def converge_order(resolved: Resolved, states: dict) -> list[str]:
    """What goes down first, dependants before what they require; then
    what comes up, what is required before what requires it"""
    requires = {state.name: tuple(state.manifest.get("requires") or ())
                for state in resolved.overlays}
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(name: str) -> None:
        # rule 10 refuses a cycle; `seen` keeps one from recursing anyway
        if name in seen:
            return
        seen.add(name)
        for required in requires.get(name, ()):
            visit(required)
        ordered.append(name)

    for name in requires:
        visit(name)
    down = [name for name in reversed(ordered)
            if states.get(name) != ENABLED]
    return down + [name for name in ordered if states.get(name) == ENABLED]


def plan_overlay(name: str, wanted: str | None, units: tuple[str, ...],
                 state: ApplianceState, live: bool,
                 available: frozenset[str]) -> Step:
    field = f"overlays.{name}"
    if units and live and "systemctl" not in available:
        return Step(field, (Refuse(
            "systemctl not found: the units cannot be converged"),))
    systemctl = ("systemctl",) if live else (
        "systemctl", f"--root={state.root}")
    on = wanted == ENABLED
    hooks = state.hooks.get(name)
    if hooks and hooks.problems:
        # a hook that is not safe to run as root stops the whole step
        return Step(field, tuple(Refuse(problem)
                                 for problem in hooks.problems))
    hooked = plan_hooks(name, ENABLED if on else DISABLED, hooks, live)
    masked = [unit for unit in units if on and state.units[unit].is_masked]
    if masked:
        # refused before anything is made, CrowdSec's identity included
        return Step(field, tuple(Refuse(
            f"{unit} is masked, and keel never unmasks a unit: systemctl"
            f" unmask {unit}, then apply again") for unit in masked))
    actions: list[Action] = []
    identity: list[Action] = []
    if on and name == CROWDSEC:
        identity = plan_identity(state.crowdsec, live, available)
        actions += identity
    made = any(not isinstance(action, Note) for action in identity)
    if on and name == ETCD and state.etcd is not None:
        rendered, made = plan_etcd(state.etcd, live)
        if waiting(state.etcd) or any(isinstance(action, Refuse)
                                      for action in rendered):
            return Step(field, tuple(rendered))
        actions += rendered
    if not on:
        # what reacts to the overlay lets go of it before its units stop
        actions += hooked
    for unit in (units if on else tuple(reversed(units))):
        found = state.units[unit]
        if on:
            actions += start(systemctl, unit, found, live, made,
                             name == ETCD)
        else:
            actions += stop(systemctl, unit, found, live)
    if on:
        actions += hooked
    if all(isinstance(action, Note) for action in actions):
        # under --root a hook was not run, which is not "unchanged"
        listed = units + tuple(hook.path for hook in hooks.hooks
                               if live) if hooks else units
        if listed or live:
            what = f": {', '.join(listed)}" if listed else ""
            actions.append(Note(f"unchanged ({wanted or DISABLED}{what})"))
    return Step(field, tuple(actions))


def start(systemctl: tuple[str, ...], unit: str, found, live: bool,
          made: bool, no_block: bool = False) -> list[Action]:
    """`no_block` for etcd, which says it started only once a majority
    of its cluster runs"""
    actions: list[Action] = []
    later = ("--no-block",) if no_block else ()
    if not found.is_enabled and not found.is_fixed:
        actions.append(Run((*systemctl, "enable", unit),
                           f"enable {unit}: the overlay is enabled"))
    if live and not found.is_running:
        actions.append(Run(("systemctl", "start", *later, unit),
                           f"start {unit}"))
    elif live and made:
        actions.append(Run(("systemctl", "restart", *later, unit),
                           f"restart {unit}: its configuration changed"
                           if no_block else
                           f"restart {unit}: its identity or its bouncer's"
                           " mode changed"))
    return actions


def stop(systemctl: tuple[str, ...], unit: str, found,
         live: bool) -> list[Action]:
    actions: list[Action] = []
    if live and found.is_running:
        actions.append(Run(("systemctl", "stop", unit), f"stop {unit}"))
    if found.is_enabled:
        actions.append(Run((*systemctl, "disable", unit),
                           f"disable {unit}: the overlay is disabled"))
    return actions


def plan_monit(doc: dict, states: dict, state: ApplianceState, live: bool,
               available: frozenset[str]) -> Step:
    resolved = state.resolved
    wg = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    rendered = render(resolved, states, wg.get("address"), NOTIFY,
                      state.cycle.seconds)
    probes = sum(1 for name in rendered.services
                 if name.startswith("keel-check-"))
    summary = (f"{len(rendered.services) - probes} unit(s) and {probes}"
               f" probe(s) of {resolved.name}")
    actions: list[Action] = [Note(note) for note in rendered.notes]
    target = "/" + MANIFEST_MONIT
    included = state.monit_link == target
    if state.monit_link_present and not included:
        return Step(MONIT_FIELD, (*actions, Refuse(
            f"/{MONIT_LINK} is there and is not keel's link to {target}:"
            " it is not replaced; move it away and apply again"),))
    monitor = doc.get("monitor")
    wanted = included if monitor is None else monitor.get("enabled") is True
    written = state.monit_file.text != rendered.text
    if written:
        actions.append(WriteFile(MANIFEST_MONIT, rendered.text, MODE, None,
                                 f"write {target}: {summary}"))
    moved = wanted != included
    if wanted and not included:
        actions.append(Symlink(MONIT_LINK, target,
                               f"include {target} from /etc/monit/conf.d:"
                               " the monitor is enabled"))
    elif included and not wanted:
        actions.append(RemoveFile(MONIT_LINK,
                                  f"stop including {target}: the monitor"
                                  " is off"))
    if moved or (written and wanted):
        actions += reload(live, available)
    if all(isinstance(action, Note) for action in actions):
        where = "included" if included else "not included"
        actions.append(Note(f"unchanged ({target}, {summary}, {where})"))
    return Step(MONIT_FIELD, tuple(actions))
