# Copyright (c) 2026 KeelLinux maintainers
"""Plan network.overlay: the WireGuard interface (decisions 0018, 0020)

The overlay belongs to the appliance on either kind of machine: its file
is /etc/wireguard/<interface>.conf, which the host of a container does
not write, so it is converged from inside even when the uplink is
`managed_by: host`. A management session can run over it, and the routes
wg-quick adds for a peer can capture the uplink's, so a change goes
through the same window as the uplink's (keel.network.switch), with
wg-quick in place of ifupdown.

keel owns the file: it is rewritten whenever it is not exactly what the
spec renders. The private key is not in it (keel.network.wireguard), and
is made on this machine the first time the overlay is converged, never
under --root, where it would end up in an image (keel-core#8).
wg-quick@<interface> is enabled once a change is confirmed, not before,
so a reboot inside the window of a first overlay leaves nothing up.
"""

from keel.network import marker
from keel.network.wireguard import conf_path
from keel.system.actions import (
    Action,
    GenerateKey,
    Note,
    Refuse,
    Run,
    Step,
    SwitchNetwork,
    WriteFile,
)
from keel.system.ovstate import OverlayState

FIELD = "network.overlay"
CONF_MODE = 0o600
LIVE_COMMANDS = ("wg", "wg-quick", "ip", "systemd-run", "systemctl")
NO_TOOLS = (
    "cannot bring the overlay up without {missing}: install wireguard-tools"
    " (Debian 13 ships it; the core layer is where every appliance gets it)"
)
NO_MODULE = (
    "the wireguard kernel module is not loaded, and a container cannot"
    " load one: on the host, run `modprobe wireguard` and list wireguard"
    " in /etc/modules-load.d/ so it is loaded at every boot, then apply"
    " again (decision 0018)"
)


def plan_overlay(state: OverlayState | None, live: bool,
                 available: frozenset[str], window: int,
                 skip: bool = False, uplink_moves: bool = False) -> (
    list[Step]
):
    """`uplink_moves` is a SwitchNetwork of the uplink in this same plan"""
    if state is None:
        return []
    missing = [one for one in LIVE_COMMANDS if one not in available]
    if live and missing:
        return [Step(FIELD, (Refuse(NO_TOOLS.format(
            missing=", ".join(missing))),))]
    key = key_actions(state, live)
    if skip:
        return [Step(FIELD, (*key, Note(
            "not brought up in this run (--skip-network)"),))]
    if state.current == state.rendered:
        return [Step(FIELD, (*key, *kept(state, live)))]
    return [Step(FIELD, (*key, *change(state, live, window, uplink_moves)))]


def key_actions(state: OverlayState, live: bool) -> tuple[Action, ...]:
    if state.key_problem:
        return (Refuse(f"the private key file cannot be used:"
                       f" {state.key_problem}"),)
    if state.key_present:
        return ()
    if not live:
        return (Note(f"{state.key_path} is not made under --root: a private"
                     " key is made on the machine that uses it, at its"
                     " first converge, never in an image (keel-core#8)"),)
    return (GenerateKey(state.key_path),)


def kept(state: OverlayState, live: bool) -> tuple[Action, ...]:
    """The file says what the spec renders; only the boot unit may lack"""
    note = Note(f"unchanged (/{conf_path(state.iface)} says what the spec"
                " declares)")
    if not live or state.enabled or state.pending:
        return (note,)
    unit = f"wg-quick@{state.iface}"
    return (note, Run(("systemctl", "enable", unit),
                      f"enable {unit}, so the overlay comes up at boot"))


def change(state: OverlayState, live: bool, window: int,
           uplink_moves: bool) -> list[Action]:
    path = conf_path(state.iface)
    if state.pending:
        return [Refuse("a network change is waiting for its confirmation:"
                       " keel network confirm from a new session, or let it"
                       " revert, before another one")]
    if uplink_moves:
        return [Refuse("the uplink changes in this run and waits for its"
                       " confirmation; confirm it, then apply again for the"
                       " overlay, one change in the window at a time")]
    if live and state.in_container and not state.module_loaded:
        return [Refuse(NO_MODULE)]
    if not live:
        return [
            WriteFile(path, state.rendered, CONF_MODE, None, f"write /{path}"),
            Note("not the live system: no interface brought up, no revert"
                 " armed, nothing enabled"),
        ]
    return [SwitchNetwork(
        iface=state.iface, path=path, content=state.rendered, window=window,
        addresses=state.addresses, gateways=(), old_gateways=(),
        kind=marker.OVERLAY,
    )]
