# Copyright (c) 2026 KeelLinux maintainers
"""Plan network.access: the administrators' interface (decision 0098)

The interface's file, /etc/keel/access/<interface>.conf, is keel's and
rewritten whenever it is not what the spec renders. The node's private
key is made on the node at the first converge, never under --root, as
the mesh's is (keel.network.wgkeys); no private key of an administrator
is ever on the node.

No confirmation window, unlike the overlay (decision 0018): the
interface routes only the /128 of each declared computer inside its own
unique local /64, which validation keeps apart from the uplink and the
mesh, so a change cannot capture the route of the session that runs
apply. A session that runs over the access interface itself lives
through a change of peers, which `wg set` makes one peer at a time with
no restart; only a change of the [Interface] lines (the address, the
port, the key file) restarts `keel-access@<interface>`, and that cuts
such a session for a moment.

`wg set` also removes a peer the interface holds and the spec does not
declare, so a removal (keel access remove) takes effect at once:
WireGuard drops each packet of that key.

The database relays of answer 5 are systemd units of keel's: a socket on
the access address with FreeBind, so it binds before the interface is
up, and systemd-socket-proxyd to the loopback. A unit file of that name
that keel did not write is never replaced.
"""

from keel.network import access as acc
from keel.network.access import conf_path
from keel.system.accstate import AccessState, keel_file
from keel.system.actions import (
    Action,
    GenerateKey,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Step,
    WriteFile,
)

FIELD = "network.access"
CONF_MODE = 0o600
UNIT_MODE = 0o644
LIVE_COMMANDS = ("wg", "wg-quick", "ip", "systemctl")
NO_TOOLS = ("cannot bring the access network up without {missing}: install"
            " wireguard-tools (the core layer gives it to every appliance)")


def plan_access(state: AccessState | None, live: bool,
                available: frozenset[str]) -> list[Step]:
    if state is None:
        return []
    if not state.declared:
        return [Step(FIELD, removed(state, live))]
    missing = [one for one in LIVE_COMMANDS if one not in available]
    if live and missing:
        return [Step(FIELD, (Refuse(NO_TOOLS.format(
            missing=", ".join(missing))),))]
    foreign = [path for path, text in state.relays.items()
               if path in state.wanted and text and not keel_file(text)]
    if state.current and not keel_file(state.current):
        foreign.insert(0, conf_path(state.iface))
    if foreign:
        return [Step(FIELD, tuple(Refuse(
            f"/{path} is there and keel did not write it: it is not"
            " replaced; move it away and apply again") for path in foreign))]
    actions = key_actions(state, live)
    actions += conf_actions(state, live)
    actions += relay_actions(state, live)
    return [Step(FIELD, tuple(actions))]


def key_actions(state: AccessState, live: bool) -> list[Action]:
    if state.key_problem:
        return [Refuse(f"the access network's private key file cannot be"
                       f" used: {state.key_problem}")]
    if state.key_present:
        return []
    if not live:
        return [Note(f"{state.key_path} is not made under --root: the"
                     " node's key is made on the node, at its first"
                     " converge, never in an image (keel-core#8)")]
    return [GenerateKey(state.key_path)]


def conf_actions(state: AccessState, live: bool) -> list[Action]:
    path = conf_path(state.iface)
    unit = acc.UNIT.format(iface=state.iface)
    actions: list[Action] = []
    written = state.current != state.rendered
    if written:
        actions.append(WriteFile(path, state.rendered, CONF_MODE, None,
                                 f"write /{path}"))
    if not live:
        return actions + [Note("not the live system: the access interface"
                               " is not brought up, nothing is enabled")]
    if not state.enabled:
        actions.append(Run(("systemctl", "enable", unit),
                           f"enable {unit}, so the access interface comes"
                           " up at boot"))
    if not state.up:
        return actions + [Run(("systemctl", "restart", unit),
                              f"bring {state.iface} up ({unit})")]
    if acc.interface_lines(state.current) != acc.interface_lines(
            state.rendered):
        return actions + [Run(("systemctl", "restart", unit), (
            f"restart {unit}: its address, port or key file changes; a"
            f" session over {state.iface} breaks for a moment"))]
    if state.held is None:
        return actions + [Run(("systemctl", "restart", unit), (
            f"restart {unit}: the peers {state.iface} holds cannot be"
            " read"))]
    actions += peer_actions(state)
    return actions or [Note(f"unchanged (/{path} says what the spec"
                            f" declares, and {state.iface} holds its"
                            " peers)")]


def peer_actions(state: AccessState) -> list[Action]:
    add, remove = acc.peer_changes(state.wanted_peers, state.held or {})
    found: list[Action] = [
        Run(("wg", "set", state.iface, "peer", key, "allowed-ips", prefix),
            f"add the computer {prefix} to {state.iface}, live")
        for key, prefix in add]
    found += [Run(("wg", "set", state.iface, "peer", key, "remove"),
                  f"remove a peer of {state.iface} that the spec does not"
                  " declare: its packets get no answer from now on")
              for key in remove]
    return found


def relay_actions(state: AccessState, live: bool) -> list[Action]:
    actions: list[Action] = []
    stale = sorted(path for path in state.relays if path not in state.wanted)
    actions += stop_relays(stale, live)
    changed = sorted(path for path, text in state.wanted.items()
                     if state.relays.get(path) != text)
    actions += [WriteFile(path, state.wanted[path], UNIT_MODE, None,
                          f"write /{path} (a database relay on the access"
                          " address, decision 0098)") for path in changed]
    if not live:
        return actions
    if stale or changed:
        actions.append(Run(("systemctl", "daemon-reload"),
                           "reload systemd for the relay units"))
    for unit in acc.relay_socket_units(state.wanted):
        path = f"{acc.RELAY_DIR}/{unit}"
        if unit not in state.sockets_enabled:
            actions.append(Run(("systemctl", "enable", "--now", unit),
                               f"start {unit}: the relay to the database"))
        elif path in changed:
            actions.append(Run(("systemctl", "restart", unit),
                               f"restart {unit}: its file changed"))
    return actions


def stop_relays(paths: list[str], live: bool) -> list[Action]:
    actions: list[Action] = []
    for path in paths:
        unit = path.rsplit("/", 1)[-1]
        if live and unit.endswith(".socket"):
            actions.append(Run(("systemctl", "disable", "--now", unit),
                               f"stop {unit}: the spec has no relay there"))
        actions.append(RemoveFile(path, f"remove /{path}, which keel"
                                  " wrote"))
    return actions


def removed(state: AccessState, live: bool) -> tuple[Action, ...]:
    """The spec has no network.access now: take down what keel wrote.
    The key file stays, so the node keeps its identity if the section
    comes back"""
    unit = acc.UNIT.format(iface=state.iface)
    actions: list[Action] = []
    if live and (state.enabled or state.up):
        actions.append(Run(("systemctl", "disable", "--now", unit),
                           f"stop {unit}: the spec declares no"
                           " network.access"))
    if keel_file(state.current):
        path = conf_path(state.iface)
        actions.append(RemoveFile(path, f"remove /{path}, which keel"
                                  " wrote"))
    actions += stop_relays(sorted(state.relays), live)
    if live and state.relays:
        actions.append(Run(("systemctl", "daemon-reload"),
                           "reload systemd for the relay units"))
    return tuple(actions) or (Note("unchanged (no network.access)"),)
