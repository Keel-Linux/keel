# Copyright (c) 2026 KeelLinux maintainers
"""Plan the network section on a running machine (decision 0018)

The one field whose converge can cut off the operator who runs it, so it
is the last step of the plan and never a plain write on the live system:
the change is a SwitchNetwork, which reverts by itself unless confirmed
over the new configuration (keel.network).

It converges only what 01ipconfig writes, and only where that file is
the configuration:

- `managed_by: host`, a container: the host writes the interfaces, so
  they are compared by `keel diff` and never converged from inside;
- one interface: the hook configures one, and so does this;
- a field `keel diff` reports as drift. A field inspect could not infer
  (SLAAC and DHCPv6 look alike in the file) is not a reason to bounce an
  interface.
"""

import ipaddress

from keel.diff.compare import compare_section
from keel.diff.report import DRIFT
from keel.system.actions import Action, Note, Refuse, Step, SwitchNetwork
from keel.system.actions import WriteFile, unchanged
from keel.system.netstate import NetworkState

FIELD = "network"
INTERFACES = "etc/network/interfaces"
INTERFACES_MODE = 0o644
DEFAULT_WINDOW = 120
LIVE_COMMANDS = ("ifup", "ifdown", "ip", "systemd-run", "systemctl")
# drift under these changes the file; nameservers only when it can hold them
INTERFACE_FIELDS = ("network.interfaces.", "network.managed_by")


def plan_network(network: dict, state: NetworkState | None, live: bool,
                 available: frozenset[str], window: int = DEFAULT_WINDOW,
                 skip: bool = False) -> list[Step]:
    if state is None:
        return []
    if skip:
        return [Step(FIELD, (Note(
            "not converged in this run (--skip-network)"),))]
    if state.owner == "host":
        return [Step(FIELD, (Note(
            "the host owns this container's interfaces: compared by keel"
            " diff, not converged from inside (decision 0018)"),))]
    drift = [
        found.field for found in compare_section(
            FIELD, network, state.observed, state.unknowns)
        if found.status == DRIFT
    ]
    if not drift:
        return [unchanged(FIELD, "the interfaces file says what the spec"
                          " declares")]
    rendered = state.rendered.text if state.rendered else None
    if rendered is not None and rendered == state.current:
        return [Step(FIELD, (Note(
            f"differs: {', '.join(drift)}; the interfaces file already says"
            " what this converge would write, so the difference is outside"
            " it and the interface is left alone"),))]
    if not [one for one in drift if one.startswith(INTERFACE_FIELDS)] \
            and not expressed(network, rendered):
        return [Step(FIELD, (Note(
            f"differs: {', '.join(drift)}; ifupdown writes nameservers only"
            " in a static stanza of their family, so the interfaces file"
            " cannot hold them and the interface is left alone"),))]
    refusal = not_convergeable(network, state)
    actions = (refusal,) if refusal else tuple(
        change(network, state, live, available, window))
    return [Step(FIELD, (Note(f"differs: {', '.join(drift)}"), *actions))]


def not_convergeable(network: dict, state: NetworkState) -> Refuse | None:
    """Drift this converge will not touch; refused, so the run says so

    A container is refused even when declared `managed_by: file`: besides
    its host owning the interfaces, lxcfs dates /proc/uptime from the
    container's start while process start times count from the host's
    boot, so the confirmation could not tell an old session from a new one.
    """
    if state.in_container:
        return Refuse("declared managed_by: file, but this is a container,"
                      " whose host writes its interfaces")
    interfaces = network.get("interfaces") or {}
    if len(interfaces) != 1:
        return Refuse(f"{len(interfaces)} interfaces declared; the"
                      " interfaces file configures one, as 01ipconfig does")
    name = str(next(iter(interfaces)))
    present = [str(one) for one in
               ((state.observed or {}).get("interfaces") or {})]
    if present and name not in present:
        return Refuse(f"{name} is declared and the file configures"
                      f" {', '.join(present)}: moving the configuration to"
                      " another interface would leave the old one up with"
                      " its addresses, so it is not converged")
    return None


def expressed(network: dict, rendered: str | None) -> bool:
    """Whether every declared nameserver appears in the rendered file"""
    if rendered is None:
        return True  # the refusal for an unrenderable file says more
    written = " ".join(
        line.strip() for line in rendered.splitlines()
        if line.strip().startswith("dns-nameservers")
    ).split()
    return all(str(server) in written
               for server in network.get("nameservers") or [])


def change(network: dict, state: NetworkState, live: bool,
           available: frozenset[str], window: int) -> list[Action]:
    if state.pending:
        return [Refuse("a network change is waiting for its confirmation:"
                       " keel network confirm from a new session, or let it"
                       " revert, before another one")]
    rendered = state.rendered
    if rendered is None or rendered.text is None:
        reason = rendered.problem if rendered else "nothing rendered"
        return [Refuse(f"cannot render the interfaces file: {reason}")]
    if not live:
        return [
            WriteFile(INTERFACES, rendered.text, INTERFACES_MODE, None,
                      f"write /{INTERFACES}"),
            Note("not the live system: no interface brought up, no revert"
                 " armed"),
        ]
    missing = [name for name in LIVE_COMMANDS if name not in available]
    if missing:
        return [Refuse(f"cannot change the network safely without"
                       f" {', '.join(missing)}")]
    iface, declared = next(iter((network.get("interfaces") or {}).items()))
    return [SwitchNetwork(
        iface=str(iface),
        path=INTERFACES,
        content=rendered.text,
        window=window,
        addresses=static_addresses(declared or {}),
        gateways=gateways(declared or {}),
        old_gateways=observed_gateways(state.observed),
    )]


def static_addresses(iface: dict) -> tuple[str, ...]:
    return tuple(
        str(ipaddress.ip_interface(str(family["address"])).ip)
        for family in ((iface.get(name) or {}) for name in ("ipv6", "ipv4"))
        if family.get("method") == "static" and family.get("address")
    )


def gateways(iface: dict) -> tuple[str, ...]:
    return tuple(
        str(family["gateway"])
        for family in ((iface.get(name) or {}) for name in ("ipv6", "ipv4"))
        if family.get("gateway")
    )


def observed_gateways(observed: dict | None) -> tuple[str, ...]:
    interfaces = (observed or {}).get("interfaces") or {}
    return tuple(
        found for iface in interfaces.values()
        for found in gateways(iface or {})
    )
