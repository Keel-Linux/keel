# Copyright (c) 2026 KeelLinux maintainers
"""Drift of the access network (decision 0098)

Compared with what apply renders, not with what inspect reads: keel's
file under /etc/keel/access, on the live system `keel-access@<iface>`
enabled and the interface up, each declared computer held with its
/128, and each database relay unit. A peer the interface holds and the
spec does not declare is drift by itself, named by its public key: it is
someone who can reach the access ports, and apply removes it. Peers are
read from `wg show <iface> allowed-ips`, never from `dump`, which holds
the node's private key.
"""

from keel.diff.report import DRIFT, SAME, FieldDiff
from keel.network import access as acc
from keel.system.accstate import AccessState, observe_access

FIELD = "network.access"
APPLY = "keel spec apply --system"


def access_fields(declared: dict, root: str, live: bool) -> list[FieldDiff]:
    return fields_of(observe_access(root, declared), declared, live)


def fields_of(state: AccessState | None, declared: dict,
              live: bool) -> list[FieldDiff]:
    if state is None:
        return []
    if not state.declared:
        return [FieldDiff(FIELD, DRIFT, None, f"keel's {state.iface}",
                          note="the spec declares no network.access, and"
                          f" keel's access interface is there: {APPLY}"
                          " takes it down")]
    fields = [file_field(state)] + [
        FieldDiff(f"{FIELD}.relays.{path.rsplit('/', 1)[-1]}",
                  SAME if state.relays.get(path) == text else DRIFT,
                  "keel's relay unit",
                  "same" if state.relays.get(path) == text else
                  ("missing" if state.relays.get(path) is None
                   else "another"))
        for path, text in sorted(state.wanted.items())]
    fields += [FieldDiff(f"{FIELD}.relays.{path.rsplit('/', 1)[-1]}", DRIFT,
                         None, "keel's relay unit", note=f"{APPLY} removes"
                         " it") for path in sorted(state.relays)
               if path not in state.wanted]
    if live:
        fields += live_fields(state, declared)
    return fields


def file_field(state: AccessState) -> FieldDiff:
    path = f"/{acc.conf_path(state.iface)}"
    if state.current == state.rendered:
        return FieldDiff(f"{FIELD}.file", SAME, path, path)
    observed = "missing" if state.current is None else "another content"
    return FieldDiff(f"{FIELD}.file", DRIFT, path, observed,
                     note=f"{path} is not what the spec renders: {APPLY}")


def live_fields(state: AccessState, declared: dict) -> list[FieldDiff]:
    unit = acc.UNIT.format(iface=state.iface)
    found = ("enabled" if state.enabled else "disabled") + ", " + (
        "up" if state.up else "down")
    fields = [FieldDiff(f"{FIELD}.unit", SAME if found == "enabled, up"
                        else DRIFT, "enabled, up", f"{unit} {found}")]
    if not state.up:
        return fields
    held = state.held or {}
    names = {str(peer["public_key"]): str(peer.get("name"))
             for peer in acc.peers(acc.section(declared) or {})}
    for key, prefix in sorted(state.wanted_peers.items()):
        name = f"{FIELD}.peers.{names.get(key, key)}"
        fields.append(FieldDiff(name, SAME if held.get(key) == prefix
                                else DRIFT, prefix,
                                held.get(key) or "not held"))
    fields += [FieldDiff(f"{FIELD}.peers.{key}", DRIFT, None,
                         held[key] or "no address",
                         note=f"{state.iface} holds a peer the spec does not"
                         f" declare: {APPLY} removes it")
               for key in sorted(held) if key not in state.wanted_peers]
    return fields
