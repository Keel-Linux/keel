# Copyright (c) 2026 KeelLinux maintainers
"""Run the inspect collector and compare, in one call for library users"""

from dataclasses import replace

from keel.diff.appliance import appliance_fields, vip_fields
from keel.diff.compare import LISTEN_FIELD, compare
from keel.diff.filesync import filesync_fields
from keel.diff.handshakes import handshake_fields, mtu_fields
from keel.diff.report import DRIFT, Comparison, FieldDiff
from keel.inspect import ROOT_DEFAULT, inspect_root
from keel.inspect.tree import Tree
from keel.inspect.units import read_units

SOCKET_NOTE = (
    "{units} override bind-address with socket activation: the server"
    " answers on the socket's addresses, not the declared ones."
    " keel spec apply --system masks the socket and restarts the server"
)


def diff_root(declared: dict, root: str = ROOT_DEFAULT) -> Comparison:
    """Compare `declared` with the machine under `root`; nothing is written

    The overlays and Monit's derived file last: they are compared with
    systemd and with what apply renders, not with what inspect writes;
    on the live system, each peer's WireGuard handshake (keel#117), and
    the file replication's counters (0050's amendment).
    """
    found = compare(declared, inspect_root(root))
    fields = _listen_socket_note(found.fields, declared, root)
    return Comparison(found.root, fields + tuple(
        appliance_fields(declared, root) + vip_fields(declared, root)
        + handshake_fields(declared, root == ROOT_DEFAULT)
        + mtu_fields(declared, root, root == ROOT_DEFAULT)
        + filesync_fields(declared, root, root == ROOT_DEFAULT)
        + first_boot_fields(root)))


def first_boot_fields(root: str) -> list[FieldDiff]:
    """A first boot that refused its spec is drift until an apply succeeds
    (keel#268): the boot continued, and nothing else says so"""
    from keel.system import bootrefusal
    found = bootrefusal.read(root)
    if found is None:
        return []
    return [FieldDiff(bootrefusal.FIELD, DRIFT, "accepted", "refused",
                      note=found.line())]


def _listen_socket_note(
    fields: tuple[FieldDiff, ...], declared: dict, root: str,
) -> tuple[FieldDiff, ...]:
    """When database.server.listen drifts and a socket unit is active,
    name the unit and the remedy (keel#110)"""
    engine = ((declared.get("database") or {}).get("server") or {}).get(
        "engine")
    if engine != "mariadb":
        return fields
    listen = next((one for one in fields if one.field == LISTEN_FIELD
                   and one.status == DRIFT), None)
    if listen is None:
        return fields
    from keel.system.dbmariadb import socket_units
    tree = Tree(root)
    live = root == ROOT_DEFAULT
    units = read_units(tree, socket_units(), live)
    active = [unit for unit in units.values()
              if unit.is_enabled or unit.is_running]
    if not active:
        return fields
    names = ", ".join(unit.unit for unit in active)
    note = SOCKET_NOTE.format(units=names)
    if listen.note:
        note = f"{listen.note}; {note}"
    replaced = replace(listen, note=note)
    return tuple(replaced if one is listen else one for one in fields)
