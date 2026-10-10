# Copyright (c) 2026 KeelLinux maintainers
"""Run the inspect collector and compare, in one call for library users"""

from keel.diff.appliance import appliance_fields, vip_fields
from keel.diff.compare import compare
from keel.diff.handshakes import handshake_fields, mtu_fields
from keel.diff.report import Comparison
from keel.inspect import ROOT_DEFAULT, inspect_root


def diff_root(declared: dict, root: str = ROOT_DEFAULT) -> Comparison:
    """Compare `declared` with the machine under `root`; nothing is written

    The overlays and Monit's derived file last: they are compared with
    systemd and with what apply renders, not with what inspect writes;
    on the live system, each peer's WireGuard handshake (keel#117).
    """
    found = compare(declared, inspect_root(root))
    return Comparison(found.root, found.fields + tuple(
        appliance_fields(declared, root) + vip_fields(declared, root)
        + handshake_fields(declared, root == ROOT_DEFAULT)
        + mtu_fields(declared, root, root == ROOT_DEFAULT)))
