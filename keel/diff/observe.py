# Copyright (c) 2026 KeelLinux maintainers
"""Run the inspect collector and compare, in one call for library users"""

from keel.diff.compare import compare
from keel.diff.report import Comparison
from keel.inspect import ROOT_DEFAULT, inspect_root


def diff_root(declared: dict, root: str = ROOT_DEFAULT) -> Comparison:
    """Compare `declared` with the machine under `root`; nothing is written"""
    return compare(declared, inspect_root(root))
