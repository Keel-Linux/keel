# Copyright (c) 2026 KeelLinux maintainers
"""Write a spec from a machine, reporting what could not be inferred

Brief section 5.2, and the first half of keel-transition (section 7).
Every probe is a pure function over file contents; keel.inspect.collect
is the only code that reads the filesystem, under a root that defaults
to `/` and may be an offline tree.
"""

from keel.inspect.collect import inspect_root
from keel.inspect.constants import REQUIRED, ROOT_DEFAULT, SECRETS_DIR_DEFAULT
from keel.inspect.emit import report_lines, to_yaml
from keel.inspect.report import Finding, Inspection

__all__ = [
    "REQUIRED",
    "ROOT_DEFAULT",
    "SECRETS_DIR_DEFAULT",
    "Finding",
    "Inspection",
    "inspect_root",
    "report_lines",
    "to_yaml",
]
