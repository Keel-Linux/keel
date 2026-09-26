# Copyright (c) 2026 KeelLinux maintainers
"""Report drift between the declared spec and the machine

Brief section 5.2. The observed side is exactly what `keel inspect`
collects, through the same code path, so every probe is shared and a spec
written by inspect diffs clean against the machine it was read from.
Nothing here writes to the system.
"""

from keel.diff.compare import compare
from keel.diff.emit import report_lines, to_json
from keel.diff.observe import diff_root
from keel.diff.report import (
    DRIFT,
    NOT_COMPARED,
    NOT_DECLARED,
    SAME,
    UNKNOWN,
    Comparison,
    FieldDiff,
)

__all__ = [
    "DRIFT",
    "NOT_COMPARED",
    "NOT_DECLARED",
    "SAME",
    "UNKNOWN",
    "Comparison",
    "FieldDiff",
    "compare",
    "diff_root",
    "report_lines",
    "to_json",
]
