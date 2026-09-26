# Copyright (c) 2026 KeelLinux maintainers
"""Serialise a Comparison: report lines for a terminal, JSON for a caller"""

import json

from keel.diff.report import STATUSES, Comparison


def report_lines(comparison: Comparison) -> list[str]:
    """One line per field, in spec order, then the summary"""
    lines = [field.line() for field in comparison.fields]
    lines.append(comparison.summary())
    return lines


def to_json(comparison: Comparison, spec_path: str) -> str:
    """The same content for a caller such as confconsole

    `exit_code` is the code the command returns, so a caller can show the
    right message without reproducing the precedence rule.
    """
    document = {
        "spec": spec_path,
        "root": comparison.root,
        "fields": [field.to_dict() for field in comparison.fields],
        "counts": {
            status.replace(" ", "_"): comparison.count(status)
            for status in STATUSES
        },
        "drift": comparison.drift,
        "incomplete": comparison.incomplete,
        "exit_code": comparison.code,
    }
    return json.dumps(document, indent=2) + "\n"
