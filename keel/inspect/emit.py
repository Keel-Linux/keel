# Copyright (c) 2026 KeelLinux maintainers
"""Serialise an Inspection: the spec as YAML, the findings as a report"""

import yaml

from keel.inspect.report import Inspection


def to_yaml(inspection: Inspection) -> str:
    """The spec document, headed by a comment naming its origin"""
    header = (
        f"# Written by keel inspect from {inspection.root}:"
        f" {inspection.appliance}\n"
        "# Fields that could not be inferred are listed in the report;"
        " edit before apply.\n"
    )
    body = yaml.safe_dump(
        inspection.spec, sort_keys=False, default_flow_style=False,
        allow_unicode=True,
    )
    return header + body


def report_lines(inspection: Inspection) -> list[str]:
    """One line per finding, then the summary"""
    lines = [finding.line() for finding in inspection.findings]
    lines += list(inspection.vip)
    lines.append(inspection.summary())
    return lines
