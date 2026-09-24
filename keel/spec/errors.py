# Copyright (c) 2026 KeelLinux maintainers
"""The single exception type the spec code raises"""


class SpecError(Exception):
    """A spec file, or something it references, cannot be used"""
