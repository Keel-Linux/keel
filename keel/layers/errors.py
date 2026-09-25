# Copyright (c) 2026 KeelLinux maintainers
"""The single exception type the layer code raises"""


class ManifestError(Exception):
    """A manifest, or a file it names, cannot be used

    `errors` lists every problem found, so a caller can print them all;
    the message joins them for callers that want one line.
    """

    def __init__(self, path: str, errors: list[str]):
        self.path = path
        self.errors = list(errors)
        super().__init__(f"{path}: " + "; ".join(self.errors))
