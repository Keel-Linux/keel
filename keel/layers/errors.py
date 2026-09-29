# Copyright (c) 2026 KeelLinux maintainers
"""The exception types the layer code raises"""


class FileProblem(Exception):
    """A file, or something it names, cannot be used

    `errors` lists every problem found, so a caller can print them all;
    the message joins them for callers that want one line.
    """

    def __init__(self, path: str, errors: list[str]):
        self.path = path
        self.errors = list(errors)
        super().__init__(f"{path}: " + "; ".join(self.errors))


class ManifestError(FileProblem):
    """A manifest, or a file it names, cannot be used"""


class ChannelError(FileProblem):
    """A channel pointer, or the state record of one, cannot be used"""


class SignatureError(Exception):
    """A clear signed file is not signed by a key that may have signed it

    Raised instead of returning the text, because gpgv writes the plain
    text of a document whose signature it refused: a caller that read
    the output of a failed verification would be reading unsigned data.
    """


class LayerError(Exception):
    """pull or assemble cannot go on; `code` is the exit code to return

    Raised with the code from keel.exits that names the reason, so the
    command function prints the message and returns the code without
    knowing which step failed.
    """

    def __init__(self, code: int, message: str):
        self.code = code
        super().__init__(message)
