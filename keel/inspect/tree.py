# Copyright (c) 2026 KeelLinux maintainers
"""Read only access to a root filesystem, live or offline

The probes never touch the disk: they receive File values and return
findings. This is the one place that reads, so `--root DIR` works on a
mounted container filesystem or on a tree `keel assemble` produced as
well as on `/`.
"""

import glob
import os
from dataclasses import dataclass

NOT_PRESENT = "not present"
PERMISSION_DENIED = "permission denied (root only)"


@dataclass(frozen=True)
class File:
    """The content of one file, or why it could not be read

    `path` is the path as shown in the report; for a command output it is
    the command line.
    """

    path: str
    text: str | None = None
    problem: str | None = None

    @property
    def readable(self) -> bool:
        return self.text is not None

    def lines(self) -> list[str]:
        """Non blank lines with comments removed"""
        found = []
        for line in (self.text or "").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                found.append(stripped)
        return found

    def assignments(self) -> dict[str, str]:
        """KEY=value lines, as in a shell fragment; quotes are stripped"""
        found = {}
        for line in self.lines():
            if line.startswith("export "):
                line = line[len("export "):]
            key, sep, value = line.partition("=")
            if sep and key.strip():
                found[key.strip()] = value.strip().strip("'\"")
        return found


class Tree:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    def path(self, relative: str) -> str:
        return os.path.join(self.root, relative)

    def read(self, relative: str) -> File:
        path = self.path(relative)
        try:
            with open(path, encoding="utf-8", errors="replace") as fob:
                return File(path, fob.read())
        except FileNotFoundError:
            return File(path, problem=NOT_PRESENT)
        except PermissionError:
            return File(path, problem=PERMISSION_DENIED)
        except OSError as e:
            return File(path, problem=f"not readable: {e.strerror}")

    def exists(self, relative: str) -> bool:
        return os.path.lexists(self.path(relative))

    def present(self, relative: str) -> File:
        """Whether a file is there, without opening it

        For a file that holds a secret and whose presence alone is the
        answer: nothing is read, so nothing of it is in memory. The File
        has empty text when present, and says why when it cannot tell.
        """
        path = self.path(relative)
        try:
            os.lstat(path)
        except FileNotFoundError:
            return File(path, problem=NOT_PRESENT)
        except PermissionError:
            return File(path, problem=PERMISSION_DENIED)
        except OSError as e:
            return File(path, problem=f"not readable: {e.strerror}")
        return File(path, "")

    def readlink(self, relative: str) -> str | None:
        try:
            return os.readlink(self.path(relative))
        except OSError:
            return None

    def glob(self, pattern: str) -> list[str]:
        """Matching paths, relative to the root, sorted"""
        prefix = self.root.rstrip("/") + "/"
        return sorted(
            path[len(prefix):] for path in glob.glob(self.path(pattern))
        )

    def read_dir(self, relative: str) -> list[File]:
        """Every regular file directly under a directory, sorted by name"""
        return [
            self.read(name)
            for name in self.glob(os.path.join(relative, "*"))
            if os.path.isfile(self.path(name))
        ]
