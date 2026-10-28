# Copyright (c) 2026 KeelLinux maintainers
"""keel's version comes from one place (keel#98)

The installed package's metadata when there is one (what dpkg
installed, from pyproject.toml), else the fallback the package carries,
which the changelog and pyproject.toml must agree with: keel --version
printed 0.19.0 on keel 0.23.0 because __init__.py had its own number.
"""

import importlib.metadata
import os
import re
import unittest
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

import keel

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def changelog_version() -> str:
    with open(os.path.join(REPO, "debian", "changelog")) as fob:
        first = fob.readline()
    return re.match(r"keel \(([^)]+)\)", first).group(1)


def pyproject_version() -> str:
    with open(os.path.join(REPO, "pyproject.toml")) as fob:
        return re.search(r'^version = "([^"]+)"', fob.read(),
                         re.MULTILINE).group(1)


def entries_without_a_trailer(text: str) -> list[str]:
    """The versions of the entries that have no trailer line before the
    next entry starts. dpkg-parsechangelog only warns about one ("found
    start of entry where expected more change data or trailer"), and the
    package still builds (keel#155, item 3: the entry of 0.23.18)."""
    missing: list[str] = []
    current = None
    for line in text.splitlines():
        header = re.match(r"keel \(([^)]+)\) ", line)
        if header:
            if current is not None:
                missing.append(current)
            current = header.group(1)
        elif line.startswith(" -- ") and current is not None:
            current = None
    if current is not None:
        missing.append(current)
    return missing


class TestTheChangelog(unittest.TestCase):
    def test_every_entry_has_its_trailer(self):
        with open(os.path.join(REPO, "debian", "changelog")) as fob:
            self.assertEqual(entries_without_a_trailer(fob.read()), [])

    def test_an_entry_without_a_trailer_is_found(self):
        text = ("keel (2.0) unstable; urgency=medium\n\n  * b\n\n"
                "keel (1.0) unstable; urgency=medium\n\n  * a\n\n"
                " -- A <a@example.org>  Thu, 15 Oct 2026 09:00:00 +0000\n")
        self.assertEqual(entries_without_a_trailer(text), ["2.0"])
        self.assertEqual(entries_without_a_trailer(text + text[:40]),
                         ["2.0", "2.0"])


class TestTheVersion(unittest.TestCase):
    def test_the_fallback_is_the_changelog_s_and_pyproject_s(self):
        self.assertEqual(keel.FALLBACK_VERSION, changelog_version())
        self.assertEqual(keel.FALLBACK_VERSION, pyproject_version())

    def test_the_installed_metadata_wins_when_there_is_one(self):
        with mock.patch.object(importlib.metadata, "version",
                               return_value="9.9.9"):
            self.assertEqual(keel.version(), "9.9.9")

    def test_without_metadata_the_fallback_answers(self):
        with mock.patch.object(
                importlib.metadata, "version",
                side_effect=importlib.metadata.PackageNotFoundError("keel")):
            self.assertEqual(keel.version(), keel.FALLBACK_VERSION)

    def test_dunder_version_is_what_version_gives(self):
        self.assertEqual(keel.__version__, keel.version())


if __name__ == "__main__":
    unittest.main()
