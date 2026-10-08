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
