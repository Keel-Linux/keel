# Copyright (c) 2026 KeelLinux maintainers
"""Decision 0070: the CLI parser loads without the library

Building the parser and printing help must not import keel.commands,
keel.system, keel.network or any other heavy module.  The test imports
keel.cli, builds the parser, then checks that the heavy modules are
absent from sys.modules.
"""

import json
import os
import subprocess
import sys
import textwrap
import unittest


# The source tree that holds keel/, so the subprocess can find it.
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The modules the parser must NOT pull in (the library proper).
HEAVY = frozenset((
    "keel.commands",
    "keel.diff",
    "keel.inspect",
    "keel.layers",
    "keel.network.confirm",
    "keel.network.live",
    "keel.network.session",
    "keel.network.switch",
    "keel.network.wgkeys",
    "keel.system",
    "keel.system.filesync",
    "dataclasses",
    "importlib.metadata",
))


class TestLazyImports(unittest.TestCase):
    """The parser must be buildable without loading the library"""

    def _loaded_after(self, snippet: str) -> set[str]:
        """Run `snippet` in a clean subprocess, return the set of loaded
        module names that overlap with HEAVY."""
        script = (
            "import sys, json\n"
            + snippet + "\n"
            + "print(json.dumps(sorted(sys.modules.keys())))\n"
        )
        env = dict(os.environ, PYTHONPATH=_SRC)
        result = subprocess.run(
            [sys.executable, "-S", "-c", script],
            capture_output=True, text=True, check=True, env=env,
        )
        names = set(json.loads(result.stdout))
        return names & HEAVY

    def test_build_parser_does_not_load_heavy_modules(self):
        """keel.cli.build_parser() must not import any library module"""
        leaked = self._loaded_after(
            "from keel.cli import build_parser; build_parser()"
        )
        self.assertEqual(leaked, set(),
                         f"build_parser() imported heavy modules: {leaked}")

    def test_help_does_not_load_heavy_modules(self):
        """keel --help must not import any library module"""
        leaked = self._loaded_after(
            "import contextlib, io\n"
            "from keel.cli import main\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n"
            "    try:\n"
            "        main(['--help'])\n"
            "    except SystemExit:\n"
            "        pass"
        )
        self.assertEqual(leaked, set(),
                         f"--help imported heavy modules: {leaked}")

    def test_version_is_lazy(self):
        """Importing keel must not load importlib.metadata"""
        leaked = self._loaded_after("import keel")
        self.assertNotIn("importlib.metadata", leaked,
                         "importing keel loaded importlib.metadata eagerly")

    def test_version_access_loads_metadata(self):
        """Accessing keel.__version__ must load importlib.metadata"""
        script = textwrap.dedent("""\
            import sys, json, keel
            _ = keel.__version__
            print(json.dumps("importlib.metadata" in sys.modules))
        """)
        env = dict(os.environ, PYTHONPATH=_SRC)
        result = subprocess.run(
            [sys.executable, "-S", "-c", script],
            capture_output=True, text=True, check=True, env=env,
        )
        self.assertTrue(json.loads(result.stdout),
                        "accessing __version__ did not load importlib.metadata")
