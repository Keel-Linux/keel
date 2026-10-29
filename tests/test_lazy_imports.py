# Copyright (c) 2026 KeelLinux maintainers
"""The CLI's parser is built without loading the library behind it"""

import subprocess
import sys
import unittest

HEAVY = (
    "keel.commands",
    "keel.diff",
    "keel.inspect",
    "keel.layers",
    "keel.manifest",
    "keel.mesh.commands",
    "keel.system",
)


class TestLazyImports(unittest.TestCase):
    def test_importing_the_cli_loads_no_command_implementation(self):
        code = (
            "import sys, keel.cli; "
            f"loaded = {HEAVY!r}; "
            "print([name for name in loaded if name in sys.modules]); "
            "raise SystemExit(1 if any(name in sys.modules "
            "for name in loaded) else 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
