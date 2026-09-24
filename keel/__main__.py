# Copyright (c) 2026 KeelLinux maintainers
"""Entry point for `python3 -m keel`"""

import sys

from keel.cli import main

if __name__ == "__main__":
    sys.exit(main())
