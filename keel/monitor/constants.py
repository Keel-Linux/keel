# Copyright (c) 2026 KeelLinux maintainers
"""Monitor constants the CLI parser needs without loading the library

Decision 0070: the values live here so that keel.cli can import them
without loading keel.monitor.notify or keel.monitor.channelfile.
"""

PATH = "/etc/keel/monitor.json"
LEVELS = ("warn", "critical", "recovery")
CHECKS = ("disk", "inodes", "memory", "swap", "cpu", "load", "link",
          "throughput", "service", "restarts")
DIRECTIONS = ("upload", "download")
