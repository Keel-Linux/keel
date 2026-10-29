# Copyright (c) 2026 KeelLinux maintainers
"""The monitor's names, without importing its channels or its sender"""

LEVELS = ("warn", "critical", "recovery")
CHECKS = ("disk", "inodes", "memory", "swap", "cpu", "load", "link",
          "throughput", "service", "restarts")
DIRECTIONS = ("upload", "download")
MONITOR_PATH = "/etc/keel/monitor.json"
