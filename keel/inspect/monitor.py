# Copyright (c) 2026 KeelLinux maintainers
"""The monitor section, read back from the file keel writes for monit

/etc/monit/conf.d/keel.conf is what `apply --system` renders
(keel.monitor.render), so its tests are read back into the thresholds
they came from and `keel diff` compares like for like. The file is read
from its `if` lines, which are what monit acts on, and not from a
comment that could say something else.

Two limits, stated in the report rather than guessed around:

- the channels are not in the file. monit runs keel notify, which reads
  them from the spec when an alert fires, so `monitor.notify` has no
  trace to read and diff does not compare it;
- the file says what monit was told, not that monit is installed or
  running; that is the package's and the service's business.
"""

import re
from dataclasses import dataclass, field

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import NOT_PRESENT, File
from keel.monitor.settings import mbit, minutes, number

KEEL_HEADER = "# written by keel"
# Debian's monitrc, when the file sets no cycle of its own
DEBIAN_CYCLE = 120
DAEMON_RE = re.compile(r"^set\s+daemon\s+(\d+)")
SERVICE_RE = re.compile(
    r"^check\s+(filesystem|system|network)\s+(\S+)"
    r"(?:\s+with\s+(?:path|interface)\s+(\S+))?"
)
HOLD = r"(?:\s+for\s+(\d+)\s+cycles)?"
TESTS = (
    ("usage", re.compile(
        r"^if\s+(space|inode|memory|swap|cpu) usage > ([0-9.]+)%" + HOLD)),
    ("load", re.compile(
        r"^if\s+loadavg \(1min\) per core > ()([0-9.]+)" + HOLD)),
    ("rate", re.compile(
        r"^if\s+(upload|download) > ([0-9]+) B/s" + HOLD)),
)
LINK_RE = re.compile(r"^if\s+failed\s+link\b" + HOLD)
SYSTEM_SERVICES = {
    "keel_memory": "memory", "keel_swap": "swap", "keel_cpu": "cpu",
    "keel_load": "load_per_core",
}
FILESYSTEM_TESTS = (
    ("disk", "warn", "space"),
    ("disk", "critical", "space"),
    ("inodes", "critical", "inode"),
)
NOTIFY_REASON = (
    "the channels are not written to monit's file: keel notify reads them"
    " from the spec when an alert fires; declare at least one before apply,"
    " since enabled: true without a channel does not validate"
)


@dataclass(frozen=True)
class Test:
    measure: str
    limit: float
    hold: int


@dataclass
class Service:
    kind: str
    name: str
    target: str
    tests: list[Test] = field(default_factory=list)


def probe_monitor(conf: File) -> tuple[dict | None, list[Finding]]:
    key = "monitor.enabled"
    if not conf.readable:
        if conf.problem == NOT_PRESENT:
            return {"enabled": False}, [
                inferred(key, "false", f"{conf.path} not present")]
        return None, [missing(key, f"{conf.path} {conf.problem}")]
    text = conf.text or ""
    if not text.startswith(KEEL_HEADER):
        return None, [missing(key, f"{conf.path} was not written by keel,"
                              " so it says nothing about the monitor"
                              " section")]
    checks, findings = read_checks(text, conf.path)
    section = {"enabled": True, "checks": checks}
    return section, [inferred(key, "true", conf.path), *findings,
                     missing("monitor.notify", NOTIFY_REASON)]


def read_services(text: str) -> list[Service]:
    services: list[Service] = []
    for raw in text.splitlines():
        line = raw.strip()
        found = SERVICE_RE.match(line)
        if found:
            services.append(Service(found.group(1), found.group(2),
                                    found.group(3) or ""))
            continue
        if not services:
            continue
        link = LINK_RE.match(line)
        if link:
            services[-1].tests.append(
                Test("link", 0, int(link.group(1) or 1)))
            continue
        for kind, pattern in TESTS:
            test = pattern.match(line)
            if test:
                measure = test.group(1) if kind == "usage" else kind
                services[-1].tests.append(Test(
                    measure, float(test.group(2)), int(test.group(3) or 1)))
    return services


def daemon_cycle(text: str) -> int:
    """The last `set daemon` of the file, as monit reads it, or Debian's"""
    found = [int(match.group(1)) for match in (
        DAEMON_RE.match(line.strip()) for line in text.splitlines()
    ) if match]
    return found[-1] if found else DEBIAN_CYCLE


def whole(value: float) -> int | float:
    return int(value) if float(value).is_integer() else value


def read_checks(text: str, path: str) -> tuple[dict, list[Finding]]:
    services = read_services(text)
    cycle = daemon_cycle(text)
    checks: dict = {}
    findings: list[Finding] = []
    for check, level, measure in FILESYSTEM_TESTS:
        limits = sorted({
            test.limit for service in services
            if service.kind == "filesystem"
            and service.name.startswith(f"keel_{check}_{level}_")
            for test in service.tests if test.measure == measure
        })
        key = f"monitor.checks.{check}.{level}"
        if len(limits) == 1:
            checks.setdefault(check, {})[level] = whole(limits[0])
            findings.append(inferred(key, number(limits[0]), path))
        elif limits:
            findings.append(missing(key, f"{path}: the filesystems carry"
                                    " different thresholds ("
                                    + ", ".join(map(number, limits)) + ")"))
    for service in services:
        name = SYSTEM_SERVICES.get(service.name)
        if service.kind == "system" and name and service.tests:
            test = service.tests[0]
            checks[name] = {"warn": whole(test.limit),
                            "for_minutes": whole(minutes(test.hold, cycle))}
            findings.append(inferred(
                f"monitor.checks.{name}",
                f"warn {number(test.limit)} for"
                f" {number(minutes(test.hold, cycle))} min", path))
        if service.kind == "network" and service.target:
            checks.setdefault("network", {})[service.target] = network(
                service, cycle)
            findings.append(inferred(
                f"monitor.checks.network.{service.target}",
                ", ".join(f"{k} {v}" for k, v in
                          checks["network"][service.target].items()), path))
    return checks, findings


def network(service: Service, cycle: int) -> dict:
    """link, max_mbit and the hold every test of the interface shares

    No link test is `link: false`, which is what a spec declaring
    throughput alone means, so the two compare the same.
    """
    found: dict = {"link": False}
    for test in service.tests:
        if test.measure == "link":
            found["link"] = True
        elif test.measure == "rate":
            found.setdefault("max_mbit", whole(mbit(test.limit)))
        found.setdefault("for_minutes", whole(minutes(test.hold, cycle)))
    return found
