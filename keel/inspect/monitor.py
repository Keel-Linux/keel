# Copyright (c) 2026 KeelLinux maintainers
"""The monitor section, read back from the file keel writes for monit

/etc/monit/conf.d/keel.conf is what `apply --system` renders
(keel.monitor.render), so its tests are read back into the thresholds
they came from and `keel diff` compares like for like. Thresholds and
cycles are read from the `if` lines, which are what monit acts on. A
duration is the one value a cycle count cannot give back exactly (5
minutes at a 120 s cycle is 3 cycles, which is 6 minutes), so the
minutes keel wrote in the comment above a test are taken when they still
give that test's cycles at monit's cycle, and the cycles' own duration
otherwise, which diff then shows as drift.

monit's cycle is read as monit reads it: `set daemon` in
/etc/monit/monitrc and the files it includes, in order, the last one
winning; keel does not set it.

Two limits, stated in the report rather than guessed around:

- the channels are not in the file. monit runs keel notify, which reads
  them from /etc/keel/monitor.json, so `monitor.notify` is read from
  there, tokens by reference (keel#60), and diff does not compare it: a
  URL can be a secret;
- the file says what monit was told, not that monit is installed or
  running; that is the package's and the service's business.
"""

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from keel.inspect import constants as paths
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import NOT_PRESENT, File, Tree
from keel.monitor.channelfile import written_by_keel
from keel.monitor.render import MINUTES_COMMENT
from keel.monitor.settings import DEBIAN_CYCLE, cycles, mbit, minutes, number

KEEL_HEADER = "# written by keel"
# monit's keywords are case insensitive: SET DAEMON 30 is a cycle too
DAEMON_RE = re.compile(r"^set\s+daemon\s+(\d+)", re.IGNORECASE)
INCLUDE_RE = re.compile(r"^include\s+(\S+)", re.IGNORECASE)
# monitrc includes conf.d, whose files could include more; not deeper
MAX_INCLUDE_DEPTH = 3
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
MINUTES_RE = re.compile(r"^" + re.escape(MINUTES_COMMENT) + r"\s*(\d+)$")
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
    "the channels are not in monit's file: keel notify reads them from"
    " /etc/keel/monitor.json, which apply writes from the spec; declare at"
    " least one before apply, since enabled: true without a channel does"
    " not validate"
)


@dataclass(frozen=True)
class Test:
    measure: str
    limit: float
    hold: int
    declared: int | None = None


@dataclass
class Service:
    kind: str
    name: str
    target: str
    tests: list[Test] = field(default_factory=list)


@dataclass(frozen=True)
class Cycle:
    """monit's cycle in seconds, and where it was read"""

    seconds: int
    source: str


def monit_cycle(tree: Tree) -> Cycle:
    """The last `set daemon` monit reads, following its includes"""
    found = None
    for path, line in control_lines(tree, paths.MONITRC, 0):
        daemon = DAEMON_RE.match(line)
        if daemon:
            found = Cycle(int(daemon.group(1)),
                          f"set daemon {daemon.group(1)} in {path}")
    return found or Cycle(DEBIAN_CYCLE, (
        f"no set daemon in {tree.path(paths.MONITRC)} or its includes;"
        f" Debian's {DEBIAN_CYCLE} s assumed"))


def control_lines(tree: Tree, relative: str, depth: int) -> (
    Iterator[tuple[str, str]]
):
    """Every line monit reads from a control file, includes in place"""
    file = tree.read(relative)
    for line in file.lines():
        include = INCLUDE_RE.match(line)
        if include is None:
            yield file.path, line
            continue
        if depth >= MAX_INCLUDE_DEPTH:
            continue
        for name in tree.glob(include.group(1).strip("\"'").lstrip("/")):
            if os.path.isfile(tree.path(name)):
                yield from control_lines(tree, name, depth + 1)


def probe_monitor(conf: File, cycle: Cycle,
                  settings: File | None = None) -> (
    tuple[dict | None, list[Finding]]
):
    """The section from monit's file, and its channels from `settings`

    `settings` is /etc/keel/monitor.json, which apply writes from the
    same spec; without it (None) the channels are reported as not read.
    """
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
    checks, findings = read_checks(text, conf.path, cycle)
    section = {"enabled": True, "checks": checks}
    if settings is None:
        return section, [inferred(key, "true", conf.path), *findings,
                         missing("monitor.notify", NOTIFY_REASON)]
    notify, finding = read_notify(settings)
    if notify is not None:
        section["notify"] = notify
    return section, [inferred(key, "true", conf.path), *findings, finding]


def read_notify(settings: File) -> tuple[dict | None, Finding]:
    """monitor.notify as the spec wrote it, from what apply resolved

    keel#60: without it, the emitted spec did not validate (enabled
    needs a channel) and re-applying it needed the channels added by
    hand. The file holds token files and secret URL files by path, so
    they come back as references; a URL the spec gave literally comes
    back literally, and neither ever reaches the report line.
    """
    field = "monitor.notify"
    if not settings.readable:
        return None, missing(field, f"{settings.path} {settings.problem}")
    if not written_by_keel(settings.text):
        return None, missing(field, f"{settings.path} was not written by"
                             " keel, so it says nothing of the channels")
    found = json.loads(settings.text or "")
    notify: dict = {}
    if found.get("email"):
        notify["email"] = True
    telegram = found.get("telegram")
    if isinstance(telegram, dict):
        notify["telegram"] = {"chat_id": telegram.get("chat_id"),
                              "token": {"file": telegram.get("token_file")}}
    for name in ("ntfy", "webhook"):
        channel = found.get(name)
        if not isinstance(channel, dict):
            continue
        url = channel.get("url")
        notify[name] = {"url": url if url is not None
                        else {"file": channel.get("url_file")}}
        if channel.get("token_file"):
            notify[name]["token"] = {"file": channel["token_file"]}
    notify["details"] = found.get("details") is True
    names = ", ".join(name for name in notify if name != "details")
    return notify, inferred(field, names, settings.path)


def read_services(text: str) -> list[Service]:
    services: list[Service] = []
    declared = None
    for raw in text.splitlines():
        line = raw.strip()
        found = SERVICE_RE.match(line)
        if found:
            services.append(Service(found.group(1), found.group(2),
                                    found.group(3) or ""))
            continue
        comment = MINUTES_RE.match(line)
        if comment:
            declared = int(comment.group(1))
            continue
        if not services:
            continue
        test = read_test(line, declared)
        if test is not None:
            services[-1].tests.append(test)
            declared = None
    return services


def read_test(line: str, declared: int | None) -> Test | None:
    link = LINK_RE.match(line)
    if link:
        return Test("link", 0, int(link.group(1) or 1), declared)
    for kind, pattern in TESTS:
        test = pattern.match(line)
        if test:
            measure = test.group(1) if kind == "usage" else kind
            return Test(measure, float(test.group(2)),
                        int(test.group(3) or 1), declared)
    return None


def whole(value: float) -> int | float:
    return int(value) if float(value).is_integer() else value


def held(test: Test, cycle: int) -> int | float:
    """The minutes keel wrote, while they still give the test's cycles"""
    if test.declared is not None and cycles(test.declared, cycle) == \
            test.hold:
        return test.declared
    return whole(minutes(test.hold, cycle))


def read_checks(text: str, path: str, cycle: Cycle) -> (
    tuple[dict, list[Finding]]
):
    services = read_services(text)
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
    source = f"{path}, at {cycle.source}"
    for service in services:
        name = SYSTEM_SERVICES.get(service.name)
        if service.kind == "system" and name and service.tests:
            test = service.tests[0]
            duration = held(test, cycle.seconds)
            checks[name] = {"warn": whole(test.limit),
                            "for_minutes": duration}
            findings.append(inferred(
                f"monitor.checks.{name}",
                f"warn {number(test.limit)} for {number(duration)} min",
                source))
        if service.kind == "network" and service.target:
            checks.setdefault("network", {})[service.target] = network(
                service, cycle.seconds)
            findings.append(inferred(
                f"monitor.checks.network.{service.target}",
                ", ".join(f"{k} {v}" for k, v in
                          checks["network"][service.target].items()),
                source))
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
        found.setdefault("for_minutes", held(test, cycle))
    return found
