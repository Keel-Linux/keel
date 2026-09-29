# Copyright (c) 2026 KeelLinux maintainers
"""keel notify: what monit runs when a test fails, lasts or recovers

monit puts the event in the environment (MONIT_EVENT, MONIT_SERVICE,
MONIT_DESCRIPTION); the level, the check and what it is about come from
the argument vector keel.monitor.render wrote; the channels come from
the spec. One message is built and sent to every declared channel, and
a channel that fails does not stop the others.

It writes nothing on its way: monit runs it as `python3 -B`, so not even
bytecode is written, the tokens are read from their secret files and
never reach an argument vector or a line of output, and a line about a
channel names the channel, never its URL.
"""

import re
import socket
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from keel.monitor import advice, channels
from keel.spec.secretstore import resolve_secret
from keel.spec.errors import SpecError
from keel.spec.validate_monitor import alerts_address, working_channels

LEVELS = ("warn", "critical", "recovery")
CHECKS = ("disk", "inodes", "memory", "swap", "cpu", "load", "link",
          "throughput")
MASK = "[masked]"
COMMAND_TIMEOUT = 5
PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)%")
OF_RE = re.compile(r"\bof (\d+(?:\.\d+)?)")
WHAT = {
    "memory": "memory", "swap": "swap", "cpu": "CPU",
    "load": "the load per core",
}


@dataclass(frozen=True)
class Event:
    level: str
    check: str
    target: str
    threshold: str
    service: str
    event: str
    description: str

    @property
    def value(self) -> str:
        """The measured value monit put in its description, or empty"""
        found = (OF_RE if self.check == "load" else PERCENT_RE).search(
            self.description)
        return found.group(1) if found else ""


@dataclass(frozen=True)
class Message:
    title: str
    text: str
    fields: dict


@dataclass(frozen=True)
class Delivery:
    channel: str
    problem: str | None = None

    def line(self) -> str:
        if self.problem is None:
            return f"{self.channel}: sent"
        return f"{self.channel}: failed: {self.problem}"


def event_from(level: str, check: str, target: str, threshold: str,
               environ: dict[str, str]) -> Event:
    return Event(level, check, target, threshold,
                 environ.get("MONIT_SERVICE", ""),
                 environ.get("MONIT_EVENT", ""),
                 environ.get("MONIT_DESCRIPTION", ""))


def address_of(doc: dict) -> str:
    """The first static address the spec declares, IPv6 first"""
    interfaces = (doc.get("network") or {}).get("interfaces") or {}
    for family in ("ipv6", "ipv4"):
        for iface in interfaces.values():
            declared = (iface or {}).get(family) or {}
            if declared.get("method") == "static" and declared.get("address"):
                return str(declared["address"]).split("/")[0]
    return ""


def headline(event: Event) -> str:
    """What happened, in one sentence"""
    value, limit = event.value, event.threshold
    if event.check in ("disk", "inodes"):
        what = "full" if event.check == "disk" else "of its inodes used"
        if event.level == "recovery":
            return f"{event.target} is back under {limit}% {what}."
        now = f"{value}%" if value else "over the threshold"
        return f"{event.target} is {now} {what} ({event.level} at {limit}%)."
    if event.check == "link":
        if event.level == "recovery":
            return f"the link of {event.target} is up again."
        return f"the link of {event.target} is down."
    if event.check == "throughput":
        if event.level == "recovery":
            return f"{event.target} is back under {limit} Mbit/s."
        return f"{event.target} carries more than {limit} Mbit/s."
    what = WHAT[event.check]
    unit = "" if event.check == "load" else "%"
    if event.level == "recovery":
        return f"{what} is back under {limit}{unit}."
    now = f"{value}{unit}" if value else "over the threshold"
    return f"{what} is at {now} ({event.level} at {limit}{unit})."


def compose(event: Event, host: str, address: str, details: bool,
            probe: advice.Probe) -> Message:
    """The message: what happened, what to do, and, with details, where

    `details: false` leaves the directory and process lists out: they
    name what the machine holds, and the message goes to whichever
    service the operator declared, Telegram's servers included.
    """
    label = f"{host} ({address})" if address else host
    lines = [f"{label}: {headline(event)}"]
    if event.level != "recovery":
        lines += advice.steps(event.check, event.target, event.threshold,
                              probe)
        if details:
            lines += detail_lines(event, probe)
    if event.description:
        lines.append(f"monit: {event.description}")
    title = f"[{event.level}] {host}: {event.check}" + (
        f" {event.target}" if event.target else "")
    fields = {
        "host": host, "address": address, "check": event.check,
        "target": event.target, "value": event.value,
        "threshold": event.threshold, "level": event.level,
        "service": event.service, "event": event.event,
    }
    return Message(title, "\n".join(lines), fields)


def detail_lines(event: Event, probe: advice.Probe) -> list[str]:
    if event.check in ("disk", "inodes"):
        found = advice.largest_directories(event.target, probe)
        return [f"Largest directories: {found}."] if found else []
    if event.check in ("memory", "swap", "cpu", "load"):
        found = advice.largest_processes(event.check, probe)
        return [f"Largest processes: {found}."] if found else []
    return []


def run_probe(argv: tuple[str, ...]) -> str | None:
    """A read only command's output, or None; never longer than it may

    du is given longer than the others, and still a bound: a directory
    list that takes too long is left out rather than holding the alert.
    """
    timeout = advice.DU_TIMEOUT if argv[0] == "du" else COMMAND_TIMEOUT
    try:
        out = subprocess.run(list(argv), capture_output=True, text=True,
                             timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 or argv[0] == "du" else None


Secret = Callable[[dict], str]


def send(doc: dict, message: Message, level: str,
         context: ssl.SSLContext | None = None,
         telegram_api: str | None = None,
         sendmail: str = channels.SENDMAIL,
         secret: Secret = resolve_secret) -> list[Delivery]:
    """Every declared channel, one Delivery each, none stopping the others

    A token that cannot be read fails its own channel. What a Delivery
    says is masked of every token read on the way, whatever path the
    words took to get there.
    """
    monitor = doc.get("monitor") or {}
    notify = monitor.get("notify") or {}
    tokens: list[str] = []

    def token(spec: dict) -> str:
        value = secret(spec)
        tokens.append(value)
        return value

    senders: dict[str, Callable[[], None]] = {
        "email": lambda: channels.email(
            alerts_address(doc.get("security")) or "", message.title,
            message.text, sendmail),
        "telegram": lambda: channels.telegram(
            str(notify["telegram"]["chat_id"]),
            token(notify["telegram"]["token"]), message.text, context,
            telegram_api or channels.TELEGRAM_API),
        "ntfy": lambda: channels.ntfy(
            str(notify["ntfy"]["url"]),
            token(notify["ntfy"]["token"]) if notify["ntfy"].get("token")
            else None, message.title, level, message.text, context),
        "webhook": lambda: channels.webhook(
            str(notify["webhook"]["url"]),
            {"text": f"{message.title}\n{message.text}", **message.fields},
            context),
    }
    deliveries = []
    for name in working_channels(notify, doc.get("security")):
        try:
            senders[name]()
            deliveries.append(Delivery(name))
        except (channels.ChannelError, SpecError, OSError, ValueError,
                KeyError, TypeError) as e:
            # ValueError is also a token file that is not UTF-8; its text
            # is replaced by its kind, since it quotes the bytes
            if isinstance(e, ValueError | KeyError | TypeError):
                e = channels.ChannelError(channels.reason(e))
            deliveries.append(Delivery(name, masked(str(e), tokens)))
    return deliveries


def masked(text: str, tokens: list[str]) -> str:
    for value in tokens:
        if value:
            text = text.replace(value, MASK)
    return text


def hostname() -> str:
    return socket.gethostname()
