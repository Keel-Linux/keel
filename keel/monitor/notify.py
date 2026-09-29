# Copyright (c) 2026 KeelLinux maintainers
"""keel notify: what monit runs when a test fails, lasts or recovers

monit puts the event in the environment (MONIT_EVENT, MONIT_SERVICE,
MONIT_DESCRIPTION); the level, the check and what it is about come from
the argument vector keel.monitor.render wrote; the channels come from
/etc/keel/monitor.json, which apply wrote as root (keel.monitor.
channelfile), never from the spec. One message is built and sent to
every channel there, and a channel that fails does not stop the others.
When none takes it, the message goes to syslog at user.crit and to
root's mailbox, the two places left on the machine itself.

It writes nothing of its own: monit runs it as `python3 -B`, so not even
bytecode is written, the tokens are read from their secret files and
never reach an argument vector or a line of output, and a line about a
channel names the channel, never its URL. The one exception is an empty
lock file under /run/lock, a tmpfs, so that two alerts do not measure
the same filesystem at once.
"""

import contextlib
import fcntl
import os
import re
import socket
import ssl
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from keel.monitor import advice, channels
from keel.monitor.render import slug
from keel.spec.errors import SpecError
from keel.spec.secretstore import read_secret_file
from keel.spec.validate_monitor import url_problem

LEVELS = ("warn", "critical", "recovery")
CHECKS = ("disk", "inodes", "memory", "swap", "cpu", "load", "link",
          "throughput")
DIRECTIONS = ("upload", "download")
MASK = "[masked]"
COMMAND_TIMEOUT = 5
LOCK_DIR = "/run/lock"
LOGGER = ("logger", "-p", "user.crit", "-t", "keel-notify")
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
    direction: str = ""

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
               environ: dict[str, str], direction: str = "") -> Event:
    return Event(level, check, target, threshold,
                 environ.get("MONIT_SERVICE", ""),
                 environ.get("MONIT_EVENT", ""),
                 environ.get("MONIT_DESCRIPTION", ""), direction)


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
        which = f"{event.target} {event.direction}".strip()
        if event.level == "recovery":
            return f"{which} is back under {limit} Mbit/s."
        return f"{which} carries more than {limit} Mbit/s."
    what = WHAT[event.check]
    unit = "" if event.check == "load" else "%"
    if event.level == "recovery":
        return f"{what} is back under {limit}{unit}."
    now = f"{value}{unit}" if value else "over the threshold"
    return f"{what} is at {now} ({event.level} at {limit}{unit})."


def compose(event: Event, host: str, address: str, details: bool,
            probe: advice.Probe, lock_dir: str = LOCK_DIR) -> Message:
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
            lines += detail_lines(event, probe, lock_dir)
    if event.description:
        lines.append(f"monit: {event.description}")
    title = f"[{event.level}] {host}: {event.check}" + (
        f" {event.target}" if event.target else "")
    fields = {
        "host": host, "address": address, "check": event.check,
        "target": event.target, "direction": event.direction,
        "value": event.value, "threshold": event.threshold,
        "level": event.level, "service": event.service,
        "event": event.event,
    }
    return Message(title, "\n".join(lines), fields)


@contextlib.contextmanager
def measuring(target: str, lock_dir: str) -> Iterator[bool]:
    """Whether this alert may measure `target` now: one du per filesystem

    False while another alert holds the lock. A lock that cannot be made
    at all (no /run/lock) does not stop the measure: there is nothing to
    coordinate with.
    """
    path = os.path.join(lock_dir, f"keel-notify-du-{slug(target)}.lock")
    try:
        # /run/lock is world writable: never follow a link planted there
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        yield True
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        yield False
        return
    try:
        yield True
    finally:
        os.close(fd)


def detail_lines(event: Event, probe: advice.Probe, lock_dir: str) -> (
    list[str]
):
    if event.check in ("disk", "inodes"):
        with measuring(event.target, lock_dir) as free:
            if not free:
                return ["Largest directories: not measured, another alert"
                        " is measuring this filesystem."]
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


Secret = Callable[[str], str]


def url_of(channel: dict, secret: Secret) -> str:
    """A channel's URL, from the file when it is a secret; checked again"""
    if channel.get("url_file"):
        path = str(channel["url_file"])
        url = secret(path)
        if url_problem(url):
            raise channels.ChannelError(f"{path} does not hold an https URL")
        return url
    return str(channel["url"])


def send(settings: dict, message: Message, level: str,
         context: ssl.SSLContext | None = None,
         telegram_api: str | None = None,
         sendmail: str = channels.SENDMAIL,
         secret: Secret = read_secret_file) -> list[Delivery]:
    """Every channel of the settings, one Delivery each, none stopping
    the others

    A token or URL file that cannot be read, or that anybody but root
    could write, fails its own channel. What a Delivery says is masked of
    every secret read on the way, whatever path the words took.
    """
    read: list[str] = []

    def value(path: str) -> str:
        found = secret(path)
        read.append(found)
        return found

    senders: dict[str, Callable[[dict], None]] = {
        "email": lambda _: channels.email(
            str(settings["email"]), message.title, message.text, sendmail),
        "telegram": lambda channel: channels.telegram(
            str(channel["chat_id"]), value(str(channel["token_file"])),
            message.text, context, telegram_api or channels.TELEGRAM_API),
        "ntfy": lambda channel: channels.ntfy(
            url_of(channel, value),
            value(str(channel["token_file"])) if channel.get("token_file")
            else None, message.title, level, message.text, context),
        "webhook": lambda channel: channels.webhook(
            url_of(channel, value),
            {"text": f"{message.title}\n{message.text}", **message.fields},
            context),
    }
    deliveries = []
    for name, sender in senders.items():
        channel = settings.get(name)
        if not channel:
            continue
        try:
            sender(channel if isinstance(channel, dict) else {})
            deliveries.append(Delivery(name))
        except (channels.ChannelError, SpecError, OSError) as e:
            deliveries.append(Delivery(name, masked(str(e), read)))
        except (ValueError, KeyError, TypeError) as e:
            # also a token file that is not UTF-8: its text quotes the
            # bytes, so only its kind is said
            deliveries.append(Delivery(name, channels.reason(e)))
    return deliveries


def masked(text: str, secrets: list[str]) -> str:
    for value in secrets:
        if value:
            text = text.replace(value, MASK)
    return text


def last_resort(message: Message, reason: str,
                sendmail: str = channels.SENDMAIL,
                run: Callable = subprocess.run) -> list[str]:
    """syslog at user.crit and root's mailbox, when no channel took it

    Both best effort and both on the machine: a journal survives a full
    disk better than a mail queue, and root's mailbox is where an
    operator who logs in looks. Neither carries a token or a URL. Returns
    which of the two took the message, so the caller says only that.
    """
    took = []
    first = message.text.splitlines()[0] if message.text else ""
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        out = run([*LOGGER, f"{message.title}: {first} (no channel:"
                   f" {reason})"],
                  capture_output=True, timeout=COMMAND_TIMEOUT, check=False)
        if out.returncode == 0:
            took.append("syslog (user.crit)")
    with contextlib.suppress(channels.ChannelError):
        channels.email("root", message.title,
                       f"{message.text}\n\nNo channel took this: {reason}",
                       sendmail)
        took.append("root's mailbox")
    return took


def hostname() -> str:
    return socket.gethostname()
