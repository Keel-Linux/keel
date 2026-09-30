# Copyright (c) 2026 KeelLinux maintainers
"""The database server apply converges answers before it is asked anything

Measured on a first boot: inithooks.service is ordered after nothing but
the getty, and mariadb.service is started beside it, so the hook
10keel-system asked MariaDB what it was a second before it accepted
connections. The question failed, the role was unknown, the database
field was refused and the boot went on with the packaged server_id of 1
until somebody ran apply again (docs/apply.md, "The server is up first").

So before the questions of keel.inspect.dbengines are put, the server is
made to answer: a run that may change the machine starts it (systemctl
start on a unit that is activating joins the start already queued, and
returns once the unit says it is ready), a dry run only waits for one
that is starting, and either gives up within one bound and says why. Only
the reason comes back; keel.system.database refuses the field with it.
"""

import os
import shlex
import subprocess
import time

# InnoDB recovery after an unclean stop is the long case; a first boot
# takes seconds. The bound is for the start and the wait together.
READY_TIMEOUT = 300
# One question to a server that is up takes milliseconds; a client that
# hangs on a wedged one must not hang apply.
ASK_TIMEOUT = 10
POLL_INTERVAL = 1
ACTIVATING = "activating"
ACTIVE = "active"
# The controlling terminal, where the first boot dialogs draw.
TTY = "/dev/tty"
WAITING = (
    "keel: waiting for the database server ({service}) to start,"
    " up to {timeout} s"
)


def ready(
    service: str, ping: tuple[str, ...], start: bool,
    timeout: int = READY_TIMEOUT,
) -> str:
    """An empty string once `ping` succeeds, else why the server is not up

    `start` is whether this run may change the machine. Without it a
    stopped server is named, never started, and one that is activating is
    still waited for, since waiting changes nothing.
    """
    deadline = time.monotonic() + timeout
    why = _ask(ping)
    if not why:
        return ""
    told = False
    if start:
        _tell(WAITING.format(service=service, timeout=timeout))
        told = True
        problem = _start(service, max(1, deadline - time.monotonic()))
        if problem:
            return problem
        why = _ask(ping)
        if not why:
            return ""
    while True:
        unit = _unit(service)
        if unit != ACTIVATING:
            return _not_answering(service, unit, start, why)
        if time.monotonic() >= deadline:
            return (
                f"{service} is still activating after {timeout} s and"
                f" does not answer ({why})"
            )
        if not told:
            _tell(WAITING.format(service=service, timeout=timeout))
            told = True
        time.sleep(min(POLL_INTERVAL, deadline - time.monotonic()))
        why = _ask(ping)
        if not why:
            return ""


def enabled(service: str) -> str:
    """What `systemctl is-enabled` says of the unit, or an empty string

    Read so that a server apply had to start is also one that starts at
    boot: `disabled` is the one answer keel.system.database acts on.
    is-enabled exits non zero for most answers, so its word is taken
    whatever the exit code.
    """
    try:
        out = subprocess.run(
            ["systemctl", "is-enabled", service], capture_output=True,
            text=True, check=False, timeout=ASK_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout.strip()


def _tell(line: str) -> None:
    """Say `line` on the terminal, never into the output apply prints

    10keel-system reads apply's output through a pipe and logs it, so a
    line printed there shows up only when the hook is over, and tty1 is
    blank while the server is waited for. So the line goes where the
    dialogs of the other first boot hooks draw (libinithooks,
    screen_on_terminal): standard output when it is the terminal, else
    the controlling terminal, else nowhere.
    """
    if os.isatty(1):
        print(line, flush=True)
        return
    try:
        tty = os.open(TTY, os.O_WRONLY | os.O_NOCTTY)
    except OSError:
        return
    try:
        os.write(tty, (line + "\n").encode())
    except OSError:
        pass
    finally:
        os.close(tty)


def _not_answering(service: str, unit: str, start: bool, why: str) -> str:
    if unit == ACTIVE:
        return f"{service} is active and does not answer ({why})"
    if start:
        return (
            f"{service} is {unit} after systemctl start {service} and does"
            f" not answer ({why})"
        )
    return (
        f"{service} is {unit} and a dry run does not start it ({why})"
    )


def _ask(ping: tuple[str, ...]) -> str:
    """An empty string when the server answered, else the client's error"""
    command = shlex.join(ping)
    try:
        out = subprocess.run(
            list(ping), capture_output=True, text=True, check=False,
            timeout=ASK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return f"{command} did not finish within {ASK_TIMEOUT} s"
    except OSError as e:
        return f"{command} failed: {e.strerror}"
    if out.returncode == 0:
        return ""
    return _exited(command, out)


def _start(service: str, timeout: float) -> str:
    """Start the unit and wait for it, or say why that did not work"""
    argv = ("systemctl", "start", service)
    command = shlex.join(argv)
    try:
        out = subprocess.run(
            list(argv), capture_output=True, text=True, check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"{command} did not finish within {int(timeout)} s"
    except OSError as e:
        return f"{command} failed: {e.strerror}"
    if out.returncode == 0:
        return ""
    return _exited(command, out)


def _unit(service: str) -> str:
    """What systemd says the unit is doing: active, activating, failed..."""
    try:
        out = subprocess.run(
            ["systemctl", "is-active", service], capture_output=True,
            text=True, check=False, timeout=ASK_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return out.stdout.strip() or "unknown"


def _exited(command: str, out: subprocess.CompletedProcess) -> str:
    detail = (out.stderr or out.stdout or "").strip().splitlines()
    tail = f": {detail[-1]}" if detail else ""
    return f"{command} exited {out.returncode}{tail}"
