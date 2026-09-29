# Copyright (c) 2026 KeelLinux maintainers
"""Plan the security section: where the machine's alerts are mailed

security.alerts is written once at first boot by the 85secalerts hook,
which leaves two traces keel inspect reads back: a root alias in
/etc/aliases and MAILON in the cron-apt config. This converges the same
two traces on a running machine, read through the same reader inspect
uses (keel.inspect.security.root_alias), so apply and diff cannot
disagree about what the machine says.

What the hook also does and this never does: register the address with
hub.turnkeylinux.org. Brief section 5.6 makes the Hub one optional
backend, and a converge that ran on every apply would re-subscribe the
machine to somebody else's service each time.

updates_at_first_boot is a first boot input with no trace on the machine
(docs/spec.md), so there is nothing to converge.
"""

from keel.inspect.security import root_alias
from keel.inspect.tree import NOT_PRESENT, File
from keel.system.actions import Action, Note, Refuse, Run, Step, WriteFile
from keel.system.state import SystemState

FIELD = "security.alerts"
SKIP = "skip"
ALIASES = "etc/aliases"
CRON_APT_CONFIG = "etc/cron-apt/config"
ETC_MODE = 0o644
ROOT = "root"
# what the hook writes, quoted the way it quotes them
CRON_APT_MAIL = (("MAILON", "output"), ("MAILTO", "root"))


def plan_security(security: dict, state: SystemState) -> list[Step]:
    alerts = security.get("alerts")
    if alerts is None:
        return []
    alerts = str(alerts)
    if alerts.lower() == SKIP:
        return [skip_step(state)]
    return [address_step(alerts, state)]


def address_step(address: str, state: SystemState) -> Step:
    aliases = state.aliases or File(f"{state.root}/{ALIASES}",
                                    problem=NOT_PRESENT)
    if unreadable(aliases):
        return Step(FIELD, (Refuse(
            f"cannot read {aliases.path} ({aliases.problem}), so the root"
            " alias cannot be converged"
        ),))
    actions: list[Action] = []
    # diff compares the field case insensitively (keel.diff.compare), so a
    # difference of case alone is not one to write
    if (root_alias(aliases) or "").lower() != address.lower():
        actions.append(WriteFile(
            ALIASES, with_root_alias(aliases, address), ETC_MODE, None,
            f"write /{ALIASES} with root: {address}",
        ))
        actions.append(rebuild(state))
    actions += cron_apt_mail(state)
    if all(isinstance(action, Note) for action in actions):
        return Step(FIELD, (Note(f"unchanged ({address})"),))
    return Step(FIELD, tuple(actions))


def skip_step(state: SystemState) -> Step:
    """skip: no external root alias; cron-apt keeps mailing root locally

    inspect reads skip from a root alias that is absent or local, so only
    an alias that sends mail off the machine is removed. The hook itself
    does nothing for skip, which is why cron-apt is left as it is.
    """
    aliases = state.aliases
    current = root_alias(aliases) if aliases is not None else None
    if current is None or "@" not in current:
        return Step(FIELD, (Note("unchanged (skip)"),))
    return Step(FIELD, (
        WriteFile(ALIASES, without_root_alias(aliases), ETC_MODE, None,
                  f"write /{ALIASES} without the root alias to {current}"),
        rebuild(state),
    ))


def unreadable(file: File) -> bool:
    return not file.readable and file.problem != NOT_PRESENT


def rebuild(state: SystemState) -> Action:
    """The aliases database is what the MTA reads, not the text file"""
    if not state.live:
        return Note("aliases database not rebuilt: not the live system")
    if "newaliases" not in state.available:
        return Note("aliases database not rebuilt: newaliases not found")
    return Run(("newaliases",), "rebuild the aliases database")


def cron_apt_mail(state: SystemState) -> list[Action]:
    config = state.cron_apt_config
    if config is None or not config.readable:
        return [Note("cron-apt not installed: its mail settings left alone")]
    current = config.assignments()
    if all(current.get(key) == value for key, value in CRON_APT_MAIL):
        return []
    return [WriteFile(
        CRON_APT_CONFIG, with_assignments(config, CRON_APT_MAIL), ETC_MODE,
        None, f"write /{CRON_APT_CONFIG} with MAILON=output, MAILTO=root",
    )]


def is_root_line(line: str) -> bool:
    key, sep, _ = line.partition(":")
    return bool(sep) and key.strip() == ROOT


def with_root_alias(aliases: File, address: str) -> str:
    """The file with its root line replaced in place, or appended"""
    entry = f"{ROOT}:    {address}"
    lines, replaced = [], False
    for line in (aliases.text or "").splitlines():
        if is_root_line(line):
            if not replaced:
                lines.append(entry)
                replaced = True
            continue
        lines.append(line)
    if not replaced:
        lines.append(entry)
    return "".join(f"{line}\n" for line in lines)


def without_root_alias(aliases: File) -> str:
    return "".join(
        f"{line}\n" for line in (aliases.text or "").splitlines()
        if not is_root_line(line)
    )


def with_assignments(config: File, pairs: tuple[tuple[str, str], ...]) -> str:
    """KEY="value" lines replaced in place or appended; the rest kept"""
    wanted = dict(pairs)
    lines, done = [], set()
    for line in (config.text or "").splitlines():
        key = line.split("=", 1)[0].strip()
        if "=" in line and key in wanted and not line.lstrip().startswith("#"):
            if key not in done:
                lines.append(f'{key}="{wanted[key]}"')
                done.add(key)
            continue
        lines.append(line)
    lines += [f'{key}="{value}"' for key, value in pairs if key not in done]
    return "".join(f"{line}\n" for line in lines)
