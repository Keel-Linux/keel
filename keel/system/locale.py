# Copyright (c) 2026 KeelLinux maintainers
"""Plan the locale section: timezone and language

On the live system the timezone goes through timedatectl when it exists
and the language is generated with locale-gen, else localedef; under any
other root only the files are written, since a scratch tree has no
systemd to talk to and no locale archive of its own. Every action is
planned only when the observed state differs.
"""

from keel.inspect.locale import current_timezone
from keel.inspect.tree import File
from keel.system.actions import Action, Note, Run, Step, WriteFile, Symlink
from keel.system.state import LOCALE_GEN, SystemState

TIMEZONE = "etc/timezone"
LOCALTIME = "etc/localtime"
DEFAULT_LOCALE = "etc/default/locale"
ZONEINFO_DIR = "/usr/share/zoneinfo"
ETC_MODE = 0o644
BUILTIN_LOCALES = ("C", "POSIX", "C.UTF-8", "C.utf8")


def plan_locale(locale: dict, state: SystemState) -> list[Step]:
    steps: list[Step] = []
    zone = locale.get("timezone")
    if zone is not None:
        steps.append(timezone_step(str(zone), state))
    lang = locale.get("lang")
    if lang is not None:
        steps.append(lang_step(str(lang), state))
    return steps


def timezone_step(zone: str, state: SystemState) -> Step:
    field = "locale.timezone"
    current, _ = current_timezone(state.timezone, state.localtime_target)
    link_ok = (state.localtime_target or "").endswith(f"zoneinfo/{zone}")
    if current == zone and link_ok:
        return Step(field, (Note(f"unchanged ({zone})"),))
    if state.live and "timedatectl" in state.available:
        return Step(field, (Run(
            ("timedatectl", "set-timezone", zone), f"set timezone to {zone}"
        ),))
    return Step(field, (
        WriteFile(TIMEZONE, f"{zone}\n", ETC_MODE, None, f"write /{TIMEZONE}"),
        Symlink(LOCALTIME, f"{ZONEINFO_DIR}/{zone}", f"link /{LOCALTIME}"),
    ))


def lang_step(lang: str, state: SystemState) -> Step:
    field = "locale.lang"
    actions: list[Action] = []
    current = state.default_locale.assignments().get("LANG")
    if current != lang:
        actions.append(WriteFile(
            DEFAULT_LOCALE, with_lang(state.default_locale, lang), ETC_MODE,
            None, f"write /{DEFAULT_LOCALE} with LANG={lang}",
        ))
    actions += generation(lang, state)
    if all(isinstance(action, Note) for action in actions):
        notes = [f"unchanged ({lang})"] + [a.summary for a in actions]
        return Step(field, (Note("; ".join(notes)),))
    return Step(field, tuple(actions))


def with_lang(default_locale: File, lang: str) -> str:
    """The file with its LANG line replaced, or appended; the rest kept"""
    kept = [
        line for line in (default_locale.text or "").splitlines()
        if not line.strip().startswith("LANG=")
    ]
    return "".join(f"{line}\n" for line in kept) + f"LANG={lang}\n"


def generation(lang: str, state: SystemState) -> list[Action]:
    """How to make the locale exist, or a Note saying why it is not done"""
    if lang in BUILTIN_LOCALES:
        return []
    if not state.live:
        return [Note("not generated: not the live system")]
    if state.generated is not None and is_generated(lang, state.generated):
        return []
    charset = charset_of(lang)
    if charset is None:
        return [Note("not generated: the name has no charset")]
    if "locale-gen" in state.available:
        actions: list[Action] = []
        entry = f"{lang} {charset}"
        if entry not in state.locale_gen.lines():
            actions.append(WriteFile(
                LOCALE_GEN, (state.locale_gen.text or "") + f"{entry}\n",
                ETC_MODE, None, f"add {entry} to /{LOCALE_GEN}",
            ))
        actions.append(Run(("locale-gen",), f"generate {lang}"))
        return actions
    if "localedef" in state.available:
        source = lang.split(".", 1)[0] + modifier_of(lang)
        return [Run(
            ("localedef", "-i", source, "-c", "-f", charset, lang),
            f"generate {lang}",
        )]
    return [Note("not generated: neither locale-gen nor localedef found")]


def is_generated(lang: str, generated: tuple[str, ...]) -> bool:
    """`locale -a` prints en_US.utf8 for en_US.UTF-8"""
    return normalize(lang) in {normalize(name) for name in generated}


def normalize(name: str) -> str:
    return name.lower().replace("-", "")


def charset_of(lang: str) -> str | None:
    """en_US.UTF-8@euro has charset UTF-8; en_US has none"""
    if "." not in lang:
        return None
    return lang.split(".", 1)[1].split("@", 1)[0] or None


def modifier_of(lang: str) -> str:
    return "@" + lang.split("@", 1)[1] if "@" in lang else ""
