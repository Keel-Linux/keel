# Copyright (c) 2026 KeelLinux maintainers
"""A minimal parser of /etc/network/interfaces stanzas

The approach is the one confconsole's ifutil uses: a non indented
`iface` line opens a stanza, indented lines are its options, and every
other line (auto, allow-hotplug, source, comments) is left alone. Only
what inspect needs is kept: interface, family, method and options.
"""

from dataclasses import dataclass

IFACE_FIELDS = 4


@dataclass(frozen=True)
class Stanza:
    iface: str
    family: str
    method: str
    options: tuple[tuple[str, ...], ...] = ()

    def option(self, name: str) -> str | None:
        """The value of the first option with this name, or None"""
        for fields in self.options:
            if fields[0] == name and len(fields) > 1:
                return fields[1]
        return None

    def values(self, name: str) -> list[str]:
        """Every value of every option with this name"""
        found = []
        for fields in self.options:
            if fields[0] == name:
                found.extend(fields[1:])
        return found


def parse_interfaces(text: str) -> tuple[list[Stanza], list[str]]:
    """Return the iface stanzas and the header lines that were malformed"""
    stanzas: list[Stanza] = []
    problems: list[str] = []
    current: list | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = line[0] in " \t"
        if indented and current is not None:
            current[3].append(tuple(stripped.split()))
            continue
        if current is not None:
            stanzas.append(_stanza(current))
            current = None
        fields = stripped.split()
        if fields[0] != "iface":
            continue
        if len(fields) != IFACE_FIELDS:
            problems.append(stripped)
            continue
        current = [fields[1], fields[2], fields[3], []]

    if current is not None:
        stanzas.append(_stanza(current))
    return stanzas, problems


HOTPLUG = "allow-hotplug"
AT_BOOT = ("auto", "allow-auto")


def hotplug_only(text: str) -> frozenset[str]:
    """The interfaces an `allow-hotplug` line names and no `auto` line does

    Such an interface is brought up when its card appears, and not at
    boot: a stanza for it is a placeholder until then, as the eth1 every
    TurnKey and Keel image ships is. Only unindented lines count, as for
    `iface`; an indented one belongs to the stanza above it.
    """
    hotplug: set[str] = set()
    at_boot: set[str] = set()
    for line in text.splitlines():
        if not line.strip() or line[0] in " \t#":
            continue
        fields = line.split()
        if fields[0] == HOTPLUG:
            hotplug.update(fields[1:])
        elif fields[0] in AT_BOOT:
            at_boot.update(fields[1:])
    return frozenset(hotplug - at_boot)


def _stanza(fields: list) -> Stanza:
    iface, family, method, options = fields
    return Stanza(iface, family, method, tuple(options))
