# Copyright (c) 2026 KeelLinux maintainers
"""An appliance resolved along its base chain down to Core

docs/manifest-v1.md, "Resolution: what a consuming appliance inherits":
overlays with their states, processes, checks, ports, secrets, options
and first boot hooks are inherited as they are, and a child only adds.
This is where the rules that need the whole chain are checked: 13 (the
chain), 14 (installed overlays, ask), 15 (requires, per mode), 16 to 19
(once in the chain), 21 (embedded services) and 23 (replicated paths
against the data of the overlays).
"""

from dataclasses import dataclass, field
from typing import Any

from keel.manifest.constants import (
    APP_SECTIONS,
    APPLIANCE,
    ASK,
    EMBEDDED,
    ENABLED,
    MIGRATE,
    MODES,
    NO_BASE,
    OVERLAY,
)
from keel.manifest.fields import inside
from keel.manifest.validate_app import replicate_paths


@dataclass(frozen=True)
class Owned:
    """One thing of the chain, and who declared it"""

    item: Any
    appliance: str
    overlay: str | None = None

    @property
    def origin(self) -> str:
        """`core`, or `core (etcd)` for what an overlay of core declares"""
        if self.overlay is None:
            return self.appliance
        return f"{self.appliance} ({self.overlay})"


@dataclass(frozen=True)
class OverlayState:
    name: str
    appliance: str
    states: dict
    manifest: dict


@dataclass(frozen=True)
class Resolved:
    name: str
    title: str
    chain: tuple[str, ...]
    overlays: tuple[OverlayState, ...]
    processes: tuple[Owned, ...]
    checks: tuple[Owned, ...]
    secrets: tuple[Owned, ...]
    options: tuple[Owned, ...]
    hooks: tuple[Owned, ...]
    application: Owned | None


def overlay_units(resolved: Resolved, overlay: str) -> tuple[str, ...]:
    """The units of an overlay's processes, in its manifest's order"""
    return tuple(owned.item["unit"] for owned in resolved.processes
                 if owned.overlay == overlay)


def application_of(doc: dict) -> dict:
    """The application sections a manifest declares, hooks.migrate too"""
    found = {key: doc[key] for key in APP_SECTIONS if key in doc}
    hooks = doc.get("hooks") or {}
    if MIGRATE in hooks:
        found["hooks"] = {MIGRATE: hooks[MIGRATE]}
    return found


def resolve(catalog, top: dict) -> tuple[Resolved | None, list[str]]:
    """Resolve TOP, a valid appliance manifest, along its base chain

    Returns None and the reason when the chain cannot be built, else the
    resolved appliance and every error of the chain, which a caller that
    needs a sound chain (show) treats as a refusal.
    """
    chain, errors = _chain(catalog, top)
    if chain is None:
        return None, errors
    builder = _Builder(catalog, top["name"])
    for doc in chain:
        builder.add(doc)
    errors = builder.errors + builder.requires_errors()
    application, more = _application(chain, top["name"], builder)
    errors.extend(more)
    return Resolved(
        name=top["name"], title=top["title"],
        chain=tuple(doc["name"] for doc in chain),
        overlays=tuple(builder.overlays.values()),
        processes=tuple(builder.items["process"].values()),
        checks=tuple(builder.items["check"].values()),
        secrets=tuple(builder.items["secret"].values()),
        options=tuple(builder.items["option"].values()),
        hooks=tuple(builder.hooks), application=application,
    ), errors


def _chain(catalog, top: dict) -> tuple[list[dict] | None, list[str]]:
    """Rule 13: the bases, bottom first, ending at core"""
    docs, names = [top], [top["name"]]
    doc = top
    while doc["base"] != NO_BASE:
        base = doc["base"]
        where = _where(doc["name"], top["name"])
        if base in names:
            cycle = ", ".join(names + [base])
            return None, [f"{where}base: the chain has a cycle: {cycle}"]
        found, reason = catalog.usable(APPLIANCE, base)
        if found is None and not reason:
            return None, [f"{where}base: {base} is not an installed"
                          " appliance"]
        if found is None:
            return None, [f"{where}base: {base} cannot be used: {reason}"]
        docs.append(found)
        names.append(base)
        doc = found
    return list(reversed(docs)), []


def _where(name: str, top: str) -> str:
    """How an error about a base of the chain names its appliance"""
    return "" if name == top else f"in {name}: "


@dataclass
class _Builder:
    catalog: Any
    top: str
    overlays: dict = field(default_factory=dict)
    items: dict = field(default_factory=lambda: {
        "process": {}, "check": {}, "secret": {}, "option": {}})
    ports: dict = field(default_factory=dict)
    hooks: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add(self, doc: dict) -> None:
        """One appliance of the chain: its own, then its overlays'"""
        name = doc["name"]
        where = _where(name, self.top)
        self._add_own(doc, Owned(None, name))
        for overlay, states in (doc.get("overlays") or {}).items():
            self._add_overlay(name, where, overlay, states)
        processes = set(self.items["process"])
        for index, check in enumerate(doc.get("checks") or []):
            process = check.get("process")
            if process is not None and process not in processes:
                self.errors.append(
                    f"{where}checks[{index}].process: {process} is not a"
                    f" process of the chain of {name}")

    def _add_overlay(self, name: str, where: str, overlay: str,
                     states: dict) -> None:
        if overlay in self.overlays:
            self.errors.append(f"{where}overlays.{overlay}: already carried"
                               f" by {self.overlays[overlay].appliance}")
            return
        doc, reason = self.catalog.usable(OVERLAY, overlay)
        if doc is None:
            why = (f"{overlay} cannot be used: {reason}" if reason
                   else "no installed overlay manifest")
            self.errors.append(f"{where}overlays.{overlay}: {why}")
            return
        for mode in MODES:
            if states[mode] == ASK and "screen" not in doc:
                self.errors.append(
                    f"{where}overlays.{overlay}.{mode}: ask needs a screen,"
                    f" and {overlay} declares none")
        self.overlays[overlay] = OverlayState(
            overlay, name, {mode: states[mode] for mode in MODES}, doc)
        self._add_own(doc, Owned(None, name, overlay))

    def _add_own(self, doc: dict, owner: Owned) -> None:
        """The processes, checks, secrets, options and hooks of DOC"""
        for kind, key in (("process", "processes"), ("check", "checks"),
                          ("secret", "secrets"), ("option", "options")):
            for item in doc.get(key) or []:
                self._add_item(kind, Owned(item, owner.appliance,
                                           owner.overlay))
        for process in doc.get("processes") or []:
            for listen in process.get("listen") or []:
                self._add_port(listen, Owned(process, owner.appliance,
                                             owner.overlay))
        for path in (doc.get("hooks") or {}).get("first_boot") or []:
            self.hooks.append(Owned(path, owner.appliance, owner.overlay))

    def _add_item(self, kind: str, owned: Owned) -> None:
        """Rule 18: a name once across the chain

        Only valid manifests reach here, and one file never repeats a
        name (rule 3), so a second one is always another manifest's.
        """
        name = owned.item["name"]
        first = self.items[kind].get(name)
        if first is None:
            self.items[kind][name] = owned
        else:
            self.errors.append(f"{kind} {name}: declared by {first.origin},"
                               f" and again by {owned.origin}")

    def _add_port(self, listen: dict, owned: Owned) -> None:
        """Rule 17: a (port, protocol) once, whatever the states

        As for names, a file never repeats a pair of its own.
        """
        pair = (listen["port"], listen["protocol"])
        first = self.ports.get(pair)
        if first is None:
            self.ports[pair] = owned
        else:
            self.errors.append(
                f"port {pair[0]}/{pair[1]}: declared by"
                f" {first.item['name']}, {first.origin}, and again by"
                f" {owned.item['name']}, {owned.origin}")

    def requires_errors(self) -> list[str]:
        """Rule 15: what an enabled (or ask) overlay requires is enabled"""
        errors = []
        for state in self.overlays.values():
            where = _where(state.appliance, self.top)
            key = f"{where}overlays.{state.name}"
            for required in state.manifest.get("requires") or []:
                other = self.overlays.get(required)
                if other is None:
                    errors.append(f"{key}: requires {required}, which no"
                                  " appliance of the chain carries")
                    continue
                for mode in MODES:
                    mine, theirs = state.states[mode], other.states[mode]
                    if mine in (ENABLED, ASK) and theirs != ENABLED:
                        errors.append(
                            f"{key}.{mode}: {mine}, but {state.name}"
                            f" requires {required}, which is {theirs} in"
                            f" {mode}")
        return errors


def _application(chain: list[dict], top: str,
                 builder: _Builder) -> tuple[Owned | None, list[str]]:
    """Rules 19, 21 and 23 for the application of the chain, if any"""
    owners = [doc for doc in chain if application_of(doc)]
    if not owners:
        return None, []
    names = [doc["name"] for doc in owners]
    if len(owners) > 1:
        return None, [f"application sections: declared by"
                      f" {' and by '.join(names)}; a chain has one"
                      " application, at its top"]
    if names[0] != top:
        return None, [f"application sections: declared by {names[0]}, which"
                      f" is not the top of the chain of {top}"]
    doc = owners[0]
    errors = _embedded_errors(doc.get("services") or {}, builder.overlays)
    errors.extend(_state_data_errors(doc.get("state"), builder.overlays))
    return Owned(application_of(doc), top), errors


def _embedded_errors(services: dict, overlays: dict) -> list[str]:
    """Rule 21: an embedded service has its engine's overlay enabled"""
    errors = []
    for name, service in services.items():
        engine = service["engine"]
        engines = engine if isinstance(engine, list) else [engine]
        for mode in MODES:
            if service["placement"][mode] != EMBEDDED:
                continue
            if not any((state.manifest.get("provides") or {}).get("engine")
                       in engines and state.states[mode] == ENABLED
                       for state in overlays.values()):
                errors.append(
                    f"services.{name}.placement.{mode}: embedded, but no"
                    " overlay of the chain that provides"
                    f" {' or '.join(engines)} is enabled in {mode}")
    return errors


def _state_data_errors(state: Any, overlays: dict) -> list[str]:
    """Rule 23: a replicated path is never inside an overlay's data"""
    errors = []
    for index, path in replicate_paths(state):
        for overlay in overlays.values():
            for data in overlay.manifest.get("data") or []:
                if inside(path, data["path"]):
                    errors.append(
                        f"state.replicate[{index}]: {path} is inside"
                        f" {data['path']}, the data of {overlay.name}")
    return errors
