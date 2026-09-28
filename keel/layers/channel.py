# Copyright (c) 2026 KeelLinux maintainers
"""The channel pointer, and the record of the one this instance follows

A channel is the only mutable object in the mirror: a clear signed text
file called `stable` or `testing` that names one immutable release
revision, when it was signed and when it stops being believable.

    channel stable
    release 2026-09-28
    rev 1
    signed_at 2026-09-28T04:11:09Z
    expires_at 2026-10-05T04:11:09Z
    layer core 5f3a...            the sha256 of that layer's manifest
    layer lamp 9c1b...

The expiry is the load bearing part, and the reason it is an error and
never a warning. A mirror that is stale, broken or hostile can hold an
appliance on an old and vulnerable release simply by not updating, and
without a timestamp inside the signature the client cannot tell that
apart from "nothing new". Past `expires_at` the client stops believing
the pointer instead of believing it forever.

The grammar is the manifest's, one `key value` per line, except that
`layer` repeats. Verifying the signature is keel.layers.signature; this
module only reads what a verified text says.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

from keel.layers import layout
from keel.layers.constants import (
    CHANNEL_REQUIRED_KEYS,
    KEY_RE,
    LAYER_KEY,
    NAME_RE,
    SHA256_RE,
    STATE_REQUIRED_KEYS,
    TIMESTAMPS,
    TIMESTAMP_FORMAT,
)
from keel.layers.errors import ChannelError


@dataclass(frozen=True)
class Channel:
    """One verified channel pointer"""

    path: str
    fields: Mapping[str, str]
    layers: Mapping[str, str]
    text: str

    @property
    def name(self) -> str:
        return self.fields["channel"]

    @property
    def release(self) -> str:
        return self.fields["release"]

    @property
    def rev(self) -> int:
        return int(self.fields["rev"])

    @property
    def signed_at(self) -> datetime:
        return parse_stamp(self.fields["signed_at"])

    @property
    def expires_at(self) -> datetime:
        return parse_stamp(self.fields["expires_at"])

    @property
    def revision(self) -> tuple[str, int]:
        """What orders two pointers: the release date, then the revision"""
        return (self.release, self.rev)

    def describe(self) -> str:
        return f"{self.name} {self.release}/{self.rev}"

    def expired(self, now: datetime) -> bool:
        """The moment of expiry is already expired, never still valid"""
        return now >= self.expires_at

    def staleness(self, now: datetime) -> str | None:
        """Why an expired pointer is refused, or None when it is fresh"""
        if not self.expired(now):
            return None
        return (
            f"{self.name} expired at {format_stamp(self.expires_at)},"
            f" signed at {format_stamp(self.signed_at)}: the mirror is not"
            " being updated, or is holding this instance back"
        )


@dataclass(frozen=True)
class State:
    """What the instance records about the channel it follows"""

    path: str
    channel: str
    release: str
    rev: int
    source: str
    pulled_at: str = ""

    @property
    def revision(self) -> tuple[str, int]:
        return (self.release, self.rev)

    def describe(self) -> str:
        return f"{self.channel} {self.release}/{self.rev}"


def format_stamp(when: datetime) -> str:
    return when.strftime(TIMESTAMP_FORMAT)


def parse_stamp(value: str) -> datetime:
    """A UTC timestamp as the pointer spells it; raises ValueError"""
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(
        tzinfo=timezone.utc
    )


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse(text: str) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """Split pointer text into fields, layer digests and problems

    Returns all three rather than raising, so validate() can report the
    problems of the grammar and of the values in one list.
    """
    fields: dict[str, str] = {}
    layers: dict[str, str] = {}
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        key, _, value = line.partition(" ")
        value = value.strip()
        if not KEY_RE.match(key):
            errors.append(f"line {number}: invalid key {key!r}")
        elif not value:
            errors.append(f"line {number}: {key}: missing value")
        elif key == LAYER_KEY:
            errors += _layer_line(value, layers)
        elif key in fields:
            errors.append(f"line {number}: {key}: repeated key")
        else:
            fields[key] = value
    return fields, layers, errors


def _layer_line(value: str, layers: dict[str, str]) -> list[str]:
    name, _, digest = value.partition(" ")
    digest = digest.strip()
    if not digest:
        return [f"layer: needs a layer name and a sha256, got {value!r}"]
    if not NAME_RE.match(name):
        return [f"layer: invalid layer name {name!r}"]
    if name in layers:
        return [f"layer {name}: named twice"]
    if not SHA256_RE.match(digest):
        layers[name] = digest
        return [f"layer {name}: sha256 must be 64 lowercase hex digits"]
    layers[name] = digest
    return []


def validate(fields: Mapping[str, str], fetched_as: str) -> list[str]:
    """Every problem with the fields; empty when the pointer is sound"""
    missing = [key for key in CHANNEL_REQUIRED_KEYS if key not in fields]
    if missing:
        return [f"missing keys: {', '.join(missing)}"]
    errors = []
    name = fields["channel"]
    if not layout.is_channel(name):
        errors.append(
            f"channel: {name!r} is not one of"
            f" {', '.join(layout.CHANNELS)}"
        )
    elif name != fetched_as:
        errors.append(
            f"channel: names {name!r}, fetched as {fetched_as!r}"
        )
    if not layout.is_release(fields["release"]):
        errors.append(
            f"release: must be YYYY-MM-DD, got {fields['release']!r}"
        )
    if not layout.is_rev(fields["rev"]):
        errors.append(
            "rev: must be a whole number above zero, got"
            f" {fields['rev']!r}"
        )
    errors += _validate_stamps(fields)
    return errors


def _validate_stamps(fields: Mapping[str, str]) -> list[str]:
    errors = []
    parsed = {}
    for key in TIMESTAMPS:
        try:
            parsed[key] = parse_stamp(fields[key])
        except ValueError:
            errors.append(
                f"{key}: must be a UTC timestamp such as"
                f" 2026-09-28T04:11:09Z, got {fields[key]!r}"
            )
    if len(parsed) == len(TIMESTAMPS):
        if parsed["expires_at"] <= parsed["signed_at"]:
            errors.append("expires_at: must be after signed_at")
    return errors


def validate_layers(layers: Mapping[str, str]) -> list[str]:
    """A pointer with no layer line binds nothing and is refused

    The digests on the layer lines are what makes the signature cover the
    content: without them the pointer names a directory and a mirror may
    put anything in it.
    """
    if not layers:
        return ["layer: the pointer must name at least one layer"]
    return []


def from_text(fetched_as: str, text: str, path: str | None = None) -> Channel:
    """Read a verified pointer text; raises ChannelError with every problem

    `fetched_as` is the channel the caller asked the mirror for. A
    pointer that names another channel is refused, so a mirror cannot
    answer a request for `stable` with the pointer it signed for
    `testing`.
    """
    path = path or fetched_as
    fields, layers, errors = parse(text)
    errors += validate(fields, fetched_as)
    errors += validate_layers(layers)
    if errors:
        raise ChannelError(path, errors)
    return Channel(
        path=path,
        fields=MappingProxyType(dict(fields)),
        layers=MappingProxyType(dict(layers)),
        text=text,
    )


def state_text(
    channel: str, release: str, rev: int, source: str, when: datetime
) -> str:
    """The record an instance keeps of the channel it followed"""
    return (
        f"channel {channel}\n"
        f"release {release}\n"
        f"rev {rev}\n"
        f"source {source}\n"
        f"pulled_at {format_stamp(when)}\n"
    )


def write_state(
    path: str, channel: str, release: str, rev: int, source: str,
    when: datetime | None = None,
) -> str:
    """Record the channel this instance now follows; raises OSError

    Written for a pull that followed a pointer and for one that pinned a
    revision by hand, because an operator who rolled back is behind the
    channel on purpose and `keel inspect` has to be able to say so.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fob:
        fob.write(
            state_text(channel, release, rev, source, when or now())
        )
    return path


def record(
    path: str, channel: Channel, source: str, when: datetime | None = None
) -> str:
    """write_state for a pointer that was fetched and verified"""
    return write_state(
        path, channel.name, channel.release, channel.rev, source, when
    )


def state_from_text(path: str, text: str) -> State:
    """The record, from text a caller has already read; raises ChannelError"""
    fields, _, errors = parse(text)
    missing = [key for key in STATE_REQUIRED_KEYS if key not in fields]
    if missing:
        errors.append(f"missing keys: {', '.join(missing)}")
    elif not layout.is_rev(fields["rev"]):
        errors.append(f"rev: must be a whole number, got {fields['rev']!r}")
    if errors:
        raise ChannelError(path, errors)
    return State(
        path=path,
        channel=fields["channel"],
        release=fields["release"],
        rev=int(fields["rev"]),
        source=fields["source"],
        pulled_at=fields.get("pulled_at", ""),
    )


def read_state(path: str) -> State | None:
    """The record, None when there is none; raises ChannelError on a bad one"""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
    except (OSError, UnicodeDecodeError) as e:
        raise ChannelError(path, [f"cannot read: {e}"]) from e
    return state_from_text(path, text)


def is_rollback(state: State | None, channel: Channel) -> bool:
    """The mirror offers an older revision of the channel this instance is on

    A mirror that serves a signed older pointer sends an instance back to
    a release whose vulnerabilities are known. Going back is something an
    operator asks for by naming the release and the revision, never
    something a pointer does by itself.
    """
    if state is None or state.channel != channel.name:
        return False
    return channel.revision < state.revision


def behind(state: State | None, channel: Channel) -> str | None:
    """What the channel holds that this instance does not, or None"""
    if state is None or state.channel != channel.name:
        return None
    if channel.revision <= state.revision:
        return None
    return (
        f"{channel.name} is at {channel.release}/{channel.rev},"
        f" this instance is on {state.release}/{state.rev}"
    )
