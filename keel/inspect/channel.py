# Copyright (c) 2026 KeelLinux maintainers
"""Which channel and which release revision this machine is on

Read from the record `keel pull` leaves at `/var/lib/keel/channel`, so
the question an operator actually asks, "what is this box running and is
there anything newer", is answered without the network and without the
machine being the live one. Whether anything newer exists is a separate
question that costs a fetch, and `keel inspect --check-channel` is where
that is asked.

A machine that follows no channel produces no finding at all: an
appliance published before the conversion follows the flat layout, and
saying nothing is the honest report of that.
"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File
from keel.layers import channel as channels
from keel.layers.errors import ChannelError

FIELD = "layers.channel"
REVISION_FIELD = "layers.revision"
SOURCE_FIELD = "layers.source"
AVAILABLE_FIELD = "layers.available"
UP_TO_DATE = "up to date"
NO_CHANNEL = "this instance follows no channel"


def probe_channel(state: File) -> tuple[channels.State | None, list[Finding]]:
    """The recorded channel and the findings for it, or nothing at all"""
    if not state.readable:
        return None, []
    try:
        found = channels.state_from_text(state.path, state.text)
    except ChannelError as e:
        return None, [missing(FIELD, "; ".join(e.errors))]
    return found, [
        inferred(FIELD, found.channel, state.path),
        inferred(
            REVISION_FIELD, f"{found.release}/{found.rev}", state.path
        ),
        inferred(SOURCE_FIELD, found.source, state.path),
    ]


def available_finding(
    state: channels.State, found: channels.Channel
) -> Finding:
    """What the mirror now offers on that channel, as one report line"""
    behind = channels.behind(state, found)
    return inferred(
        AVAILABLE_FIELD, behind or UP_TO_DATE, found.path
    )
