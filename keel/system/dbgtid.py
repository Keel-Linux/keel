# Copyright (c) 2026 KeelLinux maintainers
"""GTID sets compared: what an old primary holds that the new one lacks

0049, "The old primary coming back", MariaDB: the errant transactions
are the GTIDs of the old primary's `@@gtid_binlog_state` the new
primary's lacks, "for each domain and server ID, a sequence number on
the old primary higher than the one the new primary records for the
same domain and server ID". The new primary records them in its own
binlog state (log_slave_updates keeps a GTID as it came) and, for what
it applied but never logged, in `gtid_slave_pos`; both are read.

Pure: text in, text out.
"""

import re

GTID = re.compile(r"^(\d+)-(\d+)-(\d+)$")


def parse(text: str) -> dict[tuple[int, int], int]:
    """`domain-server-sequence,...` as (domain, server) to the highest
    sequence; a value that is no GTID list raises ValueError"""
    found: dict[tuple[int, int], int] = {}
    for one in (part.strip() for part in (text or "").split(",")):
        if not one:
            continue
        hit = GTID.match(one)
        if hit is None:
            raise ValueError(f"{one!r} is not a GTID")
        domain, server, sequence = (int(hit.group(i)) for i in (1, 2, 3))
        found[(domain, server)] = max(found.get((domain, server), 0),
                                      sequence)
    return found


def errant(own_state: str, holder_state: str, holder_pos: str = "") -> (
        list[str]):
    """The GTIDs of `own_state` the holder has not got, as text, sorted

    The holder has a GTID when its binlog state, or its slave position,
    records the same domain and server at that sequence or above.
    """
    mine = parse(own_state)
    theirs = parse(holder_state)
    for key, sequence in parse(holder_pos).items():
        theirs[key] = max(theirs.get(key, 0), sequence)
    return [f"{domain}-{server}-{sequence}"
            for (domain, server), sequence in sorted(mine.items())
            if theirs.get((domain, server), 0) < sequence]


def carried(state: str, position: str) -> str:
    """The binary log state a replica takes from its primary's copy

    The copy holds the effect of every transaction the primary logged,
    and the replica does not log the load. So its binary log state must
    say it has them all, or the primary, back from a cut, reads as
    diverged by the GTIDs of its first boot (keel#202). These are the
    GTIDs of `state` under a server id that `position` does not name,
    then `position` itself, last, so it stays the last GTID of its domain.
    What the primary logged under the server id of `position` after the
    copy was taken is not taken: the replica has not got it yet, and
    strict mode would refuse the events that bring it.

    Raises ValueError for a value that is no GTID list.
    """
    taken = parse(position)
    others = [(key, sequence) for key, sequence in sorted(parse(state).items())
              if key not in taken]
    wanted = [f"{domain}-{server}-{sequence}"
              for (domain, server), sequence in others]
    wanted += [one.strip() for one in (position or "").split(",")
               if one.strip()]
    return ",".join(wanted)


def newest(text: str) -> dict[int, int]:
    """The newest sequence of each domain in a GTID list"""
    found: dict[int, int] = {}
    for (domain, _), sequence in parse(text).items():
        found[domain] = max(found.get(domain, 0), sequence)
    return found


def describe(found: list[str]) -> str:
    """One line naming each errant GTID by domain, server id and sequence"""
    parts = []
    for one in found:
        domain, server, sequence = one.split("-")
        parts.append(f"domain {domain}, server id {server}, up to sequence"
                     f" {sequence}")
    return "; ".join(parts)
