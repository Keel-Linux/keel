# Copyright (c) 2026 KeelLinux maintainers
"""The signal of a first boot that refused its spec (keel#268)

firstboot.d/10keel-system does not stop the boot when keel refuses the spec.
So the refusal needs a place that stays after the log: this record. keel diff
reports it as drift, keel spec validate and keel database status say it, and
it fires one alert when it is made. A keel spec apply with the system phase
that succeeds removes it. It holds what the validator said, and no secret.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from keel.network.marker import write_private

RECORD = "var/lib/keel/first-boot-refused.json"
FIELD = "first_boot.spec"
REASON_LIMIT = 4000
REMEDY = ("Correct the spec, then run keel spec apply --system-only. The"
          " hooks of this first boot did not get a valid spec, so check that"
          " the application is complete")


@dataclass(frozen=True)
class Refusal:
    at: str
    spec: str
    reason: str

    def line(self) -> str:
        return (f"first boot refused {self.spec} at {self.at}: {self.reason}."
                f" {REMEDY}")


def read(root: str) -> Refusal | None:
    """The record; a damaged one is still a refusal, so it is not hidden"""
    try:
        with open(os.path.join(root, RECORD)) as fob:
            found = json.load(fob)
        return Refusal(str(found["at"]), str(found["spec"]),
                       str(found["reason"]))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, KeyError, TypeError):
        return Refusal("an unknown time", "the spec",
                       f"/{RECORD} cannot be read")


def record(root: str, spec: str, reason: str) -> bool:
    """Keep the refusal; True when this is a new one, which the caller
    alerts on. Written before the alert, so an alert fires once"""
    new = read(root) is None
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_private(root, RECORD, json.dumps({
        "at": at, "spec": spec, "reason": reason.strip()[:REASON_LIMIT],
    }, sort_keys=True) + "\n")
    return new


def clear(root: str) -> None:
    try:
        os.unlink(os.path.join(root, RECORD))
    except FileNotFoundError:
        pass
