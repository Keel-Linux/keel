# Copyright (c) 2026 KeelLinux maintainers
"""What the spec declared of its overlays when it was last applied

Rule 25 of docs/manifest-v1.md wants every overlay of the chain written
out (decisions 0027, 0041). An upgrade can add one to the chain, as
keel-core 0.1.3 added `vip`, and a spec written before it cannot name
it. This record tells the two cases apart: an overlay the spec leaves
out that is in the record was declared and is now missing, the error;
one that is not was gained by the chain since, and takes its manifest
default (keel.spec.validate_appliance.undeclared_defaults).

`apply --system` writes it after a run that did not fail, from the
overlays the spec itself declared, never from the defaults it filled in,
so a gained overlay stays a warning until the operator writes it out.
It is a list of names, not states, root's and world readable.
"""

import os

import yaml

RECORD = "var/lib/keel/spec/overlays.yaml"
MODE = 0o644
HEADER = ("# Written by keel spec apply --system: the overlays the spec"
          " declared\n# when it was last applied (keel docs/spec.md)\n")


def read(root: str, appliance: str) -> frozenset[str] | None:
    """The names recorded for APPLIANCE, or None without a usable one"""
    try:
        with open(os.path.join(root, RECORD)) as fob:
            doc = yaml.safe_load(fob)
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(doc, dict) or doc.get("appliance") != appliance:
        return None
    names = doc.get("overlays")
    if not isinstance(names, list) or not all(isinstance(name, str)
                                              for name in names):
        return None
    return frozenset(names)


def write(root: str, appliance: str, names) -> None:
    """Replace the record, through a temporary file in its directory"""
    path = os.path.join(root, RECORD)
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    text = HEADER + yaml.safe_dump(
        {"appliance": appliance, "overlays": sorted(names)},
        sort_keys=False, default_flow_style=False)
    temporary = f"{path}.tmp"
    with open(temporary, "w") as fob:
        fob.write(text)
    os.chmod(temporary, MODE)
    os.replace(temporary, path)
