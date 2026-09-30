# Copyright (c) 2026 KeelLinux maintainers
"""What the manifests of the spec's appliance declare, for the spec

`keel spec validate` becomes manifest-aware here (decision 0041): the
appliance the spec names is looked up under the root, validated and
resolved along its chain, and what rules 25 to 27 hold the spec against
is handed to keel.spec as plain data. A chain that cannot be used is
one problem, rule 25's, rather than a spec checked against half of it.
"""

from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.resolve import resolve
from keel.spec.validate_appliance import ManifestFacts


def gather(root: str, name: str) -> ManifestFacts:
    """The facts of the appliance NAME installed under ROOT"""
    catalog = Catalog(root)
    doc, reason = catalog.usable(APPLIANCE, name)
    if doc is None:
        return ManifestFacts(name, problems=(
            reason or f"{name} is not an installed appliance under"
            f" {catalog.directory()}",))
    resolved, errors = resolve(catalog, doc)
    if resolved is None or errors:
        return ManifestFacts(name, problems=tuple(
            f"the chain of {name} does not resolve: {error}"
            for error in errors))
    return ManifestFacts(
        appliance=name,
        chain=resolved.chain,
        overlays={state.name: tuple(state.manifest.get("requires") or ())
                  for state in resolved.overlays},
        secrets={owned.item["name"]: (owned.item["generate"], owned.origin)
                 for owned in resolved.secrets},
        options=tuple((owned.item, owned.origin)
                      for owned in resolved.options),
        resolved=resolved,
    )
