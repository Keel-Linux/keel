# Copyright (c) 2026 KeelLinux maintainers
"""keel firewall check: is the table the kernel holds the file's?

Decision 0097, section 4. Run by keel-firewall-watch.timer (with
--restore) and by Monit's check where the spec enables the monitor.
Nothing in the file is trusted for itself (the real test of PR 307: a
broken file whose digest comment was intact passed):

- the rules in the file must be the ones its digest names
  (keel.manifest.firewall.digest_of), else it was edited by hand;
- `nft -c` must accept the file;
- the table `inet keel` the kernel holds must carry that digest and the
  file's policy.

Exit 0 when they agree or when there is no file of keel's; DRIFT_FOUND
otherwise. A table that is absent or another, beside a sound file, is
`restorable`: --restore loads the file again with `nft -f`, one
transaction that replaces keel's table only. A broken file is never
loaded: that is for keel spec apply --system.
"""

import os
import re
import subprocess
from dataclasses import dataclass

from keel import exits
from keel.manifest.firewall import (
    CHAIN_HEAD,
    PATH,
    POLICY,
    POLICY_RE,
    TABLE,
    TAIL,
    TYPE_RE,
    digest_of,
    file_state,
    keel_owns,
    loaded_digest,
)

APPLY = "keel spec apply --system writes it again"


@dataclass(frozen=True)
class Checked:
    code: int
    message: str
    restorable: bool = False
    # the listing of the table the check accepted (the watch's mark)
    listing: str | None = None


def check(root: str, run=None) -> Checked:
    run = run or subprocess.run
    path = os.path.join(root, PATH)
    try:
        with open(path) as fob:
            text = fob.read()
    except FileNotFoundError:
        text = None
    except OSError as e:
        return Checked(exits.DRIFT_FOUND,
                       f"{path} cannot be read: {e.strerror}")
    if text is None:
        return missing(root, path, run)
    state = file_state(text)
    if state is None and not keel_owns(text):
        return Checked(exits.DRIFT_FOUND, (
            f"{path} is not keel's (no header of keel's): keel spec apply"
            " does not replace it; move it away, and the apply writes"
            " keel's"))
    if state is None:
        return Checked(exits.DRIFT_FOUND, (
            f"{path} is empty or cut short (it loads no table): {APPLY}"))
    return compare(path, text or "", state, run)


def missing(root: str, path: str, run) -> Checked:
    """No ruleset file: a failure only where there is evidence the node
    had a firewall (a trusted record, or a loaded table of keel's);
    else NOT APPLIED, a state, with the exit it always had (0). A spec
    that cannot be read or parsed does not hide that evidence"""
    from keel.system import fwrepair
    doc = fwrepair.spec_doc(root)
    if doc is not None and not fwrepair.wants_firewall(doc):
        return Checked(exits.OK,
                       f"{path}: no ruleset of keel's, nothing to compare")
    found = fwrepair.evidence_of(root, run)
    if found is None:
        if doc is None:
            return Checked(exits.OK,
                           f"{path}: no ruleset of keel's, nothing to compare")
        return Checked(exits.OK, (
            f"NOT APPLIED: {path} is not there, and nothing says this node"
            " had a firewall of keel's; keel spec apply --system writes it"))
    spec = "" if doc is not None else (
        f"; /{fwrepair.SPEC} cannot be read or parsed")
    return Checked(exits.DRIFT_FOUND, (
        f"{path}: no ruleset file, and keel's record says {found} (or the"
        f" loaded table does){spec}: keel spec apply --system writes it"
        " again"))


def compare(path: str, text: str, state: str, run) -> Checked:
    wanted = loaded_digest(text)
    if digest_of(text) != wanted:
        return Checked(exits.DRIFT_FOUND, (
            f"the rules in the file are not the ones its digest names"
            f" ({path}, a change by hand): {APPLY}"))
    refused = nft_refuses(path, run)
    if refused is not None:
        return Checked(exits.DRIFT_FOUND,
                       f"nft -c refuses {path}: {refused}; {APPLY}")
    listing = table_listing(run)
    if listing is None:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel is not loaded; {path} says {wanted}"), True)
    held = loaded_digest(listing)
    if held != wanted:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel holds {held}; {path} says {wanted}"), True)
    policy = POLICY_RE.search(listing)
    found = policy.group(1) if policy else "none"
    if found != POLICY[state]:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel has policy {found}, and the file says"
            f" {POLICY[state]}"), True)
    differs = rules_differ(listing, text)
    if differs is not None:
        return Checked(exits.DRIFT_FOUND, differs, True)
    root = path[:-len(PATH)].rstrip("/") or "/"
    from keel.system import fwrepair
    if fwrepair.spec_doc(root) is None:
        # closed by keel's file (or its last good copy), and a failure
        # until the spec is put right (the sixth real test)
        return Checked(exits.DRIFT_FOUND, f"table inet keel is the one"
                       f" {path} says; but {fwrepair.SPEC_BROKEN}")
    return Checked(exits.OK,
                   f"table inet keel is the one {path} says ({wanted})",
                   listing=listing)


# the rule firewall/firewall-ssh-guard inserts at a load, where the file
# closes IPv4 22 and the node lost its global IPv6 (decision 0098): keel's
# own, and no edit by hand
GUARD_COMMENT = 'comment "keel-ssh-guard"'
SET_RE = re.compile(r"\{ ([^{}]*) \}")
HOST_RE = re.compile(r"(\b\d{1,3}(?:\.\d{1,3}){3})/32\b|"
                     r"([0-9a-fA-F:]*:[0-9a-fA-F:]*)/128\b")
COUNTERS_RE = re.compile(r"counter packets \d+ bytes \d+")


def canonical(rule: str) -> str:
    """One rule in the form nft prints it: a host prefix (/32, /128)
    dropped, the elements of an anonymous set in one order, counters
    without their numbers, one space between words"""
    rule = COUNTERS_RE.sub("counter", " ".join(rule.split()))
    rule = HOST_RE.sub(lambda m: m.group(1) or m.group(2), rule)
    return SET_RE.sub(lambda m: "{ " + ", ".join(
        sorted(m.group(1).split(", "))) + " }", rule)


def file_rule_lines(text: str) -> list[str]:
    """The rules of the input chain in a file keel wrote"""
    head = TYPE_RE.search(text, text.index(CHAIN_HEAD))
    return [line.strip() for line in text[head.end():-len(TAIL)]
            .splitlines() if line.strip()]


def file_rules(text: str) -> int:
    return len(file_rule_lines(text))


def listed_rule_lines(listing: str) -> list[str]:
    """The rules of the input chain in `nft -s list table inet keel`:
    the lines after its type line, up to the chain's closing brace"""
    head = POLICY_RE.search(listing)
    if head is None:
        return []
    found = []
    for line in listing[listing.index("\n", head.end()) + 1:].splitlines():
        if line.strip() == "}":
            break
        if line.strip():
            found.append(line.strip())
    return found


def rules_differ(listing: str, text: str) -> str | None:
    """Why the loaded input chain is not the one the file loads, rule by
    rule and in order; None when it is"""
    held = [line for line in listed_rule_lines(listing)
            if GUARD_COMMENT not in line]
    wanted = file_rule_lines(text)
    if len(held) != len(wanted):
        return (f"table inet keel holds {len(held)} rule(s), and the file"
                f" has {len(wanted)} (a chain flushed or edited by hand)")
    for number, (one, other) in enumerate(zip(held, wanted), 1):
        if canonical(one) != canonical(other):
            return (f"rule {number} of table inet keel is '{one}', and the"
                    f" file says '{other}' (a rule edited by hand)")
    return None


def nft_refuses(path: str, run) -> str | None:
    try:
        out = run(["nft", "-c", "-f", path], capture_output=True, text=True,
                  check=False)
    except OSError as e:
        return f"nft cannot run: {e.strerror}"
    if out.returncode == 0:
        return None
    return (out.stderr or out.stdout or "").strip() or "refused"


def table_listing(run) -> str | None:
    try:
        out = run(["nft", "-s", "list", "table", *TABLE],
                  capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def restore(root: str, run=None) -> str | None:
    """Load keel's file again; None, or why it failed"""
    run = run or subprocess.run
    path = os.path.join(root, PATH)
    try:
        out = run(["nft", "-f", path], capture_output=True, text=True,
                  check=False)
    except OSError as e:
        return f"nft cannot run: {e.strerror}"
    if out.returncode == 0:
        return None
    return (out.stderr or out.stdout or "").strip() or "refused"
