# Copyright (c) 2026 KeelLinux maintainers
"""keel firewall repair: a node that was in enforce is never open
without a loud signal (decision 0097; the fourth real test)

An empty, cut or missing ruleset file was written again only by a
person's apply: the watch and the boot left the node open. This runs
the firewall step of the apply itself, unattended, from the spec on
disk, so the same code writes the file and loads it: the state comes
from the evidence the apply reads (the record, the loaded table), and an
unattended run never begins enforcement nor leaves it. keel-firewall.
service runs it before its load at boot, and the watch on a broken file.

Where the step cannot write the file (the spec cannot be read, sshd's
ports are unknown, ...), and the evidence says enforce, a closed
fallback table is loaded instead, and the run fails: the unit stays
failed and the node degraded until an apply. The fallback lets in the
loopback, established traffic, ICMPv6, the DHCP client, sshd's ports
(22 when they cannot be read), and, where the spec declares a mesh, the
WireGuard port and everything on the overlay's interface. It never
opens. A missing file with no evidence of a firewall (no trusted record, no
loaded table: a node upgraded from 0.23.97, or a new node before its
first apply) is NOT APPLIED, a state: nothing is written, loaded or
failed, and nothing is said.
"""

import os
import shutil
import subprocess

import yaml

from keel import exits
from keel.inspect.tree import Tree
from keel.manifest.firewall import (
    ALWAYS,
    OFF,
    PATH,
    digest_of,
    file_state,
    loaded_digest,
)
from keel.network import wireguard
from keel.spec.validate_firewall import declared_state
from keel.system import fwrecord

SPEC = "etc/keel/instance.yaml"
# how long the repair waits for an apply that holds the firewall lock
LOCK_WAIT = 5.0
FALLBACK = "run/keel/firewall-fallback.nft"
SPEC_BROKEN = (f"/{SPEC} cannot be read or parsed: the node keeps the"
               " ruleset of its last apply, and this stays a failure until"
               " the spec is put right and keel spec apply --system runs")


def spec_doc(root: str) -> dict | None:
    """The spec on disk, or None when there is none to read"""
    try:
        with open(os.path.join(root, SPEC)) as fob:
            found = yaml.safe_load(fob)
    except (OSError, yaml.YAMLError):
        return None
    return found if isinstance(found, dict) else None


def wants_firewall(doc: dict | None) -> bool:
    """A spec that names an appliance and does not say off"""
    return (doc is not None and isinstance(doc.get("appliance"), dict)
            and declared_state(doc) != OFF)


def read_file(root: str) -> str | None:
    try:
        with open(os.path.join(root, PATH)) as fob:
            return fob.read()
    except FileNotFoundError:
        return None
    except OSError:
        return ""


def sound(text: str | None) -> bool:
    return bool(text) and file_state(text) is not None and \
        digest_of(text) == loaded_digest(text)


def repair(root: str, live: bool = True, run=None, boot: bool = False,
           lock: bool | None = None) -> tuple[int, list[str]]:
    """The exit code and the lines to say; (OK, []) when there is
    nothing to repair. A node with no evidence of a firewall (no file,
    no trusted record, no loaded table) is NOT APPLIED, not a failure.
    `boot` is kept for the unit's command line. On the live system (or
    with `lock`) it holds the lock the apply holds, and skips its run
    when an apply has it (keel.system.fwlock)"""
    if not (live if lock is None else lock):
        return attempt(root, live, run)
    from keel.system import fwlock
    with fwlock.held(root, LOCK_WAIT) as held:
        if not held:
            return exits.OK, ["an apply holds the firewall lock: this"
                              " repair skips its run; the next one, or the"
                              " apply, puts the ruleset right"]
        return attempt(root, live, run)


def attempt(root: str, live: bool, run) -> tuple[int, list[str]]:
    """The repair itself, under the lock where there is one"""
    run = run or subprocess.run
    doc = spec_doc(root)
    text = read_file(root)
    if sound(text) or (doc is not None and not wants_firewall(doc)):
        return exits.OK, []
    evidence = prior(root, live, run)
    if evidence is None:
        # no trusted record, no loaded table: a node upgraded from
        # 0.23.97, or a new node before its first apply, is NOT APPLIED,
        # a state (0097); an upgrade changes nothing by itself (0073).
        # A broken file with no evidence goes to the step if the spec
        # can be read, which writes what an unattended apply writes
        if text is None or doc is None:
            return exits.OK, []
        return finish(root, doc, live, run, evidence, step(root, doc, live))
    restored, said = restore_copy(root, live, run)
    if restored and doc is None:
        # closed by the copy, and loud until the spec is put right (the
        # sixth real test: check exit 0, the node running)
        return exits.DRIFT_FOUND, said + [SPEC_BROKEN]
    if restored:
        return exits.OK, said
    if doc is None:
        code, lines = unreadable(root, live, run, evidence)
        return code, said + lines
    code, lines = finish(root, doc, live, run, evidence,
                         step(root, doc, live))
    return code, said + lines


def finish(root: str, doc: dict, live: bool, run, evidence: str | None,
           lines: list[str]) -> tuple[int, list[str]]:
    """After the step: the file sound, else the fallback where the node
    was in enforce, else a loud failure"""
    if sound(read_file(root)):
        return exits.OK, lines + [f"/{PATH} written again by the"
                                  " firewall step of the apply"]
    if evidence == "enforce":
        return exits.APPLY_FAILED, lines + load_fallback(root, doc, live,
                                                         run)
    return exits.DRIFT_FOUND, lines + [f"/{PATH} is not written again:"
                                       " keel spec apply --system says why"]


def unreadable(root: str, live: bool, run,
               evidence: str) -> tuple[int, list[str]]:
    """A spec that cannot be read or parsed never means do nothing on a
    node with evidence of a firewall (the fifth real test): closed and
    failed where it was in enforce, loud where it was in report"""
    said = (f"/{SPEC} cannot be read or parsed, and keel's record (or the"
            f" loaded table) says {evidence}")
    if evidence != "enforce":
        return exits.DRIFT_FOUND, [f"{said}: /{PATH} is not written again;"
                                   " keel spec apply --system writes it"
                                   " once the spec is put right"]
    return exits.APPLY_FAILED, [said] + load_fallback(root, {}, live, run)


def restore_copy(root: str, live: bool, run) -> tuple[bool, list[str]]:
    """keel's last good copy of the ruleset, put back and loaded: it does
    not need the spec, and keeps the declared ports open. Valid only when
    its sha256 is the one keel's record holds, the ruleset of the last
    apply (the sixth real test: an old copy opened a removed port again,
    and a report copy put an enforce node in report). Whether it was
    restored, and what to say"""
    from keel.system.actions import InstallRuleset
    from keel.system.effects import Effects
    copy, _ = fwrecord.read_copy(Tree(root))
    if not sound(copy):
        return False, []
    _, digest, _ = fwrecord.read_full(Tree(root))
    if digest != fwrecord.ruleset_hash(copy):
        return False, [f"/{fwrecord.COPY} is not the ruleset of the last"
                       " apply (its hash is not the one keel's record"
                       " holds): it is not restored"]
    problem = Effects(root).apply(InstallRuleset(
        PATH, copy, f"restore /{PATH} from keel's last good copy"))
    if problem is None and live:
        try:
            out = run(["nft", "-f", os.path.join(root, PATH)],
                      capture_output=True, text=True, check=False)
            problem = None if out.returncode == 0 else "nft -f refused it"
        except OSError as e:
            problem = f"nft cannot run: {e.strerror}"
    if problem:
        return False, [f"keel's last good copy is not restored: {problem}"]
    return True, [f"/{PATH} restored from keel's last good copy"
                  f" (/{fwrecord.COPY})"]


def evidence_of(root: str, run=None) -> str | None:
    """prior() for keel firewall check: the live system when root is /"""
    return prior(root, os.path.abspath(root) == "/", run or subprocess.run)


def prior(root: str, live: bool, run) -> str | None:
    """enforce or report from keel's record, else from the loaded
    table's policy; None when nothing says"""
    recorded, warning = fwrecord.read(Tree(root))
    if recorded in ("enforce", "report"):
        return recorded
    if recorded == "off":
        return None
    if warning:
        # a record that is there and not trusted: the state is unknown,
        # and the safe side is closed (the fifth real test: the boot
        # moved such a node from enforce to report)
        return "enforce"
    if not live:
        return None
    from keel.system.fwcheck import table_listing
    listing = table_listing(run) or ""
    if "policy drop;" in listing:
        return "enforce"
    return "report" if "policy accept;" in listing else None


def step(root: str, doc: dict, live: bool,
         no_fence: bool = False) -> list[str]:
    """The apply's firewall step, unattended; the lines it printed.
    `no_fence`: the fence failed, and its ports are not opened"""
    from dataclasses import replace
    from keel.commands import manifest_facts
    from keel.spec.validate_appliance import with_defaults
    from keel.system import appstate
    from keel.system.actions import Plan
    from keel.system.effects import Effects
    from keel.system.execute import execute
    from keel.system.firewall import plan_firewall
    full, _ = with_defaults(doc, manifest_facts(doc, root))
    appliance = appstate.observe_appliance(root, full)
    if appliance is None:
        return ["no appliance is resolved: the firewall step does not run"]
    available = frozenset(name for name in ("nft", "systemctl")
                          if live and shutil.which(name))
    state = appliance.firewall
    if no_fence and state.fence:
        from keel.system.fwstate import FENCE_FAILED
        state = replace(state, fence=(), fence_note=FENCE_FAILED)
    steps = plan_firewall(full, appliance.resolved, state,
                          live, available, attended=False)
    outcome = execute(Plan(tuple(steps)), Effects(root), False,
                      "keel firewall repair")
    return list(outcome.lines)


FENCE_SPEC = (f"/{SPEC} cannot be read or parsed: /{PATH} keeps the"
              " rule of the init fence, and keel spec apply --system writes"
              " it again once the spec is put right")


def refresh(root: str, live: bool = True, run=None,
            lock: bool | None = None,
            wait: float = LOCK_WAIT,
            failed: bool = False) -> tuple[int, list[str]]:
    """keel firewall refresh: the ruleset written again when the init
    fence is gone (decision 0097, section 2, item 4; keel#322)

    The ExecStopPost of turnkey-init-fence.service runs it, through
    keel's drop-in. While the fence is enabled (a shutdown, a stop by
    hand) it does nothing: the fence comes back at the next boot, and its
    rule stays. When the fence is no longer enabled, it runs the apply's
    firewall step, unattended, from the spec on disk: the fence rule goes
    from the file and from the loaded table, and the state stays what
    the evidence says. It never begins a firewall (no evidence: NOT
    APPLIED), never restores the copy and never loads the fallback: the
    old ruleset stays, and the line says why. It never fails, because
    the stop of the fence must succeed

    `failed`: the fence's start failed (SERVICE_RESULT is not success).
    systemd runs the ExecStopPost then, while the fence is still
    enabled, and a later disable and stop of the failed unit runs none.
    The fence redirects nothing, so its ports go from the ruleset now,
    also while it is enabled"""
    from keel.system.fwstate import fence_enabled
    if fence_enabled(Tree(root)) and not failed:
        return exits.OK, []
    if not (live if lock is None else lock):
        return exits.OK, refreshed(root, live, run or subprocess.run,
                                   failed)
    from keel.system import fwlock
    with fwlock.held(root, wait) as held:
        if not held:
            return exits.OK, ["an apply holds the firewall lock: this"
                              " refresh skips its run; the apply renders"
                              " the ruleset from the same state"]
        return exits.OK, refreshed(root, live, run or subprocess.run,
                                   failed)


def refreshed(root: str, live: bool, run,
              failed: bool = False) -> list[str]:
    """The step, where keel's firewall is on; what it said"""
    if prior(root, live, run) is None:
        return []
    doc = spec_doc(root)
    if doc is None:
        return [FENCE_SPEC]
    if not wants_firewall(doc):
        return []
    return step(root, doc, live, failed)


def fallback(ssh: tuple[int, ...], overlay: tuple[str, int] | None) -> str:
    """A closed table: what keeps the node reachable and nothing else"""
    rules = list(ALWAYS)
    ports = ", ".join(str(port) for port in sorted(set(ssh)))
    rules.append(f"tcp dport {{ {ports} }} accept" if len(set(ssh)) > 1
                 else f"tcp dport {ports} accept")
    if overlay:
        rules.append(f"udp dport {overlay[1]} accept")
        rules.append(f'iifname "{overlay[0]}" accept')
    body = "".join(f"\t\t{rule}\n" for rule in rules)
    return ("table inet keel\ndelete table inet keel\ntable inet keel {\n"
            '\tcomment "keel-fallback"\n\tchain input {\n'
            "\t\ttype filter hook input priority filter; policy drop;\n"
            f"{body}\t}}\n}}\n")


def load_fallback(root: str, doc: dict, live: bool, run) -> list[str]:
    from keel.system.fwstate import ssh_ports
    ssh, _ = ssh_ports(Tree(root), live)
    wg = ((doc.get("network") or {}).get("overlay") or {}).get("wireguard")
    overlay = None
    if isinstance(wg, dict):
        overlay = (wg.get("interface") or wireguard.DEFAULT_INTERFACE,
                   wg.get("listen_port") or wireguard.DEFAULT_PORT)
    path = os.path.join(root, FALLBACK)
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path, "w") as fob:
        fob.write(fallback(ssh or (22,), overlay))
    try:
        out = run(["nft", "-f", path], capture_output=True, text=True,
                  check=False)
        problem = None if out.returncode == 0 else (
            (out.stderr or out.stdout or "").strip() or "refused")
    except OSError as e:
        problem = f"nft cannot run: {e.strerror}"
    said = (f"the node was in enforce and /{PATH} cannot be written again:"
            " the closed fallback table is loaded (drop; sshd's ports"
            f" {', '.join(str(p) for p in (ssh or (22,)))}"
            + (", the mesh" if overlay else "") + "); the node stays"
            " degraded until keel spec apply --system")
    if problem:
        said = (f"the node was in enforce and /{PATH} cannot be written"
                f" again, and the closed fallback did not load: {problem}")
    return [said]
