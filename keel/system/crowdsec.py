# Copyright (c) 2026 KeelLinux maintainers
"""CrowdSec's identity, made on the first enable (tracker#47)

trixie's crowdsec registers the machine with its local API (LAPI) and
with CrowdSec's central API (CAPI) in its postinst, and the firewall
bouncer adds itself and stores its key. In an image that happens once,
so every machine made from it would share one identity; the Core image
deletes those files, and keel makes them again when the spec first turns
the overlay on:

- `cscli machines add --auto --force`, which writes the LAPI password to
  local_api_credentials.yaml itself;
- an empty online_api_credentials.yaml, which is how the Debian package
  records "not registered yet" and without which its unit does not
  start, then `cscli capi register`. That one needs the network; when it
  fails the file stays empty, the local API runs without the central
  one, and the run goes on and says so;
- `cscli bouncers add`, whose key is read from its standard output into
  memory and written to the bouncer's `.local` file, mode 0600. A
  registration the Debian package queued and never finished is replaced
  the same way, since its queue file keeps the bouncer from starting.
  The bouncer's `mode:` is always nftables (NFTABLES below).

No secret reaches an argument vector, a plan line or an error message.
Only what is missing is made, so a second apply makes nothing; nothing
is made under --root, since an image is exactly where an identity must
not be made. The planner here is pure; add_bouncer is carried out for
keel.system.effects, its only caller.
"""

import contextlib
import os
import secrets
import subprocess
from dataclasses import dataclass

from keel.inspect.tree import File, Tree
from keel.system.actions import (
    Action,
    AddBouncer,
    Attempt,
    Note,
    Refuse,
    Run,
    SetBouncerMode,
    WriteFile,
)

OVERLAY = "crowdsec"
LAPI = "etc/crowdsec/local_api_credentials.yaml"
CAPI = "etc/crowdsec/online_api_credentials.yaml"
BOUNCER = "etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local"
BOUNCER_ID = "etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.id"
# The bouncer's backend, whatever the iptables alternative says. The
# Debian postinst picks iptables under iptables-legacy, which TurnKey
# selects for Webmin, and that mode needs ipset, which nothing installs:
# the bouncer then dies with "unable to find ipset". nftables is trixie's
# default, needs nothing more, and its tables live beside legacy
# iptables rules, both evaluated at the same hooks.
NFTABLES = "nftables"
# where the bouncer's postinst queues its registration when crowdsec is
# not configured yet; crowdsec's postinst skips the queue whenever its
# unit is not active, and the bouncer's unit will not start while it is
# there (ConditionPathExists=!), so keel registers anew and removes it
PENDING = "var/lib/crowdsec/pending-registration"
# the Debian package's name for a bouncer: a prefix and 32 random letters
BOUNCER_PREFIX = "FirewallBouncer-"
CSCLI = "cscli"
ID_MODE = 0o644
KEY_MODE = 0o600


@dataclass(frozen=True)
class CrowdsecState:
    """What of the identity is on the machine; never a secret itself

    `capi` is `absent`, `empty` (created, not registered: offline, or an
    operator's choice) or `present`. `bouncer_mode` is the `mode:` line
    of the bouncer's `.local` file and `bouncer_id` the name the `.id`
    file records.
    """

    lapi: bool
    capi: str
    bouncer_key: bool
    bouncer_mode: str | None
    bouncer_id: str | None
    pending: bool = False


def value_of(text: str | None, key: str) -> str | None:
    """The value of a top level `key: value` line; never logged"""
    for line in (text or "").splitlines():
        name, colon, value = line.partition(":")
        if colon and name.strip() == key and value.strip():
            return value.strip()
    return None


def capi_state(capi: File) -> str:
    """absent, empty or present, as CrowdsecState has it

    A file of comments only is absent, not a registration: the Core
    image build seeds one so the package's postinst does not register in
    the chroot, and one left in an image would otherwise keep `cscli capi
    register` from ever running (keel#61). An empty one is the package's
    "not registered yet", which an operator may also keep on purpose.
    """
    if not capi.readable:
        return "absent"
    if not (capi.text or "").strip():
        return "empty"
    return "present" if capi.lines() else "absent"


def observe_crowdsec(tree: Tree) -> CrowdsecState:
    capi = tree.read(CAPI)
    bouncer = tree.read(BOUNCER).text
    return CrowdsecState(
        lapi=value_of(tree.read(LAPI).text, "password") is not None,
        capi=capi_state(capi),
        bouncer_key=value_of(bouncer, "api_key") is not None,
        bouncer_mode=value_of(bouncer, "mode"),
        bouncer_id=(tree.read(BOUNCER_ID).text or "").strip() or None,
        pending=tree.exists(PENDING),
    )


def missing(state: CrowdsecState) -> bool:
    return (not state.lapi or state.capi == "absent"
            or not state.bouncer_key or state.pending)


def plan_identity(state: CrowdsecState, live: bool,
                  available: frozenset[str]) -> list[Action]:
    """What the first enable makes, before the units start"""
    mode: list[Action] = []
    if (state.bouncer_key and not state.pending
            and state.bouncer_mode != NFTABLES):
        mode = [SetBouncerMode(BOUNCER, NFTABLES, state.bouncer_mode)]
    if not missing(state):
        if state.capi == "empty":
            return [Note(
                f"/{CAPI} is empty: CrowdSec runs on its local API alone;"
                " `cscli capi register` joins the central one, where the"
                " machine reaches it")] + mode
        return mode
    if not live:
        return [Note(
            "CrowdSec's identity is not made under --root: an image would"
            " give every machine made from it the same one (tracker#47);"
            " apply on the machine makes it")] + mode
    if CSCLI not in available:
        return [Refuse("cscli not found: the crowdsec package is not"
                       " installed, and keel installs no package")]
    actions: list[Action] = []
    # cscli refuses to run without the file, so it comes first
    if state.capi == "absent":
        actions.append(WriteFile(
            CAPI, "", KEY_MODE, None,
            f"create /{CAPI} empty, which CrowdSec's unit needs and which"
            " says not registered yet"))
    if not state.lapi:
        actions.append(Run(
            (CSCLI, "--error", "machines", "add", "--auto", "--force"),
            f"register this machine with CrowdSec's local API; cscli writes"
            f" the password to /{LAPI}"))
    # an empty file with no local registration is a first enable that
    # stopped half way, so the central API is still asked; an empty one
    # beside a registered machine is offline or the operator's choice
    if state.capi == "absent" or (state.capi == "empty" and not state.lapi):
        actions.append(Attempt(
            (CSCLI, "--error", "capi", "register"),
            "register with CrowdSec's central API",
            "the local API runs without it; `cscli capi register` joins"
            " later, where the machine reaches api.crowdsec.net"))
    if not state.bouncer_key or state.pending:
        actions.append(AddBouncer(BOUNCER, BOUNCER_ID, NFTABLES,
                                  state.bouncer_id,
                                  PENDING if state.pending else None))
    return actions + mode


def set_mode(root: str, action: SetBouncerMode) -> str | None:
    """Rewrite the `mode:` line of the bouncer's file, keeping the rest"""
    path = os.path.join(root, action.config)
    text = _read(path)
    if text is None:
        return f"/{action.config} cannot be read"
    kept = [line for line in text.splitlines() if value_key(line) != "mode"]
    _write(path, "".join(f"{line}\n" for line in
                         [f"mode: {action.mode}", *kept]), KEY_MODE)
    return None


def add_bouncer(root: str, action: AddBouncer) -> str | None:
    """Register a new bouncer, then store its key; None when done"""
    if action.old_id:
        # a bouncer this machine made before; gone already is fine
        subprocess.run([CSCLI, "--error", "bouncers", "delete", "--",
                        action.old_id], capture_output=True, text=True,
                       check=False)
    name = BOUNCER_PREFIX + secrets.token_hex(16)
    try:
        out = subprocess.run(
            [CSCLI, "--error", "-oraw", "bouncers", "add", name],
            capture_output=True, text=True, check=False)
    except OSError as e:
        return f"cannot run {CSCLI}: {e.strerror}"
    if out.returncode != 0:
        return (f"{CSCLI} bouncers add exited {out.returncode}:"
                f" {out.stderr.strip()}")
    key = out.stdout.strip()
    if not key or len(key.split()) != 1:
        return f"{CSCLI} bouncers add printed no key"
    # the name first: a bouncer registered is one the next run can delete
    _write(os.path.join(root, action.id_file), f"{name}\n", ID_MODE)
    path = os.path.join(root, action.config)
    kept = [line for line in (_read(path) or "").splitlines()
            if value_key(line) not in ("mode", "api_key")]
    _write(path, "".join(f"{line}\n" for line in
                         [f"mode: {action.mode}", f"api_key: {key}", *kept]),
           KEY_MODE)
    if action.pending:
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(root, action.pending))
    return None


def value_key(line: str) -> str:
    return line.partition(":")[0].strip()


def _read(path: str) -> str | None:
    try:
        with open(path) as fob:
            return fob.read()
    except OSError:
        return None


def _write(path: str, text: str, mode: int) -> None:
    """Write through a file made with MODE, so the key is never readable
    by others, not even for a moment"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.keel-new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, "w") as fob:
        fob.write(text)
    os.replace(temporary, path)
