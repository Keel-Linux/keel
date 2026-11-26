# Copyright (c) 2026 KeelLinux maintainers
"""keel's own networks are never banned (keel#330, keel#303)

CrowdSec and fail2ban ban an address after a few failed logins or 401
answers. On an administrator's computer on the access network (decision
0098, section 4.7) that cuts SSH and the database relay; on a node of
the mesh (decision 0086, answer 1) it cuts etcd and the pair. So keel
writes:

- `/etc/crowdsec/parsers/s02-enrich/keel-whitelist.yaml`: a whitelist
  parser with the access /64 of `network.access.address` and the mesh
  /64 of `network.overlay.wireguard.address`, only the prefixes this
  node has, never all of fd00::/8;
- `/etc/fail2ban/jail.d/keel-ignoreip.local`: `ignoreip` of [DEFAULT]
  with the access /64. A later [DEFAULT] ignoreip replaces the one
  before it, so keel's file first carries every entry of every [DEFAULT]
  ignoreip, in the order fail2ban reads the files (jail.conf,
  jail.d/*.conf, jail.local, jail.d/*.local, keel's own file left out),
  continuation lines included: no entry of an operator is lost. The
  loopback where none has one. A jail's own ignoreip replaces the
  [DEFAULT] one for that jail; keel does not change it.

A prefix is never shorter than a /64: a mesh or access address declared
with a shorter prefix gives the /64 of the node's address, so the
whitelist never holds all of fd00::/8.

Each file is written only where its package is on the node (its
directory under /etc), and only while the spec declares a prefix; keel's
file goes when none is left. A file of that path that keel did not write
is left alone. The daemon reloads with `systemctl try-reload-or-restart`,
which does nothing where it does not run. keel diff compares both files
with what apply writes.
"""

import ipaddress
from dataclasses import dataclass

from keel.inspect.tree import File, Tree
from keel.network import access as accessnet
from keel.system.actions import (
    Action,
    Attempt,
    Note,
    RemoveFile,
    Step,
    WriteFile,
)

HEADER = "# keel: written by keel spec apply; do not edit (keel#330)\n"
CROWDSEC_DIR = "etc/crowdsec"
CROWDSEC_PATH = "etc/crowdsec/parsers/s02-enrich/keel-whitelist.yaml"
CROWDSEC_FIELD = "derived.crowdsec.whitelist"
CROWDSEC_UNIT = "crowdsec.service"
FAIL2BAN_DIR = "etc/fail2ban"
FAIL2BAN_PATH = "etc/fail2ban/jail.d/keel-ignoreip.local"
FAIL2BAN_FIELD = "derived.fail2ban.ignoreip"
FAIL2BAN_UNIT = "fail2ban.service"
JAIL_LOCAL = "etc/fail2ban/jail.local"
# the files fail2ban reads for its jails, in its order (jail.conf(5));
# keel's own file is left out of what is read back
JAIL_FILES = ("etc/fail2ban/jail.conf", "etc/fail2ban/jail.d/*.conf",
              JAIL_LOCAL, "etc/fail2ban/jail.d/*.local")
# the shortest prefix of keel's own networks that a whitelist holds
OWN_PREFIX = 64
# the [DEFAULT] ignoreip of the image's jail.local (common, turnkey.d)
LOOPBACK = ("127.0.0.1/8", "::1")
MODE = 0o644
APPLY = "keel spec apply --system"


def own_network(found: ipaddress.IPv6Interface) -> str:
    """The node's network, never shorter than a /64: a shorter prefix
    gives the /64 of the node's address"""
    if found.network.prefixlen >= OWN_PREFIX:
        return str(found.network)
    return str(ipaddress.ip_network((found.ip, OWN_PREFIX), strict=False))


def access_prefix(doc: dict) -> tuple[str, ...]:
    found = accessnet.section(doc)
    if found is None:
        return ()
    try:
        return (own_network(accessnet.address(found)),)
    except (KeyError, ValueError):
        return ()


def mesh_prefix(doc: dict) -> tuple[str, ...]:
    overlay = ((doc.get("network") or {}).get("overlay") or {})
    wireguard = overlay.get("wireguard") if isinstance(overlay, dict) \
        else None
    value = wireguard.get("address") if isinstance(wireguard, dict) \
        else None
    try:
        found = ipaddress.ip_interface(str(value))
    except ValueError:
        return ()
    return (own_network(found),) if found.version == 6 else ()


def crowdsec_prefixes(doc: dict) -> tuple[str, ...]:
    """The access /64 and the mesh /64 (decision 0086, answer 1)"""
    return tuple(dict.fromkeys(access_prefix(doc) + mesh_prefix(doc)))


def fail2ban_prefixes(doc: dict) -> tuple[str, ...]:
    """The access /64: the administrators' computers log in by SSH"""
    return access_prefix(doc)


def render_crowdsec(prefixes: tuple[str, ...]) -> str | None:
    if not prefixes:
        return None
    cidrs = "".join(f'    - "{prefix}"\n' for prefix in prefixes)
    return (f"{HEADER}"
            "# the access network and the mesh of this node (decision"
            " 0098, section 4.7; decision 0086, answer 1)\n"
            "name: keel/whitelist\n"
            'description: "keel: the networks of this node that are never'
            ' banned"\n'
            "whitelist:\n"
            '  reason: "keel: access network or mesh of this node"\n'
            "  cidr:\n"
            f"{cidrs}")


def ignoreip(*texts: str | None) -> tuple[str, ...]:
    """Every entry of every [DEFAULT] ignoreip of these files, in their
    order, continuation lines (indented) included; the loopback where
    none has one. An interpolation (%(...)s) is not an entry"""
    found: list[str] = []
    for text in texts:
        found += default_ignoreip(text)
    entries = tuple(dict.fromkeys(entry for entry in found
                                  if "%(" not in entry))
    return entries or LOOPBACK


def default_ignoreip(text: str | None) -> list[str]:
    found: list[str] = []
    section = ""
    inside = False
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0]
        if not line.strip():
            continue
        if raw[:1] in (" ", "\t"):
            # a continuation of the option before it
            if inside:
                found += line.split()
            continue
        line = line.strip()
        inside = False
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        name, equal, value = line.partition("=")
        if equal and section == "DEFAULT" and name.strip() == "ignoreip":
            inside = True
            found += value.split()
    return found


def jail_texts(tree: Tree) -> tuple[str | None, ...]:
    """The files fail2ban reads for its jails, in its order, without
    keel's own"""
    found: list[str | None] = []
    for pattern in JAIL_FILES:
        names = sorted(tree.glob(pattern)) if "*" in pattern else [pattern]
        found += [tree.read(name).text for name in names
                  if name.lstrip("/") != FAIL2BAN_PATH]
    return tuple(found)


def render_fail2ban(prefixes: tuple[str, ...],
                    base: tuple[str, ...] = LOOPBACK) -> str | None:
    if not prefixes:
        return None
    entries = tuple(dict.fromkeys(base + prefixes))
    return (f"{HEADER}"
            "# the access network of this node (decision 0098, section 4.7),"
            " after every [DEFAULT] ignoreip of fail2ban's other files\n"
            "[DEFAULT]\n"
            f"ignoreip = {' '.join(entries)}\n")


@dataclass(frozen=True)
class Target:
    field: str
    path: str
    unit: str
    # None where the package is not on the node
    current: File | None
    wanted: str | None

    @property
    def keel_s(self) -> bool:
        return self.current is not None and bool(self.current.text) and \
            self.current.text.startswith(HEADER)

    @property
    def present(self) -> bool:
        return self.current is not None and self.current.readable


@dataclass(frozen=True)
class TrustedState:
    crowdsec: File | None
    fail2ban: File | None
    # the files fail2ban reads for its jails, in its order (jail_texts)
    jails: tuple[str | None, ...] = ()


def observe_trusted(root: str) -> TrustedState:
    tree = Tree(root)
    return TrustedState(
        crowdsec=tree.read(CROWDSEC_PATH) if tree.exists(CROWDSEC_DIR)
        else None,
        fail2ban=tree.read(FAIL2BAN_PATH) if tree.exists(FAIL2BAN_DIR)
        else None,
        jails=jail_texts(tree))


def targets(doc: dict, state: TrustedState) -> list[Target]:
    """The files whose package is on the node, and that the spec wants
    or keel wrote"""
    found = [Target(CROWDSEC_FIELD, CROWDSEC_PATH, CROWDSEC_UNIT,
                    state.crowdsec, render_crowdsec(crowdsec_prefixes(doc))),
             Target(FAIL2BAN_FIELD, FAIL2BAN_PATH, FAIL2BAN_UNIT,
                    state.fail2ban, render_fail2ban(
                        fail2ban_prefixes(doc), ignoreip(*state.jails)))]
    return [one for one in found if one.current is not None
            and (one.wanted is not None or one.present)]


def plan_trusted(doc: dict, state: TrustedState, live: bool,
                 available: frozenset[str]) -> list[Step]:
    return [Step(one.field, actions(one, live, available))
            for one in targets(doc, state)]


def actions(target: Target, live: bool,
            available: frozenset[str]) -> tuple[Action, ...]:
    path = f"/{target.path}"
    if target.present and not target.keel_s:
        return (Note(f"{path} is there and keel did not write it: it is"
                     " left alone; move it away and apply again"),)
    if target.wanted is None:
        change: Action = RemoveFile(target.path, f"remove {path}, which"
                                    " keel wrote: the spec declares no"
                                    " prefix for it now")
    elif target.current.text == target.wanted:
        return (Note(f"unchanged ({path})"),)
    else:
        change = WriteFile(target.path, target.wanted, MODE, None,
                           f"write {path}: keel's own networks are never"
                           " banned")
    found: list[Action] = [change]
    if live and "systemctl" in available:
        found.append(Attempt(
            ("systemctl", "try-reload-or-restart", target.unit),
            f"reload {target.unit} where it runs, so it reads {path}",
            f"{target.unit} reads {path} at its next start"))
    return tuple(found)


def trusted_fields(declared: dict, root: str) -> list:
    from keel.diff.report import DRIFT, SAME, FieldDiff
    fields = []
    for one in targets(declared, observe_trusted(root)):
        path = f"/{one.path}"
        if one.present and not one.keel_s:
            fields.append(FieldDiff(one.field, DRIFT, "keel's file",
                                    "another file", note=f"{path} is not"
                                    f" keel's: {APPLY} leaves it alone"))
        elif one.wanted is None:
            fields.append(FieldDiff(one.field, DRIFT, None, "keel's file",
                                    note=f"the spec declares no prefix for"
                                    f" it: {APPLY} removes {path}"))
        elif one.current.text == one.wanted:
            fields.append(FieldDiff(one.field, SAME, path, path))
        else:
            fields.append(FieldDiff(
                one.field, DRIFT, path,
                "another content" if one.present else "missing",
                note=f"{path} is not what the spec renders: {APPLY}"))
    return fields
