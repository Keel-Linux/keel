# Copyright (c) 2026 KeelLinux maintainers
"""etcd's configuration, rendered from the state (decisions 0025, 0048)

The spec says only `overlays.etcd: enabled`; who the members are, and
this member's certificates, are state under /var/lib/keel/etcd (0048,
third round, point 2; keel.mesh.etcdstate). When the overlay is
enabled, apply writes from that state:

- /etc/default/etcd, which trixie's etcd.service reads as its
  environment (keel.mesh.etcdconf), 0644, as Debian ships it;
- /etc/etcd/keel/member.crt and member.key, the member's certificate
  with its chain and its key, ca.crt, the mesh's root, and crl.pem, the
  root's CRL, owned by the etcd user the Debian unit runs as, 0600: no
  other user reads the key; etcd reads the CRL at each handshake;
- the systemd drop-in that orders etcd after the overlay and sandboxes
  it, followed by `systemctl daemon-reload`.

Before this member is in a cluster there is nothing to render: a cloud
advanced installation enables the overlay from its first boot (0041's
defaults), and etcd waits for its cluster without failing the run
(`waiting`), started by the join or `keel mesh etcd form` that forms or
joins it (keel.mesh.etcd). etcd is started with `--no-block`: it says it
is ready only once a majority runs.

etcd is restarted when its environment changes, but not for the
`ETCD_INITIAL_*` lines once its data directory holds a member: etcd
reads them only at its first start. A renewed certificate is not a
restart: etcd reads its certificate files at each handshake.
"""

import os
from dataclasses import dataclass

from keel.inspect.accounts import passwd_entries
from keel.inspect.constants import PASSWD
from keel.inspect.tree import Tree
from keel.mesh import etcdconf, etcdstate
from keel.mesh.etcdstate import Cluster, StateError
from keel.network import wireguard
from keel.system.actions import Action, Note, Refuse, Run, WriteFile

OVERLAY = "etcd"
USER = "etcd"
INITIALIZED = "var/lib/etcd/default/member"
SECRET_MODE = 0o600
PUBLIC_MODE = 0o644


@dataclass(frozen=True)
class EtcdState:
    """What apply renders from, and what is there now"""

    cluster: Cluster | None
    problem: str | None
    address: str | None
    iface: str
    wanted: dict[str, str | None]
    current: dict[str, str | None]
    has_user: bool
    initialized: bool
    # keel started etcd here for this mesh's cluster
    started: bool = True


def wanted_files(root: str) -> dict[str, str | None]:
    found = {
        etcdconf.MEMBER_CERT: etcdstate.read(root, etcdstate.MEMBER_CERT),
        etcdconf.MEMBER_KEY: etcdstate.read(root, etcdstate.MEMBER_KEY),
        etcdconf.TRUSTED: etcdstate.read(root, etcdstate.ROOT_CERT),
    }
    crl = etcdstate.read(root, etcdstate.CRL)
    if crl:
        found[etcdconf.CRL] = crl
    return found


def observe_etcd(tree: Tree, doc: dict) -> EtcdState:
    wg = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    address = str(wg["address"]).split("/")[0] if wg.get("address") \
        else None
    try:
        cluster, problem = etcdstate.cluster(tree.root), None
    except StateError as e:
        cluster, problem = None, str(e)
    paths = (etcdconf.ENVIRONMENT, etcdconf.DROP_IN, etcdconf.MEMBER_CERT,
             etcdconf.MEMBER_KEY, etcdconf.TRUSTED, etcdconf.CRL)
    return EtcdState(
        cluster=cluster, problem=problem, address=address,
        iface=wireguard.interface(wg),
        wanted=wanted_files(tree.root),
        current={one: tree.read(one).text for one in paths},
        has_user=USER in passwd_entries(tree.read(PASSWD)),
        initialized=os.path.isdir(tree.path(INITIALIZED)),
        started=tree.exists(etcdstate.STARTED))


def waiting(state: EtcdState | None) -> bool:
    """Whether etcd waits for its cluster: nothing to render, nothing
    started, and nothing wrong"""
    return state is not None and state.cluster is None and \
        state.problem is None


def restarts(before: str | None, after: str, initialized: bool) -> bool:
    """Whether a new environment needs etcd restarted"""
    def kept(text: str | None) -> list[str]:
        return [line for line in (text or "").splitlines()
                if not (initialized and line.startswith("ETCD_INITIAL_"))]
    return kept(before) != kept(after)


def plan_etcd(state: EtcdState, live: bool) -> tuple[list[Action], bool]:
    """The files etcd runs from, and whether a running etcd restarts"""
    if state.problem:
        return [Refuse(state.problem)], False
    if state.cluster is None:
        return [Note("etcd waits for its cluster: it forms at the third"
                     " cloud advanced member's join, or with keel mesh etcd"
                     " form; nothing is started until then")], False
    if not state.has_user:
        return [Refuse("there is no etcd user: is etcd-server installed?"
                       " (keel-overlay-etcd depends on it)")], False
    if state.address is None or None in state.wanted.values():
        return [Refuse("this member holds no etcd certificate yet: keel"
                       " mesh etcd tend issues it")], False
    if state.initialized and not state.started:
        return [Refuse(f"/{INITIALIZED} holds a member keel never started:"
                       " etcd-server's own start at its installation leaves"
                       " a lone member of no cluster; this node joins only"
                       " once it is gone, which the join or keel mesh etcd"
                       " form does")], False
    actions: list[Action] = []
    environment = etcdconf.environment(
        state.address, state.cluster, etcdconf.CRL in state.wanted)
    if state.current[etcdconf.ENVIRONMENT] != environment:
        actions.append(WriteFile(etcdconf.ENVIRONMENT, environment,
                                 PUBLIC_MODE, None,
                                 f"write /{etcdconf.ENVIRONMENT}: a cluster"
                                 f" of {len(state.cluster.members)}"))
    for path, text in state.wanted.items():
        if state.current[path] != text:
            actions.append(WriteFile(path, text, SECRET_MODE, USER,
                                     f"write /{path} for etcd"))
    drop_in = etcdconf.drop_in(state.iface)
    moved = state.current[etcdconf.DROP_IN] != drop_in
    if moved:
        actions.append(WriteFile(etcdconf.DROP_IN, drop_in, PUBLIC_MODE,
                                 None, f"write /{etcdconf.DROP_IN}: after"
                                 f" wg-quick@{state.iface}, sandboxed"))
        if live:
            actions.append(Run(("systemctl", "daemon-reload"),
                               "systemctl daemon-reload: etcd's drop-in"))
    return actions, moved or restarts(state.current[etcdconf.ENVIRONMENT],
                                      environment, state.initialized)
