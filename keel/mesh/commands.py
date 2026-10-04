# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh: create, invite, join, accept, status (decision 0048)

`invite` reserves the new node's address in a pending invite, starts
its root helper as a transient unit, and prints the one line a new node
runs, `keel mesh join - <<< keel1:<token>`, alone on standard output.
`join` runs the join (keel.mesh.joining), or with `--dry-run` prints the
change of the spec it would make. `accept` is the fallback's half on
the inviter (keel.mesh.inviting), `create` makes the mesh on the first
node (keel.mesh.create), `serve` is what the root helper's unit runs,
`listen` what the unprivileged listener's runs (keel.mesh.bridge), and
`status` shows the peers and the pending invites. Like every command,
nothing here prompts, so confconsole calls the same commands.
"""

import ipaddress
import os
import secrets
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone

import yaml

from keel import exits, spec, system
from keel.commands import error, manifest_facts, read_spec
from keel.inspect import ROOT_DEFAULT
from keel.mesh import (
    adopt,
    allocate,
    bridge,
    certificate,
    create,
    endpoint,
    etcd,
    etcdform,
    identity,
    invites,
    inviting,
    join,
    joining,
    memberd,
    ports,
    remove,
    status,
    sync,
)
from keel.mesh.etcdstate import CLIENT_PORT
from keel.mesh.node import Node, NodeError, static_addresses
from keel.mesh.token import (
    LIFETIME,
    MAX_TEXT,
    SECRET_BYTES,
    Token,
    TokenError,
    encode,
    hmac_key,
    invite_id,
    parse,
    shown,
)
from keel.network import live, session, wgkeys, wireguard
from keel.system.ovstate import overlay_of

STDIN = "-"


def mesh_invite(args) -> int:
    """Print the join line for a new node; reserve its address"""
    root = os.path.abspath(args.root)
    if root == ROOT_DEFAULT and os.geteuid() != 0:
        error("keel mesh invite must run as root: it reads this node's"
              " WireGuard key and writes /var/lib/keel/mesh")
        return exits.APPLY_NEEDS_ROOT
    doc, code = inviter_spec(args.spec, root)
    if doc is None:
        return code
    overlay = overlay_of(doc) or {}
    public, code = public_key(root, overlay)
    if public is None:
        return code
    try:
        hosts = invite_endpoints(args.endpoint, doc, root == ROOT_DEFAULT,
                                 err)
    except ValueError as e:
        error(str(e))
        return exits.MESH_REFUSED
    try:
        mesh_id = invite_identity(root, args.spec)
        tls_key, cert = certificate.make()
    except adopt.Refused as e:
        error(str(e))
        return exits.MESH_REFUSED
    except (certificate.CertificateError, ValueError) as e:
        error(str(e))
        return exits.APPLY_FAILED
    now = datetime.now(timezone.utc).replace(microsecond=0)
    secret = secrets.token_bytes(SECRET_BYTES)
    state = etcd.token_state(etcd.Etcd(Node(root, args.spec), utcnow, err))
    draft = Token(
        public_key=public, endpoints=hosts, port=wireguard.port(overlay),
        https_port=args.port, fingerprint=certificate.fingerprint(cert),
        address=str(ipaddress.IPv6Interface(str(overlay["address"]))),
        assigned="", mesh_id=mesh_id, invite_id=invite_id(secret),
        expires=now + LIFETIME, secret=secret, etcd=state,
        etcd_port=CLIENT_PORT if state == "running" else None)
    try:
        made, line = invite(root, now, draft, overlay, (tls_key, cert))
    except (allocate.AllocationError, TokenError, invites.InviteError) as e:
        error(str(e))
        return exits.MESH_REFUSED
    opened, code = listening(made, args.spec, root, now)
    if code != exits.OK:
        return code
    print(f"keel mesh join - <<< {line}")
    report(made, opened)
    return exits.OK


def invite_identity(root: str, path: str) -> bytes:
    """The mesh identity the invite carries: on the live system, never a
    second one for the mesh its peers are in (keel.mesh.sync); raises
    sync.Refused, or ValueError"""
    if root != ROOT_DEFAULT:
        return identity.ensure(root)
    return adopt.invite_identity(sync.Syncer(
        Node(root, path), utcnow, err))


def listening(made: invites.Pending, path: str, root: str,
              now: datetime) -> tuple[str, int]:
    """Start the invite's listener and open its port; what was done

    Off the live system nothing is started. An invite whose listener
    cannot start is removed: a line nothing answers is not printed.
    """
    if root != ROOT_DEFAULT:
        return ("not the live system: no listener started, so the line"
                " can be checked with keel mesh join --dry-run only"), \
            exits.OK
    problem = inviting.start(made, os.path.abspath(path), now, live.run)
    if problem:
        invites.remove(root, made.invite_id)
        error(f"the invite's listener could not start ({problem}); nothing"
              " is reserved")
        return "", exits.APPLY_FAILED
    # as long as the listener may wait for a join's confirmation
    seconds = int((made.expires - now).total_seconds()) + inviting.LINGER
    return ports.open_port(made.https_port, seconds, live.run,
                           live.output), exits.OK


def invite(root: str, now: datetime, draft: Token, overlay: dict,
           tls: tuple[str, str]) -> tuple[invites.Pending, str]:
    """The pending invite, reserved, and its token

    The token is written before the invite is, so one that cannot be
    written reserves nothing.
    """
    lines: list[str] = []

    def make(others: tuple[invites.Pending, ...]) -> invites.Pending:
        for one in others:
            if one.https_port == draft.https_port:
                raise invites.InviteError(
                    f"invite {one.invite_id} is pending on TCP port"
                    f" {one.https_port} until {shown(one.expires)}: give"
                    " this one another with --port, or wait")
        assigned = allocate.free_address(
            draft.address,
            allocate.taken(overlay) + [
                str(ipaddress.IPv6Interface(one.address).ip)
                for one in others])
        lines.append(encode(replace(draft, assigned=assigned)))
        return invites.Pending(
            invite_id=draft.invite_id, address=assigned,
            expires=draft.expires, https_port=draft.https_port,
            certificate=tls[1], hmac_key=hmac_key(draft.secret),
            tls_key=tls[0])

    made = invites.reserve(root, now, make)
    return made, lines[0]


def report(made: invites.Pending, opened: str) -> None:
    """What the invite did, on standard error: never the token"""
    print("on the new node, keel mesh join - reads the token from standard"
          " input, out of the process list and the shell's history",
          file=sys.stderr)
    print(f"invite {made.invite_id}: {made.address} reserved for the new"
          f" node until {shown(made.expires)}, the listener on TCP port"
          f" {made.https_port} ({inviting.unit(made.invite_id)})",
          file=sys.stderr)
    print(opened, file=sys.stderr)


def inviter_spec(path: str, root: str) -> tuple[dict | None, int]:
    """The spec, which must declare the overlay this node invites into"""
    if not os.path.exists(path):
        error(f"{path}: not found; this node has no overlay to invite"
              " into (network.overlay.wireguard)")
        return None, exits.MESH_REFUSED
    doc, code = read_spec(path, False, root)
    if doc is None:
        return None, code
    overlay = overlay_of(doc)
    if overlay is None or not overlay.get("address"):
        error(f"{path} declares no network.overlay.wireguard: this node"
              " is in no mesh to invite into; keel mesh create makes one")
        return None, exits.MESH_REFUSED
    return doc, exits.OK


def public_key(root: str, overlay: dict) -> tuple[str | None, int]:
    """This node's public key, as `wg pubkey` gives it from its key file

    The key is not made here: a node that invites is in the mesh, so
    apply has made its key already.
    """
    key = wireguard.key_path(overlay)
    path = os.path.join(root, key.lstrip("/"))
    if not os.path.exists(path):
        error(f"no WireGuard key at {key}: converge the overlay first"
              " (keel spec apply --system), which makes it")
        return None, exits.MESH_REFUSED
    public, problem = wgkeys.public(path)
    if public is None:
        error(str(problem))
        return None, exits.APPLY_FAILED
    return public, exits.OK


def invite_endpoints(declared: list[str] | None, doc: dict, live_system: bool,
                     say: Callable[[str], None]) -> tuple[str, ...]:
    """Where the new node reaches this one: IPv6 first, one per family

    The --endpoint addresses when given (a port forward, say), else the
    static addresses network.interfaces declares, else, on the live
    system, the uplink's (keel.mesh.endpoint), each said with `say`.
    Raises ValueError.
    """
    if declared:
        hosts = [ipaddress.ip_address(one) for one in declared]
    else:
        hosts = list(static_addresses(doc))
    why: tuple[str, ...] = ()
    if not hosts and live_system:
        found = endpoint.detect(live.output)
        for line in found.said:
            say(line)
        why = found.refused
        hosts = [ipaddress.ip_address(one) for one in found.addresses]
    found = {}
    for host in hosts:
        if host.version in found and declared:
            raise ValueError(f"--endpoint {host}: one endpoint per family,"
                             f" and {found[host.version]} is already one")
        found.setdefault(host.version, host)
    if not found:
        raise ValueError(
            "no endpoint: network.interfaces declares no static address,"
            " and none was found on the uplink, that the new node could"
            f" reach this one at{': ' if why else ''}{'; '.join(why)}."
            " Give it with --endpoint ADDRESS (a stable address, or a port"
            " forward's)")
    return tuple(str(found[version]) for version in (6, 4)
                 if version in found)


ARGV_WARNING = (
    "the token is an argument, so it shows in the process list and the"
    " shell's history: keel mesh join - <<< TOKEN, the line keel mesh"
    " invite prints, reads it from standard input")


def read_token(args) -> tuple[Token | None, int]:
    # never more than a token can be: parse refuses the excess unread
    if args.token == STDIN:
        text = sys.stdin.read(MAX_TEXT + 1)
    else:
        text = args.token
        err(f"Warning: {ARGV_WARNING}")
    try:
        return parse(text, datetime.now(timezone.utc)), exits.OK
    except TokenError as e:
        error(str(e))
        return None, exits.MESH_TOKEN_INVALID


def mesh_join(args) -> int:
    """Join the mesh the token names; with --dry-run, print the change"""
    if args.dry_run:
        return join_dry_run(args)
    refusal = system.needs_root(os.path.abspath(args.root), "keel mesh join")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    token, code = read_token(args)
    if token is None:
        return code
    node = live_node(args)
    try:
        doc = node.document()
        found = None
        if not args.endpoint and not list(static_addresses(doc)):
            found = endpoint.detect(live.output)
            for line in found.said:
                err(line)
            for line in found.refused:
                err(f"no endpoint is sent, as from a node behind NAT:"
                    f" {line}; --endpoint gives one")
        own = joining.own_endpoint(args.endpoint, doc, found)
    except (NodeError, ValueError) as e:
        error(str(e))
        return exits.MESH_REFUSED
    return joining.run(joining.Joiner(node, token, utcnow, out, err), own)


def join_dry_run(args) -> int:
    """Print the change a token makes to this node's spec; apply nothing"""
    token, code = read_token(args)
    if token is None:
        return code
    doc: dict = {"version": 1}
    if os.path.exists(args.spec):
        doc, code = read_spec(args.spec, False, args.root)
        if doc is None:
            return code
    try:
        made = join.change(overlay_of(doc), token)
    except join.JoinError as e:
        error(str(e))
        return exits.MESH_REFUSED
    after = join.merged(doc, made)
    problems = spec.validate(after, check_secret_files=False,
                             facts=manifest_facts(after, args.root))
    if problems:
        for problem in problems:
            error(f"{args.spec}, once joined: {problem}")
        return exits.MESH_REFUSED
    print(yaml.safe_dump({"network": {"overlay": {"wireguard": made}}},
                         sort_keys=False), end="")
    print(f"dry run, nothing written or applied: {args.spec} would get this"
          f" overlay, joining {token.prefix()} through {token.endpoint()}"
          f" (invite {token.invite_id}, valid until {shown(token.expires)},"
          f" etcd: {token.etcd})", file=sys.stderr)
    return exits.OK


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def out(line: str) -> None:
    print(line, flush=True)


def err(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def operator_clients() -> tuple[str, ...]:
    """The client of the SSH session this command runs in, if any: the
    route check asks that it still leaves through the uplink"""
    origin = session.origin("/proc", os.getpid(), live.sockets)
    if origin.kind == session.SSH and origin.peer:
        return (origin.peer,)
    return ()


def live_node(args) -> Node:
    return Node(os.path.abspath(args.root), args.spec,
                window=getattr(args, "network_window", system.DEFAULT_WINDOW),
                clients=operator_clients())


def as_root(args, verb: str) -> int:
    refusal = system.needs_root(os.path.abspath(args.root), verb)
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    return exits.OK


def mesh_create(args) -> int:
    """Make the mesh on its first node; with --adopt, give a mesh built
    by hand its identity"""
    code = as_root(args, "keel mesh create")
    if code != exits.OK:
        return code
    if args.adopt:
        return adopt.adopt_mesh(syncer(args), out)
    return create.create(live_node(args), out, err)


def syncer(args) -> sync.Syncer:
    return sync.Syncer(live_node(args), utcnow, err)


def overlay_address(text: str) -> str:
    """An overlay address as the spec writes it; ValueError"""
    try:
        return str(ipaddress.IPv6Address(text))
    except ValueError:
        raise ValueError(f"{text}: not an IPv6 address; a member is named"
                         " by its overlay address") from None


def mesh_sync(args) -> int:
    """Pull the members this node's peers know; with --adopt, take a
    member's identity first"""
    code = as_root(args, "keel mesh sync")
    if code != exits.OK:
        return code
    try:
        hosts = tuple(overlay_address(one) for one in args.source or ())
        adopted = overlay_address(args.adopt) if args.adopt else None
    except ValueError as e:
        error(str(e))
        return exits.MESH_REFUSED
    if adopted:
        return adopt.adopt_from(syncer(args), adopted)
    return sync.pull(syncer(args), hosts)


def mesh_members(args) -> int:
    """What keel-mesh-members.service runs: the members' channel's root
    helper, which starts its unprivileged listener"""
    code = as_root(args, "keel mesh members")
    if code != exits.OK:
        return code
    stop = threading.Event()

    def stopped(signum, frame):
        stop.set()
        # out of the bridge's read, through serve's cleanup
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stopped)
    return memberd.serve(syncer(args), stop)


def mesh_members_listen(args) -> int:
    """What keel-mesh-members-listen runs: the unprivileged listener"""
    return memberd.listen(args.socket, utcnow, err)


def mesh_remove(args) -> int:
    """A peer out of this node's spec, and its tombstone"""
    code = as_root(args, "keel mesh remove")
    if code != exits.OK:
        return code
    return remove.remove(syncer(args), args.member, out)


def inviter(args) -> inviting.Inviter:
    return inviting.Inviter(live_node(args), utcnow, out, err)


def mesh_serve(args) -> int:
    """What keel-mesh-invite@<id> runs: the invite's listener"""
    code = as_root(args, "keel mesh serve")
    if code != exits.OK:
        return code
    signal.signal(signal.SIGTERM, inviting.terminated)
    return inviting.serve_invite(inviter(args), args.invite)


def mesh_accept(args) -> int:
    """The fallback's line, run on the inviter"""
    code = as_root(args, "keel mesh accept")
    if code != exits.OK:
        return code
    text = sys.stdin.read(512 + 1) if args.line == STDIN else args.line
    return inviting.accept(inviter(args), text)


def mesh_listen(args) -> int:
    """What keel-mesh-listen@<id> runs: the unprivileged listener"""
    return bridge.listen(args.socket, utcnow, err)


def mesh_status(args) -> int:
    """The peers, their handshakes and the pending invites; no secret"""
    root = os.path.abspath(args.root)
    overlay = None
    if os.path.exists(args.spec):
        doc, code = read_spec(args.spec, False, root)
        if doc is None:
            return code
        overlay = overlay_of(doc)
    for line in status.lines(overlay, root, utcnow(),
                             live.output if root == ROOT_DEFAULT else None):
        print(line)
    if overlay and overlay.get("address"):
        for line in etcd.status(etcd.Etcd(Node(root, args.spec), utcnow,
                                          err), root == ROOT_DEFAULT):
            print(line)
    return exits.OK


def member(args) -> etcd.Etcd:
    return etcd.Etcd(live_node(args), utcnow, err)


def mesh_etcd_form(args) -> int:
    """etcd on a mesh that never saw a third join, or what it lacks"""
    code = as_root(args, "keel mesh etcd form")
    if code != exits.OK:
        return code
    return etcdform.form(member(args), args.dry_run, out)


def mesh_etcd_tend(args) -> int:
    """What keel-mesh-etcd.timer runs: learners, and the leaves"""
    code = as_root(args, "keel mesh etcd tend")
    if code != exits.OK:
        return code
    return etcd.tend(member(args))
