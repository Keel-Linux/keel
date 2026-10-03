# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh invite and keel mesh join --dry-run (decision 0048)

`invite` prints the one line a new node runs, `keel mesh join
keel1:<token>`, alone on standard output, and reserves the new node's
address in a pending invite. No listener answers it yet: the token can
be read with `join --dry-run`, which prints the change of the new node's
spec it makes and applies nothing. Like every command, nothing here
prompts, so confconsole calls the same functions.
"""

import ipaddress
import os
import secrets
import sys
from dataclasses import replace
from datetime import datetime, timezone

import yaml

from keel import exits, spec
from keel.commands import error, manifest_facts, read_spec
from keel.inspect import ROOT_DEFAULT
from keel.mesh import allocate, certificate, identity, invites, join
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
from keel.network import wgkeys, wireguard
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
        hosts = endpoints(args.endpoint, doc)
    except ValueError as e:
        error(str(e))
        return exits.MESH_REFUSED
    try:
        tls_key, cert = certificate.make()
        mesh_id = identity.ensure(root)
    except (certificate.CertificateError, ValueError) as e:
        error(str(e))
        return exits.APPLY_FAILED
    now = datetime.now(timezone.utc).replace(microsecond=0)
    secret = secrets.token_bytes(SECRET_BYTES)
    draft = Token(
        public_key=public, endpoints=hosts, port=wireguard.port(overlay),
        https_port=args.port, fingerprint=certificate.fingerprint(cert),
        address=str(ipaddress.IPv6Interface(str(overlay["address"]))),
        assigned="", mesh_id=mesh_id, invite_id=invite_id(secret),
        expires=now + LIFETIME, secret=secret)
    try:
        made, line = invite(root, now, draft, overlay, (tls_key, cert))
    except (allocate.AllocationError, TokenError, invites.InviteError) as e:
        error(str(e))
        return exits.MESH_REFUSED
    print(f"keel mesh join {line}")
    report(made)
    return exits.OK


def invite(root: str, now: datetime, draft: Token, overlay: dict,
           tls: tuple[str, str]) -> tuple[invites.Pending, str]:
    """The pending invite, reserved, and its token

    The token is written before the invite is, so one that cannot be
    written reserves nothing.
    """
    lines: list[str] = []

    def make(others: tuple[invites.Pending, ...]) -> invites.Pending:
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


def report(made: invites.Pending) -> None:
    """What the invite did, on standard error: never the token"""
    print("on the new node, keel mesh join - reads the token from standard"
          " input, out of the process list and the shell's history",
          file=sys.stderr)
    print(f"invite {made.invite_id}: {made.address} reserved for the new"
          f" node until {shown(made.expires)}", file=sys.stderr)
    print("no listener answers it in this keel yet: the line can be checked"
          " with keel mesh join --dry-run on the new node", file=sys.stderr)


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
              " is in no mesh to invite into (keel mesh create comes in a"
              " later keel; docs/mesh.md)")
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


def endpoints(declared: list[str] | None, doc: dict) -> tuple[str, ...]:
    """Where the new node reaches this one: IPv6 first, one per family

    The --endpoint addresses when given (a port forward, say), else the
    static addresses network.interfaces declares. Raises ValueError.
    """
    if declared:
        hosts = [ipaddress.ip_address(one) for one in declared]
    else:
        hosts = list(static_addresses(doc))
    found = {}
    for host in hosts:
        if host.version in found and declared:
            raise ValueError(f"--endpoint {host}: one endpoint per family,"
                             f" and {found[host.version]} is already one")
        found.setdefault(host.version, host)
    if not found:
        raise ValueError(
            "no endpoint: network.interfaces declares no static address"
            " the new node could reach this one at; give it with"
            " --endpoint ADDRESS")
    return tuple(str(found[version]) for version in (6, 4)
                 if version in found)


def static_addresses(doc: dict):
    interfaces = (doc.get("network") or {}).get("interfaces") or {}
    for iface in interfaces.values():
        for family in ("ipv6", "ipv4"):
            block = (iface or {}).get(family) or {}
            if block.get("method") == "static" and block.get("address"):
                yield ipaddress.ip_interface(str(block["address"])).ip


def mesh_join(args) -> int:
    """Print the change a token makes to this node's spec; apply nothing"""
    if not args.dry_run:
        error("keel mesh join applies nothing in this keel yet: with"
              " --dry-run it prints the change it will make")
        return exits.NOT_IMPLEMENTED
    # never more than a token can be: parse refuses the excess unread
    text = sys.stdin.read(MAX_TEXT + 1) if args.token == STDIN \
        else args.token
    try:
        token = parse(text, datetime.now(timezone.utc))
    except TokenError as e:
        error(str(e))
        return exits.MESH_TOKEN_INVALID
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
