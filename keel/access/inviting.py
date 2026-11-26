# Copyright (c) 2026 KeelLinux maintainers
"""keel access invite, serve, invites and cancel (decision 0098)

`invite`, in this order: refuse a node with no global IPv6 address
(answer 8, A: IPv6 only for now); on a node with no network.access,
write the section with a random unique local /64 (answer 3) and apply,
so the key, the interface and the firewall's set exist; refuse a name
in use; reserve a free /128 that no computer and no waiting enrolment
holds; make the listener's key and certificate; save the enrolment;
open its TCP port in keel's set `access_invites` for the time it is
valid (token_minutes, answer 10); start `keel-access-invite@<id>`, the
root helper, as a transient unit; print the one command to paste.

`serve` is what that unit runs: it starts the unprivileged listener
(keel.mesh.bridge, kind "access") and answers it with the root side
(keel.access.enrol.AccessAdmitter) until the enrolment is used,
cancelled or expired; then the enrolment's file and its port go.
"""

import ipaddress
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from keel import exits
from keel.access import enrol, invites
from keel.manifest.firewall import ACCESS_INVITES_SET
from keel.mesh import bridge, ports
from keel.mesh.listener import Params
from keel.network import access as acc

UNIT = "keel-access-invite@{id}"
PORTS = (49152, 65535)
TRIES = 64
EVERY_ADDRESS = "::"
# the unit lives this much past the expiry, for the last answer
GRACE = 30
# what systemctl says of a unit that does not exist: a listener that
# never started, or that ended by itself
NOT_LOADED = "not loaded"
NO_IPV6 = ("this node has no global IPv6 address and IPv6 default route:"
           " the enrolment and the tunnel use IPv6 only (decision 0098,"
           " answer 8); give --endpoint where the computer reaches it")


@dataclass
class Inviter:
    """The machine as an enrolment needs it; tests give fakes"""

    root: str
    node: object
    clock: Callable[[], datetime]
    run: Callable[[tuple[str, ...]], str | None]
    output: Callable[[tuple[str, ...]], str | None]
    out: Callable[[str], None]
    err: Callable[[str], None]
    endpoints: Callable[[], list[str]]
    public_key: Callable[[dict], tuple[str | None, str]]
    certificate: Callable[[], tuple[str, str]]
    pin: Callable[[str], str]
    random: Callable[[int], bytes]
    spec_path: str


def invite(inviter: Inviter, name: str, endpoint: str | None) -> int:
    if endpoint is not None:
        try:
            enrol.parse_endpoint(endpoint)
        except ValueError as e:
            inviter.err(f"--endpoint {endpoint!r}: {e}")
            return exits.USAGE
    found = [endpoint] if endpoint else inviter.endpoints()
    if not found:
        inviter.err(NO_IPV6)
        return exits.MESH_REFUSED
    if not acc.NAME_RE.match(name):
        inviter.err(f"{name!r} is not a name: 1 to 32 of a-z 0-9 and -")
        return exits.USAGE
    doc = inviter.node.document()
    if acc.section(doc) is None:
        code = first_section(inviter, doc)
        if code != exits.OK:
            return code
        doc = inviter.node.document()
    access = acc.section(doc)
    now = inviter.clock()
    waiting = invites.pending(inviter.root, now)
    if name in [peer.get("name") for peer in acc.peers(access)] + [
            one.name for one in waiting]:
        inviter.err(f"the name {name} is in use on this node: keel access"
                    " list and keel access invites name them")
        return exits.USAGE
    return made(inviter, access, name, found[0], waiting, now)


def first_section(inviter: Inviter, doc: dict) -> int:
    """network.access with a random unique local /64, written and
    applied, before any port is opened"""
    address = acc.suggest_address(inviter.random(5))
    network = {**(doc.get("network") or {}), "access": {"address": address}}
    done = inviter.node.change({**doc, "network": network})
    if done.code != exits.OK:
        for line in done.lines:
            inviter.err(line)
        inviter.err(f"network.access could not be applied (exit"
                    f" {done.code}); nothing is opened")
        return done.code
    inviter.out(f"network.access made: {address} (decision 0098)")
    return exits.OK


def made(inviter: Inviter, access: dict, name: str, endpoint: str,
         waiting: list[invites.Invite], now: datetime) -> int:
    used = {acc.host(peer) for peer in acc.peers(access)} | {
        str(ipaddress.IPv6Interface(one.address).ip) for one in waiting}
    address = None
    for _ in range(TRIES):
        address = address or free_address(access, used, inviter.random)
    public, problem = inviter.public_key(access)
    if address is None or public is None:
        inviter.err(problem or "no free address in the access prefix")
        return exits.APPLY_FAILED
    tls_key, certificate = inviter.certificate()
    secret = invites.new_secret()
    minutes = acc.token_minutes(access)
    taken = {one.port for one in waiting}
    port = next(one for one in (PORTS[0] + int.from_bytes(
        inviter.random(2), "big") % (PORTS[1] - PORTS[0])
        for _ in range(TRIES)) if one not in taken)
    found = invites.Invite(
        invite_id=invites.new_id(), name=name, address=address,
        expires=now + timedelta(minutes=minutes), port=port,
        certificate=certificate, tls_key=tls_key,
        hmac_key=invites.derive(secret), endpoint=endpoint)
    invites.save(inviter.root, found)
    seconds = minutes * 60
    inviter.err(ports.open_port(port, seconds, inviter.run, inviter.output,
                                ACCESS_INVITES_SET))
    problem = inviter.run((
        "systemd-run", f"--unit={UNIT.format(id=found.invite_id)}",
        "--collect", "--quiet", f"--property=RuntimeMaxSec={seconds + GRACE}",
        f"--description=keel: the enrolment of {name} (decision 0098)",
        sys.executable, "-m", "keel", "access", "serve", found.invite_id,
        "--spec", inviter.spec_path))
    if problem:
        invites.remove(inviter.root, found.invite_id)
        ports.close_port(port, inviter.run, ACCESS_INVITES_SET)
        inviter.err(f"the enrolment could not start: {problem}")
        return exits.APPLY_FAILED
    inviter.err(f"valid once, for {minutes} minutes; paste this line in a"
                f" terminal on the computer {name} (Linux or macOS):")
    inviter.out(enrol.command(endpoint, port, inviter.pin(certificate),
                              found.invite_id, secret))
    return exits.OK


def free_address(access: dict, used: set[str],
                 random: Callable[[int], bytes]) -> str | None:
    """A random /128 in the node's /64 that nobody holds; None for a
    draw that is taken, the node's own, or the prefix itself"""
    number = int.from_bytes(random(8), "big")
    if number < 2:
        return None
    found = acc.free_address(access, number)
    host = str(ipaddress.IPv6Interface(found).ip)
    if host in used or host == str(acc.address(access).ip):
        return None
    return found


def waiting(root: str, now: datetime) -> list[str]:
    return [f"{one.invite_id}\t{one.name}\t{one.address}\tuntil"
            f" {one.expires:%Y-%m-%dT%H:%M:%SZ}\tTCP {one.port}"
            for one in invites.pending(root, now)]


def cancel(inviter: Inviter, invite_id: str) -> int:
    found = invites.find(inviter.root, invite_id, inviter.clock())
    if found is None:
        inviter.err(f"no waiting enrolment {invite_id}")
        return exits.MESH_REFUSED
    inviter.run(("systemctl", "stop", UNIT.format(id=invite_id)))
    # the listener is its own unit: the stop of the invite unit does not
    # stop it, and it keeps its port until its RuntimeMaxSec (keel#341)
    listener = bridge.unit(invite_id, "access")
    problem = inviter.run(("systemctl", "stop", listener))
    invites.remove(inviter.root, invite_id)
    ports.close_port(found.port, inviter.run, ACCESS_INVITES_SET)
    if problem and NOT_LOADED not in problem:
        inviter.err(f"{listener} did not stop: {problem}")
        return exits.APPLY_FAILED
    inviter.out(f"cancelled the enrolment of {found.name}")
    return exits.OK


def serve(inviter: Inviter, invite_id: str) -> int:
    """What keel-access-invite@<id> runs"""
    found = invites.find(inviter.root, invite_id, inviter.clock())
    if found is None or found.consumed:
        inviter.err(f"no waiting enrolment {invite_id}")
        return exits.MESH_REFUSED
    access = acc.section(inviter.node.document()) or {}
    public, problem = inviter.public_key(access)
    code = exits.OK
    try:
        # the endpoint the invite was made with, --endpoint or the
        # node's stable global address then: never asked again
        if public is None or not found.endpoint:
            raise bridge.BridgeError(problem or NO_IPV6)
        admitter = enrol.AccessAdmitter(
            inviter.root, found, inviter.node, public, found.endpoint,
            inviter.pin(found.certificate), inviter.clock, inviter.err)
        seconds = max(int(found.expires.timestamp()
                          - inviter.clock().timestamp()) + 1, 1)
        bridge.Bridge(
            admitter, Params(found.invite_id, found.expires, EVERY_ADDRESS,
                             found.port, "", kind="access"),
            found.certificate, found.tls_key,
            bridge.socket_path(inviter.root, invite_id, "access"),
            lambda path: bridge.start_unit(invite_id, path, seconds,
                                           inviter.run, inviter.output,
                                           "access"),
            inviter.err).run()
    except (bridge.BridgeError, OSError) as e:
        inviter.err(f"enrolment {invite_id}: {e}")
        code = exits.APPLY_FAILED
    finally:
        invites.remove(inviter.root, invite_id)
        ports.close_port(found.port, inviter.run, ACCESS_INVITES_SET)
    return code


def live(args, out, err) -> Inviter:
    """The live machine's Inviter"""
    from datetime import timezone

    from keel.inspect.tree import Tree
    from keel.mesh import certificate
    from keel.mesh.commands import live_node
    from keel.network import live as link
    from keel.network import wgkeys
    from keel.system.fwstate import global_addresses, ipv6_default
    root = os.path.abspath(args.root)

    def endpoints() -> list[str]:
        tree = Tree(root)
        return (global_addresses(tree, stable=True) if ipv6_default(tree)
                else [])

    def public_key(access: dict) -> tuple[str | None, str]:
        found, problem = wgkeys.public(
            os.path.join(root, acc.key_path(access).lstrip("/")))
        return found, str(problem or "")

    def made_certificate() -> tuple[str, str]:
        return certificate.make()

    return Inviter(root, live_node(args), lambda: datetime.now(timezone.utc),
                   link.run, link.output, out, err, endpoints, public_key,
                   made_certificate, enrol.spki_pin, os.urandom, args.spec)
