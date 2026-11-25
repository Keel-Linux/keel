# Copyright (c) 2026 KeelLinux maintainers
"""One enrolment: the listener's checks and the root side (decision 0098)

The listener is keel mesh's (keel.mesh.listener.run, keel.mesh.bridge):
a unit with a dynamic user and no capability, its TLS key in memory
only, never the HMAC key. It reads two requests: `GET
/access/<id>/enrol.sh`, the script, and `POST /access/<id>` with the
computer's public key and its proof. It checks the shape and hands what
passed to the root side, which checks the proof, writes the computer
into network.access.peers and applies (keel.mesh.node, under the sync
lock), and answers with the computer's /128. A compromised listener can
forge nothing the root side accepts.

The command (`command`) fetches the script over HTTPS with the
listener's public key pinned (`curl --pinnedpubkey`, and `-k`, since
the certificate is the invite's own and no authority signed it) and
gives the script the one-use secret as its argument: the secret is in
no URL and no request, only its proof is.
"""

import hmac
import ipaddress
import json
import os
import re
import subprocess
import threading
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from keel import exits
from keel.access import invites
from keel.mesh.admit import Response, refusal
from keel.mesh.listener import Limiter, Params
from keel.network import access as acc
from keel.network import wireguard

SCRIPT = "/access/{id}/enrol.sh"
ENROL = "/access/{id}"
MAX_BODY = 1024
MAX_FORGED = 5
SCRIPT_FILE = os.path.join(os.path.dirname(__file__), "enrol.sh")
TEXT = "text/plain"
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_NAME = 253


def parse_endpoint(text: str) -> tuple[str, int | None]:
    """Where a computer reaches the node: a global IPv6 literal, bare or
    `[address]:port`, or a DNS name with an optional `:port`; the port
    is the WireGuard UDP port as the computer sees it. Raises
    ValueError: an IPv4 literal (answer 8, A), a scope id, a link local
    or loopback address, or any character a name does not have: the
    endpoint goes into the script the node serves"""
    host, port = text, None
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError("an IPv6 literal with a port is [address]:port")
        port = endpoint_port(rest[1:])
    elif text.count(":") == 1:
        host, _, digits = text.partition(":")
        port = endpoint_port(digits)
    if ":" in host:
        if "%" in host:
            raise ValueError("an IPv6 address with a scope id is no address"
                             " a computer elsewhere reaches")
        address = ipaddress.IPv6Address(host)
        if address.is_link_local or address.is_loopback or \
                address.is_multicast or address.is_unspecified:
            raise ValueError(f"{host} is not an address a computer"
                             " reaches the node at")
        return str(address), port
    name = host.lower().rstrip(".")
    labels = name.split(".")
    try:
        ipaddress.IPv4Address(name)
    except ValueError:
        pass
    else:
        raise ValueError("an IPv4 address: the access network is IPv6"
                         " only (decision 0098, answer 8)")
    if len(name) > MAX_NAME or len(labels) < 2 or not all(
            LABEL_RE.match(label) for label in labels):
        raise ValueError(f"{text!r} is not an IPv6 address or a DNS name")
    return name, port


def endpoint_port(digits: str) -> int:
    if not digits.isdigit() or not 1 <= int(digits) <= 65535:
        raise ValueError(f"{digits!r} is not a port number")
    return int(digits)


def url_host(endpoint: str) -> str:
    host, _ = parse_endpoint(endpoint)
    return f"[{host}]" if ":" in host else host


def wg_endpoint(endpoint: str, access: dict) -> str:
    """The WireGuard Endpoint line of the computer: the endpoint's port,
    else the access network's"""
    host, port = parse_endpoint(endpoint)
    return f"{url_host(host)}:{port or acc.port(access)}"


class AccessListener:
    """The front of one enrolment, in the shape keel.mesh.listener.run
    serves: `params`, `name`, `finished`, `blocked`, `handle`, `log`"""

    def __init__(self, params: Params, backend,
                 clock: Callable[[], datetime],
                 log: Callable[[str], None]):
        self.params = params
        self.backend = backend
        self.clock = clock
        self.log = log
        self.lock = threading.Lock()
        self.limiter = Limiter(clock)
        self.ended = False

    @property
    def name(self) -> str:
        return f"access enrolment {self.params.invite_id}"

    @property
    def finished(self) -> bool:
        return self.ended or self.clock() >= self.params.expires

    def blocked(self, source: str) -> bool:
        with self.lock:
            return self.limiter.blocked(source)

    def handle(self, method: str, path: str, signature: str | None,
               body: bytes | None, local: str, peer: str) -> Response:
        with self.lock:
            invite_id = self.params.invite_id
            if method == "GET" and path == SCRIPT.format(id=invite_id):
                return self.backend.forward(path, None, None, local, peer)
            if method != "POST" or path != ENROL.format(id=invite_id):
                return self.refuse(404, f"{method} {path[:64]!r}: no such"
                                   " request", peer)
            if body is None or len(body) > MAX_BODY:
                return self.refuse(400, "the enrolment's body is missing or"
                                   " too long", peer)
            found = self.backend.forward(path, None, body, local, peer)
            if found.final or found.status == 503:
                self.ended = True
            if found.status != 200:
                self.limiter.refused(peer)
            return found

    def refuse(self, status: int, reason: str, peer: str) -> Response:
        self.limiter.refused(peer)
        self.log(f"{self.name}: refused a request from {peer}: {reason}")
        return refusal(status, reason)


def client_interface(address: str) -> str:
    """The computer's interface for this node: `ka-` and the 40 bit
    Global ID of the node's /64, so the 2 tunnels of a pair differ"""
    network = ipaddress.IPv6Interface(address).network
    value = int(network.network_address) >> 80 & (1 << 40) - 1
    return f"ka-{value:010x}"


def script(endpoint: str, port: int, pin: str, invite_id: str,
           node_key: str, access: dict) -> str:
    with open(SCRIPT_FILE) as fob:
        text = fob.read()
    values = {"@URL_HOST@": url_host(endpoint),
              "@WG_ENDPOINT@": wg_endpoint(endpoint, access),
              "@PORT@": str(port), "@PIN@": pin,
              "@ID@": invite_id, "@NODE_KEY@": node_key,
              "@NODE_ADDRESS@": str(acc.address(access).ip),
              "@IFACE@": client_interface(str(access["address"]))}
    for name, value in values.items():
        text = text.replace(name, value)
    return text


def command(endpoint: str, port: int, pin: str, invite_id: str,
            secret: str) -> str:
    """The one line the administrator pastes on the computer: the script
    is written whole to a file of mktemp's (0600) before it runs, so a
    cut-off download runs nothing, and the secret reaches it on its
    standard input from the shell's own printf, in no argv"""
    path = SCRIPT.format(id=invite_id)
    url = f"https://{url_host(endpoint)}:{port}{path}"
    return (f"f=$(mktemp) && curl -fsS --proto '=https' -k --pinnedpubkey"
            f" 'sha256//{pin}' -o \"$f\" '{url}' && printf '%s\\n'"
            f" '{secret}' | sudo sh \"$f\"; rm -f \"$f\"")


def spki_pin(certificate: str) -> str:
    """base64 of the SHA-256 of the certificate's public key (SPKI DER),
    what `curl --pinnedpubkey sha256//` compares"""
    key = subprocess.run(["openssl", "x509", "-pubkey", "-noout"],
                         input=certificate, capture_output=True, text=True,
                         check=True, timeout=30).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                         input=key.encode(), capture_output=True, check=True,
                         timeout=30).stdout
    return b64encode(sha256(der).digest()).decode()


@dataclass
class AccessAdmitter:
    """The root side of one enrolment; `node` is keel.mesh.node.Node"""

    root: str
    invite: invites.Invite
    node: object
    node_public: str
    endpoint: str
    pin: str
    clock: Callable[[], datetime]
    log: Callable[[str], None]
    forged: int = 0
    enrolled: bool = False

    @property
    def name(self) -> str:
        return f"access enrolment {self.invite.invite_id}"

    def forward(self, path: str, signature: str | None, body: bytes | None,
                local: str, peer: str) -> Response:
        invite_id = self.invite.invite_id
        if path == SCRIPT.format(id=invite_id):
            access = acc.section(self.node.document()) or {}
            return Response(200, script(
                self.endpoint, self.invite.port, self.pin, invite_id,
                self.node_public, access).encode())
        if path != ENROL.format(id=invite_id):
            return refusal(404, f"{path[:64]!r}: no such request")
        return self.enrol(body or b"", peer)

    def enrol(self, body: bytes, peer: str) -> Response:
        found = invites.find(self.root, self.invite.invite_id, self.clock())
        if self.enrolled or found is None or found.consumed:
            return Response(410, refusal(410, f"{self.name} was used or"
                                         " expired").body, final=True)
        try:
            data = json.loads(body.decode())
            public = str(data["public_key"])
            given = str(data["proof"])
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return refusal(400, "the body is not {public_key, proof}")
        if not wireguard.is_key(public):
            return refusal(400, "public_key is not a WireGuard key")
        wanted = invites.proof(self.invite.hmac_key, public)
        # bytes: a str that is not ASCII makes compare_digest raise
        if not hmac.compare_digest(wanted.encode(), given.encode(
                "utf-8", "backslashreplace")):
            return self.forgery(peer)
        return self.admit(public, peer)

    def forgery(self, peer: str) -> Response:
        self.forged += 1
        self.log(f"{self.name}: a proof from {peer} does not match")
        if self.forged < MAX_FORGED:
            return refusal(403, "the proof does not match")
        invites.remove(self.root, self.invite.invite_id)
        self.log(f"{self.name}: cancelled, {MAX_FORGED} proofs failed")
        return Response(403, refusal(403, "cancelled").body, final=True)

    def admit(self, public: str, peer: str) -> Response:
        doc = self.node.document()
        access = acc.section(doc)
        if access is None:
            return Response(500, refusal(500, "the spec has no"
                                         " network.access").body, final=True)
        if any(wireguard.same_key(public, str(one.get("public_key")))
               for one in acc.peers(access)):
            return refusal(409, "this key is a computer of this node"
                           " already")
        peers = list(access.get("peers") or []) + [{
            "name": self.invite.name, "public_key": public,
            "address": self.invite.address,
            "enrolled": self.clock().strftime("%Y-%m-%d")}]
        changed = {**doc, "network": {**doc["network"], "access": {
            **access, "peers": peers}}}
        invites.consume(self.root, self.invite.invite_id)
        self.enrolled = True
        try:
            done = self.node.change(changed)
        except Exception as e:  # noqa: BLE001 (NodeError, an OSError)
            done = None
            self.log(f"{self.name}: the spec cannot take the computer: {e}")
        if done is None or done.code != exits.OK:
            return Response(500, refusal(500, "the node could not apply"
                                         " the computer").body, final=True)
        self.log(f"{self.name}: {self.invite.name} enrolled from {peer} as"
                 f" {self.invite.address}")
        return Response(200, json.dumps({
            "address": self.invite.address,
            "node_public_key": self.node_public,
            "node_address": str(acc.address(access).ip),
            "port": acc.port(access)}).encode(), final=True)
