# Copyright (c) 2026 KeelLinux maintainers
"""HTTPS between the new node and the inviter, pinned (decision 0048)

The inviter serves with the invite's own key and self signed
certificate; the new node trusts no authority and compares the SHA-256
of the certificate the inviter presents with the fingerprint in the
token, before it sends a byte of the request. Both ends speak TLS 1.3.

The invite's TLS key lives in the invite's file, not on disk as a PEM:
ssl loads a key from a path only, so it is handed over through a
memfd, an anonymous file that never has a name in any filesystem and
goes when it is closed.
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from keel.mesh import protocol

# a TCP answer within this many seconds, or the fallback (0048): two
# lost SYNs on a poor link (1 s, then 2 s more, then 4 s) still connect
CONNECT_TIMEOUT = 10
# the inviter applies its change before it answers a join
ANSWER_TIMEOUT = 180


class ChannelError(Exception):
    """The exchange did not complete, and why"""


class Unreachable(ChannelError):
    """No TCP answer: the port is closed, filtered, or nothing listens"""


class Refused(ChannelError):
    """The inviter answered with a refusal; the reason it gave"""


class Forged(ChannelError):
    """The certificate is not the pinned one, or the answer is not
    signed with the invite's key"""


@dataclass(frozen=True)
class Reply:
    """A signed answer, and the addresses the connection used"""

    body: bytes
    local: str
    peer: str


def plain(address: str) -> str:
    """A socket's address as keel compares it: an IPv4-mapped one as IPv4"""
    value = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
        return str(value.ipv4_mapped)
    return str(value)


def fingerprint(der: bytes) -> bytes:
    return hashlib.sha256(der).digest()


@contextmanager
def pem_fds(*texts: str) -> Iterator[list[int]]:
    """memfds that hold `texts`, closed afterwards"""
    fds = []
    try:
        for text in texts:
            fd = os.memfd_create("keel-mesh-invite", os.MFD_CLOEXEC)
            fds.append(fd)
            os.write(fd, text.encode())
        yield fds
    finally:
        for fd in fds:
            os.close(fd)


def context_from_paths(cert_path: str, key_path: str) -> ssl.SSLContext:
    """The listener's context, from paths that read as the PEMs"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert_path, key_path)
    return context


def server_context(certificate: str, key: str) -> ssl.SSLContext:
    """The listener's context, with the invite's certificate and key"""
    with pem_fds(certificate, key) as fds:
        return context_from_paths(*(f"/proc/self/fd/{fd}" for fd in fds))


def client_context() -> ssl.SSLContext:
    """No authority is trusted: the certificate is pinned instead"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def shown(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def post(host: str, port: int, path: str, body: bytes, key: bytes,
         pinned: bytes, connect_timeout: float = CONNECT_TIMEOUT,
         answer_timeout: float = ANSWER_TIMEOUT) -> Reply:
    """POST a signed request; the answer, its signature checked

    Raises Unreachable without a TCP answer, Forged for another
    certificate or an answer not signed with `key`, Refused for a
    refusal, and ChannelError for an exchange cut short.
    """
    where = shown(host, port)
    try:
        raw = socket.create_connection((host, port), timeout=connect_timeout)
    except OSError as e:
        raise Unreachable(f"{where}: {e.strerror or e}") from None
    raw.settimeout(answer_timeout)
    try:
        tls = client_context().wrap_socket(raw)
    except OSError as e:
        raw.close()
        raise Forged(f"{where}: the TLS handshake failed ({e}): it is not"
                     " the inviter's listener") from None
    with tls:
        der = tls.getpeercert(binary_form=True)
        if not hmac.compare_digest(fingerprint(der), pinned):
            raise Forged(f"{where} presented a certificate that is not the"
                         " one the token pins: nothing was sent")
        local, peer = plain(tls.getsockname()[0]), plain(tls.getpeername()[0])
        status, signature, data = exchange(tls, host, port, path, body, key)
    if status != 200:
        raise Refused(reason(data, status))
    if not protocol.signed(key, protocol.ANSWER, path, data, signature):
        raise Forged(f"the answer from {where} is not signed with this"
                     " invite's key")
    return Reply(data, local, peer)


def exchange(tls: ssl.SSLSocket, host: str, port: int, path: str,
             body: bytes, key: bytes) -> tuple[int, str | None, bytes]:
    connection = http.client.HTTPConnection(host, port)
    connection.sock = tls
    headers = {"Content-Type": protocol.CONTENT_TYPE, "Connection": "close",
               protocol.SIGNATURE: protocol.sign(key, protocol.METHOD, path,
                                                 body)}
    try:
        connection.request(protocol.METHOD, path, body, headers)
        response = connection.getresponse()
        data = response.read(protocol.MAX_ANSWER + 1)
    except (OSError, http.client.HTTPException) as e:
        raise ChannelError(f"{shown(host, port)} did not answer: {e}") \
            from None
    if len(data) > protocol.MAX_ANSWER:
        raise ChannelError(f"the answer from {shown(host, port)} is longer"
                           " than any the protocol has")
    return response.status, response.getheader(protocol.SIGNATURE), data


def reason(data: bytes, status: int) -> str:
    """What a refusal says, or its status when it says nothing readable"""
    try:
        found = json.loads(data.decode()).get("error")
    except (UnicodeDecodeError, ValueError, AttributeError):
        found = None
    if isinstance(found, str) and found.isprintable():
        return found[:300]
    return f"HTTP {status}"
