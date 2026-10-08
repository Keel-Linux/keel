# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh etcd reissue: a running cluster moved to the root's certificates

Before keel#83 every etcd member held an intermediate CA and issued its
own certificates, so any member could name itself any etcd user. This
command, run once on the root's holder, moves a running cluster to
certificates the root signs itself, then turns etcd's auth on
(keel.mesh.etcdauth). It is safe to run again, and goes on where a run
that stopped left off.

1. **Checks, changing nothing.** This node holds the root and is in a
   cluster, no network change waits here, every other member of the
   cluster answers a probe over the members' channel and runs keel with
   PKI 2 (keel.mesh.etcdmsg), and every voter is healthy. `--dry-run`
   stops here and prints the plan.
2. **The holder's admin certificate**, CN `root`, issued, and its own
   intermediate recorded so step 4 revokes it.
3. **One member at a time**, the others first, the holder last: its
   request (`enroll`), a certificate the root signs for its address and
   key, sent to it (`reissue`): it keeps it, drops its intermediate and
   its leaves, and apply writes it for etcd, which reads it at its next
   handshake; nothing restarts. The holder then waits until that member
   serves the new certificate on its client port and every voter is
   healthy, before the next. A member that holds no intermediate is
   left as it is.
4. **The intermediates revoked**: every one the holder signed, and its
   own, in the root's CRL, sent to every member (`crl`) and written for
   etcd; every leaf an intermediate issued goes with it. Every voter
   healthy again.
5. **Auth**: etcd's users and roles, with the pairs the VIPs' claims
   rest on, then `auth enable` as etcd's root user, recorded on the
   holder; checked by reading the mesh's keys as this member.

Quorum is kept: nothing restarts (a member's etcd takes its new
certificate at its next handshake), and no step starts before every
voter is healthy. The VIP's holder is not touched: its controller asks
etcd with the member's certificate, which keel-vip.service's helper
writes again into the controller's memfds when it changes
(keel.mesh.vipbridge), before step 4 revokes the old chain, and its
pair's role exists before auth is enabled.

**Rollback**: `keel mesh etcd reissue --rollback`, on the holder,
disables etcd's auth as its root user and records it; members' writes
are then as before keel#83. The certificates stay the root's: the
intermediates are revoked and no member holds one, which is the point
of keel#83. A run that stopped part way needs no rollback: members on
either certificate work together until step 4, and running it again
finishes it; whether auth is on is read from etcd itself, never from a
file, so a run that stopped right after step 5's `auth enable` finds it
on and goes on to the check (keel.mesh.etcdauth.enabled).
"""

import hashlib
import socket
import ssl
from collections.abc import Callable

from keel import exits
from keel.mesh import (
    etcd,
    etcdauth,
    etcdca,
    etcdform,
    etcdmsg,
    etcdpki,
    etcdstate,
    identity,
)
from keel.mesh.etcd import Etcd
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdmsg import Probe
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import StateError
from keel.mesh.memberlink import LinkError
from keel.mesh.node import NodeError
from keel.mesh.protocol import Peer, ProtocolError
from keel.mesh.signing import SigningError
from keel.network.marker import path

# how long a step waits for its member to serve the new certificate and
# for every voter to be healthy: rounds of 250 ms with loss
WAIT = 180.0
EVERY = 2.0
TLS_TIMEOUT = 10.0

said = etcd.said


class Refused(Exception):
    """The reissue is refused, or stopped, and why"""


def served(etcd_: Etcd, address: str) -> str | None:
    """The fingerprint of the certificate the member at `address` serves
    on its client port, as this member sees it, chained to the root;
    None when it does not answer"""
    tls = ssl.create_default_context(cafile=path(etcd_.root,
                                                 etcdstate.ROOT_CERT))
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(path(etcd_.root, etcdstate.MEMBER_CERT),
                        path(etcd_.root, etcdstate.MEMBER_KEY))
    try:
        with socket.create_connection((address, etcdstate.CLIENT_PORT),
                                      TLS_TIMEOUT) as raw, \
                tls.wrap_socket(raw, server_hostname=address) as conn:
            found = conn.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    return hashlib.sha256(found).hexdigest() if found else None


def healthy(etcd_: Etcd) -> list[str]:
    """The voters that are not healthy, empty when every one is"""
    try:
        client = etcd_.local()
        voters = [one for one in client.members() if not one.learner]
    except EtcdError as e:
        return [f"this member ({e})"]
    sick = []
    for one in voters:
        url = one.client_urls[0] if one.client_urls else None
        fine, why = client.health(url) if url else (False, "not started")
        if not fine:
            sick.append(f"{one.address} ({why or 'unhealthy'})")
    return sick


def settled(etcd_: Etcd, test: Callable[[], str | None], what: str) -> None:
    """`test` (why not yet, or None) asked every EVERY seconds, for WAIT
    at least; raises Refused, which stops the run where it is"""
    why = None
    for _ in range(int(WAIT / EVERY) + 1):
        why = test()
        if why is None:
            return
        etcd_.sleep(EVERY)
    raise Refused(f"{what}: {why}; stopped here, run keel mesh etcd"
                  " reissue again once it is")


def members(etcd_: Etcd) -> tuple[list[tuple[Peer, Probe]], list[str]]:
    """The cluster's other members, each with its probe; raises Refused
    when one does not answer or runs a keel before keel#83"""
    client = etcd_.local()
    listed = {one.address for one in client.members() if one.address}
    own = etcd.own_address(etcd_.node)
    peers = [one for one in etcd_.node.peers(etcd.own_key(etcd_) or "")
             if one.address in listed]
    unknown = sorted(listed - {own} - {one.address for one in peers})
    if unknown:
        raise Refused(f"etcd members this node has no peer for:"
                      f" {', '.join(unknown)}; nothing was changed")
    probes = etcdform.probed(etcd_, tuple(peers))
    found, problems = [], []
    for peer in peers:
        one = probes[peer.public_key]
        if isinstance(one, str):
            problems.append(f"{peer.address} did not answer ({one})")
        elif one.pki < etcdmsg.PKI:
            problems.append(f"{peer.address} runs a keel before keel#83:"
                            " upgrade it first")
        else:
            found.append((peer, one))
    return found, problems


def reissue(etcd_: Etcd, dry_run: bool, out: Callable[[str], None],
            serving: Callable[[Etcd, str], str | None] = served) -> int:
    """`keel mesh etcd reissue`"""
    try:
        return moved(etcd_, dry_run, out, serving)
    except Refused as e:
        etcd_.err(f"keel mesh etcd reissue: {e}")
        return exits.MESH_REFUSED
    except (StateError, NodeError, EtcdError, PkiError, OSError) as e:
        etcd_.err(f"keel mesh etcd reissue: {e}")
        return exits.APPLY_FAILED


def checked(etcd_: Etcd) -> None:
    if not etcdstate.holds_root(etcd_.root):
        at = etcdstate.holder(etcd_.root) or "the node that holds it"
        raise Refused(f"run it on the root CA's holder ({at})")
    if etcdstate.cluster(etcd_.root) is None:
        raise Refused("this node is in no etcd cluster")
    if etcd_.node.waiting():
        raise Refused("a network change waits for its confirmation on this"
                      " node: confirm or revert it first")


def moved(etcd_: Etcd, dry_run: bool, out: Callable[[str], None],
          serving: Callable[[Etcd, str], str | None]) -> int:
    checked(etcd_)
    found, problems = members(etcd_)
    sick = healthy(etcd_)
    if problems or sick:
        raise Refused("; ".join(problems + [f"{one} is not healthy"
                                            for one in sick])
                      + "; nothing was changed")
    lacking = [(peer, one) for peer, one in found if one.legacy]
    own_legacy = etcdstate.legacy(etcd_.root)
    on = etcdauth.enabled(etcd_)
    if dry_run:
        for peer, _ in lacking:
            out(f"would sign {peer.address}'s certificate with the root")
        if own_legacy:
            out("would sign this node's certificate with the root")
        out("would revoke the members' intermediates and send the CRL")
        out("would enable etcd's auth" if not on else
            "etcd's auth is on: would converge its users and roles")
        out("dry run: nothing was changed on any member")
        return exits.OK
    address = etcd.own_address(etcd_.node)
    if etcdstate.admin(etcd_.root, etcd_.clock()):
        etcd_.err("etcd: the root's admin certificate issued")
    etcdstate.keep_own_intermediate(etcd_.root, address,
                                    etcd.own_key(etcd_))
    for peer, _ in lacking:
        one_member(etcd_, peer, serving, out)
    if own_legacy:
        own(etcd_, address, serving, out)
    revoked(etcd_, [peer for peer, _ in found], out)
    authorized(etcd_, out)
    return exits.OK


def one_member(etcd_: Etcd, peer: Peer, serving, out) -> None:
    """One member moved to a certificate the root signed, and waited for"""
    try:
        grant = etcdform.enrolled(etcd_, peer)
        etcdmsg.loaded(said(etcd_, etcdmsg.REISSUE, peer.address,
                            {"grant": etcdmsg.grant_data(grant)}))
    except (LinkError, ProtocolError, SigningError, ValueError,
            etcdform.Refused) as e:
        raise Refused(f"{peer.address} did not take its certificate ({e});"
                      " the members before it hold theirs") from None
    wanted = etcdpki.fingerprint(grant.certificate)
    settled(etcd_, lambda: serves(etcd_, peer.address, wanted, serving),
            f"{peer.address}'s new certificate")
    out(f"etcd: {peer.address} holds a certificate the root signed;"
        " every voter is healthy")


def serves(etcd_: Etcd, address: str, wanted: str, serving) -> str | None:
    if serving(etcd_, address) != wanted:
        return "it does not serve its new certificate yet"
    sick = healthy(etcd_)
    return f"not healthy: {', '.join(sick)}" if sick else None


def own(etcd_: Etcd, address: str, serving, out) -> None:
    """The holder's own certificate, last"""
    grant = etcdstate.grant_for(etcd_.root,
                                etcdstate.member_request(etcd_.root),
                                address, etcd.own_key(etcd_))
    etcdstate.take_grant(etcd_.root, grant, address)
    if not etcd.start(etcd_):
        raise Refused("this node's certificate was not written for etcd")
    wanted = etcdpki.fingerprint(grant.certificate)
    settled(etcd_, lambda: serves(etcd_, address, wanted, serving),
            "this node's new certificate")
    out("etcd: this node holds a certificate the root signed")


def revoked(etcd_: Etcd, peers: list[Peer], out) -> None:
    """Every intermediate in the root's CRL, sent to every member"""
    serials = etcdca.legacy_serials(etcd_.root)
    found = etcdca.revoke_legacy(etcd_.root, serials, etcd_.clock()) \
        if serials else etcdstate.read(etcd_.root, etcdstate.CRL)
    etcd.start(etcd_)
    missed = []
    for peer in peers:
        try:
            etcdmsg.loaded(said(etcd_, etcdmsg.CRL_KIND, peer.address,
                                {"crl": found}))
        except (LinkError, ProtocolError, SigningError, ValueError) as e:
            missed.append(f"{peer.address} ({e})")
    if missed:
        raise Refused(f"the CRL did not reach {'; '.join(missed)}; the"
                      " rosters carry it, and running this again sends it")
    settled(etcd_, lambda: (lambda sick: ", ".join(sick) or None)(
        healthy(etcd_)), "the voters after the revocation")
    out(f"etcd: {len(serials)} intermediate(s) revoked; no member holds a"
        " CA key")


def authorized(etcd_: Etcd, out) -> None:
    """etcd's users and roles, then its auth on"""
    admin = etcdclient_admin(etcd_)
    mesh = identity.read(etcd_.root).hex()
    pairs = etcdauth.from_claims(etcd_, admin, mesh)
    for line in etcdauth.reconcile(etcd_, admin):
        etcd_.err(f"etcd: {line}")
    if not admin.auth_enabled():
        admin.auth_enable()
        etcdauth.forget(etcd_.root)
    try:
        etcd_.local().prefix(etcdauth.mesh_prefix(mesh))
    except EtcdError as e:
        raise Refused(f"auth is on, but this member cannot read the mesh's"
                      f" keys ({e}): keel mesh etcd reissue --rollback turns"
                      " it off") from None
    out(f"etcd: auth enabled; {pairs} VIP pair(s) hold their keys alone")


def etcdclient_admin(etcd_: Etcd):
    if etcd_.client:
        return etcd_.client()
    from keel.mesh import etcdclient
    return etcdclient.admin(etcd_.root)


def rollback(etcd_: Etcd, out: Callable[[str], None]) -> int:
    """`keel mesh etcd reissue --rollback`: etcd's auth off"""
    try:
        if not etcdstate.holds_root(etcd_.root):
            raise Refused("run it on the root CA's holder")
        admin = etcdclient_admin(etcd_)
        if admin.auth_enabled():
            admin.auth_disable()
        etcdauth.forget(etcd_.root)
    except Refused as e:
        etcd_.err(f"keel mesh etcd reissue: {e}")
        return exits.MESH_REFUSED
    except (StateError, EtcdError) as e:
        etcd_.err(f"keel mesh etcd reissue: {e}")
        return exits.APPLY_FAILED
    out("etcd: auth disabled; the certificates stay the root's")
    return exits.OK
