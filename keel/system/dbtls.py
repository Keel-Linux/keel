# Copyright (c) 2026 KeelLinux maintainers
"""TLS on the replication channel: the database leaf of the mesh root CA

Required beside WireGuard (0031; the maintainer, 2026-10-03). The
certificate is the mesh root's (keel.mesh.etcdpki, kind `database`):
CN `<member name> <engine>` (`mariadb` or `postgresql`, 0054), which
is no etcd user, so the key the database system user reads opens
nothing in etcd; its IP SANs this node's own overlay address and the
pair's VIP, so a client verifying the VIP works later; 30 days,
renewed with a third left (`ensure`, from apply and keel database
watch). The root's holder signs it: here when this node holds the
root, else asked over the members' channel of the holder. Every member
learns the holder's address from a notice the root's key signed, in
its peers' rosters (keel.mesh.rootholder, keel#105); a node that knows
no holder fetches its peers' rosters first, and asks the other member
of the pair only when none says where the holder is (a cloud simple
pair, whose first node made the root at keel mesh create). When this
node holds a root certificate or learned one, the leaf is taken only
under it.

The module is parameterized by engine, not forked (0054): the layout —
the directory under the root, the file group the server reads as —
and the spelling of the drop-in and client options differ per engine;
the PKI flow is the same. MariaDB keeps the historical module-level
paths (keel.system.dbmariadb and the tests read them); every function
takes the engine word, defaulting to mariadb. `ensure` reads the
engine from the instance description when the caller names none, so
keel.system.actions and keel.system.effects stay engine neutral.

MariaDB's files live under /etc/mysql/keel-tls, a directory the server
can reach as the mysql user (/var/lib/keel is root's alone): `ca.pem`
(the root; the trust bundle of 0051 when there are several),
`server.pem`, `server.key` (0640 root:mysql: the server reads it as
mysql, keel's clients as root). PostgreSQL's twin lives under
/etc/postgresql/keel-tls, group postgres. The server side is a few
lines of the drop-in (`dropin_lines`); the replica's connection and
the seed's clients carry the same files with the server's certificate
verified (`options_lines`).
"""

import grp
import os
from dataclasses import dataclass
from datetime import datetime, timedelta

from keel.mesh import etcdpki, etcdstate
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import StateError
from keel.network.marker import path, write_private

DIR = "etc/mysql/keel-tls"
CA = f"{DIR}/ca.pem"
CERT = f"{DIR}/server.pem"
KEY = f"{DIR}/server.key"
# the root's CRL, as the mesh carries it (keel.mesh.etcdstate.CRL):
# copied here for the server, which checks a client's certificate
# against it, and refreshed by keel database watch with FLUSH SSL
CRL = f"{DIR}/crl.pem"
GROUP = "mysql"
KEY_MODE = 0o640
PUBLIC_MODE = 0o644
DIR_MODE = 0o750
RENEW_WITH = timedelta(days=etcdpki.LEAF_DAYS // 3)


@dataclass(frozen=True)
class Layout:
    """Where one engine keeps the database leaf, and who reads it

    The directory is one the server reaches as its own user; the key
    is 0640 root:<group>, so the server reads it and keel's clients
    (root) too; the rest is public material the server reads as that
    user. A dev host without the group keeps root-owned files, which
    the tests run with all the same.
    """

    directory: str
    group: str

    @property
    def ca(self) -> str:
        return f"{self.directory}/ca.pem"

    @property
    def cert(self) -> str:
        return f"{self.directory}/server.pem"

    @property
    def key(self) -> str:
        return f"{self.directory}/server.key"

    @property
    def crl(self) -> str:
        return f"{self.directory}/crl.pem"


LAYOUTS = {
    "mariadb": Layout("etc/mysql/keel-tls", "mysql"),
    "postgresql": Layout("etc/postgresql/keel-tls", "postgres"),
}


def layout(engine: str = "mariadb") -> Layout:
    """The files and group of one engine's leaf; mariadb's layout is
    the historical module constants above"""
    return LAYOUTS[engine]


def present(root: str, engine: str = "mariadb") -> bool:
    lay = layout(engine)
    return all(os.path.exists(path(root, one))
               for one in (lay.ca, lay.cert, lay.key, lay.crl))


def expires(root: str, engine: str = "mariadb") -> datetime | None:
    found = etcdstate.read(root, layout(engine).cert)
    if not found:
        return None
    try:
        return etcdpki.not_after(etcdpki.blocks(found)[0])
    except (PkiError, IndexError):
        return None


def due(root: str, address: str, vip: str | None, now: datetime,
        engine: str = "mariadb") -> bool:
    """Whether the leaf is to be made or renewed: missing, with a third
    of its life left, or for other addresses than this node's and the
    pair's VIP"""
    lay = layout(engine)
    if not present(root, engine):
        return True
    leaf = etcdpki.blocks(etcdstate.read(root, lay.cert) or "")
    if not leaf:
        return True
    wanted = (address,) + ((vip,) if vip else ())
    try:
        return etcdpki.not_after(leaf[0]) - now < RENEW_WITH or \
            etcdpki.addresses(leaf[0]) != wanted
    except PkiError:
        return True


def ensure(member, address: str, vip: str | None,
           peer: str | None, own_key: str,
           owner=None, pair=None, engine: str | None = None) -> str | None:
    """The leaf made or renewed when due; what changed, or None. `pair`
    is the signed pair record (keel.mesh.vippair.Pair) the request
    carries, which binds the VIP SAN to the pair the holder verifies.
    `engine` is the engine word the certificate is named for; None
    reads it from the instance description (the engine neutral caller,
    keel.system.effects, names none)"""
    if engine is None:
        engine = declared_engine(member)
    lay = layout(engine)
    root = member.root
    if not due(root, address, vip, member.clock(), engine):
        return None
    key = _key(root, owner, engine)
    try:
        csr = etcdpki.request(key)
        if etcdstate.holds_root(root):
            grant = etcdstate.database_grant(root, csr, address, vip,
                                             own_key, engine=engine)
        else:
            grant = _asked(member, csr, address, vip, own_key, peer, pair,
                           engine)
        problem = _checked(root, grant, address, engine)
    except (PkiError, StateError) as e:
        raise StateError(str(e)) from None
    if problem:
        raise StateError(problem)
    # the root, the certificate and the CRL are public material the
    # server reads as the database user: 0644, where write_private
    # leaves 0600 (measured: 11.8 aborts at start with "Failed to
    # setup SSL" otherwise)
    crl = grant.crl or etcdstate.read(root, etcdstate.CRL)
    if not crl:
        raise StateError("the root's CRL did not come with the certificate"
                         " and this node holds none: the server checks a"
                         " client's certificate against it, so nothing was"
                         " written")
    for relative, text in ((lay.ca, grant.root), (lay.cert, grant.certificate),
                           (lay.crl, crl)):
        write_private(root, relative, text)
        os.chmod(path(root, relative), PUBLIC_MODE)
    return (f"the database certificate for {address}"
            f"{' and ' + vip if vip else ''}, signed by the mesh's root,"
            f" until {etcdpki.not_after(grant.certificate):%Y-%m-%d}")


def declared_engine(member) -> str:
    """The engine the member's description declares; mariadb when it
    names none (the description's default)"""
    from keel.system.dbstate import declared_server
    server = declared_server(member.node.document())
    return str(server.get("engine") or "mariadb")


def _asked(member, csr: str, address: str, vip: str | None,
           own_key: str, peer: str | None, pair=None,
           engine: str = "mariadb") -> etcdstate.Grant:
    """The holder asked, or the other member of the pair when the holder
    is not known (`member` is this node, keel.mesh.etcd.Etcd); raises
    StateError"""
    from keel.mesh import etcd, etcdmsg
    from keel.mesh.memberlink import LinkError
    from keel.mesh.protocol import ProtocolError
    from keel.mesh.signing import SigningError
    at = etcdstate.holder(member.root) or _learned(member) or peer
    if at is None:
        raise StateError("this node holds no root CA and knows neither its"
                         " holder nor the other node of the pair to ask")
    body = {"kind": "database", "csr": csr, "address": address,
            "public_key": own_key, "vip": vip,
            "pair": None if pair is None else pair.dumps(),
            "engine": engine}
    try:
        found = etcdmsg.loaded(etcd.said(member, etcdmsg.ISSUE, at, body))
        grant = etcdmsg.grant(found.get("grant"))
    except LinkError as e:
        raise StateError(f"the root CA's holder at {at} did not sign the"
                         f" database certificate ({e})") from None
    except (SigningError, ProtocolError, ValueError) as e:
        raise StateError(f"the answer from {at} holds no certificate:"
                         f" {e}") from None
    if grant is None:
        raise StateError(f"the answer from {at} holds no certificate")
    return grant


def _learned(member) -> str | None:
    """The holder's address, from the rosters of this node's peers
    fetched now (keel#105); None when none says"""
    from keel.mesh import etcd, identity, rootholder
    try:
        mesh_id = identity.read(member.root)
        own = etcd.own_key(member)
        if mesh_id is None or own is None:
            return None
        rootholder.asked(member.node, own, mesh_id.hex(), member.err,
                         member.clock())
    except (ValueError, OSError) as e:
        member.err(f"the root CA's holder could not be learned: {e}")
        return None
    return etcdstate.holder(member.root)


def _checked(root: str, grant: etcdstate.Grant, address: str,
             engine: str = "mariadb") -> str | None:
    """Why `grant` is not this node's database leaf, or None"""
    try:
        if etcdpki.public(grant.certificate) != etcdpki.key_public(
                path(root, layout(engine).key)):
            return "the certificate certifies another key, not this node's"
        if etcdpki.is_ca(grant.certificate) or not etcdpki.verified(
                grant.certificate, [], grant.root):
            return "the certificate is not one the root signed"
        if etcdpki.addresses(grant.certificate)[:1] != (address,) or \
                etcdpki.subject(grant.certificate) != \
                etcdstate.database_name(address, engine):
            return f"the certificate does not name this node ({address})"
        from keel.mesh import rootholder
        held = rootholder.anchor(root)
        if held and etcdpki.fingerprint(held) != etcdpki.fingerprint(
                grant.root):
            return "the certificate is under another root than this node's"
    except PkiError as e:
        return str(e)
    return None


def _key(root: str, owner, engine: str = "mariadb") -> str:
    """The key file, made when there is none, readable by the database
    group; its path"""
    lay = layout(engine)
    target = path(root, lay.key)
    if not os.path.exists(target):
        write_private(root, lay.key, etcdpki.new_key())
    (owner or _grouped(lay))(os.path.dirname(target), target)
    return target


def _grouped(lay: Layout):
    """The directory 0750 and the key 0640, group the server reads as,
    where that group exists; root alone otherwise, and the server says
    so"""
    def chown(directory: str, key: str) -> None:
        try:
            gid = grp.getgrnam(lay.group).gr_gid
        except KeyError:
            return
        os.chmod(directory, DIR_MODE)
        os.chown(directory, 0, gid)
        os.chmod(key, KEY_MODE)
        os.chown(key, 0, gid)
    return chown


def files(root: str, engine: str = "mariadb") -> dict[str, str]:
    """The absolute paths the server and the clients are given"""
    lay = layout(engine)
    return {"ca": "/" + lay.ca, "cert": "/" + lay.cert, "key": "/" + lay.key}


def dropin_lines(root: str, engine: str = "mariadb") -> str:
    """The server side: its certificate, its key, the root to verify a
    client's certificate against, and the root's CRL when it is held"""
    lay = layout(engine)
    if engine == "postgresql":
        # postgresql.conf rejects an unquoted value that starts with /
        # (a syntax error at the token, FATAL at boot): the paths are
        # quoted, the way dbpostgres' hba_file and ident_file lines are
        return (f"ssl = on\n"
                f"ssl_ca_file = '{path(root, lay.ca)}'\n"
                f"ssl_cert_file = '{path(root, lay.cert)}'\n"
                f"ssl_key_file = '{path(root, lay.key)}'\n"
                f"ssl_crl_file = '{path(root, lay.crl)}'\n")
    return (f"ssl_ca = {path(root, lay.ca)}\n"
            f"ssl_cert = {path(root, lay.cert)}\n"
            f"ssl_key = {path(root, lay.key)}\n"
            f"ssl_crl = {path(root, lay.crl)}\n")


def refresh_crl(root: str, engine: str = "mariadb") -> bool:
    """The root's CRL the mesh carries copied for the server when it
    changed; whether it did (the caller runs FLUSH SSL)"""
    found = etcdstate.read(root, etcdstate.CRL)
    lay = layout(engine)
    if not found or found == etcdstate.read(root, lay.crl):
        return False
    write_private(root, lay.crl, found)
    os.chmod(path(root, lay.crl), PUBLIC_MODE)
    return True


def issuer_name(root: str, engine: str = "mariadb") -> str:
    """The root's name as the engine spells a certificate's issuer, for
    MariaDB's `REQUIRE ... ISSUER`: from the root held in the engine's
    directory, else from the mesh's identity, which names it
    (keel.mesh.etcdpki.root)"""
    found = etcdstate.read(root, layout(engine).ca) or etcdstate.read(
        root, etcdstate.ROOT_CERT)
    if found:
        try:
            return "/CN=" + etcdpki.subject(etcdpki.blocks(found)[0])
        except (PkiError, IndexError):
            pass
    from keel.mesh import identity
    try:
        mesh_id = identity.read(root)
    except ValueError:
        mesh_id = None
    if mesh_id is None:
        return ""
    return f"/CN=keel mesh {mesh_id.hex()[:16]} etcd root"


def peer_subject(address: str, engine: str = "mariadb") -> str:
    """The other member's database certificate's subject, as the engine
    spells it for its authorization binding: MariaDB's `REQUIRE
    SUBJECT`, PostgreSQL's pg_ident map entry (0054)"""
    return "/CN=" + etcdstate.database_name(address, engine)


def options_lines(root: str, engine: str = "mariadb") -> str:
    """The client side, for an options file: the root, this node's
    certificate and key, and the server's certificate verified"""
    lay = layout(engine)
    if engine == "postgresql":
        return (f"sslmode=verify-full\n"
                f"sslrootcert={path(root, lay.ca)}\n"
                f"sslcert={path(root, lay.cert)}\n"
                f"sslkey={path(root, lay.key)}\n")
    return (f"ssl-ca={path(root, lay.ca)}\n"
            f"ssl-cert={path(root, lay.cert)}\n"
            f"ssl-key={path(root, lay.key)}\n"
            "ssl-verify-server-cert\n")


def master_options(root: str) -> str:
    """The `CHANGE MASTER TO` options of the replication connection"""
    return (f", MASTER_SSL=1, MASTER_SSL_CA='{path(root, CA)}',"
            f" MASTER_SSL_CERT='{path(root, CERT)}',"
            f" MASTER_SSL_KEY='{path(root, KEY)}',"
            " MASTER_SSL_VERIFY_SERVER_CERT=1")


def summary(root: str, engine: str = "mariadb") -> dict:
    """What inspect and status say of the leaf"""
    found = etcdstate.read(root, layout(engine).cert)
    if not found:
        return {"present": False}
    blocks = etcdpki.blocks(found)
    if not blocks:
        return {"present": True, "problem": "not a certificate"}
    try:
        leaf = blocks[0]
        return {"present": True, "subject": etcdpki.subject(leaf),
                "addresses": list(etcdpki.addresses(leaf)),
                "expires": etcdpki.not_after(leaf).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")}
    except PkiError as e:
        return {"present": True, "problem": str(e)}
