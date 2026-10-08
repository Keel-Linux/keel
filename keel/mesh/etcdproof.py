# Copyright (c) 2026 KeelLinux maintainers
"""Who may have a certificate signed for an address, and the proof

The root signs a member's certificate for an address and a WireGuard
key (keel#83). Before it does, it asks who is asking (the message's
sender, a member whose signing key the holder's trust store holds) and
whether the key in the request is the member's own; a request on its own
proves nothing about either:

- **the request's own signature** proves whoever made it holds the
  request's key (openssl `req -verify`, which keel.mesh.etcdpki checks
  before it signs anything);
- **the proof** is the member's signature, with its mesh signing key
  (keel.mesh.signing), over LABEL and the request: so the request's key
  is the member's, and no relay can put another key in its place;
- **for a member's own address** (a renewal), the sender is that member
  itself: `sender` is the address's WireGuard key, and the proof
  verifies with the signing key the trust store holds for it;
- **for a node being admitted** (its address nobody's yet, or already
  its own), the sender is its inviter, which relays the request with the
  **admission evidence** it signed (keel.mesh.trust): the evidence names
  this node, this address and the node's signing key, is signed by the
  sender's signing key, and the proof verifies with the signing key the
  evidence names. Where the trust store already knows that node's
  signing key, the evidence must name the same one.

So a trusted member cannot have a certificate signed for another
member's address or name (its own key is not that member's, and it has
no evidence that it admitted it), and an inviter cannot have the node it
admits certified for a key of its own: the proof would not verify with
the signing key the evidence names, evidence naming the inviter's own
signing key, or any other member's, for the node is refused, and the
node refuses a grant for a key not its own. Evidence naming a signing
key made up for the purpose is caught once the node's real one is
known: the join's rosters carry the evidence the node confirmed. The
holder records, with each certificate, the signing key it was issued
under and the member that relayed it; a certificate issued under a
signing key the trust store later disowns for that node is revoked
(keel.mesh.etcdca.impostors).
"""

from dataclasses import dataclass

from keel.mesh import signing, trust
from keel.mesh.protocol import ED25519_RE, Admission, ProtocolError
from keel.network.wireguard import same_key

LABEL = b"keel mesh etcd request 1\n"


@dataclass(frozen=True)
class Request:
    """A certificate request and the proof it is the member's"""

    csr: str
    proof: str


def other_sign_keys(root: str, key: str) -> set[str]:
    """The signing keys the trust store holds for every member but
    `key`, and this node's own: a node's signing key is its alone, so
    evidence naming one of these for `key` is a lie"""
    found = {signing.public(root)}
    try:
        store = trust.load(root)
    except ValueError:
        return found
    for member_key, member in store.members.items():
        if member.sign_key and not same_key(member_key, key):
            found.add(member.sign_key)
    return found


def trusted_sign_key(root: str, key: str) -> str | None:
    """The signing key this node's trust store holds for the member
    `key`, None when it holds none"""
    try:
        store = trust.load(root)
    except ValueError:
        return None
    found = store.find(key)
    return None if found is None else store.members[found].sign_key


def sign(root: str, csr: str) -> str:
    """This node's proof over `csr`; raises SigningError"""
    return signing.sign(root, LABEL + csr.encode())


def verified(sign_key: str, csr: str, proof: str) -> bool:
    return signing.verified(sign_key, LABEL + csr.encode(), proof)


def proof(value: object) -> str:
    """One Ed25519 signature in base64; raises ProtocolError"""
    if not isinstance(value, str) or not ED25519_RE.match(value):
        raise ProtocolError("not a proof over the request")
    return value


def problem(sender: str, sender_sign_key: str | None, public_key: str,
            address: str, request: Request, evidence: Admission | None,
            mesh_id: str, claimed_by: str | None,
            known_sign_key: str | None,
            others: frozenset[str] | set[str] = frozenset()
            ) -> tuple[str | None, str | None]:
    """Why the root must not sign `request` for the member at `address`
    with WireGuard key `public_key`, asked by `sender`, or None; and the
    signing key the proof verified with. `sender_sign_key` is what the
    trust store holds for the sender, `claimed_by` the key the holder
    knows the address by (None for an address nobody holds),
    `known_sign_key` the signing key the trust store holds for
    `public_key`, if any, `others` the signing keys it holds for every
    other member (the sender's among them), which no evidence may name
    for this node"""
    if claimed_by is not None and not same_key(claimed_by, public_key):
        return (f"{address} is another member's: a certificate is signed"
                " for a member's own address and key only"), None
    if sender_sign_key is None:
        return "the sender's signing key is not trusted here", None
    if same_key(sender, public_key):
        if known_sign_key is not None and known_sign_key != sender_sign_key:
            return "the sender is not known by that signing key", None
        if not verified(sender_sign_key, request.csr, request.proof):
            return ("the request is not signed by the member's own signing"
                    " key"), None
        return None, sender_sign_key
    if evidence is None:
        return ("a certificate for another member's address needs the"
                " evidence of its admission, from its inviter"), None
    if evidence.by != sender_sign_key or \
            not same_key(evidence.public_key, public_key) or \
            evidence.address != address or evidence.mesh_id != mesh_id or \
            not evidence.invite_id or \
            not signing.verified(evidence.by, evidence.message(),
                                 evidence.signature):
        return ("the admission evidence is not the sender's, or not for"
                " that node at that address"), None
    if known_sign_key is not None and known_sign_key != evidence.sign_key:
        return ("the admission evidence names a signing key this node does"
                " not know the member by"), None
    if evidence.sign_key in others or evidence.sign_key == sender_sign_key:
        return ("the admission evidence names a signing key that is"
                " another member's, not the node's"), None
    if not verified(evidence.sign_key, request.csr, request.proof):
        return ("the request is not signed by the admitted node's signing"
                " key"), None
    return None, evidence.sign_key
