# keel mesh

Joining a node to the WireGuard mesh takes one command (handbook decision
0048). On a node already in the mesh, `keel mesh invite` prints one line:

```
keel mesh join keel1:<token>
```

and that line, run on the new node, joins it. The token carries every
value the new node would otherwise copy by hand from
[docs/spec.md](spec.md), "overlay": the inviter's public key, its
endpoint and port, the overlay prefix and the address reserved for the
new node. It is valid for one hour and can be used once.

What a join writes is the same `network.overlay.wireguard` fields an
operator writes by hand, `address` and a peer, converged by the same
`apply --system` under the same confirmation window. There is no `mesh`
section in the spec, and a mesh built by joins and one typed by hand are
the same spec.

**What exists in this version:** the token, the address an invite
reserves, the pending invites, `keel mesh invite`, and `keel mesh join
--dry-run`, which prints the change a token makes and applies nothing.
The listener that answers a join, the join itself, the fallback command
`keel mesh accept`, `keel mesh create` for a node with no overlay, and
`keel mesh remove` come next; the token and the invite file already
carry what they need.

## keel mesh invite

```
keel mesh invite [--endpoint ADDRESS]... [--port PORT]
```

Root, on a node whose spec declares `network.overlay.wireguard` and whose
key file exists (apply makes it the first time it converges the overlay).
It:

1. reads this node's public key from its private key file with `wg
   pubkey`, as `keel network wireguard key` does; the key is not made
   here;
2. takes the endpoints the new node will reach this one at: the
   `--endpoint` addresses (one per family, for a port forward say), or
   else the static addresses `network.interfaces` declares, IPv6 first;
3. makes a key pair and a self signed certificate for this invite only
   (`openssl req -x509`, P-256), whose SHA-256 fingerprint the token
   carries for the new node to pin;
4. makes the mesh's identity if this node has none (below);
5. under the mesh's lock, removes the expired invites, reserves a free
   address (below) and writes the pending invite;
6. prints the `keel mesh join` line, alone, on standard output; what it
   reserved and until when go to standard error, never the token.

`--port` is the TCP port the join request will go to, 51820 by default,
the number of WireGuard's UDP port, so a provider's firewall needs one
number for both.

No listener answers the invite yet in this version, so the line can be
checked on the new node with `keel mesh join --dry-run` and not used to
join.

### The address

A random address of the inviter's overlay prefix, drawn with Python's
`secrets`, that is not its own, not inside any peer's `allowed_ips`, and
not reserved by another pending invite. Random rather than the next
free one: until etcd exists, a member does not know the invites another
member has pending, and two members inviting at the same time would both
hand out `::2`; two draws in a `/64` practically never meet. A draw that
lands on a taken address is drawn again; after 16 taken draws in a row
the prefix is nearly full and is searched from the last draw, so its
last free address is still found and a full prefix is refused. The
prefix's own address (`::`, the subnet router anycast) is never given.

## keel mesh join --dry-run

```
keel mesh join TOKEN --dry-run
keel mesh join - --dry-run       # the token on standard input
```

Reads the token, checks it whole (below), and prints on standard output
the fields of `network.overlay.wireguard` the join would set in this
node's spec:

```yaml
network:
  overlay:
    wireguard:
      address: fd00:6b65:1::3/64
      peers:
      - public_key: nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=
        endpoint: '[2001:db8:1::10]:51820'
        allowed_ips:
        - fd00:6b65:1::1/128
```

The inviter is the peer: its key, its endpoint (IPv6 when it has one),
and its overlay address as a `/128`. The spec is read and nothing is
written or applied. It refuses a node whose overlay is on another prefix
(another mesh) or at another address of this one (a node joins once),
and a change `spec validate` would refuse once made, such as an overlay
prefix that overlaps this node's uplink, naming the error. Without
`--dry-run`, `join` applies nothing in this version and exits 9.

The overlay's optional `ipv4_address` is not carried: a join gives the
new node an IPv6 overlay address and routes the inviter's IPv6 address
only. A mesh that also uses IPv4 on the overlay adds those addresses by
hand, as before.

`-` reads the token from standard input, which keeps it out of the
process list and the shell's history; confconsole will use it.

## The token

`keel1:` followed by the base64url encoding, without padding, of the
fields below in this order, big endian, and a checksum: the first four
bytes of the SHA-256 of the prefix and the fields. A typical invite,
with one IPv6 endpoint, is 250 characters; with an IPv4 endpoint as
well, 256.

| Field | Bytes | Why the new node needs it |
| --- | --- | --- |
| flags | 1 | which endpoints follow: bit 0 IPv6, bit 1 IPv4; no other bit is set |
| inviter's public key | 32 | its peer entry for the inviter |
| IPv6 endpoint | 16 | where to send the handshake, when the inviter has one |
| IPv4 endpoint | 4 | the same, for a new node without IPv6 |
| WireGuard port | 2 | the UDP port at the endpoint |
| HTTPS port | 2 | the TCP port of the join request, at the same address |
| certificate fingerprint | 32 | SHA-256 of the invite's certificate, to pin it |
| inviter's overlay address | 16 | its peer's `allowed_ips`, as a `/128` |
| prefix length | 1 | of the overlay prefix, which the inviter's address is on |
| assigned address | 16 | its own `network.overlay.wireguard.address` |
| mesh identity | 16 | names the mesh; etcd's cluster token |
| etcd state | 1 | 0 none, 1 forms at this join, 2 running |
| etcd port | 2 | only when running: the inviter's member port |
| invite id | 8 | which pending invite this is; derived from the secret |
| secret | 32 | 256 random bits, used once; the HMAC key is derived from it |
| expiry | 4 | seconds since the epoch, UTC |
| checksum | 4 | a truncated or mistyped paste is refused before anything is sent |

`join` refuses, each with its reason and exit 23:

- more than 1024 characters, before anything is decoded (a token is
  about 256);
- text that does not start with `keel1:` (the whole `keel mesh join`
  line pasted, say), and a `keel2:` or later token, naming the keel it
  needs;
- a character outside base64url, and any token whose checksum does not
  match: one character changed, or the end cut off;
- a layout that does not match its flags, unknown flags or an unknown
  etcd state;
- a value no join could use: a key that is not 32 bytes, an endpoint
  that cannot be reached from another machine (loopback, link local,
  multicast), a port 0, an overlay prefix outside `fc00::/7`, an
  assigned address outside the prefix or equal to the inviter's, an
  invite id that is not the one its secret gives;
- an expired token, with the time it expired.

The secret is the only value in the token that is not public, and it is
in no message: no error names the token or its secret, and the `repr`
of a parsed token leaves it out. `invite` writes the token to its
standard output and nowhere else.

## Where the state lives

Under `/var/lib/keel/mesh`, root's, directories mode 0700 and files 0600,
written through a temporary file and a rename as `/var/lib/keel/network`
is, every change under the lock `/var/lib/keel/mesh/lock`. State, not
configuration: never in the spec, never emitted by `inspect`, never in a
backup set.

| Path | What it holds |
| --- | --- |
| `invites/<id>.json` | one pending invite: the reserved address, the expiry, the HTTPS port, the invite's certificate and TLS key, and the HMAC key |
| `identity` | the mesh's identity, 16 bytes in hex |

The invite file holds an HMAC key derived from the secret, never the
secret, so it cannot be turned back into the token. An invite is
consumed once, under the lock: it is marked consumed, and a second
request is told it was already used. A consumed invite keeps its
address reserved until it expires, so no other invite takes the address
before the new node is a peer in the spec; an expired or damaged one is
removed by the next invite.

**Pending:** an invite whose expiry passes while the machine is down is
removed by the next invite, not yet at boot; the boot unit 0048
describes comes with the listener.

The mesh identity is made once and kept: a file that does not hold one
is an error, never replaced, since every other node of the mesh knows
the first. A mesh built by hand before `keel mesh` existed gets it from
its first invite.

## Exit codes

| Code | When |
| --- | --- |
| 0 | the line or the change was printed |
| 2, 3 | the spec cannot be read or is invalid |
| 9 | `join` without `--dry-run`: not implemented yet |
| 15 | `invite` on the live system, not as root |
| 16 | `invite`: `wg` cannot read the key file, or `openssl` cannot make the certificate, or the mesh identity is damaged |
| 23 | `join`: the token is mistyped, truncated, of a later format, inconsistent, or expired |
| 24 | refused: no overlay to invite into, no key yet, no endpoint, no free address; a node in another mesh or at another address of it, or a change the spec would refuse |

## Tests

At four seams, each written down before its tests: the token's
`encode()` and `parse()` (`tests/test_mesh_token.py`, round trips and
every damaged, foreign, inconsistent and expired form, and the secret in
no message and no repr); the allocator's `free_address()`
(`tests/test_mesh_allocate.py`); the store's `reserve`, `find`,
`consume`, `pending` and `expire` against a scratch root
(`tests/test_mesh_invites.py`, modes, one use, expiry, no secret on
disk); and the commands through `keel.cli.main`
(`tests/test_mesh_cli.py`), with the real `wg` (tests/wgtools.py) and
the real `openssl`, so the key and the fingerprint in the token are
checked against what those tools say.
