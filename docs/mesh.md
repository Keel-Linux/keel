# keel mesh

Joining a node to the WireGuard mesh takes one command (handbook decision
0048). The first node makes the mesh with `keel mesh create`. On a node
already in the mesh, `keel mesh invite` prints one line:

```
keel mesh join - <<< keel1:<token>
```

and that line, run on the new node, joins it. The token goes to `join`
on its standard input (a here-string of root's shell, bash), so it is
never an argument and never in the process list. The token carries every
value the new node would otherwise copy by hand from
[docs/spec.md](spec.md), "overlay": the inviter's public key, its
endpoint and port, the overlay prefix and the address reserved for the
new node. It is valid for one hour and can be used once.

What a join writes is the same `network.overlay.wireguard` fields an
operator writes by hand, `address` and a peer, converged by the same
`apply --system` under the same confirmation window (decision 0018).
There is no `mesh` section in the spec, and a mesh built by joins and
one typed by hand are the same spec.

**What exists in this version:** `create`, `invite` and its listener,
`join`, the fallback `accept`, and `status`. Not yet: etcd (it forms at
the third node in cloud advanced, Phase 5), the announcement of a new
node to the inviter's other peers, `keel mesh remove`, `keel mesh
invites` and `invite --cancel`, and the boot unit that removes invites
which expired while the machine was down. confconsole's "Invite a node"
and "Join a mesh" screens call these commands, in confconsole.

## keel mesh create

```
keel mesh create [--network-window SECONDS]
```

Root, on the first node, whose spec declares no overlay address. It
writes into this node's spec `network.overlay.wireguard.address`, a
random unique local /64 with this node at `::1` (as `keel network
wireguard suggest-address` gives it), makes the mesh's identity, and
converges the overlay with `apply --system-only --skip-uplink` under the
window; apply makes the key pair on the machine (keel-core#8). WireGuard
listens on its default UDP port, 51820.

No peer can confirm an overlay that has none, so `create` confirms it
itself (0048, second round, point 1, amending 0018): once apply.md's
route check finds every gateway, and the client of the SSH session
`create` runs in, still leaving through the uplink. An overlay with no
peer routes its own private prefix only; a route that does leave
through it refuses the confirmation and the change reverts when its
window ends.

```
# keel mesh create
created the mesh: this node is fd2a:9c41:7e03::1/64 on wg0, WireGuard on UDP 51820
keel mesh invite prints the line that joins the next node
```

apply's own lines, and the confirmation's, go to standard error;
standard output holds the summary alone.

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
   address (below) and writes the pending invite; another invite pending
   on the same TCP port is refused (each listener holds its port), and
   `--port` gives this one another;
6. starts the invite's root helper as a transient unit,
   `keel-mesh-invite@<id>` (`systemd-run`), which starts the unprivileged
   listener (below), so the command returns; an invite whose helper
   cannot start is removed and no line is printed;
7. opens the port where keel's firewall exists (below);
8. prints the `keel mesh join` line, alone, on standard output; what it
   reserved, until when, and whether the port was opened go to standard
   error, never the token.

`--port` is the TCP port the join request goes to, 51820 by default,
the number of WireGuard's UDP port, so a provider's firewall needs one
number for both. Under `--root` no listener is started, and the line can
be checked with `keel mesh join --dry-run` only.

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

## keel mesh join

```
keel mesh join - [--endpoint ADDRESS] [--network-window SECONDS] <<< TOKEN
keel mesh join TOKEN             # accepted, with a warning: argv is public
keel mesh join - --dry-run <<< TOKEN
```

Root, on the new node. A token given as an argument still works, and
`join` warns that it shows in the process list and the shell's history.
It:

1. reads the token whole (below), checks the spec can take it (a node
   with no overlay, or one of this mesh at the reserved address), and
   that no network change waits in its window here;
2. finds a route to the inviter's endpoint (`ip route get`); without
   one it says so and names the rendezvous point of decision 0024, and
   applies nothing;
3. keeps the mesh's identity the token carries (a node that keeps
   another is in another mesh, and is refused), and makes its key pair
   if it has none;
4. finds its own endpoint: `--endpoint`, else a static address
   `network.interfaces` declares, else a global address of an interface
   other than the overlay's; IPv6 first; none when it has none;
5. sends the join request to the inviter's HTTPS port, at its IPv6
   endpoint and then its IPv4 one, comparing the SHA-256 of the
   certificate the inviter presents with the token's fingerprint before
   a byte of the request is sent;
6. with the signed answer, which must carry its own nonce, the invite
   id, the inviter's key and address, writes its own spec (its address
   and the inviter as a peer) and applies it under the window, with
   `--skip-uplink`;
7. opens the mesh session to the inviter's overlay address, retrying
   every two seconds while the tunnel comes up: the inviter confirms its
   window on receiving it, and this node confirms its own on the
   inviter's signed answer. No `keel network confirm` is typed on
   either node.

At the end, on standard output:

```
joined the mesh: this node is fd2a:9c41:7e03::3/64 on wg0
peer: nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E= at fd2a:9c41:7e03::1, through [2001:db8:1::10]:51820
the mesh is up with 2 nodes; etcd starts when a third node joins, because 2 etcd members cannot lose one and keep a majority
```

apply's lines, the confirmation's, and every refusal go to standard
error. When the inviter knows other peers, the last line says how many
nodes the mesh has, and that this node reaches the inviter alone until
they learn of it, which this keel does not do yet (0048, "Until etcd
exists").

A join that fails after the request was accepted (the tunnel never
answers within the window, say) reverts on both sides by itself, and
the token is spent: the operator runs a new invite.

### The fallback

When the inviter's port gives no TCP answer within five seconds, `join`
does not give up, provided this node has an endpoint the inviter can
reach (behind NAT on both sides, neither can reach the other: `join`
says so, names the rendezvous point, and applies nothing). It applies
its own side under a window lengthened to the invite's remaining time,
up to 15 minutes, and prints on standard output, alone:

```
keel mesh accept keel1a:<answer>
```

to run on the inviter, then waits for the inviter over the overlay as in
step 7. Too close to the expiry (under 30 seconds) it refuses instead.

### --dry-run

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
prefix that overlaps this node's uplink, naming the error.

The overlay's optional `ipv4_address` is not carried: a join gives the
new node an IPv6 overlay address and routes the inviter's IPv6 address
only. A mesh that also uses IPv4 on the overlay adds those addresses by
hand, as before.

`-` reads the token from standard input, which keeps it out of the
process list and the shell's history; confconsole uses it.

## keel mesh accept

```
keel mesh accept LINE
keel mesh accept -               # the line on standard input
```

Root, on the inviter. It reads the `keel1a:` line (below), checks its
HMAC with the pending invite's key and the reserved address, refuses
while a network change waits, consumes the invite, stops the invite's
listener, adds the new node as a peer with its endpoint when it has one
and `persistent_keepalive` 25 (this node may be the one that has to
initiate, behind NAT), and applies. Then, in the foreground, it serves
the mesh session on its overlay address alone, on the invite's port
(opened in keel's firewall where there is one), until the new node
confirms or the window ends:

```
accepted: FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg= is a peer of this node at fd2a:9c41:7e03::3
```

A line for another invite, or one changed in the copy, is refused
before anything is spent; a second use of the token finds no pending
invite.

## keel mesh status

```
keel mesh status
```

This node's overlay, its public key, each peer of the spec with its
`allowed_ips`, its endpoint (as WireGuard last saw it) and its last
handshake, and the pending invites: id, reserved address, port, expiry,
and whether it was used and waits for its confirmation. `wg show` is
asked for `public-key`, `endpoints` and `latest-handshakes` only, never
`dump` or `private-key`, and no secret is printed. Off the live system
(`--root`) no handshake is read.

## The protocol

Two requests go to the inviter's HTTPS port, each a JSON body POSTed
with `X-Keel-Mesh-Signature`: the hex HMAC-SHA256, keyed with the
invite's HMAC key (derived from the token's secret, which never crosses
the wire), of `keel mesh 1\n`, the method, `\n`, the path, `\n`, and
the body.

| Request | Fields | Over |
| --- | --- | --- |
| `POST /v1/join` | `invite_id`, `public_key`, `endpoint` (`[address]:port`, or null), `address` (the reserved one, with its length), `nonce` (16 random bytes, hex), `time` (seconds since the epoch) | the uplink |
| `POST /v1/confirm` | `invite_id`, `public_key`, `nonce`, `time` | the overlay |

| Answer (200) | Fields |
| --- | --- |
| to a join | `invite_id`, `nonce` (the request's), `public_key` and `address` (the inviter's), `peers` (the other members the inviter knows: `public_key`, `endpoint` or null, `address`), `etcd` (`none` in this keel), `window` (the seconds the inviter's change waits) |
| to a confirmation | `invite_id`, `nonce`, `confirmed` (whether the inviter kept its change), `detail` |

An answer is signed the same way, with the method `ANSWER` and the
request's path, so the new node knows it came from the node that made
the token as well as from the pinned certificate. A refusal is a JSON
`{"error": reason}`, unsigned: it gives nothing to act on.

The fallback's `keel1a:` line carries the join request's fields in
binary, base64url without padding like the token, about 150 characters:
flags (1 byte: an IPv6 or an IPv4 endpoint follows, at most one), the
new node's key (32), the endpoint and its UDP port (16 or 4, and 2),
the reserved address and its length (16, 1), the invite id (8), the
time (4), an HMAC-SHA256 with the invite's key (32), and a checksum
(the first 4 bytes of the SHA-256 of `keel1a:` and the rest), so a
mistyped paste is told from a line for another invite.

## How the window is confirmed

0018 confirms a change only from a session that started after it,
arrived over the new configuration, and came from another machine. 0048
adds two sources, for the overlay change keel mesh itself made and no
other ([docs/apply.md](apply.md)):

- **the mesh session of a join**: on the inviter, what its root side
  sees itself, never what the unprivileged listener reports: a
  WireGuard handshake from the new peer's key since it was admitted
  (`wg show <if> latest-handshakes`), which only that key's holder,
  reaching this node over the new tunnel, can complete, and the
  confirmation request signed with the invite's key, which the listener
  does not hold. On the new node, the inviter's signed answer, which
  arrived over the tunnel to the inviter's overlay address;
- **`keel mesh create`**, for a mesh with no peer.

Each knows its change by the marker apply left (the boot and the moment
the interface came up) and refuses any other: a change that is not its
own, or an uplink change, is never confirmed this way. The route check
of apply.md runs first, unchanged, with the client of the operator's SSH
session added for `create` and `join`.

## The listener

The port faces the internet, so what answers on it can change nothing
on the machine. An invite has two processes:

- **the root helper**, `keel-mesh-invite@<id>` running `keel mesh serve
  <id>`, which reads the invite, starts the listener, and is the only
  one that holds the invite's HMAC key, verifies the HMAC, consumes the
  invite, writes the spec and applies it (keel.mesh.admit,
  keel.mesh.bridge);
- **the listener**, `keel-mesh-listen@<id>` running `keel mesh listen`,
  with `DynamicUser=yes`, an empty `CapabilityBoundingSet=` and
  `AmbientCapabilities=`, `NoNewPrivileges`, `PrivateTmp`,
  `PrivateDevices`, `ProtectSystem=strict`, `ProtectHome`, the kernel,
  clock, hostname and cgroup protections, `RestrictAddressFamilies=AF_INET
  AF_INET6 AF_UNIX`, `RestrictNamespaces`, `SystemCallFilter=@system-service`,
  `MemoryMax=64M`, `TasksMax=32` and `LimitNOFILE=64`. It refuses to run
  if it holds any capability. It does TLS 1.3 on the invite's TCP port,
  on every address (IPv6 and IPv4; so a `--port` under 1024 cannot be
  bound), and the checks below.

The listener binds the bridge's unix socket, mode 0600, in its own
RuntimeDirectory, `/run/keel/mesh-listen-<id>`, mode 0700 and its dynamic
user's, so no other user can reach it; it takes one connection, from
root, and removes the socket. The helper connects and reads the peer's
credentials (SO_PEERCRED) before it sends anything: not root, and the
unit's MainPID as systemd names it (`systemctl show -p MainPID`). A
socket held by anything else is skipped, and the helper tries again
until the listener shows (30 seconds). It then sends the listener's
parameters, which hold no key, and the invite's certificate and TLS
key as two memfds (SCM_RIGHTS): anonymous files that never have a name,
so the TLS key is written nowhere. **The invite's HMAC key never leaves
the root side.** The listener forwards each request that passed the
checks it can make without the key, as the bytes it received with the
signature header; the helper verifies the HMAC and checks the rest
again, and answers. The addresses the listener reports are logged and
decide nothing. The helper's `RuntimeMaxSec` is the time
left to the expiry plus the window a join made just before it needs to
be confirmed in (120 seconds, and 60 more); on `SIGTERM` (that limit,
or `systemctl stop`) it stops the listener and cleans up.

A join request is checked in this order, and refused with its reason:

| Check | Refused with |
| --- | --- |
| the path and the method | 404 |
| a body no longer than 16 KiB, of the protocol's shape | 413, 400 |
| the invite id: this listener's, no other | 403 |
| the request's time, within five minutes of this node's clock | 403 |
| its nonce, never seen | 403 `replayed` |
| (root side) all of the above again, and the HMAC with the invite's key, in constant time | 403 `bad HMAC` |
| (root side) the address, the one the invite reserved | 403 |
| (root side) a key this node already knows, its own or a peer's | 409: a join never replaces an entry |
| (root side) no network change waiting in its window here | 409, and the invite stays pending |
| (root side) the invite still pending: consumed under the mesh's lock, once | 410 `already used`, `expired` |

Then the new node is written into this node's spec as a peer (its key,
its endpoint when it sent one, and the reserved address as a `/128` in
`allowed_ips`), applied under the window with `--skip-uplink`, and the
answer goes back signed. If the change does not come up the invite is
spent, the answer is a 500, and the operator runs a new invite. The
confirmation request is then taken, by the root side, only with a
WireGuard handshake from the new node's key since it was admitted
(waited for up to 10 seconds); it confirms this node's window, and the
listener stops.

Against someone scanning or holding the port:

- reading a request, TLS handshake included, has a deadline of 15
  seconds, and each read a timeout of 5; the apply that follows is not
  under that deadline;
- at most 4 connections are read at once, and 2 more are kept for
  connections to this node's overlay address, which only the mesh's
  peers reach, so a join's confirmation is never starved; one source
  address has one connection at a time, so it cannot fill the slots;
- the request line and headers are capped at 8 KiB, the body at 16 KiB;
- a source refused 5 times within a minute is not answered until the
  minute has passed;
- only a request that names this invite and fails its HMAC counts
  towards cancelling it, on the root side, and 5 of those do: someone
  knows the invite and not its key. A scanner's requests cancel
  nothing. The root side's answer then says the invite is done, and the
  listener stops.

When the helper ends, however it ends, the listener is stopped, the
invite's file is removed and its port closed. A used, cancelled or
expired invite's file is not kept.

## Over a poor network

Keel must work over links of 250 ms round trip, with jitter and 2%
loss. The join's TCP connection is given 10 seconds before the fallback
is taken (two lost SYNs still connect), an answer 180, the mesh session
is retried every 2 seconds for the whole window, the request's time may
be five minutes from the inviter's clock, and the listener's deadlines
are per request. The integration test runs on clean links and again on
250 ms ±25 ms with 2% loss on every link (`tc netem`).

## The firewall port

keel touches no firewall it does not own. Where keel-firewall is enabled
(cloud advanced, `firewall.enabled: true`), the derived ruleset in
`inet keel` has a named set, `mesh_invites`, of TCP ports with a
timeout, and one rule that accepts them ([docs/apply.md](apply.md)).
`invite` adds its port to the set for as long as the listener may run,
the time left to its expiry and 180 seconds more (`nft add element inet
keel mesh_invites { 51820 timeout 3780s }`), so the port is open exactly
while the invite is pending and closes by itself even if keel dies, and
the helper's end removes it. Adding an
element is not a ruleset change, so it neither waits on nor disturbs a
network change in its window. Everywhere else keel opens nothing and
`invite` says so: a closed port is what the fallback is for.

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
request is told it was already used. The listener's end, or accept's,
removes the file.

The mesh identity is made once and kept: a file that does not hold one
is an error, never replaced, since every other node of the mesh knows
the first. The node that joins keeps the token's, and one that keeps
another is refused. A mesh built by hand before `keel mesh` existed gets
it from its first invite.

**The spec** is written by `create`, the root helper, `join` and
`accept` through keel's writer for its own state (keel.network.marker's
`write_private`: a temporary file, fsync, a rename), after the whole
document passes `spec validate`. Two things change with it, which an
operator who edits the spec by hand should know: **comments are
dropped** (it is written as YAML from the document keel read), and
**the file's mode becomes 0600**, root's alone. `keel spec set`
(keel#69) will make one writer of this and confconsole's.

## Logs

The listener's lines go to the journal of its unit: the invite id, the
reserved address, the new node's key and endpoint, each refusal with
its reason and the client's address, each line of the confirmation, and
how the invite ended. **Never the secret, the token, an HMAC or the
invite's TLS key.** The token is printed on the terminal of the root who
ran `invite`, and to nothing else. The line it prints feeds the token
to `join -` on standard input, so it is in no process list; the line
itself is in root's shell history on the new node. The unprivileged
listener's lines go to its own unit's journal, under the same rule.

## Exit codes

| Code | When |
| --- | --- |
| 0 | the line, the change or the status was printed; the join or the accept confirmed |
| 2, 3 | the spec cannot be read or is invalid |
| 15 | `create`, `invite`, `join`, `accept`, `serve` on the live system, not as root |
| 16 | `wg` cannot read or make the key, `openssl` cannot make the certificate, the mesh identity is damaged, the invite's listener cannot start or bind, or this node's change did not come up |
| 21 | the change was applied and not confirmed (the other side did not answer within the window, or refused, or the route check did): it reverts by itself |
| 23 | the token, or `accept`'s line, is mistyped, truncated, of a later format, inconsistent, or expired |
| 24 | refused: no overlay to invite into, no key yet, no endpoint, no free address, another invite on the port; a node in another mesh or at another address of it, or a change the spec would refuse; a network change waiting; no route to the inviter, or neither node can reach the other; the inviter refused the join (used, expired, bad HMAC), its certificate is not the pinned one, or its answer is not the answer to the request |

## Tests

At these seams, each written down before its tests:

- the token's `encode()` and `parse()` (`tests/test_mesh_token.py`), the
  allocator (`tests/test_mesh_allocate.py`), the store
  (`tests/test_mesh_invites.py`);
- the protocol's messages and their HMAC, pure
  (`tests/test_mesh_protocol.py`), and the `keel1a:` line
  (`tests/test_mesh_acceptline.py`);
- the HTTP handler as a function, twice: the root side's
  `Admitter.forward(path, signature, body, local, peer)` against a
  scratch root's invite and a node that records
  (`tests/test_mesh_admit.py`: every refusal, one use, replays, known
  keys, the confirmation over the overlay only), and the unprivileged
  listener's `Listener.handle` (`tests/test_mesh_listener.py`: what
  reaches the root side, what cancels the invite, the per source limit);
- the pinned channel and the listener's server, with real TLS on the
  loopback (`tests/test_mesh_channel.py`: the deadline, the slots and
  those kept for the overlay, the size cap, blocked sources);
- the bridge (`tests/test_mesh_bridge.py`): the whole path in one
  process, TLS to the listener, the memfds over the unix socket, the
  Admitter; a peer that is not the listener, one that never connects,
  messages it should not send, a listener with capabilities, and the
  sandbox of its unit;
- the spec writes and apply through `keel.mesh.node.Node`: the flows of
  `join`, `accept`, `serve` and `create` against a real Node on scratch
  roots, apply replaced by one that arms the window's marker, and the
  real `keel.network.confirm` deciding (`tests/test_mesh_joining.py`,
  `tests/test_mesh_inviting.py`, `tests/test_mesh_create_status.py`,
  `tests/test_network_mesh_confirm.py`);
- the CLI through `keel.cli.main` (`tests/test_mesh_cli.py`,
  `tests/test_mesh_cli_live.py`);
- end to end, `tests/test_mesh_netns.py` runs `tests/mesh_netns.py` as
  root in a network namespace (tests/wgtools.py), with two more
  namespaces joined to it by veths: real `wg-quick`, real TLS, the real
  listener, join, accept and confirmation logic. One node joins through
  the listener and one through the fallback, both ping the inviter over
  the overlay with no `keel network confirm` typed, the spent invite is
  refused, the inviter's journal holds no secret, and the listener, a
  process of its own under `setpriv` with every capability dropped,
  reports a CapEff of 0. apply there writes keel's rendered file and
  runs `wg-quick up` in the node's namespace, since a live apply arms
  timers on the host's systemd. It runs on clean links and on poor ones
  (250 ms ±25 ms, 2% loss), and in a Debian trixie LXC container too
  (`mesh / trixie`).
