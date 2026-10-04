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

**What exists in this version:** `create` (and `create --adopt`),
`invite` and its listener, `join`, the fallback `accept`, `status`, and
a full mesh before etcd: the announcement of a new node to the
inviter's other peers, `keel mesh sync`, and the members' channel they
use ("Members learn of each other"), only with admission evidence
("Admission evidence and trust"), and `keel mesh remove` before etcd,
whose tombstone makes the other members drop the node too; and etcd,
the mesh's registry, on the cloud advanced members: its CA, its
formation at the third of them, learners promoted from the fourth,
`keel mesh etcd form` for a mesh that never saw a third join, `keel
mesh etcd tend`, the etcd member removed under the amendment's rule,
and its section of `keel mesh status` ("etcd"). Not yet: members
learning of each other through etcd's registry (they still do through
the members' channel), the VIP controller of decision 0049, rotating
an intermediate CA or the root, the rotation of a node's signing key, `keel mesh invites` and `invite
--cancel`, and the boot unit that removes invites
which expired while the machine was down. confconsole's "Invite a node"
and "Join a mesh" screens call these commands, in confconsole.

## keel mesh create

```
keel mesh create [--network-window SECONDS]
keel mesh create --adopt
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

The confirmation's lines go to standard error, after `confirming the
new overlay…`; standard output holds the summary alone. apply's own
lines, among them its "reverts in 120 s unless `keel network
confirm`", are held, and shown only when the change does not come up
or is not confirmed: `create` confirms it itself.

`--adopt` is for a mesh built by hand before `keel mesh` existed, whose
nodes hold no identity yet ("The mesh's identity"): on one node of it,
it keeps that node's identity, else takes the one its peers hold, else
makes one, and prints it; it is refused when the peers hold another
identity than this node's, or several. It also makes the peers the
spec lists this node's trust roots ("Admission evidence and trust"):
the operator's act is what vouches for them. Each other node then runs
`keel mesh sync --adopt` with this node's overlay address. Nothing is
applied.

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
   else the static addresses `network.interfaces` declares, or else, on
   a DHCP or SLAAC host, the ones found on the uplink ("The endpoint"),
   IPv6 first, saying which;
3. makes a key pair and a self signed certificate for this invite only
   (`openssl req -x509`, P-256), whose SHA-256 fingerprint the token
   carries for the new node to pin;
4. checks the mesh's identity with its peers over the overlay: refused
   when they hold another one than this node's, it takes theirs when
   it has none, and makes one only for a node with no peer ("The mesh's
   identity");
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

### The endpoint

A host whose uplink DHCP or SLAAC configures declares no static
address, so `invite` and `join` find their endpoint in what `ip`
shows (keel.mesh.endpoint):

- on the uplink, the interfaces the default routes leave through (any
  interface without a default route), never a WireGuard one (`wg*`);
- a global IPv6 address that is not unique local (`fc00::/7`), not
  `deprecated`, and not a SLAAC privacy address (`temporary`), a static
  one before a SLAAC or DHCPv6 one (`dynamic`): the order of keel-core's
  console banner (`keel_banner_pick_ipv6`, a shell function of the
  image, so the rule is kept here in Python and the two agree);
- beside it, or alone, a public IPv4 address.

Each address chosen is said on standard error (`endpoint
2804:…:a035, found on eth0 (--endpoint overrides it)`). A privacy
address changes within a day and an RFC 1918 or carrier NAT address
(`100.64.0.0/10`) is reached from its own network only, so neither is
ever taken. A host that holds nothing better has no endpoint found:
`invite` is refused, says why (`2001:db8::7 is a SLAAC privacy address,
the only global IPv6 one eth0 holds…`) and asks for `--endpoint`, a
stable address or a port forward's; `join` sends no endpoint, as a node
behind NAT does, and says why.

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
   `network.interfaces` declares, else the one found on the uplink ("The
   endpoint"); IPv6 first; none when it has none;
5. sends the join request to the inviter's HTTPS port, at its IPv6
   endpoint and then its IPv4 one, comparing the SHA-256 of the
   certificate the inviter presents with the token's fingerprint before
   a byte of the request is sent;
6. with the signed answer, which must carry its own nonce, the invite
   id, the inviter's key and address, writes its own spec (its address,
   the inviter as a peer, and the other members the answer names, as
   `keel mesh sync` takes them) and applies it under the window, with
   `--skip-uplink`;
7. says `confirming over the overlay…` and opens the mesh session to
   the inviter's overlay address, retrying every two seconds while the
   tunnel comes up: the inviter confirms its window on receiving it, and
   this node confirms its own on the inviter's signed answer. No `keel
   network confirm` is typed on either node, and apply's "reverts in
   120 s unless `keel network confirm`" is shown only when the
   confirmation fails;
8. the inviter then announces this node to its other peers ("Members
   learn of each other").

At the end, on standard output:

```
joined the mesh: this node is fd2a:9c41:7e03::3/64 on wg0
peer: nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E= at fd2a:9c41:7e03::1, through [2001:db8:1::10]:51820
the mesh is up with 2 nodes; etcd starts when a third node joins, because 2 etcd members cannot lose one and keep a majority
```

The confirmation's lines and every refusal go to standard error. When
the inviter knows other peers, the last line says how many nodes the
mesh has, that this node has them all as peers, and that the inviter
announces it to them:

```
the mesh has 3 nodes: this node has them all as peers, and the inviter announces this node to the 1 other(s) over the overlay (one offline now learns of it at its next keel mesh sync)
etcd: this node forms with 2 other member(s)
```

The last line is etcd's, when the inviter gave this node an etcd CA
("etcd"): `forms with` at the third cloud advanced member, `joins as a
learner with` from the fourth, or how many ready members are known
before the third.

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
The line carries no answer, so no member: once confirmed, `join` pulls
them from the inviter (`learning the other members from the
inviter…`, a `keel mesh sync --from` the inviter).

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

## Members learn of each other

Until etcd exists, members learn about each other through the inviter
(0048, "The third node and after"), so that the mesh is a full one and
not a star around the node that invited:

1. the join's answer names the other members the inviter knows, each
   with its admission evidence, and the new node takes those it can
   verify as peers in its first change;
2. the inviter, once the join is confirmed (by `serve` or `accept`),
   announces the new node to each of its other peers over the overlay,
   at once; each adds it and applies, as below;
3. a member offline then, and a node that joined through the fallback,
   pull the members with `keel mesh sync`, which
   `keel-mesh-sync.timer` runs two minutes after boot and every 15
   minutes.

### Admission evidence and trust

0048 lets only an admitted join add a peer. The overlay authenticates
who speaks (below); it does not make what a member says about other
nodes true, and a member that could push any peer to the others could
add a node no member admitted, whose own handshake would then confirm
the change. So every member a roster names is taken only with evidence
of its admission:

- **a signing key per node.** Each node has an Ed25519 key pair, made on
  the machine with `openssl genpkey` the first time it joins, invites,
  adopts or serves its members (`/var/lib/keel/mesh/node.key`, 0600,
  never printed). Its public half travels in the join request, in the
  `keel1a:` line, in the join's and the confirmation's answers, and in
  each roster;
- **evidence.** An inviter that admits a node signs, with its key, the
  mesh's identity, the invite id, the new node's WireGuard and signing
  keys, its overlay address and endpoint, and the time. It keeps that
  evidence, sends it to the new node in the answer, which the invite's
  HMAC authenticates, and joins it to the node's entry in every roster
  it gives;
- **trust.** A node trusts its own key; the inviter it joined through,
  whose signing key it learned from that authenticated answer; and the
  trust roots its operator named (below). It takes a roster's entry only
  when its evidence names an invite, the entry's key and address, is for
  this mesh, and was signed by a key it trusts; the node it takes is
  then trusted in turn, so evidence chains from member to member (A
  admitted B, B admitted C: a node that trusts A takes both). An entry
  without valid evidence is left out, whoever sends it. Evidence always
  names an invite: no member vouches for a node it did not admit;
- **trust roots.** A mesh built by hand before `keel mesh` has no
  evidence. `keel mesh create --adopt` on one node and `keel mesh sync
  --adopt` on the others, explicit acts of the operator, make the peers
  each node's spec lists its trust roots. A root's signing key is
  learned from the root itself, in a roster this node fetched from the
  root's own overlay address (`keel mesh sync`), which WireGuard
  authenticates as that root's; never from an announcement, whose
  source only the listener reports. A root vouches for nobody: a node
  is another's root only if that node's operator listed it;
- **tombstones.** `keel mesh remove` records a removal, signed with the
  remover's key. A node takes a tombstone only when its signer may
  remove that node: **the member that admitted it** (as the evidence
  the node keeps names), **a trust root**, or **the node itself**,
  leaving. Any other member, trusted or not, removes a node from its own
  spec only. A node that takes a tombstone drops the peer from its spec,
  every peer a pull or the pending announcements remove in one change,
  under one 0018 window (below), and never takes the key again;
- **how many, and for how long.** Tombstones are kept for good: a
  removed key never comes back, and a tombstone that expired could let
  an old roster bring it back to a member that was offline. A node keeps
  at most 1024 of them, at most 64 signed by one key (so one member
  cannot fill the store), and each roster carries all it keeps. A node
  whose store is full refuses `keel mesh remove`, and takes no further
  tombstone.

The state is `/var/lib/keel/mesh/trust.json`: each trusted member's
signing key, whether it is a root, and its evidence; and the
tombstones. A damaged file is refused, never guessed at: `keel mesh sync
--adopt` makes the peers roots again.

**What this changes in 0048's threat model.** Before, a member could
make every other member add any peer it named, as long as it spoke over
the overlay. Now a peer is added only on evidence that a member the node
already trusts admitted it, and that evidence names the invite and the
member that signed it, so every added peer can be traced to the member
that admitted it.

**Any trusted member can vouch for a new node**, as 0048 says any
member can invite: the evidence it signs is enough for every member
that trusts it, directly or through the chain. So a compromised member
(its root, or its signing key) can admit any node it likes into the
whole mesh, signed in its own name, and every member will add that node
as a peer. It can also remove the nodes it admitted, and any node if it
is a root. What it can no longer do is add a node under another
member's name, add one to a member that does not trust it, remove a
node it did not admit (unless it is a root), or bring back a key whose
removal was taken. The way out of a compromised member is to remove it
(by its admitter or a root): its tombstone makes it trusted no more,
and evidence it signed afterwards is left out; what it admitted before
stays, and each such node is removed the same way. A handbook PR asks
that 0048 be amended to say so.

**A signing key is not rotated yet.** A node keeps the key it made; a
new key signed by the old one is follow-up work, recorded in the same
handbook PR. A node whose key may be compromised is removed and joins
again with a new invite, which makes it a new key pair.

### The members' channel

As an invite is (keel#75), the channel is two processes:

- **the root helper**, `keel mesh members` in
  `keel-mesh-members.service` (started by `keel-mesh-members.path` once
  the node holds a mesh identity), which alone holds the spec, the trust
  store and the signing key. It starts the listener as the transient
  unit `keel-mesh-members-listen`, with `DynamicUser=yes`, no
  capability and the sandbox of the invite's listener (below, "The
  listener"), connects to the unix socket the listener binds in its
  RuntimeDirectory (`/run/keel/mesh-members`, 0700, the socket 0600),
  checks with `SO_PEERCRED` that the other end is the unit's MainPID and
  not root, and sends it the overlay's interface, address and port,
  which hold no key;
- **the listener**, `keel mesh members-listen`, which refuses to run
  with any capability, listens on TCP 51821 on this node's overlay
  address, applies the limits below, and forwards what passed to the
  root side, one JSON message per line; the root side treats each as
  untrusted.

The listener's socket is bound to the overlay's interface
(`SO_BINDTODEVICE`), as is every client's: a request arrives, and an
answer comes back, only through WireGuard. WireGuard accepts a packet
on that interface only when it was decrypted with the key of the peer
whose `allowed_ips` hold its source address, so the address a request
comes from names the member that sent it, and the answer to one sent to
a member's address can only come from that member: 0048's "the overlay
authenticates the announcement: it comes from a peer's address, which
only that peer's key can use". That authenticates who speaks; what it
vouches for needs evidence (above). There is no TLS (WireGuard
encrypts).

| Request | Body | Answer |
| --- | --- | --- |
| `GET /v1/members` | none | 200, this node's roster |
| `POST /v1/announce` | the sender's roster, the new node in it | 202, queued and applied after the answer |
| `POST /v1/etcd` | a signed etcd message ("etcd", "The members' channel for etcd") | 200, answered by the root side at once |

A roster is the node's mesh identity (hex, or null), its WireGuard and
signing keys, its overlay address, every peer its spec declares
(`public_key`, `endpoint` or null, `address`, and the evidence it keeps
for it, or null), at most 256, and all the tombstones it keeps (at most
1024). The
root side refuses (403, logged) a request from an address of no peer's
`allowed_ips`, and an announcement whose roster names another key than
the sender's.

Against a member, or anything on the overlay, that sends too much:

- at most 4 connections are read at once, and 2 from one source;
- reading a request has a deadline of 15 seconds, and each read a
  timeout of 5;
- the request line and headers are capped at 8 KiB, the body at 512 KiB;
- a source refused 5 times within a minute is not answered until the
  minute has passed;
- announcements wait in a queue that keeps the latest one per sender
  and at most 64 senders (a 65th is refused with 503: its member's next
  sync brings it); one worker applies everything waiting in one change,
  under one window, not one window per announcement, once 10 seconds
  passed with no new one: so the answer has reached its sender before
  the overlay goes down and up (a connection bound to the old interface
  would not survive it), and announcements close together share the
  window.

When the overlay goes down and up, as each apply of it does, the
interface comes back as another one and the socket is bound again.
keel's firewall, where it is enabled, accepts TCP 51821 on the overlay's
interface alone (docs/apply.md).

### What a member takes, and how it confirms

From the rosters, the members whose evidence it verifies (above) and
that it does not know: never its own key or a key it has, never an
address off its overlay prefix, its own address, or one inside a peer's
`allowed_ips`; nothing it declares is replaced. Each becomes a peer with
the endpoint its evidence names, routed its address as a `/128`, in this
node's own spec (0013), all in one change applied with `apply
--system-only --skip-uplink` under 0018's window. Then it says
`confirming over the overlay…`, sends each new member a packet every
two seconds, which makes WireGuard start a handshake, and confirms its
window on the first handshake from a new member's key since the change
(`wg show <if> latest-handshakes`), which only that member, reaching
this node over the new configuration, can complete; the route check of
apply.md runs first, as for every overlay change. A change that no new
member answers within the window reverts by itself, the spec is put
back as it was (so it says what the machine runs, and the members are
new again to the next sync), and those members are not tried again for
an hour (`unreached.json`), so a node that is off does not cost the
mesh an overlay change at every timer. One sync runs at a time
(`sync.lock`); a sync that finds a network change waiting in its window
leaves the members to the next one.

## keel mesh sync

```
keel mesh sync [--from ADDRESS]... [--network-window SECONDS]
keel mesh sync --adopt ADDRESS
```

Root. Asks the roster of every peer (or of the `--from` ones, overlay
addresses of peers), at once, and adds the members they know, as
above. A peer that does not answer is said and skipped; one that
answers as another key or address is left out. A node in no mesh, or
with no peer, has nothing to sync.

```
member 9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE= added at fd2a:9c41:7e03::7, through [2001:db8:3::30]:51820
confirming over the overlay…
confirmed from a WireGuard handshake from 9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE= (14:02:11 UTC), a member its peers named
```

`--adopt ADDRESS` repairs a split identity (below): it takes the
identity of the member at that overlay address in place of this
node's, then syncs. It is refused while an invite of this node is
pending, since its token carries the old identity.

## The mesh's identity

Every node of a mesh holds the same identity (`/var/lib/keel/mesh/
identity`), which each token carries and etcd will take as its cluster
token. `create` makes it, `join` keeps the token's, and nothing else
sets it but the operator's `--adopt`:

- a node with no identity takes none from a roster or an announcement:
  its sync is refused and names `--adopt`;
- a member of another identity gives nothing; the node says which
  identities differ and how to repair it;
- `invite` on a node with peers checks their identities first: another
  identity than its own refuses the invite, naming `keel mesh sync
  --adopt`; with no identity of its own it refuses, naming `keel mesh
  create --adopt`, rather than make a second identity for a mesh. Peers
  that do not answer are warned about and decide nothing.

**A mesh built by hand**, or one whose nodes ran keel 0.17 (which kept
no evidence): `keel mesh create --adopt` on one of its nodes (web-1,
say), then, on each other node, `keel mesh sync --adopt <web-1's
overlay address>`. Each act makes the node's spec peers its trust
roots, whose signing keys are bound as each root's members' channel
answers that node's sync. A root vouches for nobody, so a peer that a
node's spec lacks and that no member admitted with an invite is added
by hand, as the mesh was built: write it into that node's spec, then
run `keel mesh sync --adopt` there again, which makes it a root too.
Nodes invited from then on carry evidence and spread by themselves.

**A split** is what keel 0.17 could leave: an invite on a node of a
hand-built mesh that held no identity made one of its own, while the
others held another. On the odd node (web-2 in the test that found it,
holding `cfc81bf2…` while web-1 and web-3 hold `9fe71b35…`):

```
keel mesh sync --adopt <web-1's overlay address>
```

takes web-1's identity, says `this node now holds the mesh identity
9fe71b35… of <address> (was cfc81bf2…), and trusts the peers its spec
lists as roots`, and syncs. web-3 joined web-1 with keel 0.17, which
signed no evidence, so the full repair is: `keel mesh create --adopt`
on web-1; on web-2, web-3 written into its spec as a peer (its key, its
endpoint, its overlay address as a /128), then `keel mesh sync --adopt
<web-1>`; on web-3, web-2 written into its spec likewise, then `keel
mesh sync --adopt <web-1>`. `keel mesh status` shows each node's
identity.

## etcd

etcd is the mesh's registry (decision 0025), control plane only. It
runs on the members whose spec says `installation.mode: cloud_advanced`
and whose appliance carries the `etcd` overlay (decision 0048, third
round, point 3; `spec validate` refuses `overlays.etcd: enabled` in any
other mode), and forms at the third of them: two etcd members have no
fault tolerance.

### The CA and the certificates

etcd uses its own TLS, peer and client, not WireGuard alone, so a
process on a member that holds no certificate signed in the mesh cannot
read or write the registry (0048, second round, point 3). All P-256,
made with openssl on the machine, never in an image (keel.mesh.etcdpki):

- **the root CA** is made by the first node: `keel mesh create` on a
  cloud advanced node, or `keel mesh etcd form` on a mesh that has none.
  Its key stays on that node;
- **an intermediate CA per member** (third round, point 1): its key is
  made on the member, its request travels in the join request, and the
  inviter signs it with its own intermediate (the first node with the
  intermediate its root signed). The join's answer, under the invite's
  HMAC, carries it with the chain above it and the root. The member
  checks it certifies its own key, chains to the root, and that the root
  is the one it holds, if any;
- **leaves**, issued by each member with its own intermediate: its
  member certificate (server and client, its overlay address and ::1 as
  addresses, a year) and keel's client certificate (root's alone). Every
  certificate can be traced to the member whose intermediate signed it.

A leaf is renewed with a third of its life left, by `keel mesh etcd
tend` (`keel-mesh-etcd.timer`); etcd reads its certificate files at each
handshake, so nothing restarts. An intermediate lasts ten years and the
root twenty; rotating either is not in this version: a member whose
intermediate may be compromised is removed and joins again.

### Birth at the third member

The inviter's token says `forms` when it and exactly one other member
are ready (cloud advanced, an intermediate held). When it admits a third
ready node, it signs the node's intermediate and writes a cluster of the
three, `new`, the mesh's identity as its token, the members named after
their overlay addresses (`keel-fd2a-9c41-7e03--3`); the answer carries
it. Once the join is confirmed, the new node and the inviter each write
`overlays.etcd: enabled` into their own spec and apply, which renders
etcd's configuration from the state and starts it ([docs/apply.md](
apply.md), "etcd's configuration"); the inviter sends the cluster to the
third member over the members' channel, which does the same. A join that
reverts leaves etcd alone on both sides.

### The fourth node and after

The token says `running`. Before it answers, the inviter adds the new
node as a **learner** (`member add --learner` for its peer URL), which
does not count towards the quorum, so a join that never finishes cannot
lower the cluster's fault tolerance; the answer says `existing` with the
member list. The new node starts as a learner; the inviter's helper
promotes it once etcd accepts (a learner in sync), for two minutes, and
`keel mesh etcd tend` on every member goes on after. A learner that
never started within an hour is a join that never came, and tend
removes it.

### keel mesh etcd form

```
keel mesh etcd form [--dry-run]
```

Root, on any cloud advanced member, for a mesh that never sees a third
join: one that already had three nodes (built with keel 0.18, or by
hand and adopted), or whose third member joined by the fallback, whose
line carries no request. It is made safe on such a mesh, which has no
CA yet:

1. it asks every peer over the members' channel (`probe`, which changes
   nothing on them): whether it can run etcd, which root it holds,
   whether it is in a cluster. It refuses while a network change waits,
   when members hold two roots, when a cluster exists and this node is
   not in it, when another member holds the CA and this node does not,
   or when this node cannot run etcd. A member that does not answer is
   left out and said;
2. with `--dry-run` it prints what it would do, and stops:

   ```
   would make the mesh's root CA on this node
   would enroll fd2a:9c41:7e03::2
   would enroll fd2a:9c41:7e03::3
   would form a cluster of 3: this node and fd2a:9c41:7e03::2, fd2a:9c41:7e03::3
   dry run: nothing was changed on any member
   ```

3. it makes the root on this node when no member holds one, and enrolls
   every ready member that holds no intermediate (`enroll`, its request,
   signed here). Any enrollment that fails stops it before anything is
   started anywhere;
4. at three ready members or more it sends each the cluster (`cluster`)
   and starts its own; with fewer, the members keep their intermediates
   and etcd forms at the third.

On a member of a formed cluster it brings in what the cluster lacks: a
ready member that is not in etcd is added as a learner and sent the
cluster, and a member of the first cluster that never started is sent it
again. So a run that stopped part way is run again, and the inviter of
a fallback join runs it by itself once the join is confirmed.

### keel mesh etcd tend

```
keel mesh etcd tend
```

Root; what `keel-mesh-etcd.timer` runs every five minutes, on a member
of a cluster: each learner etcd says is in sync is promoted, a learner
that never started within an hour is removed, and this member's leaves
are renewed with a third of their life left.

### The members' channel for etcd

`POST /v1/etcd` carries one message: `kind` (`probe`, `enroll` or
`cluster`), `mesh_id`, `sender` (its WireGuard key), `time` and `body`,
signed with the sender's Ed25519 key over `keel mesh etcd 1\n` and the
message's canonical JSON. WireGuard says who speaks; a message that acts
needs the member's own signature too (0048's amendment): the root side
takes it only when it names the key of the peer it came from, is no more
than five minutes from this node's clock, is for this node's mesh, and
is signed by the signing key its trust store holds for that member. A
`cluster` message never replaces an intermediate this node holds, never
brings another root, and names this node.

### Timeouts, two members, a partition

A heartbeat of 300 ms and an election timeout of 5000 ms, for the
design case of decision 0050, 250 ms ±25 ms with 2% loss. etcd's tuning
guide sets the heartbeat interval "around the round-trip time between
members" and the election timeout "at least 10 times the round-trip
time". Peer traffic is a TCP stream, so a lost segment holds it for one
retransmission timeout (200 ms at least, plus the round trip), and
losses back to back double it; 0050's bench, at 3 s, still re-elected
under loss. 5 s is about 17 heartbeats and 20 round trips; a dead leader
is seen in 5 to 10 s, which beside DNS's one to five minutes (0020)
costs nothing. Pre-vote stays on (etcd 3.5's default).

Two members are never formed by a join; they are left by a removal or
a failure, and `keel mesh status` and `remove` say that a majority of
two is two. A member cut off from three cannot win a pre-vote, so it
raises no term and the leader stays; it serves nothing linearizable
and catches up on heal. A leader cut off steps down after an election
timeout, and the majority elects another.

## keel mesh remove

```
keel mesh remove KEY|ADDRESS [--network-window SECONDS]
```

Root. "Before etcd, the command removes the peer on the member it ran on
and sends the same announcement as a join, so the others drop it too"
(0048):

1. it records a tombstone for the peer of that WireGuard key or overlay
   address, signed with this node's key;
2. it removes the peer from this node's spec and applies the change
   under 0018's window, confirmed as a sync's is: by a WireGuard
   handshake from a peer it keeps since the change, or, with no peer
   left, by the route check alone, as `keel mesh create` confirms a mesh
   with no peer; not confirmed, the spec is put back and the tombstone
   kept, and the next sync drops the peer again;
3. it sends its roster, the tombstone in it, to each peer it keeps.

Each member takes the tombstone if this node may remove that peer (it
admitted it, it is a root, or it is the peer itself), and drops the peer
through one window of its own; one offline then does at its next sync.

With etcd, the node's etcd member is removed too (`member remove`),
only when this node may remove it from the whole mesh (0048, third
round, point 4): this node admitted it, by the evidence it keeps, or the
node is one of this node's trust roots, which on a mesh built by hand
and adopted makes this node its root as well. Otherwise it says the
etcd member stays and the removal is local only: the node's admitter or
a root removes it from etcd. With two voters left it says so: two etcd
members have no fault tolerance.

## keel mesh status

```
keel mesh status
```

This node's overlay, the mesh's identity, its public key, each peer of the spec with its
`allowed_ips`, its endpoint (as WireGuard last saw it) and its last
handshake, and the pending invites: id, reserved address, port, expiry,
and whether it was used and waits for its confirmation. `wg show` is
asked for `public-key`, `endpoints` and `latest-handshakes` only, never
`dump` or `private-key`, and no secret is printed. Off the live system
(`--root`) no handshake is read.

Then etcd's section: not on this node (not cloud advanced); not formed,
with how many of the three ready members are known; or each member of
the cluster (its name, overlay address, voter or learner, healthy or
why not), the leader they report (`members disagree` when they do not),
and a warning with two voters. Off the live system etcd is not asked.

## The protocol

Two requests go to the inviter's HTTPS port, each a JSON body POSTed
with `X-Keel-Mesh-Signature`: the hex HMAC-SHA256, keyed with the
invite's HMAC key (derived from the token's secret, which never crosses
the wire), of `keel mesh 1\n`, the method, `\n`, the path, `\n`, and
the body.

| Request | Fields | Over |
| --- | --- | --- |
| `POST /v1/join` | `invite_id`, `public_key`, `sign_key` (the new node's Ed25519 key), `endpoint` (`[address]:port`, or null), `address` (the reserved one, with its length), `nonce` (16 random bytes, hex), `time` (seconds since the epoch), `etcd_csr` (the request for its etcd intermediate CA, PEM, sent only by a node that can run etcd, else null) | the uplink |
| `POST /v1/confirm` | `invite_id`, `public_key`, `nonce`, `time` | the overlay |

| Answer (200) | Fields |
| --- | --- |
| to a join | `invite_id`, `nonce` (the request's), `public_key` and `address` (the inviter's), `sign_key` (the inviter's signing key), `admission` (the evidence of this admission, signed with it), `peers` (the other members the inviter knows: `public_key`, `endpoint` or null, `address`, and `admission`, the evidence it keeps, or null), `etcd` (`none`, `forms` or `running`), `window` (the seconds the inviter's change waits), `etcd_grant` (the new node's intermediate CA, its chain and the root, or null), `etcd_cluster` (the cluster it starts, `new` or `existing`, or null), `etcd_ready` (the members ready for etcd: key to address) |
| to a confirmation | `invite_id`, `nonce`, `confirmed` (whether the inviter kept its change), `detail`, `sign_key` (the inviter's: what the fallback's node learns it by) |

The evidence (`admission`) is `mesh_id` (hex), `invite_id` (empty for a
trust root's), `public_key`, `sign_key`, `address`, `endpoint` or null,
`time`, `by` (the signer's signing key) and `signature` (Ed25519, in
base64, over `keel mesh admission 1\n` and those fields, but the
signature, one per line). A tombstone is `mesh_id`, `public_key`,
`time`, `by` and `signature`, over `keel mesh removal 1\n` and those
fields.

An answer is signed the same way, with the method `ANSWER` and the
request's path, so the new node knows it came from the node that made
the token as well as from the pinned certificate. A refusal is a JSON
`{"error": reason}`, unsigned: it gives nothing to act on.

The fallback's `keel1a:` line carries the join request's fields in
binary, base64url without padding like the token, about 200 characters:
flags (1 byte: an IPv6 or an IPv4 endpoint follows, at most one), the
new node's key (32) and signing key (32), the endpoint and its UDP port (16 or 4, and 2),
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
250 ms ±25 ms with 2% loss on every link (`tc netem`). The members' channel gives a connection 10 seconds and an
answer 30, a member's handshake is waited for the whole window with a
packet sent every 2 seconds, and the announcement and the sync ask
every member at once rather than one after another. etcd's timeouts are
in "etcd"; `tests/test_etcd_netns.py` forms a cluster of three on these
links, watches its leader, and cuts a member off.

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
| `node.key` | this node's Ed25519 signing key, PEM, never printed |
| `trust.json` | the members this node trusts (signing key, root or not, admission evidence), and the tombstones |
| `unreached.json` | the members a sync added that never answered, and when: each is left out for an hour |
| `sync.lock` | held while a sync or an announcement adds members |

etcd's state is beside it, under `/var/lib/keel/etcd`, root's, 0700,
files 0600: the root CA's key on the first node alone (`root.key`), the
root (`root.crt`), this member's intermediate (`ca.key`, `ca.crt`) and
the chain above it (`chain.pem`), its leaves (`member.key`,
`member.crt`, `client.key`, `client.crt`), the cluster
(`cluster.json`), the members ready for etcd (`ready.json`) and when
each unstarted learner was first seen (`learners.json`). Never in the
spec, never in a backup set.

The invite file holds an HMAC key derived from the secret, never the
secret, so it cannot be turned back into the token. An invite is
consumed once, under the lock: it is marked consumed, and a second
request is told it was already used. The listener's end, or accept's,
removes the file.

The mesh identity is made once and kept: a file that does not hold one
is an error, never replaced by an invite, since every other node of the
mesh knows the first. The node that joins keeps the token's, and one
that keeps another is refused. A mesh built by hand before `keel mesh`
existed gets it from `keel mesh create --adopt` on one node, and `keel
mesh sync --adopt` replaces it on a node that holds another than its
members' ("The mesh's identity").

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
| 15 | `create`, `invite`, `join`, `accept`, `serve`, `sync`, `members`, `remove`, `etcd form`, `etcd tend` on the live system, not as root |
| 16 | `wg` cannot read or make the key, `openssl` cannot make the certificate, the mesh identity is damaged, the invite's listener cannot start or bind, or this node's change did not come up; for `etcd form` and `etcd tend`, etcd's state cannot be read or etcd does not answer |
| 21 | the change was applied and not confirmed (the other side did not answer within the window, or refused, or the route check did; for `sync`, no new member completed a handshake): it reverts by itself |
| 23 | the token, or `accept`'s line, is mistyped, truncated, of a later format, inconsistent, or expired |
| 24 | refused: no overlay to invite into, no key yet, no endpoint, no free address, another invite on the port; a node in another mesh or at another address of it, or a change the spec would refuse; a network change waiting; an invite whose peers hold another mesh identity, or none while this node has none; members of another identity, an address that is not a peer's, or an identity repair while an invite is pending; no route to the inviter, or neither node can reach the other; the inviter refused the join (used, expired, bad HMAC), its certificate is not the pinned one, or its answer is not the answer to the request; `etcd form` on a node that cannot run etcd or holds no identity, while a network change waits, with members holding two roots, a cluster this node is not in, the CA on another member, an enrollment that failed (nothing started), or a member that did not take the cluster (run it again) |

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
- the endpoint found on the uplink (`tests/test_mesh_endpoint.py`), the
  roster and the peers taken from it (`tests/test_mesh_members.py`), the
  signing key and the evidence with the real openssl
  (`tests/test_mesh_signing.py`, `tests/test_mesh_trust.py`: chains,
  forgeries, keys not trusted, roots, tombstones), the listener's front
  and limits with real sockets on the loopback
  (`tests/test_mesh_memberlink.py`), the root helper and the listener in
  one process over their unix socket (`tests/test_mesh_memberd.py`), and
  sync, the announcement, the identity's adoption and repair, and
  remove against a real Node (`tests/test_mesh_sync.py`,
  `tests/test_mesh_adopt.py`, `tests/test_mesh_remove.py`);
- the CLI through `keel.cli.main` (`tests/test_mesh_cli.py`,
  `tests/test_mesh_cli_live.py`);
- etcd: the CA, the intermediates and the leaves with the real openssl
  (`tests/test_mesh_etcdpki.py`, `tests/test_mesh_etcdstate.py`), the
  rendered configuration (`tests/test_mesh_etcdconf.py`), the client
  against a fake gateway over real TLS (`tests/test_mesh_etcdclient.py`),
  the messages (`tests/test_mesh_etcdmsg.py`), the flows of a join, tend,
  leave and status with members in one process and a recording etcd
  (`tests/test_mesh_etcd.py`), `keel mesh etcd form` on a mesh adopted
  with no CA and the members' answers (`tests/test_mesh_etcd_form.py`),
  where etcd meets the rest (`tests/test_mesh_etcd_wiring.py`), and apply's
  step (`tests/test_system_etcd.py`);
- etcd end to end, `tests/test_etcd_netns.py` runs `tests/etcd_netns.py`
  as root in a network namespace that routes for three others: the real
  wg-quick and etcd 3.5, keel's CA (one intermediate signed by a member
  that is not the first), leaves and rendered configuration, on links of
  250 ms ±25 ms with 2% loss. It forms, keeps its leader and term, a
  follower cut off keeps the others their quorum and writes and comes
  back without raising the term, and a learner is added and removed with
  keel's client. In CI, `etcd / trixie` runs 60 s and 45 s;
  `ETCD_SOAK=full` runs 5 minutes and 2;
- end to end, `tests/test_mesh_netns.py` runs `tests/mesh_netns.py` as
  root in a network namespace (tests/wgtools.py), with two more
  namespaces joined to it by veths: real `wg-quick`, real TLS, the real
  listener, join, accept and confirmation logic. One node joins through
  the listener and one through the fallback, both ping the inviter over
  the overlay with no `keel network confirm` typed; the inviter
  announces the second to the first, which adds it, and the second
  pulls the first from the inviter (`keel mesh sync`), so the two are
  each other's confirmed peers and ping each other over the overlay
  (routed between their namespaces through the inviter's, as the
  internet would): a full mesh, on evidence the inviter signed, the
  members' channels each a root helper and a listener without
  capabilities; the spent invite is
  refused, the inviter's journal holds no secret, and the listener, a
  process of its own under `setpriv` with every capability dropped,
  reports a CapEff of 0. apply there writes keel's rendered file and
  runs `wg-quick up` in the node's namespace, since a live apply arms
  timers on the host's systemd. It runs on clean links and on poor ones
  (250 ms ±25 ms, 2% loss), and in a Debian trixie LXC container too
  (`mesh / trixie`).
