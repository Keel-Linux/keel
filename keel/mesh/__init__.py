# Copyright (c) 2026 KeelLinux maintainers
"""Joining the WireGuard mesh with one command (handbook decision 0048)

`keel mesh create` makes the mesh on its first node; `keel mesh invite`,
on a node already in it, prints one line, `keel mesh join -
<<< keel1:<token>`, and that line run on the new node joins it.

- keel.mesh.token, the `keel1:` token: what the new node needs from the
  inviter, in one URL safe line with a checksum;
- keel.mesh.allocate, the address the invite reserves for the new node;
- keel.mesh.addrreserve, that address reserved in etcd too, once etcd is
  formed;
- keel.mesh.invites, the pending invites under /var/lib/keel/mesh, which
  hold an HMAC key derived from the token's secret, never the secret;
- keel.mesh.identity, the mesh's random identity;
- keel.mesh.certificate, the self signed certificate of one invite;
- keel.mesh.protocol, the join protocol's messages and their HMAC;
- keel.mesh.acceptline, the `keel1a:` line of the fallback;
- keel.mesh.channel, HTTPS with the invite's certificate, pinned;
- keel.mesh.listener, the unprivileged listener that faces the network;
- keel.mesh.admit, the root side that admits the new node, once;
- keel.mesh.bridge, between the two: a unix socket, the keys as memfds;
- keel.mesh.node, this machine's spec, apply and confirmation: the one
  seam to the rest of keel;
- keel.mesh.join, the change of the new node's spec a token makes;
- keel.mesh.joining, inviting, create, status: the commands' flows;
- keel.mesh.ports, the invite's port in keel's firewall;
- keel.mesh.commands and parser, the CLI.

docs/mesh.md is the reference.
"""

# under the root: state, never configuration and never in the spec
DIR = "var/lib/keel/mesh"
LOCK = f"{DIR}/lock"
DIR_MODE = 0o700
FILE_MODE = 0o600
