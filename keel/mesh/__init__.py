# Copyright (c) 2026 KeelLinux maintainers
"""Joining the WireGuard mesh with one command (handbook decision 0048)

`keel mesh invite`, on a node already in the mesh, prints one line,
`keel mesh join keel1:<token>`, and that line run on the new node joins
it. What exists so far:

- keel.mesh.token, the `keel1:` token: what the new node needs from the
  inviter, in one URL safe line with a checksum;
- keel.mesh.allocate, the address the invite reserves for the new node;
- keel.mesh.invites, the pending invites under /var/lib/keel/mesh, which
  hold an HMAC key derived from the token's secret, never the secret;
- keel.mesh.identity, the mesh's random identity, which the token
  carries and etcd will take as its cluster token;
- keel.mesh.certificate, the self signed certificate of one invite,
  whose fingerprint the token carries for the new node to pin;
- keel.mesh.join, the change of the new node's spec a token makes;
- keel.mesh.commands, `keel mesh invite` and `keel mesh join --dry-run`.

The listener on the HTTPS port, the join itself, `accept`, `create` and
`remove` come later; the token and the invite file already carry what
they need. docs/mesh.md is the reference.
"""

# under the root: state, never configuration and never in the spec
DIR = "var/lib/keel/mesh"
LOCK = f"{DIR}/lock"
DIR_MODE = 0o700
FILE_MODE = 0o600
