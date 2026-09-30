# Copyright (c) 2026 KeelLinux maintainers
"""What the firewall plan looks at, read once from the root (0041)

keel's ruleset file as it was last written, the digest in the comment of
the `inet keel` table the kernel holds (asked of nft on the live system
only), the ports sshd listens on, which the ruleset must open, and
whether a network change waits for its confirmation (decision 0018).
"""

import re
import subprocess
from dataclasses import dataclass

from keel.inspect.tree import File, Tree
from keel.manifest.firewall import PATH, TABLE, loaded_digest
from keel.network import marker

SSHD_CONFIG = "etc/ssh/sshd_config"
SSHD_DROP_INS = "etc/ssh/sshd_config.d/*.conf"
SSH_DEFAULT = 22
PORT_RE = re.compile(r"^\s*port\s+(\d+)\s*$", re.IGNORECASE)
# ListenAddress host:port, [v6]:port; an address alone keeps Port's
LISTEN_RE = re.compile(r"^\s*listenaddress\s+(?:\[[^]]+\]|[^\s:]+):(\d+)\s*$",
                       re.IGNORECASE)


@dataclass(frozen=True)
class FirewallState:
    file: File
    # the digest of the table the kernel holds; None when there is none,
    # or when nothing was asked (--root)
    loaded: str | None
    ssh_ports: tuple[int, ...]
    ssh_source: str
    pending: bool


def ssh_ports(tree: Tree) -> tuple[tuple[int, ...], str]:
    """The ports sshd listens on, from its configuration; 22 by default"""
    files = [tree.read(SSHD_CONFIG)] + [tree.read(name) for name
                                        in tree.glob(SSHD_DROP_INS)]
    ports = set()
    for file in files:
        for line in file.lines():
            found = PORT_RE.match(line) or LISTEN_RE.match(line)
            if found:
                ports.add(int(found.group(1)))
    return tuple(sorted(ports or {SSH_DEFAULT})), files[0].path


def observe_firewall(tree: Tree, live: bool) -> FirewallState:
    ports, source = ssh_ports(tree)
    return FirewallState(
        file=tree.read(PATH),
        loaded=table_digest() if live else None,
        ssh_ports=ports,
        ssh_source=source,
        pending=tree.exists(marker.PENDING),
    )


def table_digest() -> str | None:
    try:
        out = subprocess.run(["nft", "list", "table", *TABLE],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return loaded_digest(out.stdout) if out.returncode == 0 else None
