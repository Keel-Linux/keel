# Copyright (c) 2026 KeelLinux maintainers
"""This node's WireGuard key pair, made and read by `wg` alone

The private key is made on the machine that uses it, at its first
converge, and never in an image: an image that carried one would give
every appliance built from it the same identity on the overlay
(keel-core#8). `wg genkey` writes it straight into a file created 0600
by root, and `wg pubkey` reads that file as its standard input, so the
private key never passes through keel's memory, its output or an
argument vector.

One exception: a wg-quick file written by hand may hold its key in a
PrivateKey line. keel rewrites that file without it, so `adopt` first
moves the key into the key file, the same way (created exclusively,
0600), and the node keeps the identity its peers know. The key is read
from the file and written to the other, never printed or passed on.
"""

import os
import subprocess
import tempfile

from keel.network.wireguard import is_key
from keel.spec.secretstore import secret_file_error

KEY_MODE = 0o600
DIR_MODE = 0o700
NO_TOOLS = ("wg is not installed: the overlay needs the wireguard-tools"
            " package")


def generate(path: str) -> str | None:
    """Make the private key at `path` unless it exists; None on success

    The file is created exclusively, so two runs never overwrite each
    other's key, and removed again when `wg genkey` fails, so a half
    written key is never taken for one.
    """
    if os.path.exists(path):
        return None
    os.makedirs(os.path.dirname(path), mode=DIR_MODE, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEY_MODE)
    except OSError as e:
        return f"cannot create {path}: {e.strerror or e}"
    with os.fdopen(fd, "w") as fob:
        os.fchmod(fob.fileno(), KEY_MODE)
        problem = run_to(("wg", "genkey"), fob)
        if problem is None:
            fob.flush()
            os.fsync(fob.fileno())
    if problem:
        os.remove(path)
    return problem


def inline_key(text: str) -> str | None:
    """The value of the [Interface] PrivateKey line of a wg-quick file"""
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        name, sep, value = line.partition("=")
        if section == "interface" and sep and \
                name.strip().lower() == "privatekey":
            return value.strip()
    return None


def adopt(conf: str, path: str) -> str | None:
    """Move the PrivateKey line of `conf` into `path`; None on success

    A key file that already holds the same key is fine; one that holds
    another is refused and left alone, since either key may be the one
    the peers know. No message carries the key.
    """
    try:
        with open(conf) as fob:
            key = inline_key(fob.read())
    except OSError as e:
        return f"cannot read {conf}: {e.strerror or e}"
    if key is None or not is_key(key):
        return (f"{conf} has no PrivateKey line keel can move (a WireGuard"
                " key is 44 characters of base64)")
    if os.path.lexists(path):
        return same_key(path, key, conf)
    os.makedirs(os.path.dirname(path), mode=DIR_MODE, exist_ok=True)
    try:
        fd, staged = tempfile.mkstemp(dir=os.path.dirname(path),
                                      prefix=".keel-key-")
    except OSError as e:
        return f"cannot create {path}: {e.strerror or e}"
    try:
        return linked(fd, staged, path, key, conf)
    finally:
        os.remove(staged)


def linked(fd: int, staged: str, path: str, key: str, conf: str) -> (
    str | None
):
    """Write the key to `staged` (mkstemp's, 0600), then link it at `path`

    The key file appears whole or not at all: a write that fails (a full
    disk) leaves nothing a later run would take for another key, and a
    link never replaces a file that appeared meanwhile.
    """
    try:
        with os.fdopen(fd, "w") as fob:
            os.fchmod(fob.fileno(), KEY_MODE)
            fob.write(key + "\n")
            fob.flush()
            os.fsync(fob.fileno())
        os.link(staged, path)
    except FileExistsError:
        return same_key(path, key, conf)
    except OSError as e:
        return f"cannot write {path}: {e.strerror or e}"
    return None


def same_key(path: str, key: str, conf: str) -> str | None:
    try:
        with open(path) as fob:
            held = fob.read().strip()
    except OSError as e:
        return f"cannot read {path}: {e.strerror or e}"
    if held == key:
        return None
    return (f"{path} holds another key than the PrivateKey line of {conf};"
            " keel does not choose between them: remove the one this node"
            " should not use, then apply again")


def run_to(argv: tuple[str, ...], fob) -> str | None:
    try:
        out = subprocess.run(list(argv), stdout=fob,
                             stderr=subprocess.PIPE, text=True, check=False)
    except OSError:
        return NO_TOOLS
    if out.returncode != 0:
        return f"{argv[0]} exited {out.returncode}: {out.stderr.strip()}"
    return None


def public(path: str) -> tuple[str | None, str | None]:
    """(the public key of the private key at `path`, or why there is none)

    The key file is refused unless it is root's and 0600, as every secret
    file of the spec is (keel.spec.secretstore).
    """
    problem = secret_file_error(path)
    if problem:
        return None, problem
    try:
        key = open(path, "rb")
    except OSError as e:
        return None, f"cannot read {path}: {e.strerror}"
    with key:
        try:
            out = subprocess.run(["wg", "pubkey"], stdin=key,
                                 capture_output=True, text=True, check=False)
        except OSError:
            return None, NO_TOOLS
    if out.returncode != 0:
        return None, (f"wg pubkey refused {path}: it does not hold a"
                      f" WireGuard private key ({out.stderr.strip()})")
    return out.stdout.strip(), None
