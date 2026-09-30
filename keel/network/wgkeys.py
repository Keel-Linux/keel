# Copyright (c) 2026 KeelLinux maintainers
"""This node's WireGuard key pair, made and read by `wg` alone

The private key is made on the machine that uses it, at its first
converge, and never in an image: an image that carried one would give
every appliance built from it the same identity on the overlay
(keel-core#8). `wg genkey` writes it straight into a file created 0600
by root, and `wg pubkey` reads that file as its standard input, so the
private key never passes through keel's memory, its output or an
argument vector.
"""

import os
import subprocess

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
