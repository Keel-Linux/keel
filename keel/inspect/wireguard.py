# Copyright (c) 2026 KeelLinux maintainers
"""network.overlay.wireguard, read back from /etc/wireguard (decision 0020)

The file wg-quick reads is the configuration, so it is what inspect
reads: the interface is named after it, the address, port, key file and
peers are its lines. The public key is reported beside the spec rather
than in it, since it follows from the private key; it is computed by
`wg pubkey` from the key file (keel.network.wgkeys), and the private key
itself is never read by keel, never printed and never written into the
spec: only the path of its file is.

In a container the kernel module is the host's to load (decision 0018),
so on the live system inspect says when it is missing, rather than
leaving the operator to find out from a converge that fails half way.
"""

from collections.abc import Callable
from dataclasses import dataclass

from keel.inspect.report import Finding, inferred, missing, placeholder
from keel.inspect.tree import File
from keel.network import wireguard

FIELD = "network.overlay.wireguard"
PublicKey = Callable[[str], tuple[str | None, str | None]]


@dataclass(frozen=True)
class Module:
    """Whether the wireguard module is loaded; `loaded` None off the live
    system, where the machine's kernel is not the one being asked"""

    loaded: bool | None
    in_container: bool


def probe_overlay(files: list[File], public_key: PublicKey,
                  module: Module) -> tuple[dict | None, list[Finding]]:
    """The overlay section from the wg-quick files, one interface

    `files` are /etc/wireguard/*.conf, sorted; the default interface's
    file is taken when there are several, and the others are named.
    `public_key` turns a key file path into its public key, or a reason.
    """
    findings = module_findings(module, bool(files))
    readable = [one for one in files if one.readable]
    if not readable:
        return None, findings
    chosen = next((one for one in readable if one.path.endswith(
        f"/{wireguard.DEFAULT_INTERFACE}.conf")), readable[0])
    findings += [missing(FIELD, f"{one.path} not read: the spec describes"
                         " one overlay interface") for one in readable
                 if one is not chosen]
    parsed = wireguard.parse(chosen.text or "")
    iface = chosen.path.rsplit("/", 1)[-1][:-len(".conf")]
    section = {"interface": iface, **parsed.section}
    findings += field_findings(section, chosen.path)
    findings += [missing(FIELD, f"{chosen.path}: {problem}")
                 for problem in parsed.problems]
    findings += key_findings(section, parsed.inline_key, chosen.path,
                             public_key)
    return {"wireguard": section}, findings


def module_findings(module: Module, configured: bool) -> list[Finding]:
    if module.loaded is None or module.loaded:
        return []
    if module.in_container:
        return [inferred(f"{FIELD}.kernel_module", "not loaded",
                         "/sys/module/wireguard is absent; a container"
                         " cannot load it: run `modprobe wireguard` on the"
                         " host")]
    if not configured:
        return []
    return [inferred(f"{FIELD}.kernel_module", "not loaded",
                     "/sys/module/wireguard is absent; wg-quick loads it"
                     " when the interface comes up")]


def field_findings(section: dict, path: str) -> list[Finding]:
    found = [inferred(f"{FIELD}.{name}", section[name], path)
             for name in ("interface", "address", "ipv4_address",
                          "listen_port") if name in section]
    if "address" not in section:
        found.append(missing(f"{FIELD}.address",
                             f"{path} has no IPv6 Address"))
    peers = section.get("peers") or []
    if peers:
        found.append(inferred(f"{FIELD}.peers", ", ".join(
            str(peer.get("public_key", "?")) for peer in peers), path))
    return found


def key_findings(section: dict, inline: bool, path: str,
                 public_key: PublicKey) -> list[Finding]:
    """The key file's path, and the public key it gives; never the key"""
    if inline:
        return [
            placeholder(f"{FIELD}.private_key", "inline", f"{path} holds a"
                        " PrivateKey line, which keel never reads; apply"
                        " moves the key to a file of its own"),
            missing(f"{FIELD}.public_key", "the private key is inline in"
                    f" {path}, which keel does not read"),
        ]
    key = (section.get("private_key") or {}).get("file")
    if not key:
        return [missing(f"{FIELD}.private_key",
                        f"{path} names no private key")]
    found = [inferred(f"{FIELD}.private_key", f"file {key}",
                      f"{path}, PostUp; the key itself is never read")]
    public, problem = public_key(key)
    if public is None:
        return found + [missing(f"{FIELD}.public_key", str(problem))]
    return found + [inferred(f"{FIELD}.public_key", public,
                             f"wg pubkey < {key}")]
