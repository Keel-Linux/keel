# Copyright (c) 2026 KeelLinux maintainers
"""The invite's TCP port in keel's firewall, where it has one (0048)

keel touches no firewall it does not own. Where keel-firewall is
enabled (cloud advanced, `firewall.enabled: true`), its derived ruleset
holds a named set of the pending invites' ports, each with a timeout,
and one rule that accepts them (keel.manifest.firewall): an invite adds
its port for the time left to its expiry, so it closes by itself even
if keel dies, and the listener's end removes it. Adding an element is
not a ruleset change, so it neither waits on nor disturbs a network
change in its window. Everywhere else nothing is opened, and the
command says so: a closed port is what the fallback is for.
"""

from collections.abc import Callable

from keel.manifest.firewall import INVITES_SET, TABLE

Runner = Callable[[tuple[str, ...]], str | None]
Reader = Callable[[tuple[str, ...]], str | None]


def element(port: int, seconds: int | None = None) -> str:
    timeout = f" timeout {seconds}s" if seconds else ""
    return f"{{ {port}{timeout} }}"


def open_port(port: int, seconds: int, run: Runner, output: Reader) -> str:
    """Open the port for `seconds` where keel's firewall has the set;
    one line that says what was done"""
    if output(("nft", "list", "set", *TABLE, INVITES_SET)) is None:
        return (f"keel's firewall is not enabled here, so keel opened"
                f" nothing: TCP port {port} must reach this node, or the"
                " new node's join prints a line to run here instead")
    problem = run(("nft", "add", "element", *TABLE, INVITES_SET,
                   element(port, seconds)))
    if problem:
        return (f"TCP port {port} could not be opened in keel's firewall"
                f" ({problem}); the new node's join prints a line to run"
                " here instead")
    return f"TCP port {port} opened in keel's firewall while the invite waits"


def close_port(port: int, run: Runner) -> None:
    """Remove the element; one that timed out or never was is fine"""
    run(("nft", "delete", "element", *TABLE, INVITES_SET, element(port)))
