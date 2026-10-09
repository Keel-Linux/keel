# Copyright (c) 2026 KeelLinux maintainers
"""The real wg and wg-quick, for the tests that hand them keel's files

The WireGuard tests used to be mocked at the command boundary, and a
mocked test cannot tell a file wg-quick rejects from one it takes. So
when wireguard-tools is at hand (on PATH, or its directory named by
KEEL_WG_DIR: `apt-get download wireguard-tools` and `dpkg-deb -x` give
one without installing it), the rendered file and the key pair go
through the real tools. In CI they are installed by the workflow, and a
missing tool fails instead of skipping.

wg-quick insists on root. It is run in a network namespace of its own,
so nothing it does reaches the host: `unshare -n` as root, `unshare -rn`
where unprivileged user namespaces are allowed, else `sudo -n unshare -n`.
"""

import os
import shutil
import subprocess
import time
import unittest

TOOLS = ("wg", "wg-quick")


def tool_dir() -> str | None:
    """The directory holding wg and wg-quick, or None"""
    named = os.environ.get("KEEL_WG_DIR")
    if named:
        return named if all(
            os.access(os.path.join(named, one), os.X_OK) for one in TOOLS
        ) else None
    found = [shutil.which(one) for one in TOOLS]
    if not all(found):
        return None
    return os.path.dirname(found[0])


def require(case: unittest.TestCase) -> str:
    """The tool directory, or skip; in CI a missing tool is a failure"""
    found = tool_dir()
    if found is None:
        if os.environ.get("CI"):
            case.fail("wireguard-tools is not installed in CI: the real"
                      " tool tests would not run, see"
                      " .github/workflows/tests.yml")
        case.skipTest("wg and wg-quick not found (set KEEL_WG_DIR)")
    return found


def namespace_child(seconds: int, within: float = 10.0) -> subprocess.Popen:
    """`sleep` in a network namespace of its own, returned once it is in
    that namespace. Popen returns before `unshare -n` made it, and a veth
    moved to the child's PID before then stays in this namespace"""
    own = os.readlink("/proc/self/ns/net")
    child = subprocess.Popen(["unshare", "-n", "sleep", str(seconds)],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + within
    while True:
        try:
            if os.readlink(f"/proc/{child.pid}/ns/net") != own:
                return child
        except OSError:
            pass
        if time.monotonic() >= deadline:
            child.kill()
            raise RuntimeError(f"unshare -n made no namespace within"
                               f" {within:g} s")
        time.sleep(0.01)


def env(tools: str) -> dict[str, str]:
    return {**os.environ, "PATH": f"{tools}:{os.environ.get('PATH', '')}"}


def namespace_prefix() -> list[str] | None:
    """How to run a command as root in a network namespace of its own"""
    candidates = (
        [["unshare", "-n"]] if os.geteuid() == 0 else []
    ) + [["unshare", "-rn"], ["sudo", "-n", "unshare", "-n"]]
    for prefix in candidates:
        try:
            done = subprocess.run(prefix + ["true"], capture_output=True,
                                  check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if done.returncode == 0:
            return prefix
    return None


def in_namespace(case: unittest.TestCase, tools: str, script: str,
                 *args: str) -> subprocess.CompletedProcess:
    """Run a bash script as root in a fresh network namespace"""
    prefix = namespace_prefix()
    if prefix is None:
        if os.environ.get("CI"):
            case.fail("no way to run wg-quick as root in a namespace in CI")
        case.skipTest("neither root, user namespaces nor sudo -n")
    argv = prefix + ["bash", "-c", f'export PATH="$1:$PATH"; shift; {script}',
                     "wgtest", tools, *args]
    return subprocess.run(argv, capture_output=True, text=True, check=False,
                          timeout=120)
