# Copyright (c) 2026 KeelLinux maintainers
"""etcdctl, as tests/vip_claim_netns.py puts it first on an agent's PATH

Every call goes to the real etcdctl, the next one on PATH, unchanged,
but one: when the node's root (read from `--cacert=ROOT/var/lib/keel/
etcd/...`) holds the file `txn-shim`, the next `txn` takes the mode the
file names, and the file is removed (it fires once; `txn-shim.fired`
says it did):

- `commit-hang`: the real transaction runs, then no answer comes: etcd
  committed it, and keel's client times out (keel#135);
- `hang`: no answer comes and nothing runs: etcd committed nothing.

Usage, from the wrapper the driver writes: etcdctl_shim.py SHIM_DIR ARGS.
"""

import os
import subprocess
import sys
import time

HANG = 60


def real(shim_dir: str) -> str:
    for one in os.environ.get("PATH", "").split(":"):
        if not one or os.path.abspath(one) == os.path.abspath(shim_dir):
            continue
        found = os.path.join(one, "etcdctl")
        if os.access(found, os.X_OK):
            return found
    raise SystemExit("etcdctl-shim: no real etcdctl on PATH")


def root_of(args: list[str]) -> str | None:
    for one in args:
        if one.startswith("--cacert=") and "/var/lib/keel/etcd/" in one:
            return one[len("--cacert="):].split("/var/lib/keel/etcd/")[0]
    return None


def main(argv: list[str]) -> None:
    shim_dir, args = argv[0], argv[1:]
    etcdctl = real(shim_dir)
    root = root_of(args)
    flag = os.path.join(root, "txn-shim") if root else None
    if "txn" in args and flag and os.path.exists(flag):
        with open(flag) as fob:
            mode = fob.read().strip()
        os.remove(flag)
        with open(flag + ".fired", "w") as fob:
            fob.write(f"{mode} {time.time():.3f}\n")
        if mode == "commit-hang":
            subprocess.run([etcdctl] + args, stdin=sys.stdin,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, close_fds=False,
                           check=False)
        time.sleep(HANG)
        sys.exit(1)
    os.execv(etcdctl, [etcdctl] + args)


if __name__ == "__main__":
    main(sys.argv[1:])
