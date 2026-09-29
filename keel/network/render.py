# Copyright (c) 2026 KeelLinux maintainers
"""The interfaces file for a spec, from inithooks' lib/ipconfig.sh

The first boot hook 01ipconfig renders /etc/network/interfaces with the
functions of lib/ipconfig.sh, from the IP_* and IP6_* variables the conf
phase exports (keel.spec.render.network_env). A day two converge that
rendered the file with code of its own would drift from the hook one
option at a time, so it runs the same functions, in the same order, with
the same variables. The library only reads its arguments and prints.

keel does not depend on inithooks (firstboot.d/10keel-system says why),
so the library is looked for under the root, and its absence is a reason
the network is not converged rather than an error.
"""

import os
import subprocess
from dataclasses import dataclass

LIBRARY = "usr/lib/inithooks/lib/ipconfig.sh"

# The rendering half of firstboot.d/01ipconfig, word for word where it
# can be. The values arrive as positional arguments, never inside the
# script text, so nothing a spec holds is ever parsed as shell.
SCRIPT = r"""
source "$1"
IP_IFACE=$2 HOST_NAME=$3 IP_CONFIG=$4 IP6_CONFIG=$5
IP_ADDRESS=$6 IP_NETMASK=$7 IP_GW=$8 IP_DNS1=$9 IP_DNS2=${10}
IP6_ADDRESS=${11} IP6_GW=${12} IP6_DNS1=${13} IP6_DNS2=${14}
fatal() { echo "$*" >&2; exit 1; }
IP_CONFIG=${IP_CONFIG:-dhcp}
ipconfig_valid_config "$IP_CONFIG" \
    || fatal "invalid IP_CONFIG '$IP_CONFIG'"
[[ -z "$IP6_CONFIG" ]] || ipconfig_valid_config "$IP6_CONFIG" \
    || fatal "invalid IP6_CONFIG '$IP6_CONFIG'"
if [[ "$IP6_CONFIG" == "static" ]]; then
    error=$(ipconfig_check_static6 "$IP6_ADDRESS" "$IP6_GW" "$IP6_DNS1" \
        "$IP6_DNS2") || fatal "$error"
fi
ipconfig_render_head "$IP_IFACE" "$IP_CONFIG" "$HOST_NAME"
if [[ "$IP_CONFIG" == "static" ]]; then
    error=$(ipconfig_check_static "$IP_ADDRESS" "$IP_NETMASK") || fatal "$error"
    ipconfig_render_static "$IP_ADDRESS" "$IP_NETMASK" "$IP_GW" "$IP_DNS1" \
        "$IP_DNS2"
fi
ipconfig_render_inet6 "$IP_IFACE" "$HOST_NAME" "$IP6_CONFIG"
if [[ "$IP6_CONFIG" == "static" ]]; then
    ipconfig_render_static6 "$IP6_ADDRESS" "$IP6_GW" "$IP6_DNS1" "$IP6_DNS2"
fi
"""
VARIABLES = (
    "IP_CONFIG", "IP6_CONFIG", "IP_ADDRESS", "IP_NETMASK", "IP_GW",
    "IP_DNS1", "IP_DNS2", "IP6_ADDRESS", "IP6_GW", "IP6_DNS1", "IP6_DNS2",
)


@dataclass(frozen=True)
class Rendered:
    """The file, or why there is none"""

    text: str | None = None
    problem: str | None = None


def render(library: str, iface: str, hostname: str,
           env: dict[str, str]) -> Rendered:
    """Run the library's functions for one interface and these variables"""
    if not os.path.isfile(library):
        return Rendered(problem=f"{library} not found: inithooks, whose"
                        " 01ipconfig writes this file, is not installed")
    argv = ["bash", "-c", SCRIPT, "ipconfig", library, iface, hostname]
    argv += [env.get(name, "") for name in VARIABLES]
    try:
        out = subprocess.run(argv, capture_output=True, text=True,
                             check=False)
    except OSError as e:
        return Rendered(problem=f"cannot run bash: {e.strerror}")
    if out.returncode != 0:
        detail = out.stderr.strip() or f"exited {out.returncode}"
        return Rendered(problem=f"{library}: {detail}")
    return Rendered(text=out.stdout)
