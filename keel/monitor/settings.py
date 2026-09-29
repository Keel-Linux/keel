# Copyright (c) 2026 KeelLinux maintainers
"""What the monitor section means once its defaults are filled in

The operator writes thresholds, not monit syntax (decision 0021). Every
check the section leaves out gets the default decided there, so
`enabled: true` with a channel is a useful monitor. Network throughput
has none: what is too much depends on the link, so an interface is
watched only when it is declared.

Minutes become monit cycles at the cycle monit already runs at: keel
does not set it, since `set daemon` is global and would reset the
operator's own cycle and start delay. monit holds a condition for at
most 64 cycles, so a duration longer than that at the machine's cycle is
refused by the plan rather than cut short.
"""

# What Debian's monitrc sets, and what is assumed when nothing sets one
DEBIAN_CYCLE = 120
# monit refuses `for N cycles` above this ("must be between 1 and 64").
MAX_CYCLES = 64
# How often a condition that lasts is told again: about once an hour
REMIND_SECONDS = 3600
DEFAULTS: dict[str, dict] = {
    "disk": {"warn": 80, "critical": 90},
    "inodes": {"critical": 90},
    "memory": {"warn": 85, "for_minutes": 5},
    "swap": {"warn": 50, "for_minutes": 5},
    "cpu": {"warn": 90, "for_minutes": 10},
    "load_per_core": {"warn": 2, "for_minutes": 10},
}
NETWORK_KEYS = ("link", "max_mbit", "for_minutes")
# A declared interface without for_minutes is held as long as memory is.
NETWORK_FOR_MINUTES = 5
CHECKS = tuple(DEFAULTS) + ("network",)
CHANNELS = ("email", "telegram", "ntfy", "webhook")
NOTIFY_KEYS = CHANNELS + ("details",)
BITS_PER_BYTE = 8
MEGA = 1_000_000


def effective(monitor: dict) -> dict:
    """Every check with its defaults filled in; network as declared"""
    checks = monitor.get("checks") or {}
    found = {
        name: {**defaults, **(checks.get(name) or {})}
        for name, defaults in DEFAULTS.items()
    }
    found["network"] = {
        str(iface): {"for_minutes": NETWORK_FOR_MINUTES, **(value or {})}
        for iface, value in (checks.get("network") or {}).items()
    }
    return found


def cycles(minutes: int, cycle: int) -> int:
    """How many cycles of `cycle` seconds cover `minutes`, at least one"""
    return max(1, -(-int(minutes) * 60 // cycle))


def reminder(cycle: int) -> int:
    """The cycles between two reminders, at least one"""
    return max(1, round(REMIND_SECONDS / cycle))


def minutes(count: int, cycle: int) -> float:
    """The duration `count` cycles of `cycle` seconds hold a condition"""
    return count * cycle / 60


def too_long(checks: dict, cycle: int) -> list[str]:
    """Every for_minutes that monit could not hold at this cycle"""
    found = [(f"monitor.checks.{name}.for_minutes", check["for_minutes"])
             for name, check in checks.items()
             if name != "network" and "for_minutes" in check]
    found += [(f"monitor.checks.network.{iface}.for_minutes",
               check["for_minutes"])
              for iface, check in checks["network"].items()]
    return [
        f"{key}: {value} minutes is {cycles(value, cycle)} cycles of"
        f" {cycle} s, and monit holds a condition for at most {MAX_CYCLES}"
        for key, value in found if cycles(value, cycle) > MAX_CYCLES
    ]


def bytes_per_second(mbit: float) -> int:
    """monit's network rates are bytes per second; the spec's are Mbit/s"""
    return round(float(mbit) * MEGA / BITS_PER_BYTE)


def mbit(rate: float) -> float:
    return float(rate) * BITS_PER_BYTE / MEGA


def number(value: float) -> str:
    """A threshold as monit and the messages print it: 2, not 2.0

    Never in exponent form (1e-05), which monit's parser does not take.
    """
    value = float(value)
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")
