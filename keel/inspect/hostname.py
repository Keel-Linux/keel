# Copyright (c) 2026 KeelLinux maintainers
"""The instance section: hostname and fully qualified name"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File


def probe_hostname(
    hostname: File, hosts: File, hostname_f: File
) -> tuple[dict | None, list[Finding]]:
    """Build the instance section from /etc/hostname, /etc/hosts, hostname -f

    The fully qualified name is taken from the /etc/hosts line that names
    the host, then from `hostname -f` when it was run, then from
    /etc/hostname itself when that already holds a dotted name.
    """
    name = _first_word(hostname)
    if not name:
        reason = hostname.problem or "file is empty"
        return None, [
            missing("instance.hostname", f"{hostname.path} {reason}"),
            missing("instance.fqdn", "no hostname to look up"),
        ]
    findings = [inferred("instance.hostname", name, hostname.path)]

    fqdn, source = _fqdn(name, hostname.path, hosts, hostname_f)
    if fqdn is None:
        findings.append(missing("instance.fqdn", source))
        return {"hostname": name}, findings
    findings.append(inferred("instance.fqdn", fqdn, source))
    return {"hostname": name, "fqdn": fqdn}, findings


def _first_word(file: File) -> str | None:
    lines = file.lines()
    return lines[0].split()[0] if lines else None


def _fqdn(
    name: str, hostname_path: str, hosts: File, hostname_f: File
) -> tuple[str | None, str]:
    for line in hosts.lines():
        names = line.split()[1:]
        if any(n == name or n.split(".")[0] == name for n in names):
            for candidate in names:
                if "." in candidate:
                    return candidate, hosts.path

    answer = _first_word(hostname_f)
    if answer and "." in answer:
        return answer, hostname_f.path

    if "." in name:
        return name, f"{hostname_path} holds a dotted name"

    checked = [f"{hosts.path} has no fully qualified name for {name}"]
    if hostname_f.problem:
        checked.append(f"{hostname_f.path} {hostname_f.problem}")
    else:
        checked.append(f"{hostname_f.path} answered {answer!r}")
    return None, "; ".join(checked)
