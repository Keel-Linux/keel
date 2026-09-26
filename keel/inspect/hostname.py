# Copyright (c) 2026 KeelLinux maintainers
"""The instance section: hostname and fully qualified name"""

from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

# No upstream hook writes a fully qualified entry, so a machine without one
# is not a machine that lost it: it is a machine where the system phase of
# apply has not run. The reason says which, so the operator reading a diff
# report knows what closes the gap (docs/diff.md, docs/apply.md).
WRITTEN_BY = "the system phase of apply writes it (spec apply --system-only)"


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


def fqdn_in_hosts(name: str, hosts: File) -> str | None:
    """The fully qualified name /etc/hosts gives `name`, or None

    The dotted name on the first line that names the host, either
    outright or as the first label of one of its names, and nothing from
    any line after it: a resolver answers from the first entry that
    carries the name, so a later line does not give the host a name it is
    not resolved by. A file where `127.0.1.1 blog` stands before
    `2001:db8:1::10 blog.example.org blog` gives blog no fully qualified
    name, and `hostname -f` on such a machine answers `blog`.

    `apply --system` asks this same function before writing the entry
    (keel.system.hosts), so what apply writes is what inspect reads, and
    a file in that state is converged rather than called settled.
    """
    for line in hosts.lines():
        names = line.split()[1:]
        if not any(n == name or n.split(".")[0] == name for n in names):
            continue
        for candidate in names:
            if "." in candidate:
                return candidate
        return None
    return None


def _fqdn(
    name: str, hostname_path: str, hosts: File, hostname_f: File
) -> tuple[str | None, str]:
    found = fqdn_in_hosts(name, hosts)
    if found is not None:
        return found, hosts.path

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
    checked.append(WRITTEN_BY)
    return None, "; ".join(checked)
