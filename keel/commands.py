# Copyright (c) 2026 KeelLinux maintainers
"""What each CLI subcommand does

Every function here takes the parsed arguments and returns an exit code.
Nothing here prompts, so confconsole can call the same functions.
"""

import os
import sys

from keel import exits, layers, spec
from keel import diff as drift
from keel import inspect as inspection
from keel import system


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def read_spec(
    path: str, check_secret_files: bool = True
) -> tuple[dict | None, int]:
    """Load and validate a spec file

    Returns (document, exit code). The document is None when the caller
    has nothing to do, which includes the successful no-op of an absent
    file, so the caller checks the code first. `check_secret_files` is
    passed to spec.validate(): a command that never reads a secret value
    passes False, so the spec is usable on a machine that does not hold
    the secret files.

    A field under a deprecated name is warned about once, naming the
    current name, and the document every command works on is the
    canonical one (keel.spec.compat), so nothing downstream knows about
    the old names.
    """
    if not os.path.exists(path):
        print(f"{path}: not found, nothing to do", file=sys.stderr)
        return None, exits.OK

    try:
        doc = spec.load(path)
    except spec.SpecError as e:
        error(str(e))
        return None, exits.SPEC_UNREADABLE

    for message in spec.deprecations(doc):
        warn(f"{path}: {message}")
    doc = spec.canonical(doc)

    errors = spec.validate(doc, check_secret_files=check_secret_files)
    if errors:
        for message in errors:
            error(f"{path}: {message}")
        return None, exits.SPEC_INVALID
    return doc, exits.OK


def spec_validate(args) -> int:
    """Check the spec and say whether the secret files were checked too

    --no-secret-files checks the structure only, for an operator who
    validates a spec on a machine that does not hold the secrets.
    """
    check_secret_files = not getattr(args, "no_secret_files", False)
    doc, code = read_spec(args.spec, check_secret_files)
    if doc is None:
        return code
    checked = "checked" if check_secret_files else "not checked"
    print(f"{args.spec}: ok (secret files {checked})")
    return exits.OK


def spec_render(args) -> int:
    """Print the conf that apply would write, with the secrets masked

    Rendering never reads or generates a real secret.
    """
    doc, code = read_spec(args.spec)
    if doc is None:
        return code
    rendered = spec.render_env(doc, spec.masked_secrets(doc))
    print(spec.mask(rendered), end="")
    return exits.OK


def spec_apply(args) -> int:
    """Write the conf; with --system, converge users and locale as well

    The conf phase is unchanged: a populated conf is never clobbered.
    The system phase (docs/apply.md) runs only with --system, refuses the
    live system without root before anything is written, and with
    --dry-run prints its plan and changes nothing at all, and reads no
    secret, so the secret files need not exist for it. A caller that
    builds the Namespace by hand, as confconsole does, gets the conf only.
    """
    with_system = getattr(args, "system", False)
    dry_run = getattr(args, "dry_run", False)
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    doc, code = read_spec(args.spec, check_secret_files=not dry_run)
    if doc is None:
        return code

    if with_system and not dry_run:
        refusal = system.needs_root(root)
        if refusal:
            error(refusal)
            return exits.APPLY_NEEDS_ROOT

    if dry_run:
        print(f"dry run: {args.conf} not written")
    else:
        code = apply_conf(args, doc, with_system)
        if code != exits.OK:
            return code
    if not with_system:
        return exits.OK
    return apply_system(doc, root, dry_run)


def apply_conf(args, doc: dict, with_system: bool) -> int:
    if spec.conf_is_populated(args.conf):
        warn(f"{args.conf} is not empty, ignoring {args.spec} for the conf")
        return exits.OK

    try:
        secrets = spec.resolve_secrets(doc)
    except spec.SpecError as e:
        error(str(e))
        return exits.SECRET_ERROR

    try:
        spec.write_conf(spec.render_env(doc, secrets), args.conf)
    except OSError as e:
        error(f"{args.conf}: {e}")
        return exits.CONF_ERROR

    print(f"{args.spec} applied to {args.conf}")
    for message in spec.check_network(doc) + spec.unsupported(doc, with_system):
        warn(message)
    return exits.OK


def apply_system(doc: dict, root: str, dry_run: bool) -> int:
    """Observe, plan, then carry out or only print; one line per action"""
    state = system.observe(root, doc)
    outcome = system.execute(
        system.plan(doc, state), system.Effects(root), dry_run
    )
    for line in outcome.lines:
        print(line)
    print(outcome.summary())
    return exits.APPLY_FAILED if outcome.failed else exits.OK


def not_implemented(command: str, section: str, summary: str) -> int:
    """A documented stub: say so plainly and fail, never pretend to work"""
    error(
        f"{command}: not implemented yet, see BRIEF.md section {section}"
        f" ({summary})"
    )
    return exits.NOT_IMPLEMENTED


def inspect(args) -> int:
    """Write a spec from the machine under --root, and report every field

    The spec goes to stdout or --output (mode 0600), the report to stderr
    or --report. A required field that could not be inferred makes the
    exit code INSPECT_INCOMPLETE, but the spec is written all the same,
    with placeholders, so the operator edits instead of starting over.
    """
    result = inspection.inspect_root(args.root, args.secrets_dir)
    text = inspection.to_yaml(result)
    report = "".join(f"{line}\n" for line in inspection.report_lines(result))
    try:
        if args.output:
            spec.write_conf(text, args.output)
        else:
            print(text, end="")
        if args.report:
            with open(args.report, "w") as fob:
                fob.write(report)
        else:
            print(report, end="", file=sys.stderr)
    except OSError as e:
        error(f"inspect: {e}")
        return exits.CONF_ERROR
    if not result.complete:
        error(
            "inspect: required fields not inferred: "
            + ", ".join(result.missing_required)
        )
        return exits.INSPECT_INCOMPLETE
    return exits.OK


def diff(args) -> int:
    """Report drift between the spec and the machine under --root

    The declared side is the spec, loaded and validated like every other
    command reads it, except that the secret files are not required to
    exist: diff never compares secrets, and the machine being compared
    may not hold them (a spec fresh from inspect names files nobody has
    created yet). The observed side is what the inspect collector finds.
    One line per field on stdout, or one JSON document with --format
    json, and nothing is written anywhere. Drift decides the exit code
    before unknown fields do (docs/diff.md).
    """
    doc, code = read_spec(args.spec, check_secret_files=False)
    if doc is None:
        return code
    comparison = drift.diff_root(doc, args.root)
    if args.format == "json":
        print(drift.to_json(comparison, args.spec), end="")
    else:
        for line in drift.report_lines(comparison):
            print(line)
    return comparison.code


def verify(args) -> int:
    """Check the installed layers, then say that packages are not checked

    One line per layer on stdout, then a summary line. A layer problem
    decides the exit code; when every layer passes, the code is still
    NOT_IMPLEMENTED because the packages half of the check (brief
    section 5.4) does not exist yet, and verify never claims more than
    it checked.
    """
    code = verify_layers(args)
    if code != exits.OK:
        return code
    return not_implemented(
        "verify packages",
        "5.4",
        "check installed packages against the manifest; the layers above"
        " were checked",
    )


def verify_layers(args) -> int:
    report = layers.verify_layers(args.layers_dir, args.tarballs_dir)
    if not report.results:
        print(
            f"{args.layers_dir}: no layer manifests found", file=sys.stderr
        )
    for result in report.results:
        print(result.line())
    print(report.summary())
    return report.code


def pull(args) -> int:
    """Fetch the layers of `args.layer` that the cache does not have

    One line per layer on stdout, fetched or cached, then a summary with
    the bytes transferred. A failure prints the reason and returns the
    code that names it.
    """
    try:
        report = layers.pull(args.layer, args.source, args.cache_dir)
    except layers.LayerError as e:
        error(str(e))
        return e.code
    for result in report.results:
        print(result.line())
    print(report.summary())
    return exits.OK


def assemble(args) -> int:
    """Extract the chain of `args.layer` into a rootfs; pack it when asked

    Runs as root only. An OSError that the library did not turn into a
    LayerError (tar or zstd missing, a disk full) is reported the same
    way and returns ASSEMBLE_FAILED.
    """
    try:
        report = layers.assemble(
            args.layer, args.cache_dir, args.rootfs, args.template,
            args.sha256,
        )
    except layers.LayerError as e:
        error(str(e))
        return e.code
    except OSError as e:
        error(f"assemble: {e}")
        return exits.ASSEMBLE_FAILED
    for line in report.lines():
        print(line)
    return exits.OK
