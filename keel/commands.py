# Copyright (c) 2026 KeelLinux maintainers
"""What each CLI subcommand does

Every function here takes the parsed arguments and returns an exit code.
Nothing here prompts, so confconsole can call the same functions.
"""

import os
import sys

from keel import exits, layers, spec


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def read_spec(path: str) -> tuple[dict | None, int]:
    """Load and validate a spec file

    Returns (document, exit code). The document is None when the caller
    has nothing to do, which includes the successful no-op of an absent
    file, so the caller checks the code first.
    """
    if not os.path.exists(path):
        print(f"{path}: not found, nothing to do", file=sys.stderr)
        return None, exits.OK

    try:
        doc = spec.load(path)
    except spec.SpecError as e:
        error(str(e))
        return None, exits.SPEC_UNREADABLE

    errors = spec.validate(doc)
    if errors:
        for message in errors:
            error(f"{path}: {message}")
        return None, exits.SPEC_INVALID
    return doc, exits.OK


def spec_validate(args) -> int:
    doc, code = read_spec(args.spec)
    if doc is None:
        return code
    print(f"{args.spec}: ok")
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
    doc, code = read_spec(args.spec)
    if doc is None:
        return code

    if spec.conf_is_populated(args.conf):
        warn(f"{args.conf} is not empty, ignoring {args.spec}")
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
    for message in spec.check_network(doc) + spec.unsupported(doc):
        warn(message)
    return exits.OK


def not_implemented(command: str, section: str, summary: str) -> int:
    """A documented stub: say so plainly and fail, never pretend to work"""
    error(
        f"{command}: not implemented yet, see BRIEF.md section {section}"
        f" ({summary})"
    )
    return exits.NOT_IMPLEMENTED


def inspect(args) -> int:
    return not_implemented(
        "inspect",
        "5.2",
        "write a spec from a running machine, reporting what it could"
        " not infer",
    )


def diff(args) -> int:
    return not_implemented(
        "diff", "5.2", "report drift between the declared and running state"
    )


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
