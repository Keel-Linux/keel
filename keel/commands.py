# Copyright (c) 2026 KeelLinux maintainers
"""What each CLI subcommand does

Every function here takes the parsed arguments and returns an exit code.
Nothing here prompts, so confconsole can call the same functions.
"""

import os
import sys

from keel import exits, spec


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
    return not_implemented(
        "verify",
        "5.4",
        "check installed layers and packages against the signed manifest",
    )
