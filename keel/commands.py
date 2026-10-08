# Copyright (c) 2026 KeelLinux maintainers
"""What each CLI subcommand does

Every function here takes the parsed arguments and returns an exit code.
Nothing here prompts, so confconsole can call the same functions.
"""

import dataclasses
import os
import sys

from keel import exits, layers, manifest, spec
from keel import diff as drift
from keel import inspect as inspection
from keel import system
from keel.monitor import channelfile
from keel.monitor import notify as notifier
from keel.network import confirm as netconfirm
from keel.manifest.facts import gather as gather_facts
from keel.network import live, session, switch, wgkeys, wireguard
from keel.spec import overlayrecord
from keel.spec.validate_appliance import default_warnings, with_defaults
from keel.spec.validate_appliance import is_name as is_manifest_name
from keel.system.ovstate import overlay_of


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def read_spec(
    path: str, check_secret_files: bool = True,
    root: str = inspection.ROOT_DEFAULT,
) -> tuple[dict | None, int]:
    """Load and validate a spec file

    Returns (document, exit code). The document is None when the caller
    has nothing to do, which includes the successful no-op of an absent
    file, so the caller checks the code first. `check_secret_files` is
    passed to spec.validate(): a command that never reads a secret value
    passes False, so the spec is usable on a machine that does not hold
    the secret files.

    A spec that names an appliance is held against the manifests
    installed under `root` (decision 0041, rules 25 to 27), the root the
    command works on: what apply converges or diff compares is what those
    manifests say.

    A field under a deprecated name is warned about once, naming the
    current name, and the document every command works on is the
    canonical one (keel.spec.compat), so nothing downstream knows about
    the old names.

    An overlay the chain gained since the spec was last applied is warned
    about, with the default it takes; the document returned is the spec
    as written, and apply and diff fill the defaults in themselves
    (keel.spec.validate_appliance.with_defaults).
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

    facts = manifest_facts(doc, root)
    errors = spec.validate(doc, check_secret_files=check_secret_files,
                           facts=facts)
    if errors:
        for message in errors:
            error(f"{path}: {message}")
        return None, exits.SPEC_INVALID
    _, defaulted = with_defaults(doc, facts)
    for message in default_warnings(doc, facts, defaulted):
        warn(f"{path}: {message}")
    return doc, exits.OK


def manifest_facts(doc: dict, root: str):
    """What the manifests of the spec's appliance declare, or None

    None when the spec names no appliance, or a name of the wrong shape,
    which the structure check reports on its own.
    """
    appliance = doc.get("appliance")
    name = appliance.get("name") if isinstance(appliance, dict) else None
    if not is_manifest_name(name):
        return None
    return gather_facts(root, name)


def spec_validate(args) -> int:
    """Check the spec and say whether the secret files were checked too

    --no-secret-files checks the structure only, for an operator who
    validates a spec on a machine that does not hold the secrets.
    """
    check_secret_files = not getattr(args, "no_secret_files", False)
    doc, code = read_spec(args.spec, check_secret_files,
                          getattr(args, "root", inspection.ROOT_DEFAULT))
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
    """Write the conf; with --system, converge the system state as well

    The conf phase is unchanged: a populated conf is never clobbered.
    The system phase (docs/apply.md) runs with --system or --system-only,
    refuses the live system without root before anything is written, and
    with --dry-run prints its plan and changes nothing at all.

    --system-only runs the system phase and nothing else, for a boot that
    has already run the conf phase: the conf is neither read nor written
    and no secret is resolved, so a `generate: true` password the earlier
    hooks already applied is never regenerated behind their back. The
    secret files therefore need not exist, as with --dry-run.

    A caller that builds the Namespace by hand, as confconsole does, gets
    the conf only.
    """
    system_only = getattr(args, "system_only", False)
    with_system = system_only or getattr(args, "system", False)
    dry_run = getattr(args, "dry_run", False)
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    no_secrets = dry_run or system_only
    doc, code = read_spec(args.spec, not no_secrets, root)
    if doc is None:
        return code

    if with_system and not dry_run:
        refusal = system.needs_root(root, phase_label(system_only))
        if refusal:
            error(refusal)
            return exits.APPLY_NEEDS_ROOT

    if system_only:
        print(f"{phase_label(True)}: {args.conf} not read or written")
    elif dry_run:
        print(f"dry run: {args.conf} not written")
    else:
        code = apply_conf(args, doc, with_system)
        if code != exits.OK:
            return code
    if not with_system:
        return exits.OK
    return apply_system(
        doc, root, dry_run, phase_label(system_only),
        getattr(args, "destroy_local_database", False),
        getattr(args, "defer_certificate", False),
        getattr(args, "network_window", system.DEFAULT_WINDOW),
        getattr(args, "skip_network", False),
        getattr(args, "skip_uplink", False),
        spec_path=args.spec,
    )


def phase_label(system_only: bool) -> str:
    """How the run names itself in its own output: the flag that asked"""
    return "apply --system-only" if system_only else "apply --system"


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


def apply_system(
    doc: dict, root: str, dry_run: bool, label: str = "apply --system",
    confirmed: bool = False, defer_certificate: bool = False,
    network_window: int = system.DEFAULT_WINDOW, skip_network: bool = False,
    skip_uplink: bool = False, spec_path: str | None = None,
) -> int:
    """Observe, plan, then carry out or only print; one line per action

    A spec that declares none of the fields this phase converges is a
    no-op that says so, so a first boot hook reading the log can tell an
    empty plan from a run that did nothing because it failed.

    `confirmed` is --destroy-local-database, and it reaches exactly one
    decision: whether becoming a replica may drop the databases this
    server holds. Nothing else in keel passes it, so a first boot cannot.

    A run that is not a dry run may start the database server it
    converges before asking it anything (keel.system.dbready).

    An overlay the chain gained since the spec was last applied is
    converged to its manifest default; a run that did not fail then
    records the overlays the spec itself declared (keel.spec.overlayrecord).
    """
    facts = manifest_facts(doc, root)
    declared = doc
    doc, _ = with_defaults(doc, facts)
    state = system.observe(root, doc, start=not dry_run, spec=spec_path)
    plan = system.plan(doc, state, confirmed, defer_certificate,
                       network_window, skip_network, skip_uplink, spec_path)
    if not plan.steps:
        print(f"{label}: nothing declared that this phase converges")
        return exits.OK
    outcome = system.execute(plan, system.Effects(root), dry_run, label)
    for line in outcome.lines:
        print(line)
    print(outcome.summary())
    if outcome.failed:
        return exits.APPLY_FAILED
    if not dry_run:
        record_overlays(declared, facts, root)
    return exits.OK


def record_overlays(doc: dict, facts, root: str) -> None:
    """What the spec declared of the chain, for the next validation"""
    if facts is None or facts.problems:
        return
    overlays = doc.get("overlays")
    names = [name for name in (overlays if isinstance(overlays, dict)
                               else {}) if name in facts.overlays]
    try:
        overlayrecord.write(root, facts.appliance, names)
    except OSError as e:
        warn(f"/{overlayrecord.RECORD} not written: {e.strerror or e}; an"
             " overlay left out of the spec is not refused until it is")


def network_confirm(args) -> int:
    """Keep a pending network change; only over the new configuration

    Decision 0018: the proof that the machine is reachable on the network
    it was just given is a session that could only have been opened on
    it, and a shell that survived the change is not one.
    """
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    refusal = system.needs_root(root, "network confirm")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    origin = session.origin("/proc", os.getpid(), live.sockets)
    confirmed, lines = netconfirm.confirm(root, origin, live.probes(),
                                          live.run)
    for line in lines:
        if confirmed:
            print(line)
        else:
            error(line)
    return exits.OK if confirmed else exits.NETWORK_NOT_CONFIRMED


def network_revert(args) -> int:
    """Put back the interfaces file a pending change replaced

    What the revert timer runs, and the boot unit with --boot; by hand it
    is the way to give up on a change without waiting for the window.
    """
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    refusal = system.needs_root(root, "network revert")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    worked, line = switch.revert(root, live.run, getattr(args, "boot", False))
    if worked:
        print(line)
    else:
        error(line)
    return exits.OK if worked else exits.APPLY_FAILED


def network_wireguard_key(args) -> int:
    """Print this node's WireGuard public key, making the key pair first

    The key file is the one network.overlay.wireguard names, or the
    default for its interface; without a spec, or without an overlay in
    it, wg0's. A missing key is made here as apply would make it, on the
    live system only (keel-core#8), so an operator can hand the public key
    to the other nodes before declaring anything. Only the public key is
    printed, on standard output, alone, for a caller to read.
    """
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    overlay: dict = {}
    if os.path.exists(args.spec):
        doc, code = read_spec(args.spec, False, root)
        if doc is None:
            return code
        overlay = overlay_of(doc) or {}
    key = wireguard.key_path(overlay)
    path = os.path.join(os.path.abspath(root), key.lstrip("/"))
    if not os.path.exists(path):
        code = make_key(root, key, path)
        if code != exits.OK:
            return code
    public, problem = wgkeys.public(path)
    if public is None:
        error(str(problem))
        return exits.APPLY_FAILED
    print(public)
    return exits.OK


def make_key(root: str, key: str, path: str) -> int:
    if os.path.abspath(root) != inspection.ROOT_DEFAULT:
        error(f"{key} is not made under --root: a private key is made on"
              " the machine that uses it, never in an image (keel-core#8)")
        return exits.APPLY_FAILED
    refusal = system.needs_root(root, "network wireguard key")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    problem = wgkeys.generate(path)
    if problem:
        error(problem)
        return exits.APPLY_FAILED
    print(f"generated {key}, mode 0600", file=sys.stderr)
    return exits.OK


def network_wireguard_suggest(args) -> int:
    """Print a fresh unique local address (RFC 4193) for a first node

    Random, so two sets formed apart do not collide when joined later;
    the other nodes take ::2, ::3 on the same /64.
    """
    print(wireguard.suggest_address(
        os.urandom(wireguard.GLOBAL_ID_BYTES)))
    return exits.OK


def notify(args) -> int:
    """Tell the operator about one monit alert, on every declared channel

    What keel.conf's exec lines run (decision 0021). It reads no spec:
    the channels come from the settings apply wrote as root
    (keel.monitor.channelfile), refused unless root owns them and nobody
    else can write them. A token that cannot be read fails its own
    channel and not the others. When no channel takes the message, it is
    logged to syslog at user.crit and mailed to root, and the exit code
    is NOTIFY_FAILED, which is all monit could do anything with.
    """
    event = notifier.event_from(
        args.level, args.check, args.name or args.path or args.iface,
        args.threshold, dict(os.environ), args.direction, args.unit,
    )
    try:
        settings, reason = channelfile.load(args.settings), ""
    except spec.SpecError as e:
        settings, reason = {}, str(e)
    message = notifier.compose(
        event, str(settings.get("host") or notifier.hostname()),
        str(settings.get("address") or ""), settings.get("details") is True,
        notifier.run_probe,
    )
    deliveries = notifier.send(settings, message, args.level)
    for delivery in deliveries:
        if delivery.problem is None:
            print(delivery.line())
        else:
            error(delivery.line())
    if any(delivery.problem is None for delivery in deliveries):
        return exits.OK
    reason = reason or ("every channel failed" if deliveries
                        else f"{args.settings} declares no channel")
    took = notifier.last_resort(message, reason)
    if took:
        error(f"notify: {reason}; told {' and '.join(took)} instead")
    else:
        error(f"notify: {reason}; syslog and root's mailbox failed too")
    return exits.NOTIFY_FAILED


def database_promote(args) -> int:
    """Make this replica a primary; never something apply decides

    Its own command because it is its own decision, and the one keel
    makes the operator type. Replication here has no automatic failover:
    whether the old primary is gone is knowledge this machine does not
    have, and two writable servers on one dataset is what promoting the
    wrong node produces.
    """
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    dry_run = getattr(args, "dry_run", False)
    doc, code = read_spec(args.spec, False, root)
    if doc is None:
        return code
    if not dry_run:
        refusal = system.needs_root(root, "database promote")
        if refusal:
            error(refusal)
            return exits.APPLY_NEEDS_ROOT
    code = promote_vip(args, doc, root, dry_run)
    if code != exits.OK:
        return code
    state = system.observe(root, doc, start=not dry_run, spec=args.spec)
    plan = system.Plan(tuple(system.plan_promote(doc, state.database,
                                                 args.spec)))
    outcome = system.execute(
        plan, system.Effects(root), dry_run, "database promote"
    )
    for line in outcome.lines:
        print(line)
    print(outcome.summary())
    return exits.APPLY_FAILED if outcome.failed else exits.OK


def database_follow(args) -> int:
    """The server made to follow the pair's VIP (keel.system.dbfollow)"""
    from keel.system import dbfollow
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    refusal = system.needs_root(root, "database follow")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    found = dbfollow.Followed(lambda line: print(
        f"database.server.role: {line}"))
    dbfollow.follow(os.path.abspath(root), args.spec,
                    getattr(args, "destroy_local_database", False), found)
    return exits.APPLY_FAILED if found.problem else exits.OK


def database_watch(args) -> int:
    from keel.system import dbwatch
    root = getattr(args, "root", inspection.ROOT_DEFAULT)
    refusal = system.needs_root(root, "database watch")
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    return dbwatch.main(args)


def database_status(args) -> int:
    from keel.system import dbstatus
    return dbstatus.main(args)


def promote_vip(args, doc: dict, root: str, dry_run: bool) -> int:
    """The pair's VIP first, when the spec declares one (decision 0049,
    third round): the old primary releases it before this node's
    database takes writes, so writes never reach two primaries; a
    database left read only by a promote that failed after it is
    reachable at the VIP and refuses them until the promote is run
    again"""
    from keel.mesh import vipcli, vippromote
    appliance = doc.get("appliance")
    if not isinstance(appliance, dict) or not appliance.get("vip"):
        return exits.OK
    if dry_run:
        print(f"would move the VIP {appliance['vip']} to this node first"
              " (keel vip promote)")
        return exits.OK
    return vippromote.promote(vipcli.here_of(args),
                              getattr(args, "old_primary_gone", False),
                              print)


def manifest_validate(args) -> int:
    """Check one manifest, the manifests of a name, or every installed one

    Every error at once, with the exit codes of spec validate (decision
    0041, docs/manifest.md). An appliance is resolved along its chain as
    well, since most of what can go wrong between manifests shows there.
    """
    return manifest_report(manifest.validate_target(
        args.root, args.target, args.kind))


def manifest_show(args) -> int:
    """Print a manifest as its file says it, or resolved along its chain"""
    return manifest_report(manifest.show(
        args.root, args.name, args.resolved, args.kind))


def manifest_report(outcome: manifest.Outcome) -> int:
    print(outcome.out, end="")
    for note in outcome.notes:
        print(note, file=sys.stderr)
    for message in outcome.errors:
        error(message)
    return outcome.code


def not_implemented(command: str, section: str, summary: str) -> int:
    """A documented stub: say so plainly and fail, never pretend to work"""
    error(
        f"{command}: not implemented yet, see BRIEF.md section {section}"
        f" ({summary})"
    )
    return exits.NOT_IMPLEMENTED


def check_channel(args, result):
    """Ask the mirror what its channel now holds; adds one report line

    Returns the inspection to report, the exit code and the message to
    print when the pointer was refused. An expired or unverifiable
    pointer is an error here exactly as it is in `keel pull`: the whole
    point of signing the pointer is that "nothing new" and "you are
    being held back" are different answers.
    """
    state = result.channel
    if state is None:
        return (
            add_finding(
                result,
                inspection.inferred(
                    inspection.AVAILABLE_FIELD, inspection.NO_CHANNEL,
                    args.root,
                ),
            ),
            exits.OK,
            None,
        )
    try:
        found = layers.fetch_channel_at(
            state.source, state.channel, args.channel_keyring,
            signers(args),
        )
    except layers.LayerError as e:
        return result, e.code, str(e)
    line = inspection.available(state, found)
    return add_finding(result, line), exits.OK, None


def add_finding(result, finding):
    return dataclasses.replace(result, findings=result.findings + (finding,))


def inspect(args) -> int:
    """Write a spec from the machine under --root, and report every field

    The spec goes to stdout or --output (mode 0600), the report to stderr
    or --report. A required field that could not be inferred makes the
    exit code INSPECT_INCOMPLETE, but the spec is written all the same,
    with placeholders, so the operator edits instead of starting over.

    --check-channel adds the one question that costs a fetch: what the
    channel this instance follows now holds. Its refusals win over
    INSPECT_INCOMPLETE, because a mirror that cannot be believed is a
    worse answer than a spec field nobody could infer.
    """
    result = inspection.inspect_root(args.root, args.secrets_dir)
    channel_code, refusal = exits.OK, None
    if getattr(args, "check_channel", False):
        result, channel_code, refusal = check_channel(args, result)
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
    if refusal is not None:
        error(refusal)
        return channel_code
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
    doc, code = read_spec(args.spec, False, args.root)
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


def signers(args) -> tuple[str, ...]:
    """The fingerprints that may move a channel, from flags or the env

    One reader, because there are two call sites and a mutation run showed
    that dropping either of them left every test passing.
    """
    named = getattr(args, "channel_signers", None)
    if named is None:
        named = os.environ.get(layers.SIGNER_ENV, "").split()
    return tuple(named)


def resolution(args) -> layers.Resolution:
    """The layout keel pull was told to resolve through

    A bad combination of options raises ValueError here, before anything
    is fetched, so the CLI turns it into a usage error rather than the
    mirror answering 404 for a path that was never going to exist.
    """
    return layers.Resolution(
        channel=getattr(args, "channel", None),
        release=getattr(args, "release", None),
        rev=getattr(args, "rev", None),
        keyring=getattr(args, "channel_keyring", None),
        signers=signers(args),
        state=getattr(args, "channel_state", None),
        allow_rollback=getattr(args, "allow_rollback", False),
    )


def pull(args) -> int:
    """Fetch the layers of `args.layer` that the cache does not have

    One line per layer on stdout, fetched or cached, then a summary with
    the bytes transferred. When a channel or a release revision was
    named, a line above them says which one was resolved and, for a
    channel, when its pointer was signed and when it expires. A failure
    prints the reason and returns the code that names it.
    """
    try:
        report = layers.pull(
            args.layer, args.source, args.cache_dir, resolution(args)
        )
    except layers.LayerError as e:
        error(str(e))
        return e.code
    print(report.resolution_line())
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
