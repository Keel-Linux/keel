# Copyright (c) 2026 KeelLinux maintainers
"""Exit codes, defined once and documented in README.md

Every caller (the CLI, confconsole, a test, a firstboot hook) reads the
codes from here so that the table never drifts between code and docs.
"""

OK = 0
USAGE = 1
SPEC_UNREADABLE = 2
SPEC_INVALID = 3
SECRET_ERROR = 4
CONF_ERROR = 5
MANIFEST_INVALID = 6
LAYER_MISMATCH = 7
SIGNATURE_UNVERIFIED = 8
NOT_IMPLEMENTED = 9
LAYER_UNAVAILABLE = 10
ASSEMBLE_NEEDS_ROOT = 11
ASSEMBLE_FAILED = 12
INSPECT_INCOMPLETE = 13
DRIFT_FOUND = 14
APPLY_NEEDS_ROOT = 15
APPLY_FAILED = 16
CHANNEL_INVALID = 17
CHANNEL_UNVERIFIED = 18
CHANNEL_EXPIRED = 19
CHANNEL_ROLLBACK = 20
NETWORK_NOT_CONFIRMED = 21
NOTIFY_FAILED = 22
MESH_TOKEN_INVALID = 23
MESH_REFUSED = 24

DESCRIPTIONS = {
    OK: "success, including the no-op cases",
    USAGE: "usage error: unknown command, option or argument",
    SPEC_UNREADABLE: "spec file, or an appliance or overlay manifest,"
    " cannot be read or is not valid YAML",
    SPEC_INVALID: "spec file, or an appliance or overlay manifest, is"
    " valid YAML but fails validation",
    SECRET_ERROR: "a referenced secret is missing or badly protected",
    CONF_ERROR: "the conf file, or the file inspect writes, cannot be"
    " written",
    MANIFEST_INVALID: "a layer manifest cannot be read or fails validation",
    LAYER_MISMATCH: "a layer does not match its manifest",
    SIGNATURE_UNVERIFIED: "a layer hash file could not be verified",
    NOT_IMPLEMENTED: "command is a documented stub, not implemented yet",
    LAYER_UNAVAILABLE: "a layer could not be fetched into the cache, or is"
    " not in it",
    ASSEMBLE_NEEDS_ROOT: "assemble must run as root",
    ASSEMBLE_FAILED: "the rootfs or the template could not be written",
    INSPECT_INCOMPLETE: "inspect wrote a spec, but a required field could"
    " not be inferred; or diff found no drift, but a declared field could"
    " not be observed",
    DRIFT_FOUND: "diff found at least one declared field whose observed"
    " value differs",
    APPLY_NEEDS_ROOT: "apply --system on the live system must run as root",
    APPLY_FAILED: "apply --system could not make a change; the conf was"
    " written and every other change was made",
    CHANNEL_INVALID: "a channel pointer, or the record of the one this"
    " instance follows, cannot be read or fails validation",
    CHANNEL_UNVERIFIED: "a channel pointer is not signed by a key that may"
    " move a channel",
    CHANNEL_EXPIRED: "a channel pointer is past its expiry: the mirror is"
    " stale, broken or holding this instance back",
    CHANNEL_ROLLBACK: "a channel pointer names an earlier revision than the"
    " one this instance is on",
    NETWORK_NOT_CONFIRMED: "keel network confirm refused: nothing waiting"
    " (a change already confirmed is not refused), or not run over the new"
    " configuration",
    NOTIFY_FAILED: "keel notify reached no channel: none declared, or every"
    " one failed",
    MESH_TOKEN_INVALID: "keel mesh join could not use the token: mistyped"
    " or truncated, of a format this keel does not read, or expired",
    MESH_REFUSED: "keel mesh refused: no overlay to invite into, no"
    " endpoint, no free address, or this node is in another mesh",
}
