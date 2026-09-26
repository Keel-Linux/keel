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

DESCRIPTIONS = {
    OK: "success, including the no-op cases",
    USAGE: "usage error: unknown command, option or argument",
    SPEC_UNREADABLE: "spec file cannot be read or is not valid YAML",
    SPEC_INVALID: "spec file is valid YAML but fails validation",
    SECRET_ERROR: "a referenced secret is missing or badly protected",
    CONF_ERROR: "the conf file cannot be written",
    MANIFEST_INVALID: "a layer manifest cannot be read or fails validation",
    LAYER_MISMATCH: "a layer does not match its manifest",
    SIGNATURE_UNVERIFIED: "a layer hash file could not be verified",
    NOT_IMPLEMENTED: "command is a documented stub, not implemented yet",
    LAYER_UNAVAILABLE: "a layer could not be fetched into the cache, or is"
    " not in it",
}
