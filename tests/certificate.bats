#!/usr/bin/env bats
# certificate/certificate-after-fence (keel#320): the certificate of
# tls.acme when the init fence stops for good
#
# systemctl and keel are replaced by scripts on PATH that record their
# arguments; the description paths are redirected into a temporary tree.

bats_require_minimum_version 1.5.0

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../certificate/certificate-after-fence"
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/bin" "$TMP/etc/keel"
    export PATH="$TMP/bin:$PATH"
    PRIMARY="$TMP/etc/keel/instance.yaml"
    LEGACY="$TMP/etc/inithooks.yaml"
    export KEEL_SPEC_PATHS="$PRIMARY:$LEGACY"
    # after keel-init: the fence is disabled, the boot run is over
    fake systemctl '[ "$1" = --quiet ] && exit 1; exit 0'
    fake keel 'echo "apply --certificate-only: 1 change(s), 0 failed"'
}

teardown() {
    rm -rf "$TMP"
}

# fake NAME BODY: a command that records its arguments, then runs BODY
fake() {
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/%s.argv"\n%s\n' \
        "$TMP" "$1" "$2" > "$TMP/bin/$1"
    chmod +x "$TMP/bin/$1"
}

argv() {
    cat "$TMP/$1.argv" 2>/dev/null || true
}

# --- the fence stops: ExecStopPost of turnkey-init-fence.service ---------

@test "a fence stopped for good starts keel-certificate.service" {
    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(argv systemctl)" = "--quiet is-enabled turnkey-init-fence.service
--quiet is-active inithooks.service
--no-block start keel-certificate.service" ]
}

@test "a fence that is still enabled (a shutdown, a stop by hand) starts nothing" {
    fake systemctl '[ "$2" = is-enabled ] && exit 0; exit 1'

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [ "$(argv systemctl)" = "--quiet is-enabled turnkey-init-fence.service" ]
}

@test "the first boot's run starts nothing: it defers the certificate" {
    fake systemctl '[ "$2" = is-active ] && exit 0; [ "$1" = --quiet ] && exit 1; exit 0'

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [[ "$output" == *"the first boot defers the certificate"* ]]
    run ! grep -q start "$TMP/systemctl.argv"
}

@test "a start that fails is said and does not fail the fence's stop" {
    fake systemctl '[ "$1" = --quiet ] && exit 1; exit 5'

    run "$SCRIPT"

    [ "$status" -eq 0 ]
    [[ "$output" == *"keel-certificate.service did not start"* ]]
}

# --- the request: keel-certificate.service -------------------------------

@test "the request applies tls.acme alone from the first description" {
    touch "$PRIMARY" "$LEGACY"

    run "$SCRIPT" --request

    [ "$status" -eq 0 ]
    [ "$(argv keel)" = "spec apply --certificate-only --spec $PRIMARY" ]
    [[ "$output" == *"apply --certificate-only: 1 change(s), 0 failed"* ]]
}

@test "the request takes the legacy description when it is the only one" {
    touch "$LEGACY"

    run "$SCRIPT" --request

    [ "$status" -eq 0 ]
    [ "$(argv keel)" = "spec apply --certificate-only --spec $LEGACY" ]
}

@test "the request with no description asks nothing" {
    run "$SCRIPT" --request

    [ "$status" -eq 0 ]
    [[ "$output" == *"no instance description"* ]]
    [ ! -e "$TMP/keel.argv" ]
}

@test "the request fails as keel fails" {
    touch "$PRIMARY"
    fake keel 'exit 4'

    run "$SCRIPT" --request

    [ "$status" -eq 4 ]
}

@test "an unknown argument is a usage error" {
    run "$SCRIPT" --other

    [ "$status" -eq 2 ]
    [[ "$output" == *usage* ]]
}

# --- the packaging -------------------------------------------------------

@test "the fence's drop-in runs the script after each stop, and never fails the stop" {
    DROPIN="$BATS_TEST_DIRNAME/../systemd/turnkey-init-fence.service.d/keel-certificate.conf"

    grep -qx 'ExecStopPost=-/usr/lib/keel/certificate-after-fence' "$DROPIN"
}

@test "the service runs the request once, after the network and the web server" {
    UNIT="$BATS_TEST_DIRNAME/../debian/keel.keel-certificate.service"

    grep -qx 'Type=oneshot' "$UNIT"
    grep -qx 'ExecStart=/usr/lib/keel/certificate-after-fence --request' "$UNIT"
    grep -q '^After=.*turnkey-init-fence.service' "$UNIT"
    grep -q '^After=.*nginx.service' "$UNIT"
}

@test "the package installs the script and the drop-in" {
    INSTALL="$BATS_TEST_DIRNAME/../debian/keel.install"

    grep -q '^certificate/certificate-after-fence /usr/lib/keel$' "$INSTALL"
    grep -q '^systemd/turnkey-init-fence.service.d/keel-certificate.conf /usr/lib/systemd/system/turnkey-init-fence.service.d$' "$INSTALL"
    grep -q -- '--name=keel-certificate --no-enable --no-start' "$BATS_TEST_DIRNAME/../debian/rules"
}

@test "the script passes shellcheck" {
    command -v shellcheck >/dev/null || skip "shellcheck is not installed"

    shellcheck "$SCRIPT"
}
