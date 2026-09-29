#!/usr/bin/env bats
# firstboot.d/10keel-system: the hook this package ships into inithooks
#
# keel is replaced by a script on PATH that records its arguments and
# answers with a chosen exit code and output, so no test runs the real
# converge, touches the live system or needs root. The description paths
# and the log are redirected into a temporary tree.

setup() {
    HOOK="$BATS_TEST_DIRNAME/../firstboot.d/10keel-system"
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/bin" "$TMP/etc/keel"
    export PATH="$TMP/bin:$PATH"
    export INITHOOKS_DEFAULT="$TMP/etc/default-inithooks"
    export INITHOOKS_LOGFILE="$TMP/inithooks.log"
    printf 'INITHOOKS_PATH=%s\n' "$TMP" > "$INITHOOKS_DEFAULT"
    : > "$INITHOOKS_LOGFILE"
    PRIMARY="$TMP/etc/keel/instance.yaml"
    LEGACY="$TMP/etc/inithooks.yaml"
    export KEEL_SPEC_PATHS="$PRIMARY:$LEGACY"
    unset _TURNKEY_INIT INITHOOKS_DECL
}

teardown() {
    rm -rf "$TMP"
}

fake_keel() {
    local status="$1" line="$2"
    cat > "$TMP/bin/keel" <<EOF
#!/bin/sh
printf '%s\n' "\$*" > "$TMP/keel.argv"
printf '%s\n' "$line"
exit $status
EOF
    chmod +x "$TMP/bin/keel"
}

describe() {
    printf 'version: 1\ninstance:\n  fqdn: forum2.keellinux.org\n' > "$1"
}

log() {
    cat "$INITHOOKS_LOGFILE"
}

@test "an interactive turnkey-init run is left alone" {
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    _TURNKEY_INIT=1 run "$HOOK"
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/keel.argv" ]
    [ ! -s "$INITHOOKS_LOGFILE" ]
}

@test "no description is a no-op that says which paths were searched" {
    fake_keel 0 "never called"
    run "$HOOK"
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/keel.argv" ]
    log | grep -q "no instance description"
    log | grep -q "$PRIMARY"
}

@test "the description at the instance path asks for the system phase" {
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    run "$HOOK"
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "spec apply --system-only --defer-certificate --spec $PRIMARY" ]
    log | grep -q "INFO: \[10keel-system\] apply --system-only: 1 change"
}

@test "the second path is read when the first is absent" {
    describe "$LEGACY"
    fake_keel 0 "apply --system-only: 0 change(s), 0 failed"
    run "$HOOK"
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "spec apply --system-only --defer-certificate --spec $LEGACY" ]
}

@test "the first path wins when both are there" {
    describe "$PRIMARY"
    describe "$LEGACY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    run "$HOOK"
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "spec apply --system-only --defer-certificate --spec $PRIMARY" ]
}

@test "INITHOOKS_DECL names the description outright" {
    named="$TMP/etc/named.yaml"
    describe "$named"
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    INITHOOKS_DECL="$named" run "$HOOK"
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "spec apply --system-only --defer-certificate --spec $named" ]
}

@test "INITHOOKS_DECL naming a file that is not there is a no-op" {
    fake_keel 0 "never called"
    INITHOOKS_DECL="$TMP/etc/absent.yaml" run "$HOOK"
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/keel.argv" ]
    log | grep -q "absent.yaml"
}

@test "a spec declaring nothing this phase converges is a no-op" {
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: nothing declared that this phase converges"
    run "$HOOK"
    [ "$status" -eq 0 ]
    log | grep -q "nothing declared that this phase converges"
}

@test "a keel failure is reported and the boot carries on" {
    describe "$PRIMARY"
    fake_keel 16 "instance.fqdn: write /etc/hosts: failed: read-only"
    run "$HOOK"
    [ "$status" -eq 0 ]
    log | grep -q "WARNING: \[10keel-system\] instance.fqdn: write /etc/hosts: failed"
    log | grep -q "exited 16"
    log | grep -q "the boot carries on"
}

@test "keel missing is reported and the boot carries on" {
    describe "$PRIMARY"
    rm -f "$TMP/bin/keel"
    KEEL="$TMP/bin/keel" run "$HOOK"
    [ "$status" -eq 0 ]
    log | grep -q "is not installed"
}

@test "an absent log file does not stop the hook" {
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    rm -f "$INITHOOKS_LOGFILE"
    run "$HOOK"
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "spec apply --system-only --defer-certificate --spec $PRIMARY" ]
}

@test "an absent inithooks default file does not stop the hook" {
    describe "$PRIMARY"
    fake_keel 0 "apply --system-only: 1 change(s), 0 failed"
    rm -f "$INITHOOKS_DEFAULT"
    run "$HOOK"
    [ "$status" -eq 0 ]
    log | grep -q "1 change"
}

@test "the hook runs after 09hostname and before the hooks at 29 and 30" {
    name="$(basename "$HOOK")"
    [ "$(printf '09hostname\n%s\n' "$name" | sort | head -1)" = "09hostname" ]
    [ "$(printf '29sudoadmin\n%s\n' "$name" | sort | head -1)" = "$name" ]
    [ "$(printf '30rootpass\n%s\n' "$name" | sort | head -1)" = "$name" ]
    [ -x "$HOOK" ]
}

@test "the hook is shellcheck clean" {
    command -v shellcheck > /dev/null || skip "shellcheck is not installed"
    run shellcheck -S warning "$HOOK"
    [ "$status" -eq 0 ]
}
