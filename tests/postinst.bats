#!/usr/bin/env bats
# debian/keel.postinst: an upgrade sets the overlay's MTU live (keel#139)
#
# keel is replaced by a script on PATH that records its arguments and
# answers with a chosen exit code, so no test touches an interface. The
# #DEBHELPER# token stays a comment, as in the source package.

setup() {
    POSTINST="$BATS_TEST_DIRNAME/../debian/keel.postinst"
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/bin"
    export PATH="$TMP/bin:$PATH"
}

teardown() {
    rm -rf "$TMP"
}

fake_keel() {
    cat > "$TMP/bin/keel" <<EOF2
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/keel.argv"
exit $1
EOF2
    chmod +x "$TMP/bin/keel"
}

@test "configure runs keel network mtu" {
    fake_keel 0
    run sh "$POSTINST" configure 0.23.13
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/keel.argv")" = "network mtu" ]
}

@test "a failure is said and never fails the upgrade" {
    fake_keel 16
    run sh "$POSTINST" configure 0.23.13
    [ "$status" -eq 0 ]
    [[ "$output" == *"keel spec apply --system sets it"* ]]
}

@test "other actions run nothing" {
    fake_keel 0
    run sh "$POSTINST" abort-upgrade
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/keel.argv" ]
}
