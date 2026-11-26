#!/usr/bin/env bats
# An upgrade of keel runs no keel unit on a tree of two versions (keel#349)
#
# debian/keel.preinst stops keel's timers before the unpack and waits for
# the oneshot services they start; debian/keel.postinst (configure) and
# debian/keel.postrm (abort-upgrade) start again the timers it stopped.
# systemctl and deb-systemd-invoke are scripts on PATH that record their
# arguments, so no test touches a unit. KEEL_UPGRADE_MARKER puts the
# marker under the test's own directory, KEEL_SYSTEMD_RUN says that
# systemd runs, and KEEL_UPGRADE_WAIT bounds the wait.

setup() {
    PREINST="$BATS_TEST_DIRNAME/../debian/keel.preinst"
    POSTINST="$BATS_TEST_DIRNAME/../debian/keel.postinst"
    POSTRM="$BATS_TEST_DIRNAME/../debian/keel.postrm"
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/bin" "$TMP/systemd" "$TMP/state"
    export PATH="$TMP/bin:$PATH"
    export KEEL_UPGRADE_MARKER="$TMP/run/keel/upgrading"
    export KEEL_SYSTEMD_RUN="$TMP/systemd"
    export KEEL_UPGRADE_WAIT=2
    export DPKG_ROOT=
    # the postinst's other step: keel network mtu, which says nothing here
    printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/keel"
    # systemctl: a unit is active when $TMP/state/NAME.active exists,
    # activating while NAME.activating holds a count above 0 (one less
    # for each look), enabled unless NAME.disabled exists
    cat > "$TMP/bin/systemctl" <<EOF2
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/systemctl.argv"
state="$TMP/state"
unit=\$(eval echo \\\${\$#})
case "\$*" in
    *is-active*) [ -e "\$state/\$unit.active" ] ;;
    *is-enabled*) [ ! -e "\$state/\$unit.disabled" ] ;;
    *ActiveState*)
        if [ -e "\$state/\$unit.activating" ]; then
            left=\$(cat "\$state/\$unit.activating")
            if [ "\$left" -gt 0 ]; then
                echo \$((left - 1)) > "\$state/\$unit.activating"
                echo activating
                exit 0
            fi
        fi
        echo inactive ;;
    *) exit 0 ;;
esac
EOF2
    cat > "$TMP/bin/deb-systemd-invoke" <<EOF2
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/invoke.argv"
EOF2
    chmod +x "$TMP/bin/keel" "$TMP/bin/systemctl" "$TMP/bin/deb-systemd-invoke"
}

teardown() {
    rm -rf "$TMP"
}

active() {
    for unit in "$@"; do
        : > "$TMP/state/$unit.active"
    done
}

@test "an upgrade stops every keel timer and the position service" {
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    stop="$(grep '^stop ' "$TMP/invoke.argv")"
    for unit in keel-mesh-sync.timer keel-mesh-etcd.timer \
        keel-database-watch.timer keel-database-dump.timer \
        keel-database-position.timer keel-firewall-watch.timer \
        keel-database-position.service; do
        [[ " $stop " == *" $unit "* ]]
    done
}

@test "the marker records the timers that were active" {
    active keel-mesh-sync.timer keel-firewall-watch.timer
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    [ "$(sort "$KEEL_UPGRADE_MARKER")" = "$(printf '%s\n' \
        keel-firewall-watch.timer keel-mesh-sync.timer)" ]
}

@test "a second preinst keeps the timers the first one recorded" {
    mkdir -p "$(dirname "$KEEL_UPGRADE_MARKER")"
    echo keel-firewall-watch.timer > "$KEEL_UPGRADE_MARKER"
    active keel-mesh-sync.timer
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    [ "$(sort "$KEEL_UPGRADE_MARKER")" = "$(printf '%s\n' \
        keel-firewall-watch.timer keel-mesh-sync.timer)" ]
}

@test "the preinst waits for a oneshot that runs" {
    echo 1 > "$TMP/state/keel-mesh-sync.service.activating"
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    [ "$(cat "$TMP/state/keel-mesh-sync.service.activating")" = 0 ]
    ! grep -q 'keel-mesh-sync.service' "$TMP/invoke.argv"
    ! grep -q 'reset-failed' "$TMP/systemctl.argv"
}

@test "a oneshot still running after the wait is stopped, and not failed" {
    echo 100 > "$TMP/state/keel-database-dump.service.activating"
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    grep -qx 'stop keel-database-dump.service' "$TMP/invoke.argv"
    grep -q 'reset-failed keel-database-dump.service' "$TMP/systemctl.argv"
    [[ "$output" == *"keel-database-dump.service"* ]]
}

@test "the preinst waits for each oneshot a timer starts" {
    for unit in keel-mesh-sync keel-mesh-etcd keel-database-watch \
        keel-database-dump keel-firewall-watch; do
        echo 1 > "$TMP/state/$unit.service.activating"
    done
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    for unit in keel-mesh-sync keel-mesh-etcd keel-database-watch \
        keel-database-dump keel-firewall-watch; do
        [ "$(cat "$TMP/state/$unit.service.activating")" = 0 ]
    done
}

@test "an install, or no systemd, stops nothing and writes no marker" {
    run sh "$PREINST" install
    [ "$status" -eq 0 ]
    rmdir "$TMP/systemd"
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/invoke.argv" ]
    [ ! -e "$KEEL_UPGRADE_MARKER" ]
}

@test "a failure of systemctl never fails the upgrade" {
    printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/deb-systemd-invoke"
    printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/systemctl"
    run sh "$PREINST" upgrade 0.23.98
    [ "$status" -eq 0 ]
}

@test "configure removes the marker and starts the enabled timers it holds" {
    mkdir -p "$(dirname "$KEEL_UPGRADE_MARKER")"
    printf '%s\n' keel-mesh-sync.timer keel-firewall-watch.timer \
        > "$KEEL_UPGRADE_MARKER"
    : > "$TMP/state/keel-firewall-watch.timer.disabled"
    DPKG_ROOT="$TMP/root" run sh "$POSTINST" configure 0.23.98
    [ "$status" -eq 0 ]
    [ ! -e "$KEEL_UPGRADE_MARKER" ]
    [ "$(cat "$TMP/invoke.argv")" = "start keel-mesh-sync.timer" ]
}

@test "configure with no marker starts nothing" {
    DPKG_ROOT="$TMP/root" run sh "$POSTINST" configure 0.23.98
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/invoke.argv" ]
}

@test "the postinst's abort-upgrade starts the timers again" {
    mkdir -p "$(dirname "$KEEL_UPGRADE_MARKER")"
    echo keel-firewall-watch.timer > "$KEEL_UPGRADE_MARKER"
    DPKG_ROOT="$TMP/root" run sh "$POSTINST" abort-upgrade 0.23.118
    [ "$status" -eq 0 ]
    [ ! -e "$KEEL_UPGRADE_MARKER" ]
    [ "$(cat "$TMP/invoke.argv")" = "start keel-firewall-watch.timer" ]
}

@test "a failed unpack removes the marker and starts the timers again" {
    mkdir -p "$(dirname "$KEEL_UPGRADE_MARKER")"
    printf '%s\n' keel-mesh-etcd.timer keel-firewall-watch.timer \
        > "$KEEL_UPGRADE_MARKER"
    run sh "$POSTRM" abort-upgrade 0.23.98
    [ "$status" -eq 0 ]
    [ ! -e "$KEEL_UPGRADE_MARKER" ]
    [ "$(cat "$TMP/invoke.argv")" = \
        "start keel-mesh-etcd.timer keel-firewall-watch.timer" ]
}

@test "remove and purge leave a marker alone" {
    mkdir -p "$(dirname "$KEEL_UPGRADE_MARKER")"
    echo keel-mesh-sync.timer > "$KEEL_UPGRADE_MARKER"
    DPKG_ROOT="$TMP/root" run sh "$POSTRM" remove
    [ "$status" -eq 0 ]
    [ -e "$KEEL_UPGRADE_MARKER" ]
    [ ! -e "$TMP/invoke.argv" ]
}
