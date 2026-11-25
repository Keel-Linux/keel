#!/bin/sh
# keel access: the enrolment of this computer on the access network of
# a Keel node (handbook decision 0098). The pasted command fetched this
# script whole from the node over HTTPS, with the node's key pinned,
# and gives it the one-use secret on its standard input. The key pair is
# made here: the private key never leaves this computer, and the node
# gets the public key only. No secret and no key is on the argv of any
# process: they go through the shell's own printf and pipes. Linux and
# macOS, with wireguard-tools, curl and openssl.
#
# Everything is in main, called on the last line: a script cut off in
# the download defines nothing and runs nothing.
set -eu
url_host='@URL_HOST@'
port='@PORT@'
pin='@PIN@'
invite='@ID@'
node_key='@NODE_KEY@'
node_address='@NODE_ADDRESS@'
wg_endpoint='@WG_ENDPOINT@'
iface='@IFACE@'

fail() {
    echo "keel access: $*" >&2
    exit 1
}

# the octal escapes of each character of $1 XOR $2, for printf: the
# HMAC's inner and outer keys, made with no process
padded() {
    rest=$1
    found=''
    while [ -n "$rest" ]; do
        char=${rest%"${rest#?}"}
        rest=${rest#?}
        code=$(printf '%d' "'$char")
        found="$found$(printf '\\%03o' $(( code ^ $2 )))"
    done
    printf '%s' "$found"
}

main() {
    IFS= read -r secret || fail "the one-use secret of the command is missing"
    for tool in wg wg-quick curl openssl; do
        command -v "$tool" >/dev/null 2>&1 \
            || fail "$tool is missing: install wireguard-tools, curl and openssl"
    done
    [ "$(id -u)" = 0 ] || fail "run the command with sudo: wg-quick needs root"
    conf=/etc/wireguard/$iface.conf
    [ ! -e "$conf" ] || fail "$conf is there already: remove it to enrol again"

    umask 077
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    key=$(wg genkey)
    pub=$(printf '%s\n' "$key" | wg pubkey)
    # the proof: begin
    # HMAC-SHA256 of the public key, keyed by the hex SHA-256 of
    # keel-access:<secret> as 64 characters (one block): openssl reads
    # data only, on its standard input
    work=${work:-$(mktemp -d)}
    hkey=$(printf 'keel-access:%s' "$secret" | openssl dgst -sha256 \
        | sed 's/^.*= //')
    # shellcheck disable=SC2059
    { printf "$(padded "$hkey" 54)"; printf '%s' "$pub"; } \
        | openssl dgst -sha256 -binary >"$work/inner"
    # shellcheck disable=SC2059
    proof=$({ printf "$(padded "$hkey" 92)"; cat "$work/inner"; } \
        | openssl dgst -sha256 | sed 's/^.*= //')
    # the proof: end

    answer=$(curl -fsS --proto '=https' -k --pinnedpubkey "sha256//$pin" \
        -H 'Content-Type: application/json' \
        --data "{\"public_key\": \"$pub\", \"proof\": \"$proof\"}" \
        "https://$url_host:$port/access/$invite") \
        || fail "the node refused the enrolment (used, expired or wrong)"
    address=$(printf '%s' "$answer" \
        | sed -n 's/.*"address": *"\([0-9a-f:]*\/128\)".*/\1/p')
    [ -n "$address" ] || fail "the node's answer has no address: $answer"

    mkdir -p /etc/wireguard
    cat >"$conf" <<CONF
# keel access network of $url_host (decision 0098)
[Interface]
PrivateKey = $key
Address = $address

[Peer]
PublicKey = $node_key
Endpoint = $wg_endpoint
AllowedIPs = $node_address/128
PersistentKeepalive = 25
CONF
    wg-quick up "$iface"
    echo "keel access: $iface is up; the node is $node_address"
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w 10 "$node_address" 22; then
            echo "keel access: SSH answers on $node_address port 22"
        else
            echo "keel access: SSH does not answer on $node_address yet" >&2
        fi
    fi
}

main "$@"
