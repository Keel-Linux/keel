#!/bin/sh
# keel access: the enrolment of this computer on the access network of
# a Keel node (handbook decision 0098). The pasted command fetched this
# script from the node over HTTPS, with the node's key pinned, and gives
# it the one-use secret. The key pair is made here: the private key
# never leaves this computer, and the node gets the public key only.
# Linux and macOS, with wireguard-tools, curl and openssl.
set -eu
secret=${1:?the one-use secret of the command is missing}
node='@NODE@'
port='@PORT@'
pin='@PIN@'
invite='@ID@'
node_key='@NODE_KEY@'
node_address='@NODE_ADDRESS@'
wg_port='@WG_PORT@'
iface='@IFACE@'

fail() {
    echo "keel access: $*" >&2
    exit 1
}

for tool in wg wg-quick curl openssl; do
    command -v "$tool" >/dev/null 2>&1 \
        || fail "$tool is missing: install wireguard-tools, curl and openssl"
done
[ "$(id -u)" = 0 ] || fail "run the command with sudo: wg-quick needs root"
conf=/etc/wireguard/$iface.conf
[ ! -e "$conf" ] || fail "$conf is there already: remove it to enrol again"

umask 077
key=$(wg genkey)
pub=$(printf '%s\n' "$key" | wg pubkey)
# the proof: begin
hkey=$(printf 'keel-access:%s' "$secret" | openssl dgst -sha256 \
    | sed 's/^.*= //')
proof=$(printf '%s' "$pub" | openssl dgst -sha256 -hmac "$hkey" \
    | sed 's/^.*= //')
# the proof: end

answer=$(curl -fsS --proto '=https' -k --pinnedpubkey "sha256//$pin" \
    -H 'Content-Type: application/json' \
    --data "{\"public_key\": \"$pub\", \"proof\": \"$proof\"}" \
    "https://[$node]:$port/access/$invite") \
    || fail "the node refused the enrolment (used, expired or wrong)"
address=$(printf '%s' "$answer" \
    | sed -n 's/.*"address": *"\([0-9a-f:]*\/128\)".*/\1/p')
[ -n "$address" ] || fail "the node's answer has no address: $answer"

mkdir -p /etc/wireguard
cat >"$conf" <<CONF
# keel access network of $node (decision 0098)
[Interface]
PrivateKey = $key
Address = $address

[Peer]
PublicKey = $node_key
Endpoint = [$node]:$wg_port
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
