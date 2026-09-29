# Copied from Keel-Linux/inithooks lib/ipconfig.sh at 11f7196, for
# keel.network.render's tests; the package runs the installed copy.
# Decisions and rendering for firstboot.d/01ipconfig.
#
# Sourced by the hook and by tests/test-ipconfig.bats. Every function here
# only reads its arguments and prints; the hook applies the results.

# ipconfig_valid_config CONFIG
# Succeeds when CONFIG is a value IP_CONFIG or IP6_CONFIG accepts.
ipconfig_valid_config() {
    case "$1" in
        manual|static|dhcp)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ipconfig_iface CODENAME
# Prints the interface configured for a build codename (turnkey-version -n).
ipconfig_iface() {
    if [[ "$1" == "lxc" ]]; then
        # LXC app not currently being built, but leaving for now...
        echo "br0"
    else
        echo "eth0"
    fi
}

# ipconfig_unchanged FILE IFACE CONFIG [CONFIG6]
# Succeeds when the interfaces FILE already configures IFACE with CONFIG
# and, when CONFIG6 is given, its inet6 stanza with CONFIG6.
ipconfig_unchanged() {
    if [[ -n "$4" ]]; then
        grep --quiet --no-messages "iface $2 inet6 $4" "$1" || return 1
    fi
    grep --quiet --no-messages "iface $2 inet $3" "$1"
}

# ipconfig_render_head IFACE CONFIG HOSTNAME
# Prints the header confconsole looks for (otherwise it refuses to edit the
# file), the loopback stanza and the IPv4 stanza of IFACE.
ipconfig_render_head() {
    local iface=$1
    local config=$2
    local hostname=$3
    cat <<EOT
# UNCONFIGURED INTERFACES
# remove the above line if you edit this file

auto lo
iface lo inet loopback

auto $iface
iface $iface inet $config
    hostname $hostname
EOT
}

# ipconfig_check_static ADDRESS NETMASK
# Succeeds when both are set; otherwise prints why not and fails.
ipconfig_check_static() {
    [[ -n "$1" ]] || { echo "IP_CONFIG=static requires IP_ADDRESS"; return 1; }
    [[ -n "$2" ]] || { echo "IP_CONFIG=static requires IP_NETMASK"; return 1; }
}

# ipconfig_render_static ADDRESS NETMASK [GATEWAY [DNS1 [DNS2]]]
# Prints the options of a static stanza; gateway and dns-nameservers only
# when set.
ipconfig_render_static() {
    local address=$1
    local netmask=$2
    local gateway=$3
    local dns
    echo "    address $address"
    echo "    netmask $netmask"
    [[ -z "$gateway" ]] || echo "    gateway $gateway"
    dns=$(echo "$4 $5" | xargs)
    [[ -z "$dns" ]] || echo "    dns-nameservers $dns"
}

# ipconfig_ip6_syntax ADDRESS
# Succeeds when ADDRESS is written as an IPv6 address: groups of one to four
# hexadecimal digits separated by colons, eight of them, or fewer with one
# '::' standing for the missing ones. No prefix length, no dotted quad.
ipconfig_ip6_syntax() {
    local ip=$1
    local group
    local groups=0
    local rest
    [[ "$ip" =~ ^[0-9A-Fa-f:]+$ && "$ip" == *:* && "$ip" != *:::* ]] || return 1
    # a single leading or trailing colon is not '::'
    [[ "$ip" != :[^:]* && "$ip" != *[^:]: ]] || return 1
    rest=${ip/::/:}
    [[ "$rest" != *::* ]] || return 1
    local IFS=:
    for group in $rest; do
        # the empty group beside a leading or trailing '::'
        [[ -n "$group" ]] || continue
        [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        groups=$((groups + 1))
    done
    if [[ "$ip" == *::* ]]; then
        [[ $groups -le 7 ]]
    else
        [[ $groups -eq 8 ]]
    fi
}

# ipconfig_ip6_first_group ADDRESS
# Prints the first group of a syntactically valid ADDRESS as four lowercase
# hexadecimal digits, the part that tells multicast and link-local apart.
ipconfig_ip6_first_group() {
    local first=${1%%:*}
    printf '%04x\n' "$((16#${first:-0}))"
}

# ipconfig_check_ip6 VALUE WHAT
# Succeeds when VALUE is a plain IPv6 unicast address; otherwise prints why
# not, naming the WHAT key, and fails. Same rules as confconsole's ifutil:
# no prefix length, IPv6 only, no multicast, loopback or unspecified address.
# Link-local is accepted, it is the usual gateway on a routed segment.
ipconfig_check_ip6() {
    local ip=$1
    local what=$2
    [[ "$ip" != */* ]] \
        || { echo "$what must be a plain address, not address/prefix: '$ip'"; return 1; }
    [[ ! "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]] \
        || { echo "$what must be IPv6, not IPv4: '$ip' (IPv4 goes in the IP_* keys)"; return 1; }
    ipconfig_ip6_syntax "$ip" \
        || { echo "$what is not a valid IPv6 address: '$ip'"; return 1; }
    [[ "$(ipconfig_ip6_first_group "$ip")" != ff* && ! "$ip" =~ ^[0:]+$ && ! "$ip" =~ ^[0:]*:0*1$ ]] \
        || { echo "$what must be a unicast address: '$ip'"; return 1; }
}

# ipconfig_check_ip6_prefix VALUE WHAT
# Succeeds when VALUE is ADDRESS/PREFIX for an 'inet6 static' stanza: the
# prefix length (0-128) is mandatory, there is no netmask line for inet6, and
# a link-local address is refused, since it is not what static means.
ipconfig_check_ip6_prefix() {
    local address=${1%%/*}
    local prefix=${1#*/}
    local what=$2
    [[ ! "$address" =~ ^[0-9]+(\.[0-9]+){3}$ ]] \
        || { echo "$what must be IPv6, not IPv4: '$1' (IPv4 goes in the IP_* keys)"; return 1; }
    [[ "$1" == */* ]] \
        || { echo "$what needs a prefix length, e.g. 2001:db8:1::10/64: '$1'"; return 1; }
    ipconfig_check_ip6 "$address" "$what" || return 1
    [[ "$prefix" =~ ^[0-9]{1,3}$ ]] && [[ $((10#$prefix)) -le 128 ]] \
        || { echo "$what has an invalid prefix length (0-128): '$prefix'"; return 1; }
    [[ ! "$(ipconfig_ip6_first_group "$address")" =~ ^fe[89ab] ]] \
        || { echo "$what must not be link-local: '$address'"; return 1; }
}

# ipconfig_check_static6 ADDRESS [GATEWAY [DNS1 [DNS2]]]
# Succeeds when the IP6_* values of a static stanza are usable; otherwise
# prints why not and fails. The address is required, the rest optional.
ipconfig_check_static6() {
    [[ -n "$1" ]] || { echo "IP6_CONFIG=static requires IP6_ADDRESS"; return 1; }
    ipconfig_check_ip6_prefix "$1" IP6_ADDRESS || return 1
    [[ -z "$2" ]] || ipconfig_check_ip6 "$2" IP6_GW || return 1
    [[ -z "$3" ]] || ipconfig_check_ip6 "$3" IP6_DNS1 || return 1
    [[ -z "$4" ]] || ipconfig_check_ip6 "$4" IP6_DNS2 || return 1
}

# ipconfig_render_inet6 IFACE HOSTNAME [CONFIG]
# Prints the IPv6 stanza; CONFIG defaults to dhcp, which keeps IPv6 on
# (SLAAC/DHCPv6) as confconsole does.
ipconfig_render_inet6() {
    local iface=$1
    local hostname=$2
    local config=${3:-dhcp}
    cat <<EOT
iface $iface inet6 $config
    hostname $hostname
EOT
}

# ipconfig_render_static6 ADDRESS [GATEWAY [DNS1 [DNS2]]]
# Prints the options of a static inet6 stanza: the address carries its
# prefix length, gateway and dns-nameservers only when set.
ipconfig_render_static6() {
    local address=$1
    local gateway=$2
    local dns
    echo "    address $address"
    [[ -z "$gateway" ]] || echo "    gateway $gateway"
    dns=$(echo "$3 $4" | xargs)
    [[ -z "$dns" ]] || echo "    dns-nameservers $dns"
}
