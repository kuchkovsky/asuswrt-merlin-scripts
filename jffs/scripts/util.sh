#!/usr/bin/env ash
# ----------------------------------------------------------------------------------
# util.sh  –  helper library for shell scripts on Asuswrt-Merlin
# ----------------------------------------------------------------------------------
# Public API
# ----------
#   is_lan_ip <ipv4>
#       → returns **0** when the address is in an RFC‑1918 private subnet, or
#         **1** when it is public / unroutable.
#
#   resolve_ip <host-or-ip>
#       → prints a single IPv4 address (LAN **or** WAN).  Accepts literal IPs,
#         /etc/hosts aliases, or DNS names.  Exits non‑zero on failure.
#
#   resolve_lan_ip <host-or-ip>
#       → like `resolve_ip`, **but additionally verifies** that the result lies
#         in a private RFC‑1918 range.  Logs an error and exits non‑zero if not.
#
#   ensure_fw_rule <table> <chain> [-I|-D] <rule...>
#       → Idempotent firewall helper:
#           •  no flag    → append rule (-A) if it's missing
#           •  -I         → insert rule (-I) at the top if missing
#           •  -D         → delete rule (-D) if it exists
#         Guarantees the rule appears **exactly once** (or not at all, for -D).
#
#   block_wan_for_host <hostname|ip>
#       → Resolves the host to a LAN IP and **inserts** a `REJECT` rule into the
#         `filter/FORWARD` chain, blocking that device's WAN access.
#
#   allow_wan_for_host <hostname|ip>
#       → Resolves the host to a LAN IP and **removes** the corresponding
#         `REJECT` rule, restoring WAN access for that device.
#
# Internal helpers (names starting with an underscore) are considered private
# implementation details and may change without notice.
# ----------------------------------------------------------------------------------

# Logger — writes the message to syslog (tag: util) and stderr
_log_util() { logger -s -t util "$1"; }

####################################################################################
# _resolve_ip_impl – shared resolver used by both public resolve* functions.
#   • If the argument already looks like an IPv4 address, return it unchanged.
#   • Else:  (1) consult /etc/hosts  (2) fall back to BusyBox nslookup.
####################################################################################
_resolve_ip_impl() {
    local arg="$1" host ip

    # 1) Literal IPv4?  Accept as-is.
    case "$arg" in *.*.*.*) echo "$arg"; return 0 ;; esac

    host="${arg%.}"     # strip trailing dot, if any

    # 2) /etc/hosts search (match any alias column)
    ip=$(awk -v h="$host" '
        $1 ~ /^[0-9]/ {
          for(i=2;i<=NF;i++) {
            gsub("\\.$","",$i)
            if($i==h){print $1; exit}
          }
        }' /etc/hosts)

    # 3) BusyBox nslookup fallback
    if [ -z "$ip" ]; then
        ip=$(nslookup "$host" 2>/dev/null |
             awk -v h="$host" '
               BEGIN{found=0}
               $0 ~ "^Name:[[:space:]]*"h {found=1; next}
               found && /^Address[[:space:]]+[0-9]+\./ {print $3; exit}')
    fi

    [ -n "$ip" ] && echo "$ip"
}

####################################################################################
# is_lan_ip — returns 0 for a private (RFC-1918) IPv4, 1 otherwise
####################################################################################
is_lan_ip() {
    case "$1" in
        10.*)                                   return 0 ;;   # 10.0.0.0/8
        192.168.*)                              return 0 ;;   # 192.168.0.0/16
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;   # 172.16.0.0/12
        *)                                      return 1 ;;
    esac
}

####################################################################################
# resolve_ip  – resolves any host/IP
####################################################################################
resolve_ip() {
    local ip

    ip=$(_resolve_ip_impl "$1")
    if [ -z "$ip" ]; then
        _log_util "resolve_ip: cannot resolve '$1'"
        return 1
    fi

    echo "$ip"
}

####################################################################################
# resolve_lan_ip  –  resolves host/IP **and enforces** private LAN constraint
####################################################################################
resolve_lan_ip() {
    local ip

    # reuse the generic resolver first
    ip=$(resolve_ip "$1") || return 1

    # then enforce RFC‑1918 check
    if ! is_lan_ip "$ip"; then
        _log_util "resolve_lan_ip: '$ip' is not a LAN address"
        return 1
    fi

    echo "$ip"
}

####################################################################################
# ensure_fw_rule  – creates `iptables` rules without duplicates
#                   and avoids attempts to delete non-existent rules
#
# Usage:
#   ensure_fw_rule <table> <chain> [-I | -A] <rule...>   # add (insert or append)
#   ensure_fw_rule <table> <chain> -D    <rule...>       # delete if present
#
# Notes
#   • Default without a flag is "append" (-A).
#   • Works only for IPv4; pair with ip6tables for IPv6.
####################################################################################
ensure_fw_rule() {
    local table=$1 chain=$2; shift 2
    local mode="-A"                        # default: append

    case "$1" in
        -I)  mode="-I"; shift ;;
        -D)  mode="-D"; shift ;;
    esac

    if [ "$mode" = "-D" ]; then
        iptables -t "$table" -C "$chain" "$@" 2>/dev/null &&
        iptables -t "$table" -D "$chain" "$@"
    else
        iptables -t "$table" -C "$chain" "$@" 2>/dev/null ||
        iptables -t "$table" $mode "$chain" "$@"
    fi
}

####################################################################################
# block_wan_for_host — resolve hostname/IP and insert the REJECT rule
# Usage: block_wan_for_host <hostname|ip>
####################################################################################
block_wan_for_host() {
    local ip
    ip=$(resolve_lan_ip "$1") || return 1

    # Insert the REJECT rule at the top of FORWARD if it isn't there already
    ensure_fw_rule filter FORWARD -I -s "$ip" -j REJECT
}

####################################################################################
# allow_wan_for_host — resolve hostname/IP and remove the REJECT rule
# Usage: allow_wan_for_host <hostname|ip>
####################################################################################
allow_wan_for_host() {
    local ip
    ip=$(resolve_lan_ip "$1") || return 1

    # remove the REJECT rule if present
    ensure_fw_rule filter FORWARD -D -s "$ip" -j REJECT
}
