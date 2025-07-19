#!/usr/bin/env ash
#
# pf_filter.sh — early drop of spoofed/bogon packets targeting exposed DNAT ports
# -------------------------------------------------------------------------------
# What this script does:
#   * Parses current VSERVER DNAT rules created by the ASUS GUI.
#   * Extracts all unique TCP/UDP destination ports forwarded to LAN.
#   * Compresses consecutive ports into compact -m multiport strings (TCP/UDP).
#   * Creates or refreshes an ipset containing well-known bogon IPv4 prefixes.
#   * Creates a dedicated chain in the raw table (VSERVER_FILTERING) with a
#     single DROP rule for packets from bogon IPs.
#   * Adds iptables raw PREROUTING rules to jump into this chain only if
#     the destination port matches one from VSERVER (i.e., exposed service).
#
# Key benefits:
#   * Spoofed traffic is dropped before DNAT, conntrack, or routing overhead.
#   * Avoids overhead from tracking bogus packets using connection tracking.
#   * Dynamically adapts to changes in DNAT configuration.
#
# Requirements / Notes:
#   * Applies only to IPv4 traffic; pair with ipset6 + ip6tables for IPv6.
#   * Multiport rules are split into ≤15-port chunks (kernel limitation).
#   * Intended for routers without double NAT — your ISP modem must be
#     in bridge mode and the router should receive a public IP
#     directly on the WAN interface.
#
# -------------------------------------------------------------------------------

set -e  # abort script on any error

#################################################################################
# User-defined variables
#################################################################################
WAN_IF='eth0'                # main WAN interface
IPSET_V4='bogon4'            # ipset that holds bad prefixes
CHAIN='VSERVER_FILTERING'    # raw table chain holding a DROP rule

# Bogon / special-purpose prefixes for IPv4
# Source: https://www.iana.org/assignments/iana-ipv4-special-registry
BOGON_V4='
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.31.196.0/24
192.52.193.0/24
192.88.99.0/24
192.168.0.0/16
192.175.48.0/24
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
'

#################################################################################
# Load shared helpers
#################################################################################
. /jffs/scripts/util.sh   # brings ensure_fw_rule

#################################################################################
# 1. Define a function to collect destination ports from VSERVER DNAT entries
#################################################################################
get_ports() {                      # $1 = tcp|udp -> one port per line, sorted
    iptables-save |
    awk -v P="$1" '
      $1 == "-A" && $2 == "VSERVER" {
        proto = ""
        port  = ""
        for (i = 1; i <= NF; i++) {
          if ($i == "-p")       proto = $(i + 1)
          if ($i == "--dport")  port  = $(i + 1)
        }
        if (proto == P && port != "") print port;
      }
    ' |
    sort -n | uniq | grep -v '^0$'
}

#################################################################################
# 2. Define a function to collapse consecutive ports into ranges
#################################################################################
compress_ports() {
    awk '
      BEGIN {
        ORS = ""; first = 1; run_start = -1; prev = -1
      }
      {
        cur = $1 + 0
        if (run_start < 0) { run_start = prev = cur; next }
        if (cur == prev + 1) { prev = cur; next }

        # flush finished run
        if (!first) printf(","); first = 0
        if (run_start == prev) printf("%s", run_start);
        else                   printf("%s:%s", run_start, prev);

        run_start = prev = cur
      }
      END {
        if (run_start < 0) exit
        if (!first) printf(",")
        if (run_start == prev) printf("%s", run_start);
        else                   printf("%s:%s", run_start, prev);
      }'
}

#################################################################################
# 3. Define a function to split a commas-separated list into ≤15-item chunks
#################################################################################
chunk15() {                   # $1 = "a,b,c,d,…"
    list="$1"
    [ -z "$list" ] && return

    count=0
    chunk=""

    # Turn commas into positional params via the IFS trick
    IFS=',' set -- $list
    for field; do
        if [ "$count" -eq 15 ]; then
            # output finished chunk (trim trailing comma)
            printf '%s\n' "${chunk%,}"
            chunk=""
            count=0
        fi
        chunk="${chunk}${field},"
        count=$((count + 1))
    done

    # output the final chunk
    printf '%s\n' "${chunk%,}"
}

#################################################################################
# 4. Collect and compress port lists
#################################################################################
TCP_PORTS=$(get_ports tcp)
UDP_PORTS=$(get_ports udp)

MP_TCP=$(echo "$TCP_PORTS" | compress_ports)
MP_UDP=$(echo "$UDP_PORTS" | compress_ports)

# If both lists empty, VSERVER not initialised -> exit quietly
[ -z "$MP_TCP$MP_UDP" ] && exit 0

#################################################################################
# 5. Refresh ipset
#################################################################################
ipset create "$IPSET_V4" hash:net family inet 2>/dev/null || true
ipset flush  "$IPSET_V4"

for net in $BOGON_V4; do
    ipset add "$IPSET_V4" "$net"
done

#################################################################################
# 6. Insert early-drop rules into raw/PREROUTING
#################################################################################

# Recreate chain each run — guarantees stale rules removed
iptables -t raw -F "$CHAIN" 2>/dev/null || iptables -t raw -N "$CHAIN"

# Ensure single DROP rule inside
ensure_fw_rule raw "$CHAIN" -m set --match-set "$IPSET_V4" src -j DROP

# Remove any existing jumps to CHAIN
iptables -t raw -S PREROUTING | grep -E " -j $CHAIN( |$)" | while read -r rule ; do
    # Delete the exact rule spec by converting '-A CHAIN ...' to parameters for -D
    iptables -t raw -D ${rule#-A }
done

add_jump_rules() {                     # $1=proto  $2=multiport list
    local proto="$1" list="$2" chunk
    [ -z "$list" ] && return

    for chunk in $(chunk15 "$list"); do
      ensure_fw_rule raw PREROUTING -I -i "$WAN_IF" -p "$proto" \
          -m multiport --dports "$chunk" -j "$CHAIN"
    done
}

# Insert rules for each protocol
add_jump_rules tcp "$MP_TCP"
add_jump_rules udp "$MP_UDP"
