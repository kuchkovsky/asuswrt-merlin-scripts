#!/usr/bin/env ash

###################################################################################################
# sdn_v6_firewall.sh - enable IPv6 forwarding and safety rules for SDN bridges on Asuswrt-Merlin
# -------------------------------------------------------------------------------------------------
# Why this script is needed:
#   This script complements sdn_v6_br.sh to provide full IPv6 support for SDN networks.
#   While sdn_v6_br.sh assigns proper /64 prefixes and router IPv6 addresses to each bridge,
#   the Asus firmware does not automatically create the corresponding IPv6 firewall rules
#   for SDNs when IPv6 is disabled in the SDN GUI settings. As a result, even though
#   IPv6 addressing and advertisements work, SDN clients may be unable to reach the
#   internet or may experience inconsistent access due to missing firewall policies.
#
#   This script applies a minimal and safe IPv6 firewall policy for each SDN bridge,
#   ensuring stable connectivity while maintaining isolation from the router itself.
#   It allows client traffic to reach the WAN, enables essential local services such as
#   DNS and DHCPv6, and blocks any direct access to the router's global IPv6 address.
#
# What this script does:
#   * Iterates through all active SDN bridge interfaces (br54, br56, ...).
#   * For each bridge, appends IPv6 rules to the firmware-managed SDN chains:
#       SDN_FF - allows egress traffic from the SDN to the WAN.
#       SDN_FI - allows UDP ports 53 (DNS) and 547 (DHCPv6) to the router,
#                 drops traffic to the router's global IPv6 address, and
#                 enforces safe client-to-router isolation.
#   * Skips bridges listed in config.sh (EXCLUDED_IFACES) and always skips br0
#
# Requirements / Notes:
#   * IPv6 must be globally enabled in router settings (Advanced Settings -> IPv6).
#   * Per-SDN IPv6 toggles in the GUI should remain disabled - the sdn_v6_* scripts handle it.
#   * The SDN_FI and SDN_FF chains are automatically created by the firmware
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Load utils and shared variables
###################################################################################################
. /jffs/scripts/utils/common.sh
. /jffs/scripts/utils/firewall.sh

DIR="$(get_script_dir)"
. "$DIR/config.sh"
. "$DIR/sdn_v6_shared.sh"

###################################################################################################
# 0b. Exit early if IPv6 is disabled
###################################################################################################
exit_if_ipv6_disabled

###################################################################################################
# 0c. Read arguments
# -------------------------------------------------------------------------------------------------
# Firmware passes:
#   $1 = WAN interface name
###################################################################################################
WAN_IF="$1"

###################################################################################################
# 0d. Define variables
# -------------------------------------------------------------------------------------------------
# br_count:
#   Counts how many SDN bridges were successfully processed and configured.
###################################################################################################
br_count=0

###################################################################################################
# 0e. Define helper functions
# -------------------------------------------------------------------------------------------------
# router_v6_for_bridge:
#   Returns the global IPv6 address assigned to a given bridge, if any.
#   Scans only for /64 addresses to avoid link-local or deprecated entries.
#   Always exits successfully; prints nothing if none is found.
###################################################################################################
router_v6_for_bridge() {
    local br="$1" ip6

    # Always succeed; prints nothing if input is empty or no /64 found
    [ -n "$br" ] || return 0

    ip6="$(
        ip -6 -o addr show dev "$br" scope global 2>/dev/null |
        awk '
            $3 == "inet6" && $4 ~ /\/64$/ {
                sub(/\/64$/, "", $4)
                print $4
                exit
            }
        '
    )" || true

    [ -n "$ip6" ] && printf '%s\n' "$ip6"
    return 0
}

###################################################################################################
# 1. Apply firewall rules for every bridge
###################################################################################################

# Block pings from the internet to LAN/SDN clients
ensure_fw_rule -6 filter FORWARD -I 1 -i "$WAN_IF" -o br+ -p ipv6-icmp \
    --icmpv6-type 128 -j DROP

# Block pings between local subnets (prevents cross-bridge discovery)
ensure_fw_rule -6 filter FORWARD -I 2 -i br+ -o br+ -p ipv6-icmp \
    --icmpv6-type 128 -j REJECT --reject-with icmp6-adm-prohibited

# Get the router's IPv6 assigned to the main LAN bridge
main_rtr_v6="$(nvram get ipv6_rtr_addr)"

for br in $(list_bridges); do
    # Skip excluded bridges
    if is_excluded "$br"; then
        log "$br is excluded (listed in EXCLUDED_IFACES or main LAN); skipping"
        continue
    fi

    # Skip bridges with GUI-managed IPv6 to avoid conflicts
    is_br_ipv6_disabled "$br" || continue

    # Allow outbound (egress) traffic from this bridge to WAN
    ensure_fw_rule -6 filter SDN_FF -i "$br" -o "$WAN_IF" -j ACCEPT

    # Allow DNS (53) and DHCPv6 (547) requests from clients to the router
    ensure_fw_rule -6 filter SDN_FI -i "$br" -p udp -m multiport --dports 53,547 -j ACCEPT

    if [ -n "$main_rtr_v6" ]; then
        # Block direct access from this bridge to the main router's IPv6 address
        ensure_fw_rule -6 filter SDN_FI -d "${main_rtr_v6}/128" -i "$br" -j REJECT \
            --reject-with icmp6-adm-prohibited
    fi

    # Get the router's IPv6 assigned to this SDN bridge
    sdn_rtr_v6="$(router_v6_for_bridge "$br")"
    if [ -n "$sdn_rtr_v6" ]; then
        # Block direct access from any bridge to this SDN router's IPv6 address
        ensure_fw_rule -6 filter SDN_FI -d "${sdn_rtr_v6}/128" -i br+ -j REJECT \
            --reject-with icmp6-adm-prohibited
    fi

    # Increment processed bridge counter
    br_count=$((br_count+1))

    log "Applied IPv6 rules: br=$br wan=$WAN_IF"
done

###################################################################################################
# 2. Finalize
###################################################################################################
if [ "$br_count" -gt 0 ]; then
    log "Successfully configured $br_count SDN bridges"
else
    log -l warn "No eligible bridges found (check EXCLUDED_IFACES)"
fi
