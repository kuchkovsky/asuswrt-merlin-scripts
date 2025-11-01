#!/usr/bin/env ash

###################################################################################################
# sdn_v6_dnsmasq.sh - enable IPv6 RA and SLAAC for Asuswrt-Merlin SDN dnsmasq instances
# -------------------------------------------------------------------------------------------------
# Why this script is needed:
#   This script works alongside sdn_v6_br.sh to fully enable IPv6 on SDN networks.
#   While sdn_v6_br.sh assigns proper /64 prefixes to each bridge, Asus firmware
#   does not automatically enable IPv6 Router Advertisements (RA) for SDN dnsmasq
#   instances. As a result, clients connected to those networks would not receive
#   IPv6 configuration via SLAAC.
#
#   This script adds the necessary RA and DHCPv6 parameters to each SDN dnsmasq
#   instance, ensuring that IPv6 Router Advertisements (RA) and SLAAC
#   are functional on all SDNs.
#
# What this script does:
#   * Maps the firmware-provided SDN index ($2) to the target bridge by parsing "get_mtlan"
#     output: for each block, it pairs "sdn_idx:[N]" with "br_ifname:[brXX]".
#   * Appends an IPv6 SLAAC configuration line using Merlin's helper:
#       dhcp-range=::,constructor:brNN,ra-stateless,64,600
#     along with supporting options:
#       enable-ra, quiet-ra, quiet-dhcp6, ra-param, and option6:23 (RDNSS).
#   * Respects EXCLUDED_IFACES from config.sh - excluded SDNs are skipped automatically.
#
# Requirements / Notes:
#   * This script is invoked automatically by the firmware for each SDN dnsmasq instance;
#     no manual run is required.
#   * All configuration lives in config.sh (EXCLUDED_IFACES variable). Edit it to exclude
#     specific bridges if needed.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Load utils and shared variables
###################################################################################################
. /jffs/scripts/utils/common.sh
. /usr/sbin/helper.sh  # Merlin helper for pc_append

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
#   $1 = path to the instance config
#   $2 = SDN index
###################################################################################################
CONFIG="$1"
SDN_IDX="$2"

###################################################################################################
# 1. Validate inputs and map SDN index -> bridge
###################################################################################################
if [ -z "$CONFIG" ] || [ -z "$SDN_IDX" ]; then
    log -l err "Missing arguments: config=${CONFIG:-} sdn_idx=${SDN_IDX:-}; exiting..."
    exit 1
fi

BR="$(list_sdn "$SDN_IDX" | awk -F'|' 'NR == 1 { print $2 }')"
if [ -z "$BR" ]; then
    log -l err "Could not map bridge for sdn_idx=$SDN_IDX; exiting..."
    exit 1
fi

if is_excluded "$BR"; then
    log -l debug "$BR is excluded (listed in EXCLUDED_IFACES); exiting..."
    exit 0
fi

# If IPv6 is enabled for this SDN in the GUI, exit to avoid conflicts
is_br_ipv6_disabled "$BR" || exit 1

###################################################################################################
# 2. Append the IPv6 lines for this bridge
###################################################################################################

# Serve only on this bridge (listen/bind + RA/DHCPv6 limited to $BR)
pc_append "interface=$BR" "$CONFIG"

# Never consider loopback as a serving interface
pc_append "except-interface=lo" "$CONFIG"

# Enable IPv6 Router Advertisements (RAs)
pc_append "enable-ra" "$CONFIG"

# Send RAs only in response to solicitations (no periodic unsolicited RAs)
pc_append "quiet-ra" "$CONFIG"

# Suppress DHCPv6 log noise
pc_append "quiet-dhcp6" "$CONFIG"

# RA timing for $BR: min 10s, max 600s between unsolicited RAs
pc_append "ra-param=$BR,10,600" "$CONFIG"

# SLAAC + stateless DHCPv6 (addresses via SLAAC; DHCPv6 only for other info);
# use prefix derived from $BR (constructor:), advertise /64, 600s DHCPv6 info lease
pc_append "dhcp-range=::,constructor:$BR,ra-stateless,64,600" "$CONFIG"

# DHCPv6 option 23 (Recursive DNS Server): advertise the router's own IPv6 as RDNSS
pc_append "dhcp-option=option6:23,[::]" "$CONFIG"

###################################################################################################
# 3. Finalize
###################################################################################################
log "Appended IPv6 settings: br=$BR sdn_idx=$SDN_IDX config=$CONFIG"
