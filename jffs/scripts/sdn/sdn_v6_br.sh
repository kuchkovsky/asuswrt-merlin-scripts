#!/usr/bin/env ash

###################################################################################################
# sdn_v6_br.sh - enable /64 IPv6 subnets and SLAAC for Asuswrt-Merlin SDN bridges
# -------------------------------------------------------------------------------------------------
# Why this script is needed:
#   ASUS firmware currently does not support stateless IPv6 (SLAAC) for SDN bridges - only
#   stateful DHCPv6 mode is implemented. As a result, when IPv6 is enabled on any SDN (br52,
#   br53, ...), the firmware truncates all subnets, including the main LAN, from /64 to /72.
#   This breaks SLAAC (automatic IPv6 addressing) on most devices, since they require a /64
#   subnet to self-assign global addresses correctly.
#
#   When IPv6 mode is enabled and the WAN receives a /56 prefix delegation (PD),
#   the main LAN correctly uses a /64 as long as SDN IPv6 is disabled. Once SDN IPv6 is turned on,
#   all bridges (including br0) get /72 subnets, effectively disabling SLAAC across the network.
#
#   This script works around that limitation by manually carving proper /64 subnets from the
#   WAN's delegated prefix and assigning them to each SDN bridge. This restores stateless IPv6
#   functionality and allows clients on all SDNs to autoconfigure addresses correctly.
#
# What this script does:
#   * Reads the delegated IPv6 prefix (PD) and prefix length from NVRAM.
#   * Builds a stable, sequential index of all bridges (br0=0, br54=1, br56=2, ...).
#     Each bridge receives its own /64 subnet calculated as an offset from the base prefix.
#     Even excluded bridges (like br0 or those in EXCLUDED_IFACES) are counted to ensure that
#     index numbering - and therefore subnet assignments - remain stable between reboots or
#     configuration changes.
#   * For each non-excluded SDN bridge, computes a unique /64 subnet inside the PD
#     (/48, /56, or /60 supported) and assigns "<prefix>::1/64" as the router address.
#   * Skips bridges that already have the expected address to avoid redundant operations.
#   * Cleans up wrong-length global IPv6 addresses (e.g. /72 leftovers) before assigning the /64.
#
# Example:
#   WAN PD = 2001:db8:abcd:1000::/56
#   br0  (idx=0) -> 2001:db8:abcd:1000::/64
#   br54 (idx=1) -> 2001:db8:abcd:1001::/64
#   br56 (idx=2) -> 2001:db8:abcd:1002::/64
#
# Requirements / Notes:
#   * This script runs automatically on DHCPv6 bound events and requires:
#       - Global IPv6 enabled in router settings (Advanced Settings -> IPv6)
#       - IPv6 disabled for individual SDN bridges in the GUI (the script handles those instead)
#   * All configuration lives in config.sh (EXCLUDED_IFACES variable). Edit it if you want
#     to exclude specific interfaces. br0 (the main LAN) is always excluded automatically.
#   * Supports PD sizes /48, /56, and /60. If the WAN PD is /64, there are no free /64s to carve
#     beyond br0, so the script exits early.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Exit early on unrelated DHCP events
###################################################################################################
{ [ "$1" = "bound" ] && [ "$2" = "6" ]; } || exit 0

###################################################################################################
# 0b. Load utils and shared variables
###################################################################################################
. /jffs/scripts/utils/common.sh

DIR="$(get_script_dir)"
. "$DIR/config.sh"
. "$DIR/sdn_v6_shared.sh"

###################################################################################################
# 0c. Exit early if IPv6 is disabled
###################################################################################################
exit_if_ipv6_disabled

###################################################################################################
# 0d. Define variables
# -------------------------------------------------------------------------------------------------
# br_count:
#   Counts how many SDN bridges were successfully processed and configured.
#
# errors:
#   Counts the number of errors or failed bridge assignments during script execution.
###################################################################################################
br_count=0
errors=0

###################################################################################################
# 0e. Define helper functions
# -------------------------------------------------------------------------------------------------
# build_bridge_index_map:
#   Lists all bridge interfaces (brNN) with sequential numeric indexes (starting from 0).
#   Includes excluded bridges and br0 so index alignment stays consistent across runs.
#
# hex2int / int2hex:
#   Convert between hexadecimal and decimal values. Used for prefix offset calculations.
#
# calc_h4_for_offset:
#   Given a bridge index and PD length (/48, /56, /60), computes the next H4 segment
#   of the IPv6 prefix for that bridge.
#
# has_expected_addr:
#   Checks whether a bridge already has the expected global IPv6 /64 address.
#
# purge_non64_globals:
#   Removes global IPv6 addresses from the bridge that are not /64
#   (cleanup of old or invalid ones).
###################################################################################################
build_bridge_index_map() {
    local i=0 br
    for br in $(list_bridges); do
        printf '%s %d\n' "$br" "$i"
        i=$((i+1))
    done
}

hex2int() { printf '%d' "0x$1"; }

int2hex() { printf '%x' "$1"; }

calc_h4_for_offset() {
    local idx="$1" base_h4i
    base_h4i="$(hex2int "$H4")"
    case "$PD_LEN" in
        48)
            # 16-bit space (0..65535)
            [ "$idx" -ge 0 ] && [ "$idx" -le 65535 ] || return 1
            int2hex "$idx"
            ;;
        56)
            # preserve upper 8 bits, vary lower 8 bits
            [ "$idx" -ge 0 ] && [ "$idx" -le 255 ] || return 1
            int2hex $(( (base_h4i & 0xFF00) | (idx & 0x00FF) ))
            ;;
        60)
            # preserve upper 12 bits, vary lower 4 bits
            [ "$idx" -ge 0 ] && [ "$idx" -le 15 ] || return 1
            int2hex $(( (base_h4i & 0xFFF0) | (idx & 0x000F) ))
            ;;
    esac
}

has_expected_addr() {
    local br="$1" expect="$2"
    ip -6 addr show dev "$br" scope global |
    awk -v want="${expect}/64" '
        $1 == "inet6" && $2 == want { exit 0 }
        END { exit 1 }
    '
}

purge_non64_globals() {
    local br="$1" addr plen
    ip -6 addr show dev "$br" scope global |
        awk '$1 == "inet6" { print $2 }' |
        while IFS=/ read -r addr plen; do
            [ "${plen:-}" = "64" ] && continue
            ip -6 addr del "${addr}/${plen}" dev "$br" 2>/dev/null || true
            log "Removed non-/64 global from $br -> ${addr}/${plen}"
        done
}

###################################################################################################
# 1. Read PD info & sanity checks
###################################################################################################
PD_PREFIX="$(nvram get ipv6_prefix)"
PD_LEN="$(nvram get ipv6_prefix_len_wan)"
IPV6_SERVICE="$(nvram get ipv6_service)"

# Must have a delegated prefix to do anything useful
if [ -z "$PD_PREFIX" ]; then
    log -l err "No IPv6 prefix (PD) in NVRAM; enable Native (DHCPv6-PD)" \
        "or configure a PD. Exiting..."
    exit 1
fi

# Guard for passthrough; router won't route LAN/SDN IPv6 in this mode
if [ "$IPV6_SERVICE" = "ipv6pt" ]; then
    log -l err "IPv6 service is set to Passthrough; the router does not route IPv6" \
        "to LAN/SDNs in this mode. Exiting..."
    exit 1
fi

# Enforce supported PD sizes, and early-exit on /64 (nothing to carve)
case "$PD_LEN" in
    48|56|60)
        :
        ;;
    64)
        log -l notice "WAN IPv6 PD is /64; no additional /64s can be carved for SDNs. Exiting..."
        exit 0
        ;;
    *)
        log -l err "Unsupported PD length /$PD_LEN (supported: /48, /56, /60). Exiting..."
        exit 1
        ;;
esac

# Normalize "2001:db8:abcd:ef00::" -> first 4 hextets (H1..H4)
BASE="${PD_PREFIX%%::*}"
IFS=':' read -r H1 H2 H3 H4 _ <<EOF
$BASE
EOF
H1="${H1:-0}"; H2="${H2:-0}"; H3="${H3:-0}"; H4="${H4:-0}"

###################################################################################################
# 2. Assign /64s to each SDN bridge (atomic replace; purge non-/64 globals; keep existing /64s)
###################################################################################################

# Build a stable map: every bridge gets a fixed sequential index (br0=0, next=1, ...)
BR_INDEX_MAP="$(build_bridge_index_map)"

# Capacity guard based on PD length
case "$PD_LEN" in
    48) max=65535 ;;
    56) max=255 ;;
    60) max=15 ;;
esac

# Walk the map; assign only to non-excluded bridges, but do count excluded in the index
while read -r br idx; do
    if [ "$max" -ge 0 ] && [ "$idx" -gt "$max" ]; then
        log -l warn "Skipping $br: index=$idx exceeds capacity of PD /$PD_LEN"
        continue
    fi

    nh4="$(calc_h4_for_offset "$idx" || true)"
    if [ -z "${nh4:-}" ]; then
        log -l warn "Failed to compute prefix for $br (idx=$idx)"
        errors=$((errors+1))
        continue
    fi

    # br0 & any excluded bridges are NOT configured,
    # but their index still affects everyone after
    if is_excluded "$br"; then
        log "$br is excluded (main LAN or EXCLUDED_IFACES); keeping it out of scope"
        continue
    fi

    # If IPv6 is enabled for this SDN in the GUI, skip it to avoid conflicts
    is_br_ipv6_disabled "$br" || continue

    prefix="${H1}:${H2}:${H3}:${nh4}"
    want="${prefix}::1"

    if has_expected_addr "$br" "$want"; then
        log "Skipping $br - already configured with ${want}/64"
        continue
    fi

    # Remove wrong-length globals (e.g. /72 leftovers), then install the desired /64
    purge_non64_globals "$br"

    if ip -6 addr replace "${want}/64" dev "$br" 2>/dev/null; then
        log "Configured $br -> ${prefix}::/64 (idx=$idx)"

        # Increment the configured bridge counter
        br_count=$((br_count+1))
    else
        log -l err "ip -6 addr replace failed on $br (idx=$idx)"

        # Increment the error counter
        errors=$((errors+1))
    fi
done <<EOF
$BR_INDEX_MAP
EOF


###################################################################################################
# 3. Finalize
###################################################################################################
if [ "$errors" -eq 0 ]; then
    if [ "$br_count" -gt 0 ]; then
        log "Successfully configured $br_count SDN bridges"
    else
        log -l warn "No eligible bridges found (check EXCLUDED_IFACES)"
    fi
else
    log -l warn "Completed with $errors errors"
    exit 1
fi
