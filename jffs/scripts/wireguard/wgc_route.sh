#!/usr/bin/env ash

#######################################################################################
# wgc_route.sh - manage static routes for a WireGuard client on Asuswrt-Merlin
# -------------------------------------------------------------------------------------
# What this script does:
#   * When <client#> matches WG_CLIENT_NUMBER:
#       - Adds or deletes routes for WG_CLIENT_SUBNETS via wgcN
#       - Ensures traffic to peers is routed correctly through the tunnel
#   * If <client#> does not match, exits silently.
#   * If <action> is not add or del, exits silently.
#   * Safe to run multiple times - does not create duplicates or break existing routes.
#
# Usage:
#   wgc_route.sh add 1   # invoked by wgclient-start
#   wgc_route.sh del 1   # invoked by wgclient-stop
#######################################################################################

# -------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------
set -euo pipefail

#######################################################################################
# 0a. Define constants & variables
#######################################################################################

# -------------------------------------------------------------------------------------
# WG_CLIENT_NUMBER - index of the WireGuard client this script manages
# -------------------------------------------------------------------------------------
# Specifies which wgcN interface is managed by this script.
#
# Example:
#   WG_CLIENT_NUMBER=1 -> interface is wgc1
# -------------------------------------------------------------------------------------
WG_CLIENT_NUMBER=1

# -------------------------------------------------------------------------------------
# WG_CLIENT_SUBNETS - subnets behind the WireGuard client that LAN should reach
# -------------------------------------------------------------------------------------
# How to choose:
#   1. Check the server-side WireGuard config for its Address.
#      Example:
#
#      Address = 10.0.0.1/24
#
#      The /24 mask implies the network is 10.0.0.0/24 (i.e. 10.0.0.0-10.0.0.255).
#
#   2. Use that full network as a WG_CLIENT_SUBNETS entry. This ensures LAN hosts
#      can respond to any tunnel peer, not just the router's own WG IP.
#
#   3. Optionally, include any additional private subnets that need LAN access.
# -------------------------------------------------------------------------------------
WG_CLIENT_SUBNETS='
10.0.0.0/24
'

#######################################################################################
# 0b. Parse args
#######################################################################################
ACTION="$1"        # add | del  (requested operation)
CLIENT_NUM="$2"    # client number passed by Merlin hook

#######################################################################################
# 0c. Guard clauses - exit early if the event isn't relevant
#######################################################################################

# Skip events for WireGuard clients we don't manage
[ "$CLIENT_NUM" = "$WG_CLIENT_NUMBER" ] || exit 0

# Validate action (must be add or del)
case "$ACTION" in
    add|del)  ;;         # allowed actions
    *) exit 0 ;;         # anything else -> silent exit
esac

#######################################################################################
# 0d. Load utils
#######################################################################################
. /jffs/scripts/utils/common.sh

#######################################################################################
# 1. Add or delete the static routes
#######################################################################################
DEV="wgc$WG_CLIENT_NUMBER"

route_exists() {
    # True if there is at least one matching line
    ip route show "$1" dev "$2" | grep -q .
}

for subnet in $(strip_comments "$WG_CLIENT_SUBNETS"); do
    case "$ACTION" in
        add)
            if ! route_exists "$subnet" "$DEV"; then
                if ip route add "$subnet" dev "$DEV" >/dev/null 2>&1; then
                    log "Route added for $subnet via $DEV"
                else
                    log -l err "Route add failed for $subnet via $DEV"
                fi
            else
                log "Route already present: $subnet via $DEV"
            fi
            ;;
        del)
            if route_exists "$subnet" "$DEV"; then
                if ip route del "$subnet" dev "$DEV" >/dev/null 2>&1; then
                    log "Route deleted for $subnet via $DEV"
                else
                    log -l err "Route del failed for $subnet via $DEV"
                fi
            else
                log "Route not present: $subnet via $DEV"
            fi
            ;;
    esac
done
