#!/bin/sh
#
# wgclient_route.sh — toggle a static route when a WireGuard client goes up/down
# -------------------------------------------------------------------------------
# Merlin fires two hook scripts:
#       /jffs/scripts/wgclient-start  <client#>
#       /jffs/scripts/wgclient-stop   <client#>
#
# Each hook calls this helper with:
#       wgclient_route.sh  add|del  <client#>
#
# When the <client#> matches WG_CLIENT_NUMBER, the script adds or deletes
# a route so that traffic for WG_CLIENT_SUBNET always leaves through the
# corresponding WG interface (wgcN). No other clients are touched.
#
# Usage examples:
#   wgclient_route.sh add 1      # run by wgclient-start
#   wgclient_route.sh del 1      # run by wgclient-stop
#
# -------------------------------------------------------------------------------
#
# How to choose WG_CLIENT_SUBNET
# ------------------------------
# 1. Open the server-side config and look at the Address line. Example:
#
#        Address = 10.0.0.1/24
#
#    The /24 mask means every peer is in 10.0.0.0-10.0.0.255, i.e. the network
#    10.0.0.0/24.
#
# 2. Use that whole network as WG_CLIENT_SUBNET below. This ensures that LAN
#    devices can reply to any peer in the tunnel, not just the router's own IP.
#
# -------------------------------------------------------------------------------

#################################################################################
#  User-defined variables
#################################################################################
WG_CLIENT_NUMBER=1                # The WG client this script manages (wgcN)
WG_CLIENT_SUBNET='10.0.0.0/24'    # Full subnet of the WireGuard server network

#################################################################################
#  Parse arguments from wgclient-start / wgclient-stop
#################################################################################
ACTION=$1                         # add | del  (requested operation)
CLIENT_NUM=$2                     # Client number passed by Merlin hook

#################################################################################
#  Guard clauses – exit early if the event isn't relevant
#################################################################################

# Skip events for WireGuard clients we don't manage
[ "$CLIENT_NUM" = "$WG_CLIENT_NUMBER" ] || exit 0

# Validate action (must be add or del)
case "$ACTION" in
  add|del) ;;          # allowed actions
  *) exit 1 ;;         # anything else -> hard error
esac

#################################################################################
#  Add or delete the static route
#################################################################################
ip route "$ACTION" "$WG_CLIENT_SUBNET" dev "wgc$WG_CLIENT_NUMBER"
