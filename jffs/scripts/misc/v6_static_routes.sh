#!/usr/bin/env ash

###################################################################################################
# v6_static_routes.sh - create static IPv6 routes to LAN hosts
# -------------------------------------------------------------------------------------------------
# Why this script is needed:
#   When your ISP delegates a larger IPv6 prefix (e.g., /56), you can carve out individual
#   subnets (commonly /64, but any prefix length is supported) for specific LAN hosts -
#   such as a Docker host or a hypervisor - instead of assigning just a single IPv6 address,
#   and route those subnets toward that hosts on your LAN.
#   Since the ASUS firmware currently lacks built-in support for IPv6 static routes,
#   this script provides that missing functionality.
#
# What this script does:
#   * Reads STATIC_ROUTE_RULES (one rule per line in the form: iface|link_local|static_route).
#     Each rule defines one static route toward a specific LAN host or downstream router.
#   * Validates each rule:
#       - Ensures the interface exists.
#       - Verifies that link_local is within fe80::/10 (link-local scope).
#   * Applies idempotent route updates:
#       - Skips routes that already exist with the same prefix, next-hop, interface, and metric.
#       - Removes conflicting routes for the same prefix that use a different next-hop,
#         interface, or metric.
#       - Otherwise, creates or updates the route via 'ip -6 route replace'.
#   * Logs all actions; warns when rules are malformed or unverifiable.
#
# Requirements / Notes:
#   * The link-local next-hop (fe80::...) must belong to the target host on the specified
#     interface. Find it on the host with:  ip -6 addr show dev <iface>
#   * Using link-local next-hops is the standard approach for on-link static routes.
#     It avoids dependency on global address churn caused by SLAAC or DHCPv6 renewals.
#   * Supports any valid IPv6 prefix size (/48-/128). Typical routed subnets are /64,
#     but smaller or larger prefixes work as well.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2086

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Exit early on unrelated DHCP events
###################################################################################################
case "$1:$2" in
    bound:6|updated:6)
        ;;
    *)
        exit 0
        ;;
esac

###################################################################################################
# 0b. Load utils
###################################################################################################
. /jffs/scripts/utils/common.sh

###################################################################################################
# 0c. Exit early if IPv6 is disabled
###################################################################################################
if [ "$(get_ipv6_enabled)" -eq 0 ]; then
    log -l err "IPv6 is globally disabled. Enable it in Web UI: Advanced Settings -> IPv6"
    exit 1
fi

###################################################################################################
# 0d. Define constants & variables
###################################################################################################

# -------------------------------------------------------------------------------------------------
# STATIC_ROUTE_RULES - one rule per line: iface|link_local|static_route
# -------------------------------------------------------------------------------------------------
# Syntax (no spaces; comments allowed with "#", blank lines ignored):
#   <iface>|<link_local>|<static_route>
#
# Fields:
#   iface        - router interface that reaches the target host (e.g., br0, br52).
#   link_local   - link-local address of the target host on that interface (must be fe80::/10).
#                  Do NOT append "/64" here - it's a single address, not a prefix.
#   static_route - IPv6 subnet to be routed to that host (typically a /64 carved from your /56).
#
# Tips:
#   * Find the host's link-local address on the host itself:
#         ip -6 addr show dev <iface>
#   * Multiple rules are supported; each will be validated and applied independently.
#   * Example carving /64 subnets from 2a10:abcd:1234:aa00::/56:
#         br0|fe80::1234:56ff:fe78:9abc|2a10:abcd:1234:aa10::/64
#         br0|fe80::1234:56ff:fe78:9abc|2a10:abcd:1234:aa20::/64
#
# Note:
#   Avoid using the first few subnets from your delegated prefix if you also use the
#   sdn_v6_br.sh script for SDN IPv6 configuration. That script automatically assigns
#   the earliest /64s (starting from index 0) to SDN bridges, so using the same ranges
#   for static routes may cause prefix conflicts.
# -------------------------------------------------------------------------------------------------
STATIC_ROUTE_RULES='
'

# -------------------------------------------------------------------------------------------------
# ROUTE_METRIC - route preference for static routes
# -------------------------------------------------------------------------------------------------
# What it is:
#   An integer "cost" value used by the kernel to choose between multiple routes with the same
#   prefix length. Lower values are preferred. For specific routed subnets (e.g., /64s),
#   route specificity already takes precedence over ::/0, so this metric typically won't compete
#   with the default route.
#
# How to choose:
#   * Use a consistent value across all your static routes (e.g., 256).
#   * If another route exists for the same prefix, assign a lower metric to the preferred path.
#   * View current metrics with:  ip -6 route  (look for "metric N")
#   * The kernel default metric for most interfaces is 256.
#   * In most setups, leaving the default value is perfectly fine.
# -------------------------------------------------------------------------------------------------
ROUTE_METRIC=256

# -------------------------------------------------------------------------------------------------
# Script state variables
# -------------------------------------------------------------------------------------------------
# route_count:
#   Counts how many routes were successfully processed and configured.
#
# errors:
#   Counts the number of errors or failed route assignments during script execution.
###################################################################################################
route_count=0
errors=0

###################################################################################################
# 1. Apply static routes
###################################################################################################

# Create temporary file to hold normalized rule definitions
static_route_rules="$(tmp_file)"

# Strip comments and whitespace from rules -> normalized version
strip_comments "$STATIC_ROUTE_RULES" |
sed -E '/^[[:space:]]*$/d; s/[[:space:]]+//g' > "$static_route_rules"

while IFS='|' read -r iface link_local static_route; do
    # Any field missing?
    if [ -z "$iface" ] || [ -z "$link_local" ] || [ -z "$static_route" ]; then
        log -l warn "Malformed rule (need iface|link_local|static_route):" \
            "iface='$iface' link_local='$link_local' static_route='$static_route'; skipping"
        continue
    fi

    # Basic validation: interface must exist
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
        log -l warn "Interface '$iface' not found; skipping $static_route"
        continue
    fi

    # Enforce link-local next-hop (fe80::/10)
    case "$link_local" in
        fe8?:*|fe9?:*|fea?:*|feb?:*) ;;
        *)
            log -l warn "Next-hop '$link_local' is not link-local (fe80::/10);" \
                "skipping $static_route on $iface"
            continue
            ;;
    esac

    matched=0
    matched_metric=""

    # Look for existing routes to this prefix and remove any that don't match our definition
    existing="$(ip -6 route show "$static_route" 2>/dev/null || true)"
    if [ -n "$existing" ]; then
        routes_file="$(tmp_file)"; printf '%s\n' "$existing" > "$routes_file"

        while IFS= read -r line; do
            # Extract via/dev/metric from the route line
            set -- $line
            via=""; dev=""; met=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    via)    via="$2";    shift 2 ;;
                    dev)    dev="$2";    shift 2 ;;
                    metric) met="$2";    shift 2 ;;
                    *)      shift ;;
                esac
            done

            # Skip lines that don't describe a via+dev route for this prefix
            [ -z "$via" ] && continue

            if [ "$via" = "$link_local" ] && [ "$dev" = "$iface" ] && \
               { [ -z "$met" ] || [ "$met" -eq "$ROUTE_METRIC" ]; };
            then
                matched=1
                matched_metric="$met"
            else
                # Remove conflicting entry for the same prefix
                set -- ip -6 route del "$static_route" via "$via" dev "$dev"
                [ -n "$met" ] && set -- "$@" metric "$met"

                if "$@" 2>/dev/null; then
                    log "Removed conflicting IPv6 route:" \
                        "$static_route via $via dev $dev${met:+ metric $met}"
                fi
            fi
        done < "$routes_file"
    fi

    # If we already have the exact route (and metric matches or is unspecified), skip it
    if [ "$matched" -eq 1 ] && { [ -z "$matched_metric" ] || \
        [ "$matched_metric" -eq "$ROUTE_METRIC" ]; };
    then
        log -l debug "IPv6 route already present: $static_route via $link_local" \
            "dev $iface metric ${matched_metric:-none}"

        # Increment the configured route counter
        route_count=$((route_count+1))

        continue
    fi

    # Create or update the route
    if ip -6 route replace "$static_route" via "$link_local" \
        dev "$iface" metric "$ROUTE_METRIC";
    then
        log "Created IPv6 route: $static_route via $link_local" \
            "dev $iface metric $ROUTE_METRIC"

        # Increment the configured route counter
        route_count=$((route_count+1))
    else
        log -l err "Failed to create route: $static_route via $link_local" \
            "dev $iface metric $ROUTE_METRIC"

        # Increment the error counter
        errors=$((errors+1))
    fi
done < "$static_route_rules"

###################################################################################################
# 2. Finalize
###################################################################################################
if [ "$route_count" -gt 0 ]; then
    log -l debug "Successfully configured $route_count static routes"
fi

if [ "$errors" -gt 0 ]; then
    log -l warn "Failed to configure $errors routes"
    exit 1
fi
