#!/usr/bin/env ash

###################################################################################################
# wgc_port_forwarder.sh - adds port forwarding support for the WireGuard client
# -------------------------------------------------------------------------------------------------
# Background:
#   Asuswrt's GUI can only forward ports to the WAN interface; it cannot forward traffic arriving
#   via a WireGuard client tunnel (wgcX) to LAN hosts. This script adds DNAT rules so services
#   behind the router are reachable through the tunnel.
#
# What this script does:
#   * Creates two dedicated iptables NAT chains:
#       - <WGC_IF>_VSERVER: hooked into PREROUTING for the WG client's IP
#       - <WGC_IF>_VSERVER_RULES: holds interface-agnostic DNAT rules
#   * Inserts per-interface jumps (WireGuard + LAN) from the _VSERVER chain into
#     the _VSERVER_RULES chain to avoid duplicate rules and keep lookups efficient.
#     The LAN jump makes forwarded ports reachable locally on the WG client IP (e.g. 10.0.0.2)
#     from devices on the home LAN - useful for services that reference the WG IP.
#   * Reads PORT_FWD_RULES (one per line) and installs DNAT rules:
#       - Preserves ranges, supports TCP, UDP, or both.
#       - "any" protocol is shorthand for TCP+UDP.
#       - Optional internal port translation, unless multiple external ports/ranges are given
#         (in which case ports are preserved).
#   * Logs every action and warns when rules are skipped due to unsupported parameters.
#
# Usage:
#   wgc_port_forwarder.sh
#
# Requirements / Notes:
#   * All configurable variables (e.g., PORT_FWD_RULES, WGC_IF) are defined inside this script.
#     Adjust them before running.
#   * IPv4 only; extend to IPv6 if needed.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2018
# shellcheck disable=SC2019
# shellcheck disable=SC2086

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Load utils
###################################################################################################
. /jffs/scripts/utils/common.sh

###################################################################################################
# 0b. Define constants & variables
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Port forwarding rules
# -------------------------------------------------------------------------------------------------
# PORT_FWD_RULES - list of port forwarding rules, one per line:
#
#   ext_ports:proto:int_ip[:int_port]
#     ext_ports - one or more external ports (e.g. 80,443) and/or ranges (e.g. 81-85),
#                 comma-separated.
#                 Note: up to 15 ports/ranges per rule are supported.
#     proto     - one of:
#                   tcp        -> match TCP only
#                   udp        -> match UDP only
#                   tcp,udp    -> match both TCP and UDP
#                   any        -> alias for tcp,udp
#     int_ip    - internal LAN host that should receive the traffic.
#     int_port  - optional destination port on the internal host.
#                 If specified and different from external port, traffic is translated.
#                 Note: if multiple external ports or a range are used, int_port must be
#                 omitted (ports are preserved).
#
# Example:
#   139,445:tcp:192.168.50.1          # SMB ports on the router
#   8080:tcp:192.168.50.1:80          # external 8080 -> internal 80 (router's Web UI)
#   443:any:192.168.50.2              # HTTPS with HTTP/3 support, TCP+UDP preserved
#   6000-6010:udp:192.168.50.3        # UDP range preserved
# -------------------------------------------------------------------------------------------------
PORT_FWD_RULES='
'

# -------------------------------------------------------------------------------------------------
# WireGuard & interface variables
# -------------------------------------------------------------------------------------------------
# WG_CLIENT_IP   - IP assigned to this router within the WG subnet.
# WGC_IF         - WireGuard client interface name on this router.
# LAN_IF         - bridge interface for the home LAN.
# -------------------------------------------------------------------------------------------------
WG_CLIENT_IP='10.0.0.2'
WGC_IF='wgc1'
LAN_IF='br0'

# Flag: non-critical issues encountered
warnings=0

###################################################################################################
# 0c. Exit early if rules are not defined
###################################################################################################
port_fwd_rules=$(strip_comments "$PORT_FWD_RULES" | sed -E 's/[[:blank:]]+//g')

if [ -z "$port_fwd_rules" ]; then
    log "No port forwarding rules defined. Exiting..."
    exit 0
fi

###################################################################################################
# 1. Create / reset chains & hook into PREROUTING
###################################################################################################
vserver_chain="$(printf '%s' "$WGC_IF" | tr 'a-z' 'A-Z')_VSERVER"
rules_chain="${vserver_chain}_RULES"

for chain in $vserver_chain $rules_chain; do
    if iptables -t nat -F "$chain" 2>/dev/null; then
        log "Flushed existing chain $chain"
    else
        iptables -t nat -N "$chain"
        log "Created new chain $chain"
    fi
done

ensure_fw_rule nat PREROUTING -d "$WG_CLIENT_IP/32" -j "$vserver_chain"
log "Inserted jump: nat PREROUTING dest=$WG_CLIENT_IP -> $vserver_chain"

for iface in $WGC_IF $LAN_IF; do
    ensure_fw_rule nat "$vserver_chain" -i "$iface" -j "$rules_chain"
    log "Inserted jump: $vserver_chain iface=$iface -> $rules_chain"
done

###################################################################################################
# 2. Parse & apply DNAT rules
###################################################################################################
log "Applying port forwarding rules..."

while IFS=: read -r ext_ports protos int_ip int_port; do
    # No need to validate ext_ports - strip_comments ensures at least one arg
    [ -z "$protos" ] && { log -l warn "Empty protos - skipping"; warnings=1; continue; }
    [ -z "$int_ip" ] && { log -l warn "Empty int_ip - skipping"; warnings=1; continue; }

    if printf '%s\n' "$ext_ports" | grep -q '[,-]'; then
        if [ -n "$int_port" ]; then
            log -l warn "int_port is not supported for multiple ext_ports - skipping"
            warnings=1
            continue
        fi
        port_spec="-m multiport --dports $(printf '%s' "$ext_ports" | tr '-' ':')"
    else
        port_spec="--dport $ext_ports"
    fi

    [ "$protos" = "any" ] && protos="tcp,udp"
    [ -n "$int_port" ] && int_port=":$int_port"

    for proto in $(printf '%s' "$protos" | tr ',' ' '); do
        ensure_fw_rule nat "$rules_chain" \
            -p "$proto" $port_spec \
            -j DNAT --to-destination "${int_ip}${int_port}"

        log "Added DNAT rule -> $rules_chain: proto=$proto ports=$ext_ports" \
            "-> ${int_ip}${int_port}"
    done
done <<EOF
$port_fwd_rules
EOF

if [ "$warnings" -eq 0 ]; then
    log "All port forwarding rules have been created successfully"
else
    log -l warn "Completed with warnings; please check logs for details"
fi
