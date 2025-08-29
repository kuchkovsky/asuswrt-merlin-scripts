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
#       - <WGC_IF>_RULES: holds interface-agnostic DNAT rules
#   * Inserts per-interface jumps (WireGuard + LAN) from the _VSERVER chain into the _RULES chain
#     to avoid duplicate rules and keep lookups efficient. The LAN jump makes forwarded ports
#     reachable locally on the WG client IP (e.g., 10.0.0.2) from devices on the home LAN -
#     useful for services that reference the WG IP.
#   * Reads PORT_FWD_RULES (one per line) and installs DNAT rules:
#       - Preserves ranges, supports TCP, UDP, or both.
#       - "any" protocol is shorthand for TCP+UDP.
#       - Optional internal port translation, unless multiple external ports/ranges are given
#         (in which case ports are preserved).
#   * Tracks rule sets by computing hashes, applying changes only when needed. This ensures
#     idempotence and avoids unnecessary firewall reloads.
#   * Logs every action and warns when rules are skipped due to unsupported parameters.
#
# Usage:
#   wgc_port_forwarder.sh
#
# Requirements / Notes:
#   * All configurable variables (e.g., PORT_FWD_RULES, WGC_IF) are defined inside this script.
#     Review, edit, then run "wpf" (helper alias) to apply changes without rebooting.
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
. /jffs/scripts/utils/firewall.sh

acquire_lock  # avoid concurrent runs

###################################################################################################
# 0b. Define constants & variables
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Port forwarding rules
# -------------------------------------------------------------------------------------------------
# PORT_FWD_RULES - list of port forwarding rules, one per line:
#
#   ext_ports:proto:int_ip[:int_port]
#     ext_ports - one or more external ports (e.g., 80,443) and/or ranges (e.g., 81-85),
#                 comma-separated.
#                 Note: up to 15 ports/ranges per rule are supported per iptables multiport limit
#     proto     - one of:
#                   tcp        -> match TCP only
#                   udp        -> match UDP only
#                   tcp,udp    -> match both TCP and UDP
#                   any        -> alias for tcp,udp
#     int_ip    - internal LAN host that should receive the traffic
#     int_port  - optional destination port on the internal host.
#                 If specified and different from external port, traffic is translated.
#                 Note: if multiple external ports or a range are used, int_port must be
#                 omitted (ports are preserved)
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
# WG_CLIENT_IP         - IP assigned to this router within the WG subnet
#
# WGC_IF               - WireGuard client interface name on this router
# LAN_IF               - bridge interface for the home LAN
#
# PORT_FWD_RULES_HASH  - path to file storing the last hash of applied port forwarding rules
#
# build_port_fwd_rules - flag: 1 if port forwarding rules need rebuild
# jumps_changed        - flag: 1 if forwarding jumps were modified
# warnings             - flag: non-critical issues encountered during run
# -------------------------------------------------------------------------------------------------
WG_CLIENT_IP='10.0.0.2'

WGC_IF='wgc1'
LAN_IF='br0'

PORT_FWD_RULES_HASH="/tmp/wgc_port_forwarder.sha256"

build_port_fwd_rules=0
jumps_changed=0
warnings=0

###################################################################################################
# 1. Calculate hash and set build flag
###################################################################################################

# Create a temp file to hold normalized port forward rules
port_fwd_rules=$(tmp_file)

# Strip comments and whitespace from PORT_FWD_RULES -> normalized version
strip_comments "$PORT_FWD_RULES" | sed -E 's/[[:blank:]]+//g' > "$port_fwd_rules"

# Hash of an empty ruleset (used for baseline checks)
empty_rules_hash="$(printf '' | compute_hash)"

# Compute current rules hash and load previous one if it exists
new_port_fwd_hash="$(compute_hash "$port_fwd_rules")"
old_port_fwd_hash="$(cat "$PORT_FWD_RULES_HASH" 2>/dev/null || printf '%s' "$empty_rules_hash")"

# Derive chain names from WG interface (uppercased)
wgc_if="$(printf '%s' "$WGC_IF" | tr 'a-z' 'A-Z')"
vserver_chain="${wgc_if}_VSERVER"
rules_chain="${wgc_if}_RULES"

# Flag port forwarding rules for rebuild if:
#   - Hash changed (list of rules was updated)
#   - vserver_chain missing
#   - rules_chain missing
if [ "$new_port_fwd_hash" != "$old_port_fwd_hash" ] \
    || ! fw_chain_exists nat "$vserver_chain" \
    || ! fw_chain_exists nat "$rules_chain";
then
    build_port_fwd_rules=1
fi

###################################################################################################
# 2. Create / reset chains & hook into PREROUTING
###################################################################################################

# Create port forwarding chains if needed
if [ "$build_port_fwd_rules" -eq 1 ]; then
    if [ "$old_port_fwd_hash" != "$empty_rules_hash" ]; then
        log "Configuration has changed; deleting existing rules..."
    fi

    for chain in $vserver_chain $rules_chain; do
        create_fw_chain -f nat "$chain"
    done
fi

# Create PREROUTING jump into the VSERVER chain for this WG client
chg sync_fw_rule --count nat PREROUTING "-d .* -j $vserver_chain$" \
                 "-d $WG_CLIENT_IP/32 -j $vserver_chain" \
    && jumps_changed=1

# -------------------------------------------------------------------------------------------------
# sync_iface_rules
# -------------------------------------------------------------------------------------------------
# Ensures traffic from WG client interface and LAN interface is forwarded into the rules_chain
# for DNAT handling. Keeps rules consistent: purges stale ones, adds missing ones.
# -------------------------------------------------------------------------------------------------
sync_iface_rules() {
    local cur_rules

    # Get current rules in vserver_chain for WG + LAN interfaces
    cur_rules="$(find_fw_rules "nat $vserver_chain" "-i ($WGC_IF|$LAN_IF) -j $rules_chain$")"

    # If both rules already exist (one for WG_IF and one for LAN_IF) -> nothing to do
    if [ "$(printf '%s\n' "$cur_rules" | wc -l)" -eq 2 ]; then
        log "Rules are already present: in_iface=$WGC_IF,$LAN_IF -> $rules_chain"
    else
        # Purge stale/duplicate iface rules to avoid drift
        chg purge_fw_rules --count "nat $vserver_chain" "-i .* -j $rules_chain$" \
            && jumps_changed=1

        # Add new rules for both WG and LAN interfaces
        for iface in $WGC_IF $LAN_IF; do
            chg ensure_fw_rule --count nat "$vserver_chain" -i "$iface" -j "$rules_chain" \
                && jumps_changed=1
        done
    fi
}

# Sync interface rules now
sync_iface_rules

###################################################################################################
# 3. Parse & apply DNAT rules
###################################################################################################

# Count multiport elements (ranges count as 2)
count_mp_elems() {
    local s="$1" n=0 f IFS=,
    set -- $s
    for f; do
        case "$f" in
            *-*) n=$((n+2)) ;;  # A-B counts as 2
            *)   n=$((n+1)) ;;
        esac
    done
    printf '%s\n' "$n"
}

if ! [ -s "$port_fwd_rules" ]; then
    log "No port forwarding rules are defined"
elif [ "$build_port_fwd_rules" -eq 0 ]; then
    log "Port forwarding rules are applied and up-to-date"
else
    log "Applying port forwarding rules..."

    # Iterate over rules
    while IFS=: read -r ext_ports protos int_ip int_port; do
        # Validate 'ext_ports'
        if [ "$ext_ports" = "any" ] || ! validate_ports "$ext_ports"; then
            log -l warn "Invalid 'ext_ports' spec '$ext_ports' -" \
                "expected a single port (1-65535), a range n-m (1-65535, n<=m)," \
                "or a comma-separated list of those; skipping rule"
            warnings=1
            continue
        fi

        # Validate presence of 'protos' and 'int_ip'
        [ -z "$protos" ] && { log -l warn "Empty 'protos'; skipping rule"; warnings=1; continue; }
        [ -z "$int_ip" ] && { log -l warn "Empty 'int_ip'; skipping rule"; warnings=1; continue; }

        # Validate / normalize 'protos'
        if ! protos_norm="$(normalize_protos "$protos")"; then
            log -l warn "Invalid 'protos' spec '$protos' - expected" \
                "'tcp', 'udp', 'tcp,udp', or 'any'; skipping rule"
            warnings=1
            continue
        fi

        # Validate 'int_ip' (must be LAN)
        if ! is_lan_ip "$int_ip"; then
            log -l warn "'int_ip' '$int_ip' is not a valid LAN address; skipping rule"
            warnings=1
            continue
        fi

        # Validate 'int_port' (optional; must be a single port)
        if [ -n "$int_port" ]; then
            if ! validate_port "$int_port"; then
                log -l warn "Invalid internal port '$int_port'" \
                    "(must be a single port 1..65535); skipping rule"
                warnings=1
                continue
            fi
            int_port_spec=":$int_port"
        else
            int_port_spec=""
        fi

        # Build port_spec:
        #   - single port      -> --dport N
        #   - single range     -> --dport A:B
        #   - list/ranges/mix  -> -m multiport --dports ...
        case "$ext_ports" in
            *,*)
                # Any comma means multiple external ports / ranges -> multiport
                if [ "$(count_mp_elems "$ext_ports")" -gt 15 ]; then
                    log -l warn "Too many ports for multiport (max 15): $ext_ports; skipping rule"
                    warnings=1
                    continue
                fi

                if [ -n "$int_port" ]; then
                    log -l warn "'int_port' is not supported when 'ext_ports'" \
                        "contains multiple entries; skipping rule"
                    warnings=1
                    continue
                fi

                port_spec="-m multiport --dports ${ext_ports//-/:}"
                ;;
            *-*)
                # No commas, one range like A-B -> use bare --dport A:B
                if [ -n "$int_port" ]; then
                    log -l warn "'int_port' is not supported when 'ext_ports'" \
                        "is a range; skipping rule"
                    warnings=1
                    continue
                fi

                port_spec="--dport ${ext_ports//-/:}"
                ;;
            *)
                # Single port
                port_spec="--dport $ext_ports"
                ;;
        esac

        # Add rules for each proto
        for proto in ${protos_norm//,/ }; do
            ensure_fw_rule nat "$rules_chain" \
                -p "$proto" $port_spec \
                -j DNAT --to-destination "${int_ip}${int_port_spec}"
        done
    done < "$port_fwd_rules"
fi

# Save hash for the current run
printf '%s\n' "$new_port_fwd_hash" > "$PORT_FWD_RULES_HASH"

###################################################################################################
# 4. Finalize
###################################################################################################
if [ "$build_port_fwd_rules" -eq 0 ] && [ "$jumps_changed" -eq 0 ]; then
    log "All firewall rules are already present"
elif [ "$warnings" -eq 0 ]; then
    log "All changes have been applied successfully"
else
    log -l warn "Completed with warnings; please check logs for details"
fi
