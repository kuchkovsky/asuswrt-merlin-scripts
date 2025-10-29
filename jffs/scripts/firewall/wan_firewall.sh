#!/usr/bin/env ash

###################################################################################################
# wan_firewall.sh - inbound WAN firewall for Asuswrt-Merlin (ipset-based blocking & DoS Protection)
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Detects the ports exposed by the ASUS GUI and targets only that inbound traffic
#     on the WAN interface.
#   * Drops malicious, bogon, geo-restricted, or custom-listed sources via ipsets before
#     they reach DNAT or the conntrack table. Integrates a predefined FireHOL Level 1
#     ipset (via the builder) for baseline protection.
#   * Adds optional flood / DoS rate limits (per-IP and per-destination-port) with controlled
#     logging using xt_hashlimit.
#   * Maintains its own rule set in a dedicated raw table chain and auto-refreshes when you
#     change port forwarding settings.
#   * Tracks rule sets by computing hashes, applying changes only when needed. This ensures
#     idempotence and avoids unnecessary firewall reloads.
#   * Integrates with the ipsets produced by ipset_builder.sh.
#   * Plays nicely with the temporary killswitch from ipset_builder.sh by inserting its jumps
#     immediately after the killswitch jump in raw PREROUTING so traffic remains blocked until
#     filtering is ready.
#
# Requirements / Notes:
#   * Designed for setups without double NAT - your ISP modem should be in bridge mode
#     so the router receives a public IP directly on its WAN interface.
#   * All important variables live in config.sh. Review, edit, then run "ipw"
#     (helper alias) to apply changes without rebooting.
#   * ipset-based filtering requires the ipsets built by ipset_builder.sh. If ipsets are
#     not yet loaded, this script falls back to DoS-only protection and skips ipset checks.
#   * GeoLite2 country ipsets require MAXMIND_LICENSE_KEY and mounted external storage;
#     sign up for a free account and set the license key if you want to use this database.
#     If the key is unset or storage is unmounted, the script falls back to IPdeny.
#   * Supports IPv4 and IPv6 (dual-stack). IPv4 ports are derived from DNAT rules in
#     the VSERVER chain; IPv6 ports are discovered from ACCEPT rules in the
#     filter FORWARD chain (populated by the ASUS GUI based on the settings defined in
#     Firewall -> General -> IPv6 Firewall).
#   * This script is designed to operate on inbound traffic only, specifically targeting
#     ports that are publicly exposed to the WAN. It intentionally does not filter or
#     inspect outbound traffic.
#   * Recommended: if possible, forward only ports <= 32767 in the ASUS GUI, avoiding
#     higher port numbers. Ports >= 32768 are commonly used as ephemeral source ports by
#     major operating systems (Linux, macOS, iOS, Windows, Android). Staying at or below 32767
#     reduces edge cases where reply traffic from outbound connections might reuse the same
#     numbers as your forwarded services, keeping matching in raw PREROUTING unambiguous.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2086
# shellcheck disable=SC2153

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
. "$DIR/fw_shared.sh"

acquire_lock  # avoid concurrent runs

###################################################################################################
# 0b. Define constants & variables
# -------------------------------------------------------------------------------------------------
# WAN_IF                         - active WAN interface (auto-detected)
# IPV6_ENABLED                   - flag: 1 if IPv6 is enabled on the router
#
# ipv4_ready                     - flag: 1 if IPv4 port mappings were detected
# build_dos_prot_rules           - flag: 1 if IPv4 DoS Protection rules should be rebuilt
# build_wan_fw_rules             - flag: 1 if IPv4 WAN Firewall ipset-based rules should be rebuilt
# jump_rules_inserted            - flag: 1 if IPv4 chain jump rules have been inserted
# dos_prot_rules_warnings        - flag: 1 if non-critical IPv4 DoS Protection issues encountered
# wan_fw_rules_warnings          - flag: 1 if non-critical IPv4 WAN Firewall issues encountered
#
# ipv6_ready                     - flag: 1 if IPv6 allow rules (FORWARD) were detected
# build_dos_prot_v6_rules        - flag: 1 if IPv6 DoS Protection rules should be rebuilt
# build_wan_fw_v6_rules          - flag: 1 if IPv6 WAN Firewall ipset-based rules should be rebuilt
# jump_v6_rules_inserted         - flag: 1 if IPv6 chain jump rules have been inserted
# dos_prot_v6_rules_warnings     - flag: 1 if non-critical IPv6 DoS Protection issues encountered
# wan_fw_v6_rules_warnings       - flag: 1 if non-critical IPv6 WAN Firewall issues encountered
#
# dos_prot_rules                 - temp file for normalized IPv4 DoS Protection rules
# wan_fw_rules                   - temp file for normalized IPv4 WAN Firewall rules
# dos_prot_v6_rules              - temp file for normalized IPv6 DoS Protection rules
# wan_fw_v6_rules                - temp file for normalized IPv6 WAN Firewall rules
###################################################################################################
WAN_IF=$(get_active_wan_if)

IPV6_ENABLED="$(get_ipv6_enabled)"

ipv4_ready=0
build_dos_prot_rules=0
build_wan_fw_rules=0
jump_rules_inserted=0
dos_prot_rules_warnings=0
wan_fw_rules_warnings=0

ipv6_ready=0
build_dos_prot_v6_rules=0
build_wan_fw_v6_rules=0
jump_v6_rules_inserted=0
dos_prot_v6_rules_warnings=0
wan_fw_v6_rules_warnings=0

_empty_file=$(tmp_file)
dos_prot_rules="$_empty_file"
wan_fw_rules="$_empty_file"
dos_prot_v6_rules="$_empty_file"
wan_fw_v6_rules="$_empty_file"

###################################################################################################
# 0c. Define helper functions
# -------------------------------------------------------------------------------------------------
# get_ports            - extract destination ports from DNAT rules for a given proto,
#                        one per line, sorted numerically
# get_ports6           - extract service ports from IPv6 FORWARD chain (tcp/udp, dport),
#                        expanding lists and ranges into individual numeric ports
#                        and sorting them uniquely
# compress_ports       - collapse a sorted list of ports into "80,81:85,443" form
# chunk15              - split a comma-separated list into ≤15-item chunks (for multiport)
#
# sanitize_hl_name     - normalize a hashlimit name (A-Z a-z 0-9 _), cap to given length
#
# calc_hashlimit_rate  - given minutes, return an iptables rate string for 1 log per window
#                        e.g., 1 -> "1/min", 30 -> "2/hour", 120 -> "12/day"
# calc_limit_rate      - given log_count and minutes, return a compact rate string that
#                        spreads log_count across the window ("/min", "/hour", or "/day"),
#                        clamped to at least 1/day
###################################################################################################

# Extract destination ports from VSERVER rules:
# - Read the target NAT chain ruleset from iptables.
# - In awk:
#     * Consider only lines that append to the chain ('-A <chain>')
#     * Walk all fields (order-agnostic), capture:
#         - protocol after '-p'
#         - destination port after '--dport'
#     * When protocol equals the requested one ('tcp' or 'udp') and a port is found:
#         - emit a single port as-is
#         - expand N:M ranges into individual ports
# - Post-process: numeric sort + unique.
get_ports() {
    iptables -t nat -S "$VSERVER_CHAIN" 2>/dev/null |
    awk -v P="$1" '
        $1 == "-A" {
            proto = ""; port = ""
            for (i = 1; i <= NF; i++) {
                if      ($i == "-p")       proto = $(i + 1)
                else if ($i == "--dport")  port  = $(i + 1)
                if (proto != "" && port != "") break
            }
            if (proto != P || port == "") next

            if (port ~ /^[0-9]+:[0-9]+$/) {
                split(port, r, ":")
                start = r[1] + 0
                stop  = r[2] + 0
                for (p = start; p <= stop; p++) print p
            } else if (port ~ /^[0-9]+$/) {
                print port + 0
            }
        }
    ' | sort -nu

    return 0
}

# Extract (src/dst) service ports from IPv6 FORWARD rules:
# - Read the filter table FORWARD chain (ip6tables -S FORWARD).
# - Consider only ACCEPT rules with a protocol match (-p tcp|udp) and any of:
#     --dport, --dports
# - Expand comma-separated lists and N:M ranges into individual ports.
# - Output: one port per line, numeric-sorted and deduplicated.
get_ports6() {
    ip6tables -t filter -S FORWARD 2>/dev/null |
    awk -v P="$1" '
        $1 == "-A" && $2 == "FORWARD" {
            proto = ""; port_spec = ""; accept = 0
            for (i = 1; i <= NF; i++) {
                if ($i == "-p" && i + 1 <= NF) proto = $(i + 1)
                else if (($i == "--dport" || $i == "--dports") && i + 1 <= NF) port_spec = $(i + 1)
                else if ($i == "-j" && i + 1 <= NF && $(i + 1) == "ACCEPT") accept = 1
            }
            if (proto != P || !accept || port_spec == "") next

            n = split(port_spec, items, ",")
            for (k = 1; k <= n; k++) {
                p = items[k]
                if (p ~ /^[0-9]+:[0-9]+$/) {
                    split(p, r, ":")
                    s = r[1] + 0; e = r[2] + 0
                    for (x = s; x <= e; x++) print x
                } else if (p ~ /^[0-9]+$/) {
                    print p + 0
                }
            }
        }
    ' | sort -nu

    return 0
}

# Collapse a sorted list of ports into a compact comma/range string:
# - Input: one port per line, already numeric-sorted and deduplicated.
# - Ignores:
#     * blank lines
#     * non-numeric entries
#     * port 0 or negative values
# - Tracks contiguous runs with 'run_start' and 'prev'. For each new 'cur':
#     * If it equals 'prev'          -> skip duplicate
#     * If it equals 'prev' + 1      -> extend the run
#     * Otherwise                    -> flush the finished run:
#         - single port  -> "N"
#         - range        -> "start:end"
# - Commas are inserted between runs (managed via 'first' flag).
# - 'ORS=""' emits everything on a single line. 'cur = $1 + 0' coerces to number.
# - The 'END' block flushes the last run; no output if no valid ports remain.
# - Assumes input is sorted; unsorted input will produce incorrect ranges.
compress_ports() {
    awk '
        BEGIN { ORS=""; first=1; run_start=""; prev="" }

        # Ignore blank or non-numeric lines
        /^[[:space:]]*$/ { next }
        $1 !~ /^[0-9]+$/ { next }

        {
            cur = $1 + 0
            if (cur <= 0) next                # drop port 0 or negatives
            if (run_start == "") {            # first valid number
                run_start = prev = cur
                next
            }
            if (cur == prev) next             # ignore duplicates
            if (cur == prev + 1) {            # continue the run
                prev = cur
                next
            }

            # Flush finished run
            if (!first) printf(","); first = 0
            if (run_start == prev)  printf("%d", run_start);
            else                    printf("%d:%d", run_start, prev);

            run_start = prev = cur
        }

        END {
            if (run_start == "") exit         # no valid input
            if (!first) printf(",")
            if (run_start == prev)  printf("%d", run_start);
            else                    printf("%d:%d", run_start, prev);
        }
    '
}

# Split a comma-separated list into lines of ≤15 items (for multiport limits):
# - Input ($1): a single string like "a,b,c,d,...".
# - Output: one line per chunk, each line a comma-joined slice of up to 15 items.
#   Example:
#     In : "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"
#     Out: "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15"
#          "16"
#
# - Implementation:
#   * Uses the IFS=',' trick to expand the list into positional params while preserving order.
#   * For each item:
#       - normal port consumes 1 slot,
#       - a:b range consumes 2 slots (since multiport counts ranges as two).
#   * Accumulates items in 'chunk', emitting when the cap (15) would be exceeded.
#   * Trims the trailing comma before printing each chunk.
#   * Always prints the final (possibly shorter) chunk at the end.
#
# - Notes:
#   * Specifically designed for iptables '-m multiport', which supports up to 15 entries
#     where a range = 2 entries.
#   * Assumes items themselves don't contain commas or spaces (true for port lists).
#   * Produces no output if input is empty.
chunk15() {
    local list="$1" cap=15 used=0 chunk="" item IFS_SAVE cost
    [ -z "$list" ] && return

    IFS_SAVE=$IFS
    IFS=','; set -- $list; IFS=$IFS_SAVE

    for item; do
        case "$item" in
            *:*) cost=2 ;;   # a:b range consumes two slots
            *)   cost=1 ;;
        esac

        if [ $((used + cost)) -gt $cap ]; then
            printf '%s\n' "${chunk%,}"
            chunk=""; used=0
        fi

        chunk="${chunk}${item},"
        used=$((used + cost))
    done

    printf '%s\n' "${chunk%,}"
}

sanitize_hl_name() {
    # $1 = desired name, $2=max length (default 15)
    local name="$1" max="${2:-15}" cleaned

    # Keep A-Z a-z 0-9 and underscore; replace others with _
    cleaned=${name//[!A-Za-z0-9_]/_}

    # Cap length
    printf '%s' "${cleaned:0:$max}"
}

# Convert a window length (in minutes) into an iptables rate string for
# "one event per window."
# - Input : m (minutes, integer)
# - Output: "X/min", "X/hour", or "X/day"
# - Logic :
#     * m <= 1         -> "1/min"
#     * 60 % m == 0    -> exact hourly mapping:  (60 / m) "/hour"
#     * 1440 % m == 0  -> exact daily  mapping:  (1440 / m) "/day"
#     * otherwise      -> fallback to "1/min" (no fractional rates)
# - Examples:
#     m=1     -> 1/min
#     m=5     -> 12/hour
#     m=30    -> 2/hour
#     m=120   -> 12/day
#     m=7     -> 1/min  (no exact hour/day divisor)
calc_hashlimit_rate() {
    local m=$1    # $1 = minutes (integer) -> prints e.g., "30/hour"
    [ "$m" -le 1 ] && { printf '%s\n' '1/min'; return; }

    if [ $((60 % m)) -eq 0 ]; then
        printf '%s\n' "$((60 / m))/hour"
        return
    fi

    if [ $((1440 % m)) -eq 0 ]; then
        printf '%s\n' "$((1440 / m))/day"
        return
    fi

    # Fallback: log once per minute if no exact integer mapping
    printf '%s\n' '1/min'
}

# Distribute a total allowance (LOG_COUNT) across a window (MINUTES) and return a
# compact iptables rate string that never uses fractions.
# - Inputs :
#     * count = LOG_COUNT (defaults to 1 if <1)
#     * mins  = MINUTES   (defaults to 1 if <1)
# - Output : "N/min", "N/hour", or "N/day"
# - Strategy (prefer exact integers first):
#     1. If count/mins is an integer -> emit that in "/min".
#     2. Else if (count*60)/mins is an integer -> emit in "/hour".
#     3. Else if (count*1440)/mins is an integer -> emit in "/day".
#     4. Otherwise pick the smallest unit with a non-zero floor:
#          floor(count/mins)/min, else floor(count*60/mins)/hour,
#          else floor(count*1440/mins)/day.
#     5. If all floors are 0 (ultra-low target), clamp to "1/day".
# - Examples:
#     (count=5,  mins=10) -> 30/hour   (exact hourly)
#     (count=1,  mins=5)  -> 12/hour   (exact hourly)
#     (count=2,  mins=7)  -> 17/day    (smallest non-zero daily floor)
#     (count=1,  mins=2000) -> 1/day   (clamped)
calc_limit_rate() {
    local count="${1:-1}" mins="${2:-1}"
    [ "$count" -ge 1 ] || count=1
    [ "$mins"  -ge 1 ] || mins=1

    # Exact integer matches first
    if [ $(( count % mins )) -eq 0 ]; then
        printf '%d/min\n' $(( count / mins ))
        return
    fi
    if [ $(( (count*60) % mins )) -eq 0 ]; then
        printf '%d/hour\n' $(((count*60) / mins))
        return
    fi
    if [ $(( (count*1440) % mins )) -eq 0 ]; then
        printf '%d/day\n' $(((count*1440) / mins))
        return
    fi

    # Otherwise, smallest unit with nonzero floor
    local per_min=$(( count / mins ))
    [ "$per_min" -ge 1 ] && { printf '%d/min\n' "$per_min"; return; }

    local per_hour=$(( (count*60) / mins ))
    [ "$per_hour" -ge 1 ] && { printf '%d/hour\n' "$per_hour"; return; }

    local per_day=$(( (count*1440) / mins ))
    [ "$per_day" -ge 1 ] && { printf '%d/day\n' "$per_day"; return; }

    # Ultra-low targets: clamp to 1/day
    printf '1/day\n'
}

###################################################################################################
# 1. Build port lists
###################################################################################################
build_port_lists() {
    local use_v6=0
    [ "${1:-}" = "-6" ] && { use_v6=1; shift; }

    # Return early if IPv6 requested but not enabled
    [ "$use_v6" -eq 1 ] && [ "$IPV6_ENABLED" -eq 0 ] && return 0

    if [ "$use_v6" -eq 1 ]; then
        tcp6_ports="$(get_ports6 tcp)"
        udp6_ports="$(get_ports6 udp)"
        mp6_tcp="$(printf '%s\n' "$tcp6_ports" | compress_ports)"
        mp6_udp="$(printf '%s\n' "$udp6_ports" | compress_ports)"

        if [ -n "${mp6_tcp}${mp6_udp}" ]; then
            ipv6_ready=1
        else
            log -l notice "No allow rules detected in FORWARD chain (IPv6)"
        fi
    else
        tcp_ports="$(get_ports tcp)"
        udp_ports="$(get_ports udp)"
        mp_tcp="$(printf '%s\n' "$tcp_ports" | compress_ports)"
        mp_udp="$(printf '%s\n' "$udp_ports" | compress_ports)"

        if [ -n "${mp_tcp}${mp_udp}" ]; then
            ipv4_ready=1
        else
            log -l notice "$VSERVER_CHAIN chain not initialized or" \
                "no port forwarding rules defined (IPv4)"
        fi
    fi
}

# Build port list for each protocol
build_port_lists
build_port_lists -6

if [ "$ipv4_ready" -eq 0 ] && [ "$ipv6_ready" -eq 0 ]; then
    log "No input port mappings detected (IPv4/IPv6). Exiting..."
    exit 0
fi

###################################################################################################
# 2. Calculate hashes and set build flags
###################################################################################################
prep_rulesets() {
    local use_v6=0 v6_flag=""
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; shift; }

    local dos_file wan_file dos_hash_file wan_hash_file
    if [ "$use_v6" -eq 1 ]; then
        dos_file="$DOS_PROT_V6_RULES"
        wan_file="$WAN_FW_V6_RULES"
        dos_hash_file="$DOS_PROT_V6_RULES_HASH"
        wan_hash_file="$WAN_FW_V6_RULES_HASH"
    else
        dos_file="$DOS_PROT_RULES"
        wan_file="$WAN_FW_RULES"
        dos_hash_file="$DOS_PROT_RULES_HASH"
        wan_hash_file="$WAN_FW_RULES_HASH"
    fi

    # Create temporary files to hold normalized rule definitions
    local dos_tmp wan_tmp
    dos_tmp="$(tmp_file)"
    wan_tmp="$(tmp_file)"

    # Strip comments and whitespace from rules -> normalized version
    strip_comments "$dos_file" | sed -E 's/[[:blank:]]+//g' > "$dos_tmp"
    strip_comments "$wan_file" | sed -E 's/[[:blank:]]+//g' > "$wan_tmp"

    # Publish tmp paths to global names (v4 vs v6)
    if [ "$use_v6" -eq 1 ]; then
        dos_prot_v6_rules="$dos_tmp"
        wan_fw_v6_rules="$wan_tmp"
    else
        dos_prot_rules="$dos_tmp"
        wan_fw_rules="$wan_tmp"
    fi

    # Hash of an empty ruleset (used for baseline checks)
    empty_rules_hash="$(printf '' | compute_hash)"

    # Compute current DoS Protection rules hash and load previous one if it exists
    local new_dos old_dos
    new_dos="$(compute_hash "$dos_tmp")"
    old_dos="$(cat "$dos_hash_file" 2>/dev/null || printf '%s' "$empty_rules_hash")"

    # Compute current WAN Firewall rules hash and load previous one if it exists
    local new_wan old_wan
    new_wan="$(compute_hash "$wan_tmp")"
    old_wan="$(cat "$wan_hash_file" 2>/dev/null || printf '%s' "$empty_rules_hash")"

    # Export hash vars globally
    if [ "$use_v6" -eq 1 ]; then
        new_dos_v6_hash="$new_dos"
        old_dos_v6_hash="$old_dos"
        new_wan_fw_v6_hash="$new_wan"
    else
        new_dos_hash="$new_dos"
        old_dos_hash="$old_dos"
        new_wan_fw_hash="$new_wan"
    fi

    # Flag DoS Protection rules for rebuild if:
    #   - Hash changed (list of rules was updated)
    #   - Filtering chain is missing
    if [ "$new_dos" != "$old_dos" ] \
        || ! fw_chain_exists $v6_flag raw "$FILTERING_CHAIN"; then
        if [ "$use_v6" -eq 1 ]; then
            build_dos_prot_v6_rules=1
        else
            build_dos_prot_rules=1
        fi
    fi

    # Flag WAN Firewall rules for rebuild if:
    #   - Hash changed (list of rules was updated)
    #   - Filtering chain is missing
    #   - ipset chain is missing
    if [ "$new_wan" != "$old_wan" ] \
        || ! fw_chain_exists $v6_flag raw "$FILTERING_CHAIN" \
        || ! fw_chain_exists $v6_flag raw "$IPSET_CHAIN"; then
        if [ "$use_v6" -eq 1 ]; then
            build_wan_fw_v6_rules=1
        else
            build_wan_fw_rules=1
        fi
    fi
}

# Prepare rulesets for each protocol
[ "$ipv4_ready" -eq 1 ] && prep_rulesets
[ "$ipv6_ready" -eq 1 ] && prep_rulesets -6

###################################################################################################
# 3. Build / refresh main filtering chain if needed
###################################################################################################
refresh_main_filter_chain() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local build_flag old_hash
    if [ "$use_v6" -eq 1 ]; then
        build_flag="$build_dos_prot_v6_rules"
        old_hash="$old_dos_v6_hash"
    else
        build_flag="$build_dos_prot_rules"
        old_hash="$old_dos_hash"
    fi

    if fw_chain_exists $v6_flag raw "$FILTERING_CHAIN"; then
        if [ "$build_flag" -eq 1 ]; then
            purge_fw_rules $v6_flag "raw $FILTERING_CHAIN" " -j (LOG|DROP)( |$)"

            # If previous rules were not empty
            if [ "$old_hash" != "$empty_rules_hash" ]; then
                log "Dropped all existing DoS Protection rules ($fam_label):" \
                    "table=raw chain=$FILTERING_CHAIN"
            fi
        fi
    else
        create_fw_chain $v6_flag raw "$FILTERING_CHAIN"
    fi
}

# Refresh main filtering chain for each protocol
[ "$ipv4_ready" -eq 1 ] && refresh_main_filter_chain
[ "$ipv6_ready" -eq 1 ] && refresh_main_filter_chain -6

###################################################################################################
# 4. Ensure xt_hashlimit is available when needed
###################################################################################################
need_hashlimit=0
[ -s "$dos_prot_rules" ] && need_hashlimit=1
grep -q '^log:' "$wan_fw_rules" && need_hashlimit=1

if [ "$IPV6_ENABLED" -eq 1 ]; then
    [ -s "$dos_prot_v6_rules" ] && need_hashlimit=1
    grep -q '^log:' "$wan_fw_v6_rules" && need_hashlimit=1
fi

if [ "$need_hashlimit" -eq 1 ]; then
    if ! grep -q '^xt_hashlimit ' /proc/modules 2>/dev/null; then
        if ! modprobe xt_hashlimit 2>/dev/null; then
            log -l err "xt_hashlimit module is not available; aborting script execution..."
            exit 1
        fi
        log "Loaded xt_hashlimit module"
    fi
fi

###################################################################################################
# 5. Add DoS Protection rules
###################################################################################################
add_dos_prot_rules() {
    local use_v6=0 v6_flag="" v6_suffix="" fam_label="IPv4"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; v6_suffix="6" fam_label="IPv6"; shift; }

    # Return early if IPv6 requested but not enabled
    [ "$use_v6" -eq 1 ] && [ "$IPV6_ENABLED" -eq 0 ] && return 0

    # Select family-specific artifacts/flags
    local rules_file build_flag warn_var new_hash hash_file
    if [ "$use_v6" -eq 1 ]; then
        rules_file="$dos_prot_v6_rules"
        build_flag="$build_dos_prot_v6_rules"
        warn_var="dos_prot_v6_rules_warnings"
        new_hash="$new_dos_v6_hash"
        hash_file="$DOS_PROT_V6_RULES_HASH"
    else
        rules_file="$dos_prot_rules"
        build_flag="$build_dos_prot_rules"
        warn_var="dos_prot_rules_warnings"
        new_hash="$new_dos_hash"
        hash_file="$DOS_PROT_RULES_HASH"
    fi

    if ! [ -s "$rules_file" ]; then
        log "No DoS Protection rules are defined ($fam_label)"
        printf '%s\n' "$new_hash" > "$hash_file"
        return 0
    elif [ "$build_flag" -eq 0 ]; then
        log "DoS Protection rules are applied and up-to-date ($fam_label)"
        printf '%s\n' "$new_hash" > "$hash_file"
        return 0
    fi

    log "Adding DoS Protection rules ($fam_label)..."
    local rule_count=0 had_warn=0

    while IFS=: read -r mode port proto above burst minutes log_count; do
        # Validate 'mode'
        case "$mode" in
            per_ip)   hash_mode="srcip"  ;;
            per_port) hash_mode="dstport";;
            *)  log -l warn "Unknown DoS Protection rule mode '$mode'; skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue ;;
        esac

        # Validate 'port' (single dest port only, 1-65535)
        if ! validate_ports "$port"; then
            log -l warn "Invalid 'port' spec '$port' - expected a single port (1-65535);" \
                "skipping rule ($fam_label)"
            had_warn=1; eval "$warn_var=1"; continue
        fi
        case "$port" in
            any|*[,-]*)
                log -l warn "Invalid 'port' spec '$port' - DoS Protection rules require" \
                    "a single port (1-65535); skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue ;;
        esac

        # Validate 'proto' and normalize
        norm_proto="$(normalize_protos "$proto")"
        if [ -z "$norm_proto" ]; then
            log -l warn "Invalid 'proto' spec '$proto' - expected 'tcp' or 'udp';" \
                "skipping rule ($fam_label)"
            had_warn=1; eval "$warn_var=1"; continue
        fi
        case "$norm_proto" in
            tcp|udp) proto="$norm_proto" ;;
            *)
                log -l warn "Invalid 'proto' spec '$proto' - DoS Protection rules require" \
                    "a single protocol ('tcp' or 'udp'); skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue ;;
        esac

        # Validate 'above' and 'burst'
        if ! is_pos_int "$above"; then
            log -l warn "Invalid 'above' value '$above' - expected positive integer (packets/sec);" \
                "skipping rule ($fam_label)"
            had_warn=1; eval "$warn_var=1"; continue
        fi

        if [ -z "$burst" ]; then
            burst=3
        elif ! is_pos_int "$burst"; then
            log -l warn "Invalid 'burst' value '$burst' - using default 3 ($fam_label)"
            burst=3; had_warn=1; eval "$warn_var=1"
        fi

        # Validate/normalize 'minutes' and 'log_count'
        case "$mode" in
            per_ip)
                if [ -n "$minutes" ]; then
                    if ! is_pos_int "$minutes"; then
                        log -l warn "Invalid 'minutes' value '$minutes' for per_ip rule" \
                            "- using default 5 ($fam_label)"
                        minutes=5; had_warn=1; eval "$warn_var=1"
                    fi
                else
                    minutes=5
                fi
                if [ -n "$log_count" ]; then
                    if ! is_pos_int "$log_count"; then
                        log -l warn "Invalid 'log_count' value '$log_count' for per_ip rule" \
                            "- using default 1 ($fam_label)"
                        log_count=1; had_warn=1; eval "$warn_var=1"
                    fi
                else
                    log_count=1
                fi
                limit_rate="$(calc_limit_rate "$log_count" "$minutes")"
                log_limit_args="-m limit --limit $limit_rate --limit-burst 1"
                log_limit_info=" log_count=$log_count (log_rate=$limit_rate)"
                ;;
            per_port)
                if [ -n "$minutes" ]; then
                    if ! is_pos_int "$minutes"; then
                        log -l warn "Invalid 'minutes' value '$minutes' for per_port rule" \
                            "- using default 5 ($fam_label)"
                        minutes=5; had_warn=1; eval "$warn_var=1"
                    fi
                else
                    minutes=5
                fi
                if [ -n "$log_count" ]; then
                    log -l warn "'log_count' is ignored for per_port rule on port $port ($fam_label)"
                    had_warn=1; eval "$warn_var=1"
                fi
                log_limit_args=""; log_limit_info=""
                ;;
        esac

        # Build short hashlimit names from UUID
        base_hl_name=$(sanitize_hl_name "$(uuid4)" 14)
        hl_name="${base_hl_name}D"
        hl_log_name="${base_hl_name}L"

        # Compact DoS log prefix
        log_name="dos${v6_suffix}_${mode#per_}_${port}_$(printf '%.1s' "$proto")"

        # Rates
        expire_ms=$((minutes * 60000))
        hashlimit_rate=$(calc_hashlimit_rate "$minutes")

        ensure_fw_rule $v6_flag -q raw "$FILTERING_CHAIN" \
            -p "$proto" --dport "$port" \
            -m hashlimit --hashlimit-name "$hl_name" \
                --hashlimit-above "${above}/sec" --hashlimit-burst "$burst" \
                --hashlimit-mode "$hash_mode" --hashlimit-htable-expire "$expire_ms" \
                --hashlimit-htable-size "$HTABLE_SIZE" --hashlimit-htable-max "$HTABLE_MAX" \
            -m hashlimit --hashlimit-name "$hl_log_name" \
                --hashlimit-upto "$hashlimit_rate" --hashlimit-burst 1 \
                --hashlimit-mode "$hash_mode" --hashlimit-htable-expire "$expire_ms" \
                --hashlimit-htable-size "$HTABLE_SIZE" --hashlimit-htable-max "$HTABLE_MAX" \
            $log_limit_args \
            -j LOG --log-prefix "$log_name: "
        log "Added $fam_label LOG rule ($log_name) -> $FILTERING_CHAIN:" \
            "type=$mode proto=$proto port=$port" \
            "above=${above}/sec burst=$burst minutes=${minutes}${log_limit_info}"

        ensure_fw_rule $v6_flag -q raw "$FILTERING_CHAIN" \
            -p "$proto" --dport "$port" \
            -m hashlimit --hashlimit-name "$hl_name" \
                --hashlimit-above "${above}/sec" --hashlimit-burst "$burst" \
                --hashlimit-mode "$hash_mode" --hashlimit-htable-expire "$expire_ms" \
                --hashlimit-htable-size "$HTABLE_SIZE" --hashlimit-htable-max "$HTABLE_MAX" \
            -j DROP
        log "Added $fam_label DROP rule -> $FILTERING_CHAIN:" \
            "type=$mode proto=$proto port=$port" \
            "above=${above}/sec burst=$burst minutes=$minutes"

        rule_count=$((rule_count + 2))
    done < "$rules_file"

    # Summary + persist hash
    if [ "$had_warn" -eq 0 ]; then
        log "Added $rule_count rules to $FILTERING_CHAIN ($fam_label)"
    else
        log -l warn "Added $rule_count rules to $FILTERING_CHAIN ($fam_label) with warnings;" \
            "please check logs for details"
    fi

    printf '%s\n' "$new_hash" > "$hash_file"
}

# Add DoS protection rules for each protocol
[ "$ipv4_ready" -eq 1 ] && add_dos_prot_rules
[ "$ipv6_ready" -eq 1 ] && add_dos_prot_rules -6

###################################################################################################
# 6. Create / update PREROUTING -> $FILTERING_CHAIN for exposed ports
###################################################################################################
sync_filter_jumps() {
    local use_v6=0 v6_flag="" fam_label="IPv4" ipt="iptables"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; ipt="ip6tables"; shift; }

    local tcp_list="$1" udp_list="$2"
    local new_tcp new_udp cur_all cur_tcp cur_udp
    local changed_tcp=0 changed_udp=0
    local kill_pos base_pos tcp_ins_pos udp_ins_pos
    local chunk tcp_n=0 last_tcp_pos

    new_tcp="$(tmp_file)"
    new_udp="$(tmp_file)"
    cur_all="$(tmp_file)"
    cur_tcp="$(tmp_file)"
    cur_udp="$(tmp_file)"

    # Build desired specs for tcp
    if [ -n "$tcp_list" ]; then
        for chunk in $(chunk15 "$tcp_list"); do
            printf '%s\n' \
                "-A PREROUTING -i $WAN_IF -p tcp -m multiport --dports $chunk -j $FILTERING_CHAIN" \
                >> "$new_tcp"
        done
        sort -o "$new_tcp" "$new_tcp"
    fi

    # Build desired specs for udp
    if [ -n "$udp_list" ]; then
        for chunk in $(chunk15 "$udp_list"); do
            printf '%s\n' \
                "-A PREROUTING -i $WAN_IF -p udp -m multiport --dports $chunk -j $FILTERING_CHAIN" \
                >> "$new_udp"
        done
        sort -o "$new_udp" "$new_udp"
    fi

    # Parse current specs for both protos
    $ipt -t raw -S PREROUTING 2>/dev/null |
    awk -v IF="$WAN_IF" -v CH="$FILTERING_CHAIN" '
        $1 == "-A" && $2 == "PREROUTING" {
            has_if = has_jump = has_multi = 0; proto=""
            for (i = 1; i <= NF; i++) {
                if ($i == "-i" && i + 1 <= NF && $(i + 1) == IF) has_if = 1
                if ($i == "-j" && i + 1 <= NF && $(i + 1) == CH) has_jump = 1
                if ($i == "-m" && i + 1 <= NF && $(i + 1) == "multiport") has_multi = 1
                if ($i == "-p" && i + 1 <= NF) proto = $(i + 1)
            }
            if (has_if && has_jump && has_multi && (proto == "tcp" || proto == "udp"))
                print $0
        }' | sort > "$cur_all"

    # Split current into per-proto files
    awk -v tcp="$cur_tcp" -v udp="$cur_udp" '
        / -p tcp / { print > tcp; next }
        / -p udp / { print > udp; next }
    ' "$cur_all"
    sort -o "$cur_tcp" "$cur_tcp"
    sort -o "$cur_udp" "$cur_udp"

    # Compare per-proto
    cmp -s "$new_tcp" "$cur_tcp" || changed_tcp=1
    cmp -s "$new_udp" "$cur_udp" || changed_udp=1

    if [ "$changed_tcp" -eq 0 ] && [ "$changed_udp" -eq 0 ]; then
        log "Jump rules are already present ($fam_label): raw PREROUTING -> $FILTERING_CHAIN"
        return 0
    fi

    # Purge only the proto(s) that actually changed
    if [ "$changed_tcp" -eq 1 ]; then
        purge_fw_rules $v6_flag \
            "raw PREROUTING" "-i $WAN_IF -p tcp -m multiport --dports [^ ]+ -j $FILTERING_CHAIN$"
    fi
    if [ "$changed_udp" -eq 1 ]; then
        purge_fw_rules $v6_flag \
            "raw PREROUTING" "-i $WAN_IF -p udp -m multiport --dports [^ ]+ -j $FILTERING_CHAIN$"
    fi

    # Find killswitch anchor
    kill_pos=$(
        $ipt -t raw -S PREROUTING 2>/dev/null |
        awk -v IF="$WAN_IF" -v CH="$KILLSWITCH_CHAIN" '
            $1 == "-A" && $2 == "PREROUTING" {
                n++
                has_if = has_jump = 0
                for (i = 1; i <= NF; i++) {
                    if ($i == "-i" && i + 1 <= NF && $(i + 1) == IF) has_if = 1
                    if ($i == "-j" && i + 1 <= NF && $(i + 1) == CH) has_jump = 1
                }
                if (has_if && has_jump) { print n; exit }
            }'
    )
    if [ -n "$kill_pos" ]; then
        base_pos=$((kill_pos + 1))
        log "Found killswitch ($fam_label) at raw PREROUTING entry #$kill_pos;" \
            "inserting jumps starting at #$base_pos..."
    else
        base_pos=1
        log "No killswitch ($fam_label) found at raw PREROUTING;" \
            "inserting jumps starting at #$base_pos..."
    fi

    # Set insertion points
    tcp_ins_pos=$base_pos
    udp_ins_pos=$base_pos

    if [ "$changed_tcp" -eq 0 ] && [ "$changed_udp" -eq 1 ]; then
        # Keep UDP after existing TCP jumps
        last_tcp_pos=$(
            $ipt -t raw -S PREROUTING 2>/dev/null |
            awk -v IF="$WAN_IF" -v CH="$FILTERING_CHAIN" '
                $1 == "-A" && $2 == "PREROUTING" {
                    n++
                    has_if = has_jump = has_multi = has_tcp = 0
                    for (i = 1; i <= NF; i++) {
                        if ($i == "-i" && i + 1 <= NF && $(i + 1) == IF) has_if = 1
                        if ($i == "-j" && i + 1 <= NF && $(i + 1) == CH) has_jump = 1
                        if ($i == "-m" && i + 1 <= NF && $(i + 1) == "multiport") has_multi = 1
                        if ($i == "-p" && i + 1 <= NF && $(i + 1) == "tcp") has_tcp = 1
                    }
                    if (has_if && has_jump && has_multi && has_tcp) last = n
                }
                END { if (last) print last }'
        )
        [ -n "$last_tcp_pos" ] && udp_ins_pos=$((last_tcp_pos + 1))
    fi

    # Insert TCP if changed
    if [ "$changed_tcp" -eq 1 ] && [ -n "$tcp_list" ]; then
        for chunk in $(chunk15 "$tcp_list"); do
            ensure_fw_rule $v6_flag raw PREROUTING -I "$tcp_ins_pos" \
                -i "$WAN_IF" -p tcp -m multiport --dports "$chunk" -j "$FILTERING_CHAIN"
            tcp_ins_pos=$((tcp_ins_pos+1))
            tcp_n=$((tcp_n+1))
        done
    fi

    # If TCP changed and UDP also changes, place UDP right after the newly inserted TCP block
    if [ "$changed_tcp" -eq 1 ] && [ "$changed_udp" -eq 1 ]; then
        udp_ins_pos=$((base_pos + tcp_n))
    fi

    # Insert UDP if changed
    if [ "$changed_udp" -eq 1 ] && [ -n "$udp_list" ]; then
        for chunk in $(chunk15 "$udp_list"); do
            ensure_fw_rule $v6_flag raw PREROUTING -I "$udp_ins_pos" \
                -i "$WAN_IF" -p udp -m multiport --dports "$chunk" -j "$FILTERING_CHAIN"
            udp_ins_pos=$((udp_ins_pos+1))
        done
    fi

    if [ "$use_v6" -eq 1 ]; then
        jump_v6_rules_inserted=1
    else
        jump_rules_inserted=1
    fi

    log "Successfully inserted jump rule(s) ($fam_label): raw PREROUTING -> $FILTERING_CHAIN"
}

# Sync filter jumps for each protocol
[ "$ipv4_ready" -eq 1 ] && sync_filter_jumps "$mp_tcp" "$mp_udp"
[ "$ipv6_ready" -eq 1 ] && sync_filter_jumps -6 "$mp6_tcp" "$mp6_udp"

###################################################################################################
# 7. Check if ipsets are ready; if not, exit early
###################################################################################################
check_ipsets_ready() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local rules_file build_flag new_hash ipsets_hash_file
    if [ "$use_v6" -eq 1 ]; then
        rules_file="$wan_fw_v6_rules"
        build_flag="$build_wan_fw_v6_rules"
        new_hash="$new_wan_fw_v6_hash"
        ipsets_hash_file="$WAN_FW_V6_IPSETS_HASH"
    else
        rules_file="$wan_fw_rules"
        build_flag="$build_wan_fw_rules"
        new_hash="$new_wan_fw_hash"
        ipsets_hash_file="$WAN_FW_IPSETS_HASH"
    fi

    local ipsets_hash
    ipsets_hash="$(cat "$ipsets_hash_file" 2>/dev/null || printf '%s' "$empty_rules_hash")"

    if [ -s "$rules_file" ] \
        && [ "$build_flag" -eq 1 ] \
        && [ "$ipsets_hash" != "$new_hash" ];
    then
        log "ipsets are not ready for current rules ($fam_label); exiting..."
        exit 0
    fi
}

# Check ipsets readiness for each protocol
[ "$ipv4_ready" -eq 1 ] && check_ipsets_ready
[ "$ipv6_ready" -eq 1 ] && check_ipsets_ready -6

###################################################################################################
# 8. Create / reset filtering subchain for ipsets
###################################################################################################
ensure_ipset_subchain() {
    local use_v6=0 v6_flag=""
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; shift; }

    # Return early if IPv6 requested but not enabled
    [ "$use_v6" -eq 1 ] && [ "$IPV6_ENABLED" -eq 0 ] && return 0

    local build_flag
    if [ "$use_v6" -eq 1 ]; then
        build_flag="$build_wan_fw_v6_rules"
    else
        build_flag="$build_wan_fw_rules"
    fi

    if [ "$build_flag" -eq 1 ]; then
        # Create a new chain or flush the existing one
        create_fw_chain $v6_flag -f raw "$IPSET_CHAIN"

        # Ensure IPSET_CHAIN is the first rule in FILTERING_CHAIN
        ensure_fw_rule $v6_flag raw "$FILTERING_CHAIN" -I -j "$IPSET_CHAIN"

        if [ "$use_v6" -eq 1 ]; then
            jump_v6_rules_inserted=1
        else
            jump_rules_inserted=1
        fi
    fi
}

# Ensure existing ipset subchain for each protocol
[ "$ipv4_ready" -eq 1 ] && ensure_ipset_subchain
[ "$ipv6_ready" -eq 1 ] && ensure_ipset_subchain -6

###################################################################################################
# 9. Add WAN Firewall rules
###################################################################################################
add_wan_fw_rules() {
    local use_v6=0 v6_flag="" v6_suffix="" fam_label="IPv4"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; v6_suffix="6"; fam_label="IPv6"; shift; }

    # Family-specific artifacts/flags
    local rules_file build_flag warn_var new_hash hash_file
    if [ "$use_v6" -eq 1 ]; then
        rules_file="$wan_fw_v6_rules"
        build_flag="$build_wan_fw_v6_rules"
        warn_var="wan_fw_v6_rules_warnings"
        new_hash="$new_wan_fw_v6_hash"
        hash_file="$WAN_FW_V6_RULES_HASH"
    else
        rules_file="$wan_fw_rules"
        build_flag="$build_wan_fw_rules"
        warn_var="wan_fw_rules_warnings"
        new_hash="$new_wan_fw_hash"
        hash_file="$WAN_FW_RULES_HASH"
    fi

    if ! [ -s "$rules_file" ]; then
        log "No WAN Firewall rules are defined ($fam_label)"
        printf '%s\n' "$new_hash" > "$hash_file"
        return 0
    elif [ "$build_flag" -eq 0 ]; then
        log "WAN Firewall rules are applied and up-to-date ($fam_label)"
        printf '%s\n' "$new_hash" > "$hash_file"
        return 0
    fi

    log "Adding WAN Firewall rules ($fam_label)..."
    local ipset_rule_count=0 had_warn=0 prt=""

    while IFS=: read -r mode ports protos sets set_excl minutes ip_count; do
        # Validate 'mode' & handle mode-specific args
        case "$mode" in
            log)
                if [ -n "$minutes" ] && ! is_pos_int "$minutes"; then
                    log -l warn "Invalid 'minutes' value '$minutes' for mode 'log'" \
                        "- using default 5 ($fam_label)"
                    minutes=; had_warn=1; eval "$warn_var=1"
                fi
                if [ -n "$ip_count" ] && ! is_pos_int "$ip_count"; then
                    log -l warn "Invalid 'ip_count' value '$ip_count' for mode 'log'" \
                        "- using default 1 ($fam_label)"
                    ip_count=; had_warn=1; eval "$warn_var=1"
                fi
                minutes=${minutes:-5}
                ip_count=${ip_count:-1}
                ;;
            block|allow|pass)
                if [ -n "$minutes" ]; then
                    log -l warn "Argument 'minutes' ignored for mode '$mode' ($fam_label)"
                    had_warn=1; eval "$warn_var=1"
                fi
                if [ -n "$ip_count" ]; then
                    log -l warn "Argument 'ip_count' ignored for mode '$mode' ($fam_label)"
                    had_warn=1; eval "$warn_var=1"
                fi
                ;;
            *)
                log -l warn "Unknown WAN Firewall rule mode '$mode'; skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue
                ;;
        esac

        # Validate 'ports'
        if ! validate_ports "$ports"; then
            log -l warn "Invalid 'ports' spec '$ports' - expected 'any', a single port (1-65535)," \
                "a range n-m, or a comma list; skipping rule ($fam_label)"
            had_warn=1; eval "$warn_var=1"; continue
        fi

        # Validate & normalize 'protos'
        if ! protos_norm="$(normalize_protos "${protos:-any}")"; then
            log -l warn "Invalid 'protos' spec '$protos' - expected 'tcp', 'udp', 'tcp,udp'," \
                "or 'any'; skipping rule ($fam_label)"
            had_warn=1; eval "$warn_var=1"; continue
        fi

        # Save original port representation for logging
        port_list="$ports"

        # Normalize input for rule building
        [ "$ports" = "any" ] && ports=""
        protos="$protos_norm"

        # Build port_spec (single port -> --dport, list/range -> multiport)
        case "$ports" in
          "")        port_spec="";;
          *[,-]*)    port_spec="-m multiport --dports ${ports//-/:}";;
          *)         port_spec="--dport $ports";;
        esac

        exclude_list="$set_excl"

        # Main ipset (single or combo)
        set="$(derive_set_name "${sets//,/_}")"

        if [ "$set" = "any" ]; then
            if [ "$mode" = "log" ]; then
                match=""
            else
                log -l warn "Meta ipset '$set' is only supported for mode 'log';" \
                    "skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue
            fi
        else
            if ! ipset list "$set" >/dev/null 2>&1; then
                log -l warn "ipset '$set' is missing; skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue
            fi
            match="-m set --match-set $set src"
        fi

        # Exclude ipsets (if any)
        if [ -n "$exclude_list" ]; then
            set_excl="$(derive_set_name "${exclude_list//,/_}")"
            if [ "$set_excl" = "any" ]; then
                log -l warn "Meta ipset '$set_excl' is not supported for exclusions;" \
                    "skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue
            fi
            if ! ipset list "$set_excl" >/dev/null 2>&1; then
                log -l warn "Exclusion ipset '$set_excl' is missing;" \
                    "skipping rule ($fam_label)"
                had_warn=1; eval "$warn_var=1"; continue
            fi
            excl="-m set ! --match-set $set_excl src"
            excl_log=" set_excl=$set_excl"
        else
            excl=""
            excl_log=""
        fi

        # Build rules for each protocol
        for proto in ${protos//,/ }; do
            case "$mode" in
                block)  # blocklist -> drop when src matches the set
                    ensure_fw_rule $v6_flag -q raw "$IPSET_CHAIN" \
                        -p "$proto" $port_spec \
                        $match \
                        $excl \
                        -j DROP
                    log "Added DROP rule -> $IPSET_CHAIN ($fam_label):" \
                        "proto=$proto ports=$port_list set=${set}${excl_log}"
                    ipset_rule_count=$((ipset_rule_count + 1))
                    ;;

                allow)  # allowlist -> accept listed ipsets, drop other traffic
                    ensure_fw_rule $v6_flag -q raw "$IPSET_CHAIN" \
                        -p "$proto" $port_spec \
                        $match \
                        $excl \
                        -j RETURN
                    log "Added RETURN rule -> $IPSET_CHAIN ($fam_label):" \
                        "proto=$proto ports=$port_list set=${set}${excl_log}"

                    ensure_fw_rule $v6_flag -q raw "$IPSET_CHAIN" \
                        -p "$proto" $port_spec \
                        -j DROP
                    log "Added DROP rule -> $IPSET_CHAIN ($fam_label):" \
                        "proto=$proto ports=$port_list"

                    ipset_rule_count=$((ipset_rule_count + 2))
                    ;;

                pass)   # passlist -> accept and skip all further checks
                    ensure_fw_rule $v6_flag -q raw "$IPSET_CHAIN" \
                        -p "$proto" $port_spec \
                        $match \
                        $excl \
                        -j ACCEPT
                    log "Added ACCEPT rule -> $IPSET_CHAIN ($fam_label):" \
                        "proto=$proto ports=$port_list set=${set}${excl_log}"
                    ipset_rule_count=$((ipset_rule_count + 1))
                    ;;

                log)    # log only -> rate-limited LOG, no accept or drop
                    limit_name=$(sanitize_hl_name "$(uuid4)")
                    prt=$(printf '%.1s' "$proto")
                    log_name="ips${v6_suffix}_${port_list}_${prt}_${set}${set_excl:+_$set_excl}"
                    hashlimit_rate=$(calc_hashlimit_rate "$minutes")
                    expire_ms=$((minutes * 60000))

                    ensure_fw_rule $v6_flag -q raw "$IPSET_CHAIN" \
                        -p "$proto" $port_spec \
                        $match \
                        $excl \
                        -m hashlimit \
                            --hashlimit-name "$limit_name" \
                            --hashlimit-mode srcip \
                            --hashlimit-upto "$hashlimit_rate" \
                            --hashlimit-burst 1 \
                            --hashlimit-htable-expire "$expire_ms" \
                            --hashlimit-htable-size "$HTABLE_SIZE" \
                            --hashlimit-htable-max "$HTABLE_MAX" \
                        -m limit \
                            --limit "$hashlimit_rate" \
                            --limit-burst "$ip_count" \
                        -j LOG --log-prefix "$log_name: "

                    log "Added LOG rule ($log_name) -> $IPSET_CHAIN ($fam_label):" \
                        "proto=$proto ports=$port_list set=${set}${excl_log}" \
                        "minutes=$minutes ip_count=$ip_count (log_rate=$hashlimit_rate)"
                    ipset_rule_count=$((ipset_rule_count + 1))
                    ;;
            esac
        done
    done < "$rules_file"

    if [ "$had_warn" -eq 0 ]; then
        log "Added $ipset_rule_count rules to $IPSET_CHAIN ($fam_label)"
    else
        log -l warn "Added $ipset_rule_count rules to $IPSET_CHAIN ($fam_label) with warnings;" \
            "please check logs for details"
    fi

    # Save hash for the current run
    printf '%s\n' "$new_hash" > "$hash_file"
}

# Add WAN Firewall rules for each protocol
[ "$ipv4_ready" -eq 1 ] && add_wan_fw_rules
[ "$ipv6_ready" -eq 1 ] && add_wan_fw_rules -6

###################################################################################################
# 10. Finalize
###################################################################################################
finalize() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1:-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local build_dos build_wan jump warn_dos warn_wan
    if [ "$use_v6" -eq 1 ]; then
        build_dos="$build_dos_prot_v6_rules"
        build_wan="$build_wan_fw_v6_rules"
        jump="$jump_v6_rules_inserted"
        warn_dos="$dos_prot_v6_rules_warnings"
        warn_wan="$wan_fw_v6_rules_warnings"
    else
        build_dos="$build_dos_prot_rules"
        build_wan="$build_wan_fw_rules"
        jump="$jump_rules_inserted"
        warn_dos="$dos_prot_rules_warnings"
        warn_wan="$wan_fw_rules_warnings"
    fi

    if [ "$build_dos" -eq 0 ] && [ "$build_wan" -eq 0 ] && [ "$jump" -eq 0 ]; then
        log "All firewall rules are already present ($fam_label)"
    elif [ "$warn_dos" -eq 0 ] && [ "$warn_wan" -eq 0 ]; then
        log "All changes have been applied successfully ($fam_label)"
    else
        log -l warn "Completed with warnings ($fam_label); please check logs for details"
    fi
}

# Print status messages for each protocol
[ "$ipv4_ready" -eq 1 ] && finalize
[ "$ipv6_ready" -eq 1 ] && finalize -6

exit 0
