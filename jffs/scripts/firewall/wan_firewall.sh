#!/usr/bin/env ash

###################################################################################################
# wan_firewall.sh - inbound WAN firewall for Asuswrt-Merlin
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Detects the ports exposed by the ASUS GUI and targets only that inbound traffic
#     on the WAN interface.
#   * Drops malicious, bogon, geo-restricted, or custom-listed sources via ipsets before
#     they ever reach DNAT or the conntrack table. Integrates a predefined FireHOL Level 1
#     ipset (via the builder) for baseline protection.
#   * Adds optional flood / DoS rate limits (per-IP and per-destination-port) with controlled
#     logging using xt_hashlimit.
#   * Maintains its own rule set in a dedicated raw table chain and auto-refreshes when you
#     change port forwarding settings.
#   * Integrates with the ipsets produced by ipset_builder.sh.
#   * Plays nicely with the temporary killswitch from ipset_builder.sh by inserting its jumps
#     immediately after the killswitch jump in raw PREROUTING so traffic remains blocked until
#     filtering is ready.
#
# Requirements / Notes:
#   * Designed for setups without double NAT - your ISP modem should be in bridge mode
#     so the router receives a public IP directly on its WAN interface.
#   * All important variables live in config.sh. Review, edit, then run 'wfr'
#     (helper alias) to apply changes without rebooting.
#   * ipset-based filtering requires the ipsets built by ipset_builder.sh. If ipsets are
#     not yet loaded, this script falls back to DoS-only protection and skips ipset checks.
#   * IPv4 only; extend to IPv6 if needed.
#   * This script is designed to operate on inbound traffic only, specifically targeting
#     ports that are publicly exposed to the WAN. It intentionally does not filter or
#     inspect outbound traffic.
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
. "$(get_script_dir)/config.sh"

###################################################################################################
# 0b. Define constants & variables
###################################################################################################

# Get active WAN interface
WAN_IF=$(get_active_wan_if)

# Mutable runtime flags
dos_rules_warnings=0    # non-critical DoS rule issues encountered
ipset_rules_warnings=0  # non-critical ipset rule issues encountered

###################################################################################################
# 0c. Define helper functions
# -------------------------------------------------------------------------------------------------
# get_ports            - extract destination ports from DNAT rules for a given proto,
#                        one per line, sorted numerically
# compress_ports       - collapse a sorted list of ports into "80,81:85,443" form
# chunk15              - split a comma-separated list into ≤15-item chunks (for multiport)
#
# sanitize_hl_name     - normalize a hashlimit name (A-Z a-z 0-9 _), cap to given length
#
# calc_hashlimit_rate  - given minutes, return an iptables rate string for 1 log per window
#                        e.g. 1 -> "1/min", 30 -> "2/hour", 120 -> "12/day"
# calc_limit_rate      - given log_count and minutes, return a compact rate string that
#                        spreads log_count across the window ("/min", "/hour", or "/day"),
#                        clamped to at least 1/day
###################################################################################################

# Extract destination ports from VSERVER rules:
# - Read the full ruleset from iptables-save.
# - In awk:
#     - Consider only lines that append to the VSERVER chain ('-A VSERVER').
#     - Walk all fields so rule-order doesn't matter:
#         * capture protocol after '-p'
#         * capture destination port after '--dport'
#     - If the captured protocol equals the requested one (P = "tcp" or "udp")
#       and a port was found, print that port.
# - Post-process:
#     - 'sort -n'  -> numeric sort (so 2 < 10).
#     - 'uniq'     -> remove duplicates (requires sorted input).
get_ports() {
    iptables-save |
    awk -v P="$1" -v CH="$VSERVER_CHAIN" '
        $1 == "-A" && $2 == CH {
            proto = ""
            port  = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "-p")       proto = $(i + 1)
                if ($i == "--dport")  port  = $(i + 1)
            }
            if (proto == P && port != "") print port;
        }
    ' |
    sort -n | uniq

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
#   * Accumulates items in 'chunk', emitting when 15 are collected; trims the trailing comma.
#   * Prints the final (possibly shorter) chunk at the end.
#
# - Notes:
#   * Intended for iptables '-m multiport' which allows up to 15 ports per rule.
#   * Assumes items themselves don't contain commas or spaces (true for port lists).
#   * No output for empty input.
chunk15() {
    # Split a comma-separated list into lines of ≤15 items (for -m multiport)
    local list="$1" count=0 chunk="" field IFS_SAVE
    [ -z "$list" ] && return

    # Use a temporary IFS for splitting, then restore it to avoid leaks
    IFS_SAVE=$IFS
    IFS=','; set -- $list; IFS=$IFS_SAVE

    for field; do
        if [ "$count" -eq 15 ]; then
            # Output finished chunk (trim trailing comma)
            printf '%s\n' "${chunk%,}"
            chunk=""
            count=0
        fi
        chunk="${chunk}${field},"
        count=$((count + 1))
    done

    # Output the final chunk
    printf '%s\n' "${chunk%,}"
}

sanitize_hl_name() {
    # $1 = desired name, $2=max length (default 15)
    local name="$1" max="${2:-15}" cleaned

    # Keep A-Z a-z 0-9 and underscore; replace others with _
    cleaned=$(printf '%s' "$name" | tr -c 'A-Za-z0-9_' '_')

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
    local m=$1    # $1 = minutes (integer) -> prints e.g. "30/hour"
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
tcp_ports=$(get_ports tcp)
udp_ports=$(get_ports udp)

mp_tcp=$(printf '%s\n' "$tcp_ports" | compress_ports)
mp_udp=$(printf '%s\n' "$udp_ports" | compress_ports)

# No port-forwarding rules (mp_tcp/mp_udp empty) or VSERVER not initialized -> exit early
if [ -z "${mp_tcp}${mp_udp}" ]; then
    log "$VSERVER_CHAIN chain not initialized or no port forwarding rules defined. Exiting..."
    exit 0
fi

###################################################################################################
# 2. Build / refresh raw table filtering chain
###################################################################################################
if iptables -t raw -F "$FILTERING_CHAIN" 2>/dev/null; then
    log "Flushed existing chain $FILTERING_CHAIN"
else
    iptables -t raw -N "$FILTERING_CHAIN"
    log "Created new chain $FILTERING_CHAIN"
fi

###################################################################################################
# 3. Ensure xt_hashlimit is available when needed
###################################################################################################
dos_rules=$(strip_comments "$DOS_RULES" | sed -E 's/[[:blank:]]+//g')
ipset_rules=$(strip_comments "$IPSET_RULES" | sed -E 's/[[:blank:]]+//g')

need_hashlimit=0
[ -n "$dos_rules" ] && need_hashlimit=1
printf '%s\n' "$ipset_rules" | grep -q '^log:' && need_hashlimit=1

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
# 4. Add DoS protection rules
###################################################################################################
dos_rule_count=0

if [ -n "$dos_rules" ]; then
    log "Adding DoS rules..."
else
    log "No DoS rules are defined"
fi

while IFS=: read -r mode port proto above burst minutes log_count; do
    case "$mode" in
        per_ip)
            # hashlimit mode for per-source
            hash_mode="srcip"

            # Per-IP window and logging cap:
            #   - minutes: tracking window; also used for hashlimit htable-expire
            #              (state for each offending IP expires after minutes of inactivity).
            #   - log_count: max log entries per offending IP across that window.
            # Defaults: 5-minute window, 1 log per IP per 5 minutes.
            minutes=${minutes:-5}
            log_count=${log_count:-1}

            # Per-IP logging cap: spread log_count over the window
            limit_rate="$(calc_limit_rate "$log_count" "$minutes")"
            log_limit_args="-m limit --limit $limit_rate --limit-burst 1"
            log_limit_info=" log_count=$log_count (log_rate=$limit_rate)"
            ;;
        per_port)
            # hashlimit mode for destination port
            hash_mode="dstport"

            # Per-Port window (per-destination-port):
            #   - minutes: tracking window; also used for hashlimit htable-expire
            #              (state expires after minutes of inactivity).
            #   - log_count: ignored for per_port; the second hashlimit already caps logging.
            # Default: 5-minute window.
            minutes=${minutes:-5}

            # Per-port logging already limited by the second hashlimit
            if [ -n "$log_count" ]; then
                log -l warn "log_count is ignored for per_port rule on port $port"
                dos_rules_warnings=1
            fi

            log_limit_args=""
            log_limit_info=""
            ;;
        '')
            continue  # ignore empty lines
            ;;
        *)
            log -l warn "Unknown mode '$mode' - skipping rule"
            dos_rules_warnings=1
            continue
            ;;
    esac

    # Build short hashlimit names from UUID
    base_hl_name=$(sanitize_hl_name "$(uuid4)" 14)
    hl_name="${base_hl_name}D"
    hl_log_name="${base_hl_name}L"

    # Build compact DoS log prefix:
    # - ${mode#per_} strips leading "per_" ("per_ip" -> "ip", "per_port" -> "port").
    # - $(printf '%.1s' "$proto") appends the first letter of proto ("t" or "u").
    # - Result: dos_<ip|port>_<port><t|u>, e.g. "dos_ip_443t".
    log_name="dos_${mode#per_}_${port}$(printf '%.1s' "$proto")"

    # Calculate rates
    expire_ms=$((minutes * 60000))
    hashlimit_rate=$(calc_hashlimit_rate "$minutes")

    ensure_fw_rule raw "$FILTERING_CHAIN" \
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
    log "Added LOG rule -> $FILTERING_CHAIN: type=$mode proto=$proto port=$port" \
        "above=${above}/sec burst=$burst minutes=${minutes}${log_limit_info}"

    ensure_fw_rule raw "$FILTERING_CHAIN" \
        -p "$proto" --dport "$port" \
        -m hashlimit --hashlimit-name "$hl_name" \
            --hashlimit-above "${above}/sec" --hashlimit-burst "$burst" \
            --hashlimit-mode "$hash_mode" --hashlimit-htable-expire "$expire_ms" \
            --hashlimit-htable-size "$HTABLE_SIZE" --hashlimit-htable-max "$HTABLE_MAX" \
        -j DROP
    log "Added DROP rule -> $FILTERING_CHAIN: type=$mode proto=$proto port=$port" \
        "above=${above}/sec burst=$burst minutes=$minutes"

    dos_rule_count=$((dos_rule_count + 2))
done << EOF
$dos_rules
EOF

# Log summary
if [ "$dos_rule_count" -gt 0 ]; then
    if [ "$dos_rules_warnings" -eq 0 ]; then
        log "Added $dos_rule_count rules to $FILTERING_CHAIN"
    else
        log -l warn "Added $dos_rule_count rules to $FILTERING_CHAIN with warnings;" \
            "please check logs for details"
    fi
fi

###################################################################################################
# 5. Create / update PREROUTING -> $FILTERING_CHAIN for exposed ports
###################################################################################################

# Look for existing jumps to FILTERING_CHAIN in raw PREROUTING
rules=$(iptables -t raw -S PREROUTING | grep -E " -j $FILTERING_CHAIN( |$)" || true)

if [ -n "$rules" ]; then
    while read -r rule; do
        # Convert '-A PREROUTING ...' to parameters for -D
        iptables -t raw -D ${rule#-A }
    done << EOF
$rules
EOF

    log "Removed existing jumps from raw PREROUTING to $FILTERING_CHAIN"
else
    log "No existing jumps found from raw PREROUTING to $FILTERING_CHAIN"
fi

# Track next insertion point across calls
unset next_ins_pos

add_jump_rules() {
    local proto="$1" list="$2" chunk kill_pos ins_pos

    [ -z "$list" ] && return

    if [ -z "${next_ins_pos:-}" ]; then
        # First call: find the killswitch line among "-A PREROUTING" entries
        kill_pos=$(
            iptables -t raw -S PREROUTING |
            awk -v IF="$WAN_IF" -v CH="$KILLSWITCH_CHAIN" '
                /^-A PREROUTING/ {
                    ++n
                    if (index($0, "-i " IF " -j " CH)) {
                        print n
                        exit
                    }
                }
            '
        )
        if [ -n "$kill_pos" ]; then
            ins_pos=$((kill_pos + 1))
            log "Found killswitch at raw PREROUTING entry #$kill_pos;" \
                "inserting jumps starting at #$ins_pos..."
        else
            ins_pos=1
            log "No killswitch found at raw PREROUTING;" \
                "inserting jumps starting at #$ins_pos..."
        fi
    else
        ins_pos=$next_ins_pos
    fi

    for chunk in $(chunk15 "$list"); do
        ensure_fw_rule raw PREROUTING -I "$ins_pos" \
            -i "$WAN_IF" -p "$proto" \
            -m multiport --dports "$chunk" \
            -j "$FILTERING_CHAIN"
        log "Inserted jump: raw PREROUTING iface=$WAN_IF" \
            "proto=$proto ports=$chunk -> $FILTERING_CHAIN at #$ins_pos"
        next_ins_pos=$((ins_pos + 1))
        ins_pos=$next_ins_pos
    done
}

# Insert jump rules for each protocol
add_jump_rules tcp "$mp_tcp"
add_jump_rules udp "$mp_udp"
log "Successfully inserted jump rules into $FILTERING_CHAIN"

###################################################################################################
# 6. Check if ipsets are ready; if not, exit early
###################################################################################################
if [ ! -f "$IPSETS_CREATED_FLAG" ]; then
    log "ipsets are not ready. Exiting..."
    exit 0
fi

###################################################################################################
# 7. Create / reset filtering subchain for ipsets
###################################################################################################
if iptables -t raw -L "$IPSET_CHAIN" >/dev/null 2>&1; then
    iptables -t raw -F "$IPSET_CHAIN"
    log "Flushed existing chain $IPSET_CHAIN"
else
    iptables -t raw -N "$IPSET_CHAIN"
    log "Created new chain $IPSET_CHAIN"
fi

# Ensure IPSET_CHAIN is the first rule in FILTERING_CHAIN
ensure_fw_rule raw "$FILTERING_CHAIN" -I 1 -j "$IPSET_CHAIN"

###################################################################################################
# 8. Add ipset rules
###################################################################################################
ipset_rule_count=0

log "Adding ipset rules..."

while IFS=: read -r mode ports protos keys excludes minutes ip_count; do
    case "$mode" in
        log)
            minutes=${minutes:-5}
            ip_count=${ip_count:-1}
            ;;
        block|allow|pass)
            if [ -n "$minutes" ]; then
                log -l warn "Argument 'minutes' ignored for mode '$mode'"
                ipset_rules_warnings=1
            fi

            if [ -n "$ip_count" ]; then
                log -l warn "Argument 'ip_count' ignored for mode '$mode'"
                ipset_rules_warnings=1
            fi
            ;;
        '')
            continue  # ignore empty lines
            ;;
        *)
            log -l warn "Unknown mode '$mode' - skipping"
            ipset_rules_warnings=1
            continue
            ;;
    esac

    # Save original port representation for logging
    port_list="$ports"

    # Normalize input
    [ "$ports"  = "any" ] && ports=""
    [ "$protos" = "any" ] && protos="tcp,udp"

    # Build PORT_SPEC (single port -> --dport, list/range -> multiport)
    if [ -z "$ports" ]; then
        port_spec=""
    elif printf '%s\n' "$ports" | grep -q '[,-]'; then
        port_spec="-m multiport --dports $ports"
    else
        port_spec="--dport $ports"
    fi

    exclude_list="$excludes"

    # Main ipset
    set=$(printf '%s' "$keys" | tr ',' '_')

    if [ "$set" = "any" ]; then
        if [ "$mode" = "log" ]; then
            match=""
        else
            log -l warn "Meta ipset '$set' is only supported for mode 'log' - skipping"
            ipset_rules_warnings=1
            continue
        fi
    else
        if ! ipset list "$set" >/dev/null 2>&1; then
            log -l warn "ipset '$set' is missing - skipping"
            ipset_rules_warnings=1
            continue
        fi

        match="-m set --match-set $set src"
    fi

    # Exclude ipsets (if any)
    if [ -n "$exclude_list" ]; then
        excl_set=$(printf '%s' "$exclude_list" | tr ',' '_')

        if [ "$excl_set" = "any" ]; then
            log -l warn "Meta ipset '$excl_set' is not supported for exclusions - skipping"
            ipset_rules_warnings=1
            continue
        fi

        if ! ipset list "$excl_set" >/dev/null 2>&1; then
            log -l warn "Exclusion ipset '$excl_set' is missing - skipping"
            ipset_rules_warnings=1
            continue
        fi

        excl="-m set ! --match-set $excl_set src"
        excl_log=" excl_set=$excl_set"
    else
        excl=""
        excl_log=""
    fi

    # Build rules for each protocol
    for proto in $(printf '%s' "$protos" | tr ',' ' '); do
        case "$mode" in
            block)  # blocklist -> drop when src matches the set
                ensure_fw_rule raw "$IPSET_CHAIN" \
                    -p "$proto" $port_spec \
                    $match \
                    $excl \
                    -j DROP
                log "Added DROP rule -> $IPSET_CHAIN:" \
                    "proto=$proto ports=$port_list set=${set}${excl_log}"

                ipset_rule_count=$((ipset_rule_count + 1))
                ;;

            allow)  # allowlist -> accept listed ipsets, drop other traffic
                ensure_fw_rule raw "$IPSET_CHAIN" \
                    -p "$proto" $port_spec \
                    $match \
                    $excl \
                    -j RETURN
                log "Added RETURN rule -> $IPSET_CHAIN:" \
                    "proto=$proto ports=$port_list set=${set}${excl_log}"

                ensure_fw_rule raw "$IPSET_CHAIN" \
                    -p "$proto" $port_spec \
                    -j DROP
                log "Added DROP rule -> $IPSET_CHAIN:" \
                    "proto=$proto ports=$port_list"

                ipset_rule_count=$((ipset_rule_count + 2))
                ;;

            pass)   # passlist  -> accept and skip all further checks (e.g. DoS, other rules)
                ensure_fw_rule raw "$IPSET_CHAIN" \
                    -p "$proto" $port_spec \
                    $match \
                    $excl \
                    -j ACCEPT
                log "Added ACCEPT rule -> $IPSET_CHAIN:" \
                    "proto=$proto ports=$port_list set=${set}${excl_log}"

                ipset_rule_count=$((ipset_rule_count + 1))
                ;;

            log)    # log only  -> log matching traffic (with rate limit), no accept or drop
                # Build short hashlimit name from UUID
                limit_name=$(sanitize_hl_name "$(uuid4)")

                # Build compact ipset log prefix:
                # - Include ports and the first letter of proto ("t" or "u") for brevity.
                # - Include set name(s) and the original port representation (may be list/range).
                # - If $excl_set is non-empty, insert "_$excl_set"; otherwise insert nothing.
                # - Result: ips_<ports><t|u>_<set>[_<excl_set>], e.g. "ips_80,443t_blk".
                log_name="ips_${port_list}$(printf '%.1s' "$proto")_${set}${excl_set:+_$excl_set}"

                # Calculate rates
                hashlimit_rate=$(calc_hashlimit_rate "$minutes")
                expire_ms=$((minutes * 60000))

                ensure_fw_rule raw "$IPSET_CHAIN" \
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

                log "Added LOG rule -> $IPSET_CHAIN:" \
                    "proto=$proto ports=$port_list set=${set}${excl_log}" \
                    "minutes=$minutes ip_count=$ip_count (log_rate=$hashlimit_rate)"

                ipset_rule_count=$((ipset_rule_count + 1))
                ;;
        esac
    done
done << EOF
$ipset_rules
EOF

# Log summary
if [ "$ipset_rule_count" -eq 0 ]; then
    log "No ipset rules are defined"
else
    if [ "$ipset_rules_warnings" -eq 0 ]; then
        log "Added $ipset_rule_count rules to $IPSET_CHAIN"
    else
        log -l warn "Added $ipset_rule_count rules to $IPSET_CHAIN with warnings;" \
            "please check logs for details"
    fi
fi

###################################################################################################
# 9. Finalize
###################################################################################################

if [ "$dos_rules_warnings" -eq 0 ] && [ "$ipset_rules_warnings" -eq 0 ]; then
    log "All filtering rules have been created successfully"
else
    log -l warn "Completed with warnings; please check logs for details"
fi
