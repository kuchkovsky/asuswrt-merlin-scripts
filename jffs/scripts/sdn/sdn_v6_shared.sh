#!/usr/bin/env ash

###################################################################################################
# sdn_v6_shared.sh - INTERNAL shared library for SDN scripts
# -------------------------------------------------------------------------------------------------
# Purpose:
#   Provides helper functions and state file paths shared by the scripts.
#   User configuration belongs in config.sh - not here.
###################################################################################################

###################################################################################################
# 1. Functions
# -------------------------------------------------------------------------------------------------
# exit_if_ipv6_disabled:
#   Exits the script early if global IPv6 is disabled in the router settings.
#   Prints a warning prompting the user to enable IPv6 globally (but keep SDN IPv6 off).
#
# is_excluded:
#   Returns 0 if the given bridge should be skipped. br0 is always excluded;
#   others can be listed in EXCLUDED_IFACES.
#
# list_bridges:
#   Lists all bridges sorted numerically (br54, br56, ...) for deterministic ordering.
#
# list_sdn:
#   Parses get_mtlan output and prints SDN definitions (name, bridge, SDN index, IPv6 state).
#   Supports optional filtering by SDN index or bridge name.
#   Use "-h" for human-readable output (name=<name> br=<br> sdn_idx=<idx>).
#
# is_br_ipv6_disabled:
#   Checks whether per-SDN IPv6 is disabled in the router GUI for a specific bridge.
#   Returns 0 if disabled (safe to configure), 1 if enabled (logs a warning and should be skipped).
###################################################################################################
exit_if_ipv6_disabled() {
    if [ "$(get_ipv6_enabled)" -eq 0 ]; then
        log -l err "IPv6 is globally disabled. Enable it in Web UI:" \
            "Advanced Settings -> IPv6; keep per-SDN IPv6 OFF"
        exit 1
    fi
}

is_excluded() {
    local iface="$1" i

    # br0 is always excluded; others can be listed in EXCLUDED_IFACES
    [ "$iface" = "br0" ] && return 0

    for i in $EXCLUDED_IFACES; do
        [ "$i" = "$iface" ] && return 0
    done

    return 1
}

list_bridges() {
    ip -o -br link |
        awk '
            $1 ~ /^br[0-9]+$/ {
                n = substr($1, 3) + 0
                printf "%09d %s\n", n, $1
            }
        ' |
        sort -n |
        awk '{ print $2 }'
}

# Outputs:
#   Machine: name|br|sdn_idx|v6_enabled
#   Human (-h): name=<name> br=<br> sdn_idx=<sdn_idx>
#
# Filters (optional):
#   list_sdn             -> list all SDNs (br* except br0)
#   list_sdn 3           -> only SDN with sdn_idx=3
#   list_sdn br56        -> only SDN with br=br56
#   list_sdn -h          -> human-readable for all
#   list_sdn -h 3        -> human-readable for sdn_idx=3
#   list_sdn -h br56     -> human-readable for br56
list_sdn() {
    local human=0 want=""
    if [ "${1:-}" = "-h" ]; then
        human=1
        want="${2:-}"
    else
        want="${1:-}"
    fi

    get_mtlan | awk -v want="$want" -v human="$human" '
        # Extract value between key:[ ... ]
        function field(line, key, start, rest, pos, open) {
            open = key ":["
            start = index(line, open); if (!start) return ""
            start += length(open)
            rest  = substr(line, start)
            pos   = index(rest, "]");  if (!pos)   return ""
            return substr(rest, 1, pos - 1)
        }

        # Decide whether to print the current block
        function maybe_print() {
            if (br ~ /^br/ && br != "br0" && sdn_idx != "") {
                if (want == "" ||
                    (want ~ /^br/      && br      == want) ||
                    (want ~ /^[0-9]+$/ && sdn_idx == want)) {
                    if (human)
                        print "name=" name " br=" br " sdn_idx=" sdn_idx
                    else
                        print name "|" br "|" sdn_idx "|" v6_enabled
                }
            }
        }

        BEGIN { name=""; br=""; sdn_idx=""; v6_enabled="" }
        { gsub(/\r/, "") }  # normalize CRLF, just in case

        # Strict, anchored matches to avoid hitting domain_name, dhcp_enable, etc.
        /^[[:space:]]*\|-[[:space:]]*name:\[/      { name       = field($0, "name") }
        /^[[:space:]]*\|-[[:space:]]*br_ifname:\[/ { br         = field($0, "br_ifname") }
        /^[[:space:]]*\|-[[:space:]]*sdn_idx:\[/   { sdn_idx    = field($0, "sdn_idx") }
        /^[[:space:]]*\|-[[:space:]]*v6_enable:\[/ { v6_enabled = field($0, "v6_enable") }

        # Block separator: a line with >=10 dashes
        /^[[:space:]]*-{10,}[[:space:]]*$/ {
            maybe_print()
            name=""; br=""; sdn_idx=""; v6_enabled=""
            next
        }
    '
}

is_br_ipv6_disabled() {
    local br="$1" info sdn_name v6_enabled

    # Grab "name|v6_enabled" for this bridge (first match only)
    info="$(list_sdn "$br" | awk -F'|' 'NR == 1 { print $1 "|" $4 }')"
    sdn_name="${info%%|*}"
    v6_enabled="${info#*|}"

    # If per-SDN IPv6 is enabled (non-zero), warn and skip
    if [ -n "$v6_enabled" ] && [ "$v6_enabled" != "0" ]; then
        log -l warn "$br (sdn_name=${sdn_name:-unknown}) has per-SDN IPv6 enabled
            in the router GUI - disable it; skipping"
        return 1
    fi

    return 0
}
