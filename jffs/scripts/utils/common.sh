#!/usr/bin/env ash

#######################################################################################
# common.sh  -  shared functions library for Asuswrt-Merlin shell scripts
# -------------------------------------------------------------------------------------
# Public API
# ----------
#   uuid4
#         Generates a kernel-provided random UUIDv4 (RFC 4122) string.
#
#   get_script_path
#         Returns the absolute path to the current script, resolving symlinks.
#
#   get_script_dir
#         Returns the directory containing the current script.
#
#   get_script_name [-n]
#         Returns the script's filename. With -n, strips the extension.
#
#   log [-l <level>] <message...>
#         Lightweight syslog wrapper. Logs to both syslog (user facility)
#         and stderr. Supports priority levels with optional -l flag.
#
#   acquire_lock [<name>]
#         Acquires an exclusive non-blocking lock via /var/lock/<name>.lock;
#         exits early if another instance is already running.
#
#   tmp_file
#         Creates a UUID-named /tmp file tied to the script and tracks it for
#         automatic cleanup on exit (via trap).
#
#   tmp_dir
#         Creates a UUID-named /tmp directory tied to the script and tracks it for
#         automatic cleanup on exit (via trap).
#
#   strip_comments [<text>]
#         Removes leading/trailing whitespace, drops blank/# lines, and strips
#         inline '#' comments. Reads from the argument if given, else stdin;
#         prints cleaned lines.
#
#   is_lan_ip <ipv4>
#         returns 0 when the address is in an RFC‑1918 private subnet, or
#         1 when it is public / unroutable.
#
#   resolve_ip <host-or-ip>
#         prints a single IPv4 address (LAN or WAN).  Accepts literal IPs,
#         /etc/hosts aliases, or DNS names.  Exits non‑zero on failure.
#
#   resolve_lan_ip <host-or-ip>
#         like resolve_ip, but additionally verifies that the result lies
#         in a private RFC‑1918 range.  Logs an error and exits non‑zero if not.
#
#   get_active_wan_if
#         Returns the name of the currently active WAN interface (e.g. eth0, eth10).
#         Falls back to wan0_ifname if none are marked primary.
#
#   ensure_fw_rule <table> <chain> [-I|-D] <rule...>
#         Idempotent firewall helper:
#           *  no flag    -> append rule (-A) if it's missing
#           *  -I         -> insert rule (-I) at the top if missing
#           *  -D         -> delete rule (-D) if it exists
#         Guarantees the rule appears exactly once (or not at all, for -D).
#
#   block_wan_for_host <hostname|ip> [wan_id]
#         Resolves the host to a LAN IP and inserts REJECT/DROP rules into the
#         filter FORWARD chain to block both outbound traffic from the device
#         to the specified WAN interface and inbound traffic from that WAN
#         back to the device.
#         If wan_id is omitted, defaults to WAN 1 (secondary/backup).
#
#   allow_wan_for_host <hostname|ip> [wan_id]
#         Resolves the host to a LAN IP and removes the corresponding
#         REJECT/DROP rules, restoring WAN access for that device.
#         If wan_id is omitted, defaults to WAN 1 (secondary/backup).
#
# Internal functions (names starting with an underscore) are considered private
# implementation details and may change without notice.
#######################################################################################

# -------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------
# shellcheck disable=SC2086
# shellcheck disable=SC2155

#######################################################################################
# _resolve_ip_impl - internal resolver used by resolve_ip / resolve_lan_ip
# -------------------------------------------------------------------------------------
# Behavior:
#   * If the argument looks like a literal IPv4, returns it as-is.
#   * Else tries:
#       (1) /etc/hosts alias match
#       (2) nslookup fallback
#   * On success: prints the resolved IP.
#   * On failure: prints nothing.
#
# Internal-only. Do not call directly.
#######################################################################################
_resolve_ip_impl() {
    local arg="$1" host ip

    # 1. Literal IPv4? Return it
    if printf '%s\n' "$arg" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        printf '%s\n' "$arg"
        return 0
    fi

    host="${arg%.}"   # strip trailing dot, if any

    # 2. /etc/hosts (match any alias column)
    ip=$(awk -v h="$host" '
        $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            for (i = 2; i <= NF; i++) {
                gsub(/\.$/, "", $i)
                if ($i == h) { print $1; exit }
            }
        }' /etc/hosts)

    # 3. nslookup fallback - only read Address lines after the first "Name:"
    if [ -z "$ip" ]; then
        ip=$(nslookup "$host" 2>/dev/null |
             awk '
                BEGIN { in_ans = 0 }
                /^Name:[[:space:]]*/ { in_ans = 1; next }   # start of answer block
                in_ans && /^Address/ {
                    for (i = 1; i <= NF; i++)
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }
                }')
    fi

    if [ -z "$ip" ]; then
        return 1
    fi

    printf '%s\n' "$ip"
    return 0
}

#######################################################################################
# uuid4 - generate a kernel-provided UUIDv4
# -------------------------------------------------------------------------------------
# Usage:
#   id=$(uuid4)
#
# Behavior:
#   * Reads from /proc/sys/kernel/random/uuid, which returns a randomly generated
#     RFC 4122 version 4 UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000").
#   * Output format is always lowercase hex with hyphens.
#   * No external dependencies; uses the kernel's built-in UUID generator.
#######################################################################################
uuid4() {
    cat /proc/sys/kernel/random/uuid
}

#######################################################################################
# get_script_path - resolve the absolute path to the current script
# -------------------------------------------------------------------------------------
# Usage:
#   full_path=$(get_script_path)
#
# Behavior:
#   * Uses 'readlink -f "$0"' to follow all symlinks and produce a canonical
#     absolute path when available.
#   * If readlink fails, falls back to the literal "$0"
#     value (which may be relative).
#######################################################################################
get_script_path() {
    local _path
    _path=$(readlink -f "$0" 2>/dev/null) || _path="$0"
    printf '%s\n' "$_path"
}

#######################################################################################
# get_script_dir - return the directory containing the current script
# -------------------------------------------------------------------------------------
# Usage:
#   script_dir=$(get_script_dir)
#
# Behavior:
#   * Uses get_script_path (above) and strips the trailing component.
#   * Always returns an absolute directory path with no trailing slash.
#
# Example:
#   # Source a sibling file:
#     . "$(get_script_dir)/config.sh"
#######################################################################################
get_script_dir() {
    local _path
    _path="$(get_script_path)"
    printf '%s\n' "${_path%/*}"
}

#######################################################################################
# get_script_name - return the basename of the current script
# -------------------------------------------------------------------------------------
# Usage:
#   script_name=$(get_script_name)   # e.g. "ipset_builder.sh"
#
# Behavior:
#   * Uses get_script_path() if it's defined; otherwise falls back to "$0".
#   * Returns only the filename, stripping path components.
#######################################################################################
get_script_name() {
    local _p="$(get_script_path)"
    local base="${_p##*/}"                  # basename with extension

    [ "$1" = "-n" ] && base="${base%%.*}"   # strip trailing ".ext" if -n supplied

    printf '%s\n' "$base"
}

#######################################################################################
# log - lightweight syslog logger (facility "user") with optional priority flag
# -------------------------------------------------------------------------------------
# Usage:
#   log [-l <level>] <message...>
#
# Behavior:
#   * <level> may be: debug | info | notice | warn | err | crit | alert | emerg
#     If -l is omitted, the message is logged with priority user.info.
#   * Non-default levels add a prefix ("ERROR: ", "WARNING: ", ...)
#     prepended to the message for readability and grep‑friendliness.
#   * The tag is auto‑derived from the script's filename:
#       /path/fw_reload.sh  ->  fw_reload
#   * Messages are written to both syslog (via logger) and stderr.
#######################################################################################
_log_tag="$(get_script_name -n)"

log() {
    local level="info"    # default priority

    # Optional "-l <level>"
    if [ "$1" = "-l" ] && [ -n "$2" ]; then
        level=$2
        shift 2
    fi

    # Prefix table for non-default levels
    local prefix=""
    case "$level" in
        debug)   prefix="DEBUG: " ;;
        notice)  prefix="NOTICE: " ;;
        warn)    prefix="WARNING: " ;;
        err)     prefix="ERROR: " ;;
        crit)    prefix="CRITICAL: " ;;
        alert)   prefix="ALERT: " ;;
        emerg)   prefix="EMERGENCY: " ;;
        # info (default) gets no prefix
    esac

    logger -s -t "$_log_tag" -p "user.$level" "${prefix}$*"
}

#######################################################################################
# acquire_lock - acquire an exclusive, non-blocking lock for the running script
# -------------------------------------------------------------------------------------
# Usage:
#   acquire_lock             # uses get_script_name -n for lock name
#   acquire_lock foo         # uses /var/lock/foo.lock
#
# Behavior:
#   * Creates /var/lock/<name>.lock and acquires exclusive lock
#     on file descriptor 200.
#   * If the lock is already held, logs the fact and exits with code 0.
#   * The lock persists until the script exits, automatically releasing it.
#######################################################################################
acquire_lock() {
    local name="${1:-$(get_script_name -n)}"
    local file="/var/lock/${name}.lock"

    # Ensure /var/lock exists (tmpfs on most routers)
    [ -d /var/lock ] || mkdir -p /var/lock 2>/dev/null

    exec 200>"$file"           # FD 200 -> /var/lock/foo.lock
    if ! flock -n 200; then
        log "Another instance is already running (lock: $file) - exiting"
        exit 0
    fi
    printf '%s\n' "$$" 1>&200  # store our PID for clarity
}

#######################################################################################
# tmp_file/tmp_dir - create and track per-script temp files and directories
# -------------------------------------------------------------------------------------
# This section provides:
#   * _tmp_list       - master file tracking all created temp paths.
#   * _tmp_path()     - internal function to create a UUID-named temp file/dir.
#   * tmp_file()      - wrapper for creating temp file in /tmp.
#   * tmp_dir()       - wrapper for creating temp dir in /tmp.
#   * _cleanup_tmp()  - deletes all temp paths listed in $_tmp_list.
#   * trap            - ensures cleanup on EXIT, INT, or TERM.
#######################################################################################

# Master list path, e.g. /tmp/ipset_builder.sh.12345.tmp_files
_tmp_list="/tmp/$(get_script_name -n).$$.tmp_files"

# Initialize (or truncate) the list file
: > "$_tmp_list"

# -------------------------------------------------------------------------------------
# _tmp_path - create a UUID-named temp file or dir in /tmp tied to this script
# -------------------------------------------------------------------------------------
# Usage:
#   _tmp_path         -> creates a temp file
#   _tmp_path -d      -> creates a temp directory
#
# Behavior:
#   * Prints the new path.
#   * Creates an empty file or directory.
#   * Appends the path to $_tmp_list for later cleanup.
# -------------------------------------------------------------------------------------
_tmp_path() {
    local arg="${1:-}" as_dir=0 path

    # Parse optional arg: directory mode
    case "$arg" in
        -d) as_dir=1; shift ;;
    esac

    # Compose full path with a UUID
    path="/tmp/$(get_script_name -n).$(uuid4)"

    # Create the file or directory
    if [ "$as_dir" -eq 0 ]; then
        : > "$path"
    else
        mkdir -p "$path"
    fi

    # Record it for cleanup
    printf '%s\n' "$path" >> "$_tmp_list"

    # Return the path
    printf '%s\n' "$path"
}

# Public wrappers
tmp_file() { _tmp_path; }
tmp_dir()  { _tmp_path -d; }

# -------------------------------------------------------------------------------------
# _cleanup_tmp - delete all temp files and directories listed in $_tmp_list
# -------------------------------------------------------------------------------------
_cleanup_tmp() {
    # Skip if the list file doesn't exist
    [ -f "$_tmp_list" ] || return

    # Remove all recorded paths
    while IFS= read -r f; do
        rm -rf "$f"
    done < "$_tmp_list"

    # Remove the master list itself
    rm -f "$_tmp_list"
}

# Ensure cleanup on script exit or interrupt
trap _cleanup_tmp EXIT INT TERM

#######################################################################################
# strip_comments - trim lines, drop blanks, and remove # comments
# -------------------------------------------------------------------------------------
# Behavior:
#   1. Trims leading/trailing whitespace
#   2. Skips empty lines
#   3. Skips lines starting with '#'
#   4. Strips inline comments (everything after the first '#')
#
# Usage:
#   clean="$(strip_comments "$DOS_RULES")"
#   # or
#   printf '%s\n' "$DOS_RULES" | strip_comments
#######################################################################################
strip_comments() {
    # If an argument is provided, use it; otherwise read stdin
    if [ $# -gt 0 ]; then
        printf '%s\n' "$1"
    else
        cat
    fi | awk '
        {
            gsub(/\r/,"")                           # drop CRs
            sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "")  # trim both sides
            if ($0 == "" || $0 ~ /^#/) next         # skip blank or full-line comments
            p = index($0, "#")                      # inline comment?
            if (p) {
                $0 = substr($0, 1, p-1)
                sub(/[ \t]+$/, "")
                if ($0 == "") next
            }
            print
        }
    '
}

#######################################################################################
# is_lan_ip - returns 0 for RFC‑1918 (private) IPv4 addresses, 1 otherwise
# -------------------------------------------------------------------------------------
# Usage:
#   is_lan_ip <ipv4>
#
# Example:
#   is_lan_ip 192.168.1.100  ->  returns 0
#   is_lan_ip 8.8.8.8        ->  returns 1
#######################################################################################
is_lan_ip() {
    case "$1" in
        192.168.*)                              return 0 ;;   # 192.168.0.0/16
        10.*)                                   return 0 ;;   # 10.0.0.0/8
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;   # 172.16.0.0/12
        *)                                      return 1 ;;
    esac
}

#######################################################################################
# resolve_ip - resolve host/IP to a single IPv4 address (LAN or WAN)
# -------------------------------------------------------------------------------------
# Usage:
#   resolve_ip <host-or-ip>
#
# Behavior:
#   * Accepts literal IPs, /etc/hosts entries, or DNS names.
#   * Returns the resolved IPv4 address on success.
#   * Fails with an error if resolution fails.
#######################################################################################
resolve_ip() {
    local ip

    ip=$(_resolve_ip_impl "$1")
    if [ -z "$ip" ]; then
        log -l err "Cannot resolve '$1'"
        return 1
    fi

    printf '%s\n' "$ip"
}

#######################################################################################
# resolve_lan_ip - resolve host/IP and validate it belongs to a private LAN range
# -------------------------------------------------------------------------------------
# Usage:
#   resolve_lan_ip <host-or-ip>
#
# Behavior:
#   * Uses resolve_ip internally.
#   * Then enforces RFC‑1918 check (10/8, 172.16/12, 192.168/16).
#   * Fails with error if the resolved IP is not private.
#######################################################################################
resolve_lan_ip() {
    local ip

    # Reuse the generic resolver first
    ip=$(resolve_ip "$1") || return 1

    # Then enforce RFC‑1918 check
    if ! is_lan_ip "$ip"; then
        log -l err "'$ip' is not a LAN address"
        return 1
    fi

    printf '%s\n' "$ip"
}

#######################################################################################
# get_active_wan_if - return the name of the currently active WAN interface
# -------------------------------------------------------------------------------------
# Usage:
#   WAN_IF=$(get_active_wan_if)  # -> eth0, eth10, ...
#
# Behavior:
#   * ASUSWRT stores a "primary" flag per WAN (wan0_primary, wan1_primary, ...).
#   * The flag is 1 for the interface that's up / in use, 0 otherwise.
#   * We loop through the known WAN slots in order and return the first one
#     whose _primary flag is 1.
#   * Falls back to wan0_ifname if none are marked primary.
#######################################################################################
get_active_wan_if() {
    local idx

    # Adjust the 0 1 2 sequence if you have more than three WANs configured
    for idx in 0 1 2; do
        if [ "$(nvram get wan${idx}_primary)" = "1" ]; then
            nvram get wan${idx}_ifname
            return
        fi
    done

    # Fallback: default to wan0 if nothing is flagged primary
    nvram get wan0_ifname
}

#######################################################################################
# ensure_fw_rule - idempotent iptables rule helper
# -------------------------------------------------------------------------------------
# Usage:
#   ensure_fw_rule <table> <chain> [-I|-D] <rule...>
#
# Behavior:
#   * No flag     -> appends rule (-A) if it's missing
#   * -I [<pos>]  -> inserts at top (or given position) if missing
#   * -D          -> deletes rule if it exists
#
# Notes:
#   * Skips duplicates and avoids invalid deletes.
#   * Ignores insert position for duplicate check (iptables -C ignores it).
#   * IPv4 only; pair with ip6tables for IPv6 support.
#######################################################################################
ensure_fw_rule() {
    local table=$1 chain=$2; shift 2

    local mode="-A"           # default action: append
    local pos=""              # insertion position (only for -I)

    case "$1" in
        -I)  mode="-I"; shift
             if [ -n "${1:-}" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
                 pos=$1        # numeric position supplied
                 shift
             else
                 pos=1         # default to position 1
             fi ;;
        -D)  mode="-D"; shift ;;
    esac

    # ---------------------------------------------------------------------
    # Existence check (position is irrelevant so we test without it)
    # ---------------------------------------------------------------------
    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        [ "$mode" = "-D" ] && iptables -t "$table" -D "$chain" "$@"
        return 0
    fi

    [ "$mode" = "-D" ] && return 0  # nothing to delete, done

    # ---------------------------------------------------------------------
    # Rule not present -> add it
    # ---------------------------------------------------------------------
    if [ "$mode" = "-I" ]; then
        if [ -n "$pos" ]; then
            iptables -t "$table" -I "$chain" "$pos" "$@"
        else
            iptables -t "$table" -I "$chain" "$@"
        fi
    else
        iptables -t "$table" -A "$chain" "$@"
    fi

    return 0
}

#######################################################################################
# block_wan_for_host - block a LAN device from using a specific WAN interface
# -------------------------------------------------------------------------------------
# Usage:
#   block_wan_for_host <hostname|ip> [wan_id]
#     - wan_id: ASUS WAN index (0 = primary, 1 = secondary). Defaults to 1.
#
# Behavior:
#   * Resolves the device to its LAN IP.
#   * Reads the egress interface for the given WAN.
#   * Inserts REJECT/DROP rules at the top of the filter chain to block traffic
#     both from the device's IP to the given WAN and from the given WAN
#     back to the device's IP.
#   * Logs the action (host, resolved IP, interface).
#   * Fails gracefully (logs and returns 1) if resolution fails or the WAN
#     interface name is empty.
#######################################################################################
block_wan_for_host() {
    local host="$1" wan_id="${2:-1}" host_ip wan_if

    host_ip=$(resolve_lan_ip "$host") || return 1
    wan_if="$(nvram get wan${wan_id}_ifname)"

    if [ -z "$wan_if" ]; then
        log -l err "wan${wan_id} interface name is empty; cannot block WAN for host"
        return 1
    fi

    # Block inbound traffic to the host from WAN
    ensure_fw_rule filter FORWARD -I 1 -i "$wan_if" -d "$host_ip" -j DROP

    # Block outbound traffic from the host to WAN
    ensure_fw_rule filter FORWARD -I 2 -s "$host_ip" -o "$wan_if" \
        -j REJECT --reject-with icmp-admin-prohibited

    log "Blocked WAN access for host=$host (ip=$host_ip)" \
        "on iface=$wan_if (wan_id=$wan_id)"
}

#######################################################################################
# allow_wan_for_host - restore WAN access for a previously blocked LAN device
# -------------------------------------------------------------------------------------
# Usage:
#   allow_wan_for_host <hostname|ip> [wan_id]
#     - wan_id: ASUS WAN index (0 = primary, 1 = secondary). Defaults to 1.
#
# Behavior:
#   * Resolves the device to its LAN IP.
#   * Reads the egress interface for the given WAN.
#   * Deletes the REJECT/DROP rules from filter FORWARD (if present).
#   * Logs the action (host, resolved IP, interface).
#   * Fails gracefully (logs and returns 1) if resolution fails or the WAN
#     interface name is empty.
#######################################################################################
allow_wan_for_host() {
    local host="$1" wan_id="${2:-1}" host_ip wan_if

    host_ip=$(resolve_lan_ip "$host") || return 1
    wan_if="$(nvram get wan${wan_id}_ifname)"

    if [ -z "$wan_if" ]; then
        log -l err "wan${wan_id} interface name is empty; cannot unblock WAN for host"
        return 1
    fi

    # Remove both directions if present
    ensure_fw_rule filter FORWARD -D -i "$wan_if" -d "$host_ip" -j DROP
    ensure_fw_rule filter FORWARD -D -s "$host_ip" -o "$wan_if" \
        -j REJECT --reject-with icmp-admin-prohibited

    log "Allowed WAN access for host=$host (ip=$host_ip)" \
        "on iface=$wan_if (wan_id=$wan_id)"
}
