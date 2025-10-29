#!/usr/bin/env ash

###################################################################################################
# common.sh  -  shared functions library for Asuswrt-Merlin shell scripts
# -------------------------------------------------------------------------------------------------
# Public API
# ----------
#   uuid4
#       Generates a kernel-provided random UUIDv4 (RFC 4122) string.
#
#   compute_hash
#       Computes a SHA-256 digest of a file or stdin.
#
#   get_script_path
#       Returns the absolute path to the current script, resolving symlinks.
#
#   get_script_dir
#       Returns the directory containing the current script.
#
#   get_script_name [-n]
#       Returns the script's filename. With -n, strips the extension.
#
#   log [-l <level>] <message...>
#       Lightweight syslog wrapper. Logs to both syslog (user facility) and stderr.
#       Supports priority levels with optional -l flag.
#
#   acquire_lock [<name>]
#       Acquires an exclusive non-blocking lock via /var/lock/<name>.lock; exits early if another
#       instance is already running.
#
#   tmp_file
#       Creates a UUID-named /tmp file tied to the script and tracks it for automatic cleanup.
#
#   tmp_dir
#       Creates a UUID-named /tmp directory tied to the script and tracks it for automatic cleanup.
#
#   is_lan_ip [-6] <ip>
#       Returns 0 when the address is in a private/LAN range, else 1.
#       IPv4: RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
#       IPv6: ULA (fc00::/7) and link-local (fe80::/10)  [heuristic prefix check]
#
#   resolve_ip [-6] [-q] [-g] [-a] <host|ip>
#       Resolves a host or literal IP to one or more addresses.
#         -6 : resolve IPv6 (default: IPv4)
#         -q : quiet on resolution failure
#         -g : only global IPv6 / public IPv4
#         -a : return ALL matches (default: first match only)
#       Accepts literal IPs, /etc/hosts aliases, or DNS names.
#
#   resolve_lan_ip [-6] [-q] [-a] <host|ip>
#       Like resolve_ip, but returns only private/LAN addresses for the selected family.
#         -6 : IPv6 (ULA / link-local considered LAN)
#         -q : quiet on resolution failure
#         -a : return ALL LAN matches (default: first only)
#
#   get_ipv6_enabled
#       Prints 1 if IPv6 is enabled in NVRAM (ipv6_service != disabled), otherwise 0.
#
#   get_active_wan_if
#       Returns the name of the currently active WAN interface (e.g., eth0, eth10).
#
#   strip_comments [<text>]
#       Removes leading/trailing whitespace, drops blank/# lines, and strips inline '#' comments.
#       Reads from the argument if given, else stdin; prints cleaned lines.
#
#   is_pos_int <value>
#       Returns success (0) if <value> is a positive integer (>=1); else returns 1.
#
# Notes
# -----
#   * Use -6 in functions to select IPv6 (where applicable).
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2086
# shellcheck disable=SC2155

###################################################################################################
# _resolve_ip_impl - internal resolver used by resolve_ip / resolve_lan_ip
# -------------------------------------------------------------------------------------------------
# Flags:
#   -6 : resolve IPv6 (default: IPv4)
#   -g : only global IPv6 or public IPv4
#   -a : return ALL matching addresses (default: first match only)
#
# Behavior:
#   * If the argument looks like a literal IP of the selected family, returns it
#     (respects -g; rejects non-global v6 / non-public v4 when -g is set).
#   * Else tries:
#       (1) /etc/hosts alias match (first column must match family)
#       (2) nslookup fallback (first "Name:" block; scan "Address ..." lines)
#   * Prints one or more IPs (depending on -a) on success; prints nothing on failure.
#
# Internal-only. Do not call directly.
###################################################################################################
_resolve_ip_impl() {
    # Parse flags
    local use_v6=0 only_global=0 return_all=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) use_v6=1; shift ;;
            -g) only_global=1; shift ;;
            -a) return_all=1; shift ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done

    local arg="${1-}"
    [ -n "$arg" ] || return 1

    # Patterns
    local ipv4_pat='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    local ipv6_pat='^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$'
    local ipv4_private_pat='^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)'
    local ipv6_private_pat='^(::1|[Ff][CcDd].*|[Ff][Ee][89AaBb][0-9A-Fa-f]{2}:.*)$'

    # Select family
    local fam_pat non_global_pat g_flags
    if [ "$use_v6" -eq 1 ]; then
        fam_pat="$ipv6_pat"; non_global_pat="$ipv6_private_pat"; g_flags='-Eiq'
    else
        fam_pat="$ipv4_pat"; non_global_pat="$ipv4_private_pat";  g_flags='-Eq'
    fi

    # Helper: emit if matches family and (if -g) is global/public
    _emit_if_ok() {
        local cand="$1"
        printf '%s\n' "$cand" | grep $g_flags -- "$fam_pat" >/dev/null || return 1
        if [ "$only_global" -eq 1 ] && printf '%s\n' "$cand" |
            grep $g_flags -- "$non_global_pat" >/dev/null;
        then
            return 1
        fi
        printf '%s\n' "$cand"
        return 0
    }

    # Literal IP fast path
    if _emit_if_ok "$arg"; then
        return 0
    fi

    local host="${arg%.}"  # strip trailing dot

    if [ "$return_all" -eq 0 ]; then
        # First match only (no dedup)
        local ip
        ip=$(
            awk -v h="$host" -v pat="$fam_pat" -v only_g="$only_global" \
                -v ng="$non_global_pat" '
                $1 ~ pat {
                    if (only_g && $1 ~ ng) next
                    for (i = 2; i <= NF; i++) {
                        gsub(/\.$/, "", $i)
                        if ($i == h) { print $1; exit }
                    }
                }' /etc/hosts 2>/dev/null
        )
        [ -n "$ip" ] && { printf '%s\n' "$ip"; return 0; }

        ip=$(
            nslookup "$host" 2>/dev/null |
            awk -v pat="$fam_pat" -v only_g="$only_global" -v ng="$non_global_pat" '
                BEGIN { in_ans = 0 }
                /^Name:[[:space:]]*/ { in_ans = 1; next }
                in_ans && /^Address/ {
                    for (i = 1; i <= NF; i++)
                        if ($i ~ pat && !(only_g && $i ~ ng)) { print $i; exit }
                }'
        )
        [ -n "$ip" ] || return 1
        printf '%s\n' "$ip"
        return 0
    fi

    # Return ALL matches (-a): gather + order-preserving dedup; avoid SC2181 by capturing output.
    local out
    out="$(
        {
            awk -v h="$host" -v pat="$fam_pat" -v only_g="$only_global" \
                -v ng="$non_global_pat" '
                $1 ~ pat {
                    if (only_g && $1 ~ ng) next
                    for (i = 2; i <= NF; i++) {
                        gsub(/\.$/, "", $i)
                        if ($i == h) print $1
                    }
                }' /etc/hosts 2>/dev/null

            nslookup "$host" 2>/dev/null |
            awk -v pat="$fam_pat" -v only_g="$only_global" -v ng="$non_global_pat" '
                BEGIN { in_ans = 0 }
                /^Name:[[:space:]]*/ { in_ans = 1; next }
                in_ans && /^Address/ {
                    for (i = 1; i <= NF; i++)
                        if ($i ~ pat && !(only_g && $i ~ ng)) print $i
                }'
        } | awk '!seen[$0]++'
    )"

    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
    return 0
}

###################################################################################################
# uuid4 - generate a kernel-provided UUIDv4
# -------------------------------------------------------------------------------------------------
# Usage:
#   id=$(uuid4)
#
# Behavior:
#   * Reads from /proc/sys/kernel/random/uuid, which returns a randomly generated
#     RFC 4122 version 4 UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000").
#   * Output format is always lowercase hex with hyphens.
#   * No external dependencies; uses the kernel's built-in UUID generator.
###################################################################################################
uuid4() {
    cat /proc/sys/kernel/random/uuid
}

###################################################################################################
# compute_hash - compute a SHA-256 digest of a file or stdin
# -------------------------------------------------------------------------------------------------
# Usage:
#   # From a file path:
#   hash=$(compute_hash /path/to/file)
#
#   # From piped/stdin content:
#   printf '%s' "$set" | compute_hash
#   echo -n "payload" | compute_hash
#   compute_hash - < /path/to/file
#
# Behavior:
#   * When given a path (not "-"), hashes that file.
#   * With no argument or with "-", reads from stdin (so it works in pipelines).
#   * Prints only the 64-char lowercase hex digest to stdout (no filename).
#   * Exits non-zero if 'sha256sum' fails (e.g., unreadable file).
###################################################################################################
compute_hash() {
    local out

    if [ $# -ge 1 ] && [ "$1" != "-" ]; then
        out=$(sha256sum "$1") || return 1
    else
        out=$(sha256sum) || return 1  # reads stdin
    fi

    printf '%s\n' "${out%% *}"
}

###################################################################################################
# get_script_path - resolve the absolute path to the current script
# -------------------------------------------------------------------------------------------------
# Usage:
#   full_path=$(get_script_path)
#
# Behavior:
#   * Uses 'readlink -f "$0"' to follow all symlinks and produce a canonical
#     absolute path when available.
#   * If readlink fails, falls back to the literal "$0"
#     value (which may be relative).
###################################################################################################
get_script_path() {
    local _path
    _path=$(readlink -f "$0" 2>/dev/null) || _path="$0"
    printf '%s\n' "$_path"
}

###################################################################################################
# get_script_dir - return the directory containing the current script
# -------------------------------------------------------------------------------------------------
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
###################################################################################################
get_script_dir() {
    local _path
    _path="$(get_script_path)"
    printf '%s\n' "${_path%/*}"
}

###################################################################################################
# get_script_name - return the basename of the current script
# -------------------------------------------------------------------------------------------------
# Usage:
#   script_name=$(get_script_name)   # e.g., "ipset_builder.sh"
#
# Behavior:
#   * Uses get_script_path() if it's defined; otherwise falls back to "$0".
#   * Returns only the filename, stripping path components.
###################################################################################################
get_script_name() {
    local _p="$(get_script_path)"
    local base="${_p##*/}"                  # basename with extension

    [ "$1" = "-n" ] && base="${base%.*}"    # strip trailing ".ext" if -n supplied

    printf '%s\n' "$base"
}

###################################################################################################
# log - lightweight syslog logger (facility "user") with optional priority flag
# -------------------------------------------------------------------------------------------------
# Usage:
#   log [-l <level>] <message...>
#
# Behavior:
#   * <level> may be: debug | info | notice | warn | err | crit | alert | emerg
#     If -l is omitted, the message is logged with priority user.info.
#   * Non-default levels add a prefix ("ERROR: ", "WARNING: ", ...)
#     prepended to the message for readability and grep-friendliness.
#   * The tag is auto-derived from the script's filename:
#       /path/fw_reload.sh  ->  fw_reload
#   * Messages are written to both syslog (via logger) and stderr.
###################################################################################################
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

###################################################################################################
# acquire_lock - acquire an exclusive, non-blocking lock for the running script
# -------------------------------------------------------------------------------------------------
# Usage:
#   acquire_lock             # uses get_script_name -n for lock name
#   acquire_lock foo         # uses /var/lock/foo.lock
#
# Behavior:
#   * Creates /var/lock/<name>.lock and acquires exclusive lock
#     on file descriptor 200.
#   * If the lock is already held, logs the fact and exits with code 0.
#   * The lock persists until the script exits, automatically releasing it.
###################################################################################################
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

###################################################################################################
# tmp_file/tmp_dir - create and track per-script temp files and directories
# -------------------------------------------------------------------------------------------------
# This section provides:
#   * _tmp_list       - master file tracking all created temp paths.
#   * _tmp_path()     - internal function to create a UUID-named temp file/dir.
#   * tmp_file()      - wrapper for creating temp file in /tmp.
#   * tmp_dir()       - wrapper for creating temp dir in /tmp.
#   * _cleanup_tmp()  - deletes all temp paths listed in $_tmp_list.
#   * trap            - ensures cleanup on EXIT, INT, or TERM.
###################################################################################################

# Master list path, e.g., /tmp/ipset_builder.sh.12345.tmp_files
_tmp_list="/tmp/$(get_script_name -n).$$.tmp_files"

# Initialize (or truncate) the list file
: > "$_tmp_list"

# -------------------------------------------------------------------------------------------------
# _tmp_path - create a UUID-named temp file or dir in /tmp tied to this script
# -------------------------------------------------------------------------------------------------
# Usage:
#   _tmp_path         -> creates a temp file
#   _tmp_path -d      -> creates a temp directory
#
# Behavior:
#   * Prints the new path.
#   * Creates an empty file or directory.
#   * Appends the path to $_tmp_list for later cleanup.
# -------------------------------------------------------------------------------------------------
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

# -------------------------------------------------------------------------------------------------
# _cleanup_tmp - delete all temp files and directories listed in $_tmp_list
# -------------------------------------------------------------------------------------------------
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

###################################################################################################
# is_lan_ip - returns 0 for private/LAN addresses, 1 otherwise
# -------------------------------------------------------------------------------------------------
# Usage:
#   is_lan_ip <ipv4>
#   is_lan_ip -6 <ipv6>
#
# Args:
#   -6    : OPTIONAL; check IPv6 instead of IPv4
#   <ip>  : address to check
#
# Behavior:
#   * IPv4: returns 0 for RFC-1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
#   * IPv6: returns 0 for ULA (fc00::/7) and link-local (fe80::/10).
#   * Returns 1 otherwise.
#
# Examples:
#   is_lan_ip 192.168.1.100   -> returns 0
#   is_lan_ip 8.8.8.8         -> returns 1
#   is_lan_ip -6 fd12::1      -> returns 0
#   is_lan_ip -6 2001:4860::  -> returns 1
###################################################################################################
is_lan_ip() {
    local use_v6=0 ip

    if [ "$1" = "-6" ]; then
        use_v6=1
        shift
    fi
    ip="${1-}"

    if [ "$use_v6" -eq 1 ]; then
        case "$ip" in
            [Ff][Cc]*|[Ff][Dd]*)                    return 0 ;;   # ULA fc00::/7
            [Ff][Ee][89AaBb]*)                      return 0 ;;   # link-local fe80::/10
            *)                                      return 1 ;;
        esac
    else
        case "$ip" in
            192.168.*)                              return 0 ;;   # 192.168.0.0/16
            10.*)                                   return 0 ;;   # 10.0.0.0/8
            172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;   # 172.16.0.0/12
            *)                                      return 1 ;;
        esac
    fi
}

###################################################################################################
# resolve_ip - resolve host/IP to one or more IPs
# -------------------------------------------------------------------------------------------------
# Usage:
#   resolve_ip [-6] [-q] [-g] [-a] <host|ip>
#
# Flags:
#   -6  : resolve IPv6 (default: IPv4)
#   -q  : quiet on resolution failure
#   -g  : only global IPv6 / public IPv4
#   -a  : return ALL matching addresses (default: first match only)
#
# Behavior:
#   * Accepts literal IPs, /etc/hosts entries, or DNS names.
#   * Prints the resolved address(es) on success (one per line if -a).
#   * Fails with an error if resolution fails or arg is missing.
###################################################################################################
resolve_ip() {
    local use_v6=0 quiet=0 only_global=0 return_all=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) use_v6=1; shift ;;
            -q) quiet=1; shift ;;
            -g) only_global=1; shift ;;
            -a) return_all=1; shift ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done

    local arg="${1-}" out
    if [ -z "$arg" ]; then
        log -l err "resolve_ip: usage: resolve_ip [-6] [-q] [-g] [-a] <host|ip>"
        return 1
    fi

    # Build argv for _resolve_ip_impl
    set --
    [ "$use_v6" -eq 1 ]      && set -- "$@" -6
    [ "$only_global" -eq 1 ] && set -- "$@" -g
    [ "$return_all" -eq 1 ]  && set -- "$@" -a
    set -- "$@" "$arg"

    if ! out="$(_resolve_ip_impl "$@")"; then
        [ "$quiet" -eq 1 ] || log -l err "Cannot resolve '$arg'"
        return 1
    fi

    printf '%s\n' "$out"
}

###################################################################################################
# resolve_lan_ip - resolve host/IP and validate it belongs to a private LAN range
# -------------------------------------------------------------------------------------------------
# Usage:
#   resolve_lan_ip [-6] [-q] [-a] <host|ip>
#
# Flags:
#   -6  : resolve IPv6 (ULA / link-local considered LAN)
#   -q  : quiet on resolution failure
#   -a  : return ALL matching LAN addresses (default: first match only)
#
# Behavior:
#   * Resolves via resolve_ip for the requested family.
#   * Filters to LAN/private addresses:
#       - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
#       - IPv6: fc00::/7 (ULA), fe80::/10 (link-local)
#   * Prints the LAN address(es) on success; errors if none match.
###################################################################################################
resolve_lan_ip() {
    local use_v6=0 v6_flag="" quiet=0 q_flag="" return_all=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) use_v6=1; v6_flag="-6"; shift ;;
            -q) quiet=1; q_flag="-q"; shift ;;
            -a) return_all=1; shift ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done

    local arg="${1-}"
    if [ -z "$arg" ]; then
        log -l err "resolve_lan_ip: usage: resolve_lan_ip [-6] [-q] [-a] <host|ip>"
        return 1
    fi

    # Resolve all candidates for the chosen family
    local all filtered out

    all="$(resolve_ip $v6_flag $q_flag -a "$arg")" || return 1

    # Keep only LAN / private addresses
    filtered="$(
        printf '%s\n' "$all" | while IFS= read -r ip; do
            is_lan_ip $v6_flag "$ip" && printf '%s\n' "$ip"
        done
    )"

    if [ -z "$filtered" ]; then
        [ "$quiet" -eq 1 ] || log -l err "No LAN address found for '$arg'"
        return 1
    fi

    out="$filtered"
    if [ "$return_all" -eq 0 ]; then
        out="$(printf '%s\n' "$filtered" | head -n1)"
    fi

    printf '%s\n' "$out"
}

###################################################################################################
# get_ipv6_enabled - check if IPv6 is enabled in router settings
# -------------------------------------------------------------------------------------------------
# Usage:
#   IPV6_ENABLED="$(get_ipv6_enabled)"
#
# Behavior:
#   * Reads the NVRAM variable "ipv6_service".
#   * Prints "1" if set and not "disabled"; otherwise prints "0".
#
# Output / Returns:
#   * Prints: 1 (enabled) or 0 (disabled)
#   * Exit status: always 0 (safe under `set -e`)
###################################################################################################
get_ipv6_enabled() {
    local s
    s="$(nvram get ipv6_service 2>/dev/null || true)"
    if [ -n "$s" ] && [ "$s" != "disabled" ]; then
        printf '1\n'
    else
        printf '0\n'
    fi
}

###################################################################################################
# get_active_wan_if - return the name of the currently active WAN interface
# -------------------------------------------------------------------------------------------------
# Usage:
#   WAN_IF=$(get_active_wan_if)  # -> eth0, eth10, ...
#
# Behavior:
#   * ASUSWRT stores a "primary" flag per WAN (wan0_primary, wan1_primary, ...).
#   * The flag is 1 for the interface that's up / in use, 0 otherwise.
#   * We loop through the known WAN slots in order and return the first one
#     whose _primary flag is 1.
#   * Falls back to wan0_ifname if none are marked primary.
###################################################################################################
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

###################################################################################################
# strip_comments - trim lines, drop blanks, and remove # comments
# -------------------------------------------------------------------------------------------------
# Behavior:
#   1. Trims leading/trailing whitespace
#   2. Skips empty lines
#   3. Skips lines starting with '#'
#   4. Strips inline comments (everything after the first '#')
#
# Usage:
#   clean="$(strip_comments "$DOS_PROT_RULES")"
#   # or
#   printf '%s\n' "$DOS_PROT_RULES" | strip_comments
###################################################################################################
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

###################################################################################################
# is_pos_int - return success if the argument is a positive integer (>= 1)
# -------------------------------------------------------------------------------------------------
# Usage:
#   is_pos_int <value>
#
# Behavior:
#   * Accepts only base-10 digits (e.g., "1", "42", "0007").
#   * Returns 0 (true) if <value> is an integer >= 1.
#   * Returns 1 (false) for empty, non-numeric, or zero values.
###################################################################################################
is_pos_int() {
    local v="$1"

    case "$v" in
        ''|*[!0-9]*) return 1 ;;
    esac

    [ "$v" -ge 1 ] 2>/dev/null
}
