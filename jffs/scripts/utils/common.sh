#!/usr/bin/env ash

###################################################################################################
# common.sh  -  shared functions library for Asuswrt-Merlin shell scripts
# -------------------------------------------------------------------------------------------------
# Public API
# ----------
#   uuid4
#         Generates a kernel-provided random UUIDv4 (RFC 4122) string.
#
#   compute_hash
#         Computes a SHA-256 digest of a file or stdin
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
#   is_lan_ip <ipv4>
#         returns 0 when the address is in an RFC-1918 private subnet, or
#         1 when it is public / unroutable.
#
#   resolve_ip <host-or-ip>
#         prints a single IPv4 address (LAN or WAN).  Accepts literal IPs,
#         /etc/hosts aliases, or DNS names.  Exits non-zero on failure.
#
#   resolve_lan_ip <host-or-ip>
#         like resolve_ip, but additionally verifies that the result lies
#         in a private RFC-1918 range.  Logs an error and exits non-zero if not.
#
#   get_active_wan_if
#         Returns the name of the currently active WAN interface (e.g., eth0, eth10).
#         Falls back to wan0_ifname if none are marked primary.
#
#   strip_comments [<text>]
#         Removes leading/trailing whitespace, drops blank/# lines, and strips
#         inline '#' comments. Reads from the argument if given, else stdin;
#         prints cleaned lines.
#
#   is_pos_int <value>
#         Returns success (0) if <value> is a positive integer (>=1); else returns 1.
#
# Notes
# -----
#   * Internal functions (names starting with an underscore) are considered private
#     implementation details and may change without notice.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2086
# shellcheck disable=SC2155

###################################################################################################
# _resolve_ip_impl - internal resolver used by resolve_ip / resolve_lan_ip
# -------------------------------------------------------------------------------------------------
# Behavior:
#   * If the argument looks like a literal IPv4, returns it as-is.
#   * Else tries:
#       (1) /etc/hosts alias match
#       (2) nslookup fallback
#   * On success: prints the resolved IP.
#   * On failure: prints nothing.
#
# Internal-only. Do not call directly.
###################################################################################################
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
# is_lan_ip - returns 0 for RFC-1918 (private) IPv4 addresses, 1 otherwise
# -------------------------------------------------------------------------------------------------
# Usage:
#   is_lan_ip <ipv4>
#
# Example:
#   is_lan_ip 192.168.1.100  ->  returns 0
#   is_lan_ip 8.8.8.8        ->  returns 1
###################################################################################################
is_lan_ip() {
    case "$1" in
        192.168.*)                              return 0 ;;   # 192.168.0.0/16
        10.*)                                   return 0 ;;   # 10.0.0.0/8
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;   # 172.16.0.0/12
        *)                                      return 1 ;;
    esac
}

###################################################################################################
# resolve_ip - resolve host/IP to a single IPv4 address (LAN or WAN)
# -------------------------------------------------------------------------------------------------
# Usage:
#   resolve_ip <host-or-ip>
#
# Behavior:
#   * Accepts literal IPs, /etc/hosts entries, or DNS names.
#   * Returns the resolved IPv4 address on success.
#   * Fails with an error if resolution fails.
###################################################################################################
resolve_ip() {
    local ip

    ip=$(_resolve_ip_impl "$1")
    if [ -z "$ip" ]; then
        log -l err "Cannot resolve '$1'"
        return 1
    fi

    printf '%s\n' "$ip"
}

###################################################################################################
# resolve_lan_ip - resolve host/IP and validate it belongs to a private LAN range
# -------------------------------------------------------------------------------------------------
# Usage:
#   resolve_lan_ip <host-or-ip>
#
# Behavior:
#   * Uses resolve_ip internally.
#   * Then enforces RFC-1918 check (10/8, 172.16/12, 192.168/16).
#   * Fails with error if the resolved IP is not private.
###################################################################################################
resolve_lan_ip() {
    local ip

    # Reuse the generic resolver first
    ip=$(resolve_ip "$1") || return 1

    # Then enforce RFC-1918 check
    if ! is_lan_ip "$ip"; then
        log -l err "'$ip' is not a LAN address"
        return 1
    fi

    printf '%s\n' "$ip"
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
