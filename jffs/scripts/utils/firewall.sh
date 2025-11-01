#!/usr/bin/env ash

###################################################################################################
# firewall.sh  - shared firewall functions library for Asuswrt-Merlin shell scripts
# -------------------------------------------------------------------------------------------------
# Public API
# ----------
#   validate_port <N>
#       Validates a single destination port: integer between 1 and 65535 (inclusive).
#       Returns 0 if valid, 1 otherwise.
#
#   validate_ports <spec>
#       Validates a destination port spec: "any", single port (N), comma list (N,N2),
#       dash range (N-M), or mixed list (e.g., 80,443,1000-2000).
#       Returns 0 if valid, 1 otherwise.
#
#   normalize_protos <spec>
#       Normalizes a protocol spec to one of: "tcp", "udp", or "tcp,udp".
#       Accepts "any", "tcp", "udp", "tcp,udp", or "udp,tcp".
#       Prints the canonical form and returns 0; non-zero on invalid input.
#
#   fw_chain_exists [-6] <table> <chain>
#       Return 0 if the chain exists in the given table (iptables/ip6tables), 1 otherwise.
#
#   create_fw_chain [-6] [-q] [-f] <table> <chain>
#       Ensure a user-defined chain exists; with -f, flush it if already present.
#       -6 uses ip6tables; -q suppresses informational logs (errors still logged).
#
#   delete_fw_chain [-6] [-q] <table> <chain>
#       Flush and delete a user-defined chain if it exists.
#       -6 uses ip6tables; -q suppresses informational logs (errors still logged).
#
#   find_fw_rules [-6] "<table> <chain>" "<grep -E pattern>"
#       Print matching rules (from 'iptables -t <table> -S <chain>') to stdout,
#       or print nothing if the chain is missing/no matches. -6 uses ip6tables.
#
#   purge_fw_rules [-6] [-q] [--count] "<table> <chain>" "<grep -E pattern>"
#       Remove rules in the specified table/chain that match the regex.
#       With --count, print the number of deleted rules (integer) to stdout.
#       -6 uses ip6tables; -q suppresses informational logs (errors still logged).
#
#   ensure_fw_rule [-6] [-q] [--count] <table> <chain> [-I [pos] | -D] <rule...>
#       Idempotent helper (iptables/ip6tables):
#         *  no flag    -> append rule (-A) if it's missing
#         *  -I [pos]   -> insert rule (-I) at position (default 1) if missing
#         *  -D         -> delete rule (-D) if it exists
#       Guarantees the rule appears exactly once (or not at all, for -D).
#       With --count, print 1 to stdout on change (insert/append/delete), else 0.
#       -6 uses ip6tables; -q suppresses informational logs (errors still logged).
#
#   sync_fw_rule [-6] [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]
#       Replace all rules matching <pattern> with a single desired rule (append by default
#       or insert at [insert_pos]). No change if exactly one match equals the desired rule.
#       With --count, print the number of changes (deleted + inserted) to stdout.
#       -6 uses ip6tables; -q suppresses informational logs (errors still logged).
#
#   block_wan_for_host <hostname|ip> [wan_id]
#       Resolve host to a LAN IPv4 and (if IPv6 is enabled) to all global IPv6.
#       Add filter/FORWARD REJECT/DROP rules to block both outbound-to and inbound-from
#       the specified WAN. Defaults to wan_id=0.
#
#   allow_wan_for_host <hostname|ip> [wan_id]
#       Resolve host to a LAN IPv4 and (if IPv6 is enabled) to all global IPv6.
#       Remove the corresponding REJECT/DROP rules, restoring access. Defaults to wan_id=0.
#
#   chg <command ...>
#       Runs a command and returns success (0) if its stdout is a non-zero integer;
#       useful with --count helpers to test whether anything changed.
#
# Notes
# -----
#   * This library expects common.sh to be sourced first.
#   * Use -6 in functions to select IPv6 (where applicable).
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2086

# -------------------------------------------------------------------------------------------------
# Ensure a logger exists
# -------------------------------------------------------------------------------------------------
if ! type log >/dev/null 2>&1; then
    logger -s -t "utils" -p "user.err" "firewall.sh requires common.sh; source it first"
    exit 1
fi

###################################################################################################
# _spec_to_log - convert an iptables spec to a compact human-readable string
# -------------------------------------------------------------------------------------------------
# Usage:
#   _spec_to_log "<iptables spec...>"
#   _spec_to_log -i br0 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.10:443
#
# Behavior:
#   * Accepts either a single-quoted string or a tokenized spec.
#   * Extracts common fields (-d/-s/-i/-o/-p/--dport/--dports/--sport/-j/--to-destination).
#   * Prints a concise form like:
#       "dest=1.2.3.4 in_iface=br0 proto=tcp port=443 -> 192.168.1.10:443"
###################################################################################################
_spec_to_log() {
    # Accept either a single-string spec or a tokenized spec
    if [ $# -eq 0 ]; then
        printf '\n'
        return
    fi

    # If a single string was provided, retokenize it respecting quotes
    if [ $# -eq 1 ]; then
        set -f
        eval "set -- $1"
        set +f
    fi

    local dest='' src='' in_if='' out_if='' proto=''
    local dport='' dports='' sport='' target='' todst=''

    # Important: consume one token per loop, and handle lookahead safely
    while [ $# -gt 0 ]; do
        arg="$1"; shift
        case "$arg" in
            -d)               [ $# -ge 1 ] && { dest="${1%/32}"; shift; } ;;
            -s)               [ $# -ge 1 ] && { src="${1%/32}";  shift; } ;;
            -i)               [ $# -ge 1 ] && { in_if="$1";      shift; } ;;
            -o)               [ $# -ge 1 ] && { out_if="$1";     shift; } ;;
            -p)               [ $# -ge 1 ] && { proto="$1";      shift; } ;;
            --dport)          [ $# -ge 1 ] && { dport="$1";      shift; } ;;
            --dports)         [ $# -ge 1 ] && { dports="$1";     shift; } ;;
            --sport|--sports) [ $# -ge 1 ] && { sport="$1";      shift; } ;;
            -j)               [ $# -ge 1 ] && { target="$1";     shift; } ;;
            --to-destination) [ $# -ge 1 ] && { todst="$1";      shift; } ;;
            -m)               [ $# -ge 1 ] && { shift; } ;;  # skip module name (e.g., "multiport")
            *)                ;;
        esac
    done

    # Build left side
    local left=""
    [ -n "$dest"   ] && left="$left dest=$dest"
    [ -n "$src"    ] && left="$left src=$src"
    [ -n "$in_if"  ] && left="$left in_iface=$in_if"
    [ -n "$out_if" ] && left="$left out_iface=$out_if"
    [ -n "$proto"  ] && left="$left proto=$proto"
    if   [ -n "$dports" ]; then left="$left ports=$dports"
    elif [ -n "$dport"  ]; then left="$left port=$dport"
    fi
    [ -n "$sport" ] && left="$left sport=$sport"
    left="${left# }"

    # Arrow target (avoid leading space when left is empty)
    if [ "$target" = "DNAT" ] && [ -n "$todst" ]; then
        [ -n "$left" ] && printf '%s -> %s\n' "$left" "$todst" || printf '-> %s\n' "$todst"
    elif [ -n "$target" ]; then
        [ -n "$left" ] && printf '%s -> %s\n' "$left" "$target" || printf '-> %s\n' "$target"
    else
        printf '%s\n' "$left"
    fi
}

###################################################################################################
# validate_port - check that a single TCP/UDP port is an integer in 1..65535
# -------------------------------------------------------------------------------------------------
# Usage:
#   validate_port <N>
#
# Behavior:
#   * Accepts only base-10 digits.
#   * Returns 0 (true) if N is an integer between 1 and 65535 (inclusive).
#   * Returns 1 (false) for empty, non-numeric, or out-of-range values.
#
# Examples:
#   validate_port 22      # -> 0
#   validate_port 70000   # -> 1
#   validate_port abc     # -> 1
###################################################################################################
validate_port() {
    local v="$1"
    case "$v" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$v" -ge 1 ] 2>/dev/null && [ "$v" -le 65535 ] 2>/dev/null
}

###################################################################################################
# validate_ports - validate a destination port spec (single/list/range) or "any"
# -------------------------------------------------------------------------------------------------
# Usage:
#   validate_ports "<spec>"
#
# Behavior:
#   * Accepts:
#       - "any"
#       - a single port:           N              (1..65535)
#       - a comma list:            N,N2,N3
#       - dash ranges:             N-M            (1..65535, N<=M)
#       - comma list with ranges:  80,443,1000-2000
#   * Prints nothing; returns 0 if valid, 1 otherwise.
###################################################################################################
validate_ports() {
    local p="$1" tok a b

    [ -z "$p" ] && return 1
    [ "$p" = "any" ] && return 0

    # Reject leading/trailing or consecutive commas
    case "$p" in
        ,*|*,|*,,*) return 1 ;;
    esac

    IFS_SAVE=$IFS
    IFS=','; set -- $p; IFS=$IFS_SAVE

    for tok in "$@"; do
        case "$tok" in
            *-*)
                a="${tok%-*}"; b="${tok#*-}"
                validate_port "$a" || return 1
                validate_port "$b" || return 1
                [ "$a" -le "$b" ] || return 1
                ;;
            *)
                validate_port "$tok" || return 1
                ;;
        esac
    done
    return 0
}

###################################################################################################
# normalize_protos - normalize a protocol spec to "tcp", "udp", or "tcp,udp"
# -------------------------------------------------------------------------------------------------
# Usage:
#   proto="$(normalize_protos "<spec>")"  || { echo "invalid"; exit 1; }
#
# Behavior:
#   * Accepts "tcp", "udp", "tcp,udp", "udp,tcp", or "any" (case-sensitive).
#   * Ignores duplicate entries.
#   * Prints the canonical form to stdout and returns 0:
#       - "tcp"     -> "tcp"
#       - "udp"     -> "udp"
#       - "tcp,udp" -> "tcp,udp"
#       - "any"     -> "tcp,udp"
#   * Returns 1 on invalid input.
###################################################################################################
normalize_protos() {
    local in="$1" have_tcp=0 have_udp=0 tok out=""

    [ -z "$in" ] && return 1

    if [ "$in" = "any" ]; then
        printf '%s\n' "tcp,udp"
        return 0
    fi

    IFS_SAVE=$IFS
    IFS=','; set -- $in; IFS=$IFS_SAVE

    for tok in "$@"; do
        case "$tok" in
            tcp) [ $have_tcp -eq 0 ] && { out="${out:+$out,}tcp"; have_tcp=1; } ;;
            udp) [ $have_udp -eq 0 ] && { out="${out:+$out,}udp"; have_udp=1; } ;;
            *)   return 1 ;;
        esac
    done

    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
}

###################################################################################################
# fw_chain_exists - check if an iptables chain exists in a given table
# -------------------------------------------------------------------------------------------------
# Usage:
#   fw_chain_exists [-6] <table> <chain>
#
# Args:
#   -6        : OPTIONAL; check in ip6tables instead of iptables
#   <table>   : iptables table (e.g., raw | nat | filter | mangle)
#   <chain>   : chain name to verify
#
# Returns:
#   * 0 (success) if the chain exists
#   * 1 (failure) if the chain does not exist or error occurs
###################################################################################################
fw_chain_exists() {
    local cmd="iptables" table="" chain=""

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) cmd="ip6tables" ;;
            --) shift; break ;;
            -*) log -l err "fw_chain_exists: unknown option: $1"; return 1 ;;
            *)
                if [ -z "$table" ]; then
                    table="$1"
                elif [ -z "$chain" ]; then
                    chain="$1"
                else
                    log -l err "fw_chain_exists: usage: fw_chain_exists [-6] <table> <chain>"
                    return 1
                fi
                ;;
        esac
        shift
    done

    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "fw_chain_exists: usage: fw_chain_exists [-6] <table> <chain>"
        return 1
    fi

    "$cmd" -t "$table" -S "$chain" >/dev/null 2>&1
}

###################################################################################################
# create_fw_chain - ensure an iptables chain exists; optionally flush if present
# -------------------------------------------------------------------------------------------------
# Usage:
#   create_fw_chain [-q] [-f] <table> <chain>
#   create_fw_chain -6 [-q] [-f] <table> <chain>
#
# Args:
#   -6        : OPTIONAL; use ip6tables instead of iptables
#   -q        : OPTIONAL; suppress informational logs (errors still logged)
#   -f        : OPTIONAL; if the chain already exists, flush its contents
#   <table>   : iptables table (raw | nat | filter | mangle)
#   <chain>   : user-defined chain name to ensure
#
# Behavior:
#   * If the chain exists:
#       - with -f: flushes it (keeps the chain), returns 0
#       - without -f: log/no-op, returns 0
#   * If the chain does not exist: creates it, returns 0
#   * On error: returns 1
###################################################################################################
create_fw_chain() {
    local cmd="iptables" fam_label="IPv4" quiet=0 flush=0
    local table chain

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) cmd="ip6tables"; fam_label="IPv6"; shift ;;
            -q) quiet=1; shift ;;
            -f) flush=1; shift ;;
            --) shift; break ;;
            -*) log -l err "create_fw_chain: unknown option: $1"; return 1 ;;
            *)  break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    # Positional args
    table="${1-}"
    chain="${2-}"

    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "create_fw_chain: usage:" \
            "create_fw_chain [-6] [-q] [-f] <table> <chain>"
        return 1
    fi

    shift 2 || true

    # Chain exists?
    if "$cmd" -t "$table" -S "$chain" >/dev/null 2>&1; then
        if [ "$flush" -eq 1 ]; then
            if "$cmd" -t "$table" -F "$chain" 2>/dev/null; then
                _qlog "Flushed existing chain ($fam_label): table=$table chain=$chain"
                return 0
            else
                log -l err "Failed to flush chain ($fam_label): table=$table chain=$chain"
                return 1
            fi
        fi
        # Exists and no flush requested -> no-op
        _qlog "Chain already exists ($fam_label): table=$table chain=$chain"
        return 0
    fi

    # Create new chain
    if "$cmd" -t "$table" -N "$chain" 2>/dev/null; then
        _qlog "Created new chain ($fam_label): table=$table chain=$chain"
        return 0
    else
        log -l err "Failed to create chain ($fam_label): table=$table chain=$chain"
        return 1
    fi
}

###################################################################################################
# delete_fw_chain - delete an iptables chain (flush, then delete)
# -------------------------------------------------------------------------------------------------
# Usage:
#   delete_fw_chain [-q] <table> <chain>
#   delete_fw_chain -6 [-q] <table> <chain>
#
# Args:
#   -6      : OPTIONAL; use ip6tables instead of iptables
#   -q      : OPTIONAL; suppress informational logs (errors still logged)
#   <table> : iptables table (raw | nat | filter | mangle)
#   <chain> : user-defined chain to delete (no effect for built-ins)
#
# Behavior:
#   * If the chain doesn't exist, logs (unless -q) and returns 0.
#   * Flushes the chain (ignore errors) and then deletes it.
#   * Returns 0 on success, 1 on failure.
###################################################################################################
delete_fw_chain() {
    local cmd="iptables" fam_label="IPv4" quiet=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) cmd="ip6tables"; fam_label="IPv6"; shift ;;
            -q) quiet=1; shift ;;
            --) shift; break ;;
            -*) log -l err "delete_fw_chain: unknown option: $1"; return 1 ;;
            *)  break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local table="${1-}" chain="${2-}"

    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "delete_fw_chain: usage: delete_fw_chain [-6] [-q] <table> <chain>"
        return 1
    fi

    # Chain present?
    if ! "$cmd" -t "$table" -S "$chain" >/dev/null 2>&1; then
        _qlog "Chain not present ($fam_label): $table -> $chain (nothing to delete)"
        return 0
    fi

    # Flush (ignore errors)
    "$cmd" -t "$table" -F "$chain" 2>/dev/null || true
    _qlog "Flushed chain ($fam_label): table=$table chain=$chain"

    # Delete
    if ! "$cmd" -t "$table" -X "$chain" 2>/dev/null; then
        log -l err "Failed to delete chain ($fam_label): $table -> $chain"
        return 1
    fi

    _qlog "Deleted chain ($fam_label): table=$table chain=$chain"
    return 0
}

###################################################################################################
# find_fw_rules - list rules in a table/chain that match a regex
# -------------------------------------------------------------------------------------------------
# Usage:
#   find_fw_rules [-6] "<table> <chain>" "<grep -E pattern>"
#
# Args:
#   -6               : OPTIONAL; use ip6tables instead of iptables
#   <table> <chain>  : e.g., "raw PREROUTING", "nat PREROUTING", "nat WGC1_VSERVER"
#   <pattern>        : extended regex tested against 'iptables -t <table> -S <chain>' lines
#
# Output / Returns:
#   * Prints matching lines verbatim to stdout.
#   * Prints nothing and returns 0 if the chain is missing or no matches.
#   * Returns 1 on misuse (bad args).
###################################################################################################
find_fw_rules() {
    local cmd="iptables" base="" pattern="" table chain out

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6) cmd="ip6tables"; shift ;;
            --) shift; break ;;
            -*) log -l err "find_fw_rules: unknown option: $1"; return 1 ;;
            *)  break ;;
        esac
    done

    base="${1-}"
    pattern="${2-}"

    if [ -z "$base" ] || [ -z "$pattern" ]; then
        log -l err "find_fw_rules: usage:" \
            "find_fw_rules \"<table> <chain>\" \"<pattern>\""
        return 1
    fi

    table=${base%% *}
    chain=${base#* }

    # Require both parts
    if [ -z "$table" ] || [ -z "$chain" ] || [ "$table" = "$chain" ]; then
        log -l err "find_fw_rules: base must be \"<table> <chain>\", got: '$base'"
        return 1
    fi

    # Get rules (chain may not exist; treat as empty)
    out="$("$cmd" -t "$table" -S "$chain" 2>/dev/null)" || return 0

    printf '%s\n' "$out" | grep -E -- "$pattern" || true
}

###################################################################################################
# purge_fw_rules - remove matching rules from a table/chain
# -------------------------------------------------------------------------------------------------
# Usage:
#   purge_fw_rules [-6] [-q] [--count] "<table> <chain>" "<grep -E pattern>"
#
# Args:
#   -6               : OPTIONAL; use ip6tables instead of iptables
#   -q               : OPTIONAL; suppress informational logs (errors still logged)
#   --count          : OPTIONAL; print number of deleted rules (integer) to stdout
#   "<table> <chain>": space-separated pair, e.g., "raw PREROUTING", "nat WGC1_VSERVER"
#   "<pattern>"      : ERE applied to 'iptables -t <table> -S <chain>' output,
#                      which looks like "-A <CHAIN> <rest-of-spec>"
#
# Behavior:
#   * Finds matches, then for each line converts "-A CHAIN rest" -> iptables -t <table>
#     -D CHAIN rest
#   * Logs deletions (unless -q) and errors; exits cleanly if chain missing or no matches.
#   * Returns 0 on success; 1 only on misuse.
###################################################################################################
purge_fw_rules() {
    local cmd="iptables" fam_label="IPv4" quiet=0 print_count=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6)       cmd="ip6tables"; fam_label="IPv6"; shift ;;
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            --)       shift; break ;;
            -*)       log -l err "purge_fw_rules: unknown option: $1"; return 1 ;;
            *)        break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local base="${1-}" pattern="${2-}" table chain rules rest
    local cnt=0

    if [ -z "$base" ] || [ -z "$pattern" ]; then
        log -l err "purge_fw_rules: usage:" \
            "purge_fw_rules [-6] [-q] [--count] \"<table> <chain>\" \"<pattern>\""
        return 1
    fi

    table=${base%% *}
    chain=${base#* }

    # Chain may not exist; no-op
    if ! "$cmd" -t "$table" -S "$chain" >/dev/null 2>&1; then
        [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
        return 0
    fi

    # Build args for find_fw_rules
    set -- "$base" "$pattern"
    [ "$cmd" = ip6tables ] && set -- -6 "$@"
    rules="$(find_fw_rules "$@")"

    if [ -z "$rules" ]; then
        [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
        return 0
    fi

    while IFS= read -r rule; do
        # Rule looks like: "-A CHAIN rest-of-spec"
        rest=${rule#-A }              # -> "CHAIN rest-of-spec"
        set -f                        # avoid glob expansion
        eval "set -- $rest"           # re-tokenize respecting original quoting
        set +f

        if "$cmd" -t "$table" -D "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Deleted rule ($fam_label):" \
                "table=$table chain=$chain $(_spec_to_log "$rest")"
        else
            log -l err "Failed to remove firewall rule ($fam_label): $table $rule"
        fi
    done <<EOF
$rules
EOF

    [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
    return 0
}

###################################################################################################
# ensure_fw_rule - idempotent iptables rule helper with optional logging/count
# -------------------------------------------------------------------------------------------------
# Usage:
#   ensure_fw_rule [-6] [-q] [--count] <table> <chain> [-I [pos] | -D] <rule...>
#
# Args:
#   -6         : OPTIONAL; use ip6tables instead of iptables
#   -q         : OPTIONAL; suppress informational logs (errors still logged)
#   --count    : OPTIONAL; on change (insert/append/delete) print "1", else "0" to stdout
#   <table>    : iptables table
#   <chain>    : chain name
#   -I [pos]   : insert at position (default 1) if the rule is missing
#   -D         : delete the rule if it exists
#   <rule...>  : the iptables rule spec (e.g., -p tcp --dport 80 -j ACCEPT)
#
# Behavior:
#   * Checks existence with iptables -C (position ignored).
#   * Adds, inserts, deletes as needed; no duplicates; safe no-op for already-present rules.
#   * Returns 0 on success; 1 on insertion/append/delete failure or misuse.
###################################################################################################
ensure_fw_rule() {
    local cmd="iptables" fam_label="IPv4"
    local mode="-A" pos=""
    local quiet=0 print_count=0 cnt=0

    # Parse flags
    while :; do
        case "${1-}" in
            -6)       cmd="ip6tables"; fam_label="IPv6"; shift ;;
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            *)        break ;;
        esac
    done

    local table="${1-}" chain="${2-}"
    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "ensure_fw_rule: usage: ensure_fw_rule [-6] [-q] [--count]" \
            "<table> <chain> [-I [pos] | -D] <rule...>"
        return 1
    fi
    shift 2

    case "${1-}" in
        -I)
            mode="-I"; shift
            if [ -n "${1-}" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
                pos="$1"; shift
            else
                pos=1
            fi
            ;;
        -D)
            mode="-D"; shift ;;
    esac

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    # Existence check (position is irrelevant so we test without it)
    if "$cmd" -t "$table" -C "$chain" "$@" 2>/dev/null; then
        if [ "$mode" = "-D" ]; then
            if "$cmd" -t "$table" -D "$chain" "$@" 2>/dev/null; then
                cnt=$((cnt+1))
                _qlog "Deleted rule ($fam_label):" \
                    "table=$table chain=$chain $(_spec_to_log "$@")"
                [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
                return 0
            else
                log -l err "Failed to delete rule ($fam_label):" \
                    "table=$table chain=$chain $(_spec_to_log "$@")"
                return 1
            fi
        fi
        # Rule already present; no action.
        _qlog "Rule is already present ($fam_label):" \
            "table=$table chain=$chain $(_spec_to_log "$@")"
        [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
        return 0
    fi

    # Nothing to delete
    if [ "$mode" = "-D" ]; then
        [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
        return 0
    fi

    # Rule not present -> add it
    if [ "$mode" = "-I" ]; then
        if "$cmd" -t "$table" -I "$chain" "$pos" "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Inserted rule at ins_pos=#$pos ($fam_label):" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
        else
            log -l err "Failed to insert rule at ins_pos=#$pos ($fam_label):" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
            return 1
        fi
    else
        if "$cmd" -t "$table" -A "$chain" "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Appended rule ($fam_label):" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
        else
            log -l err "Failed to append rule ($fam_label):" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
            return 1
        fi
    fi

    [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
    return 0
}

###################################################################################################
# sync_fw_rule - replace matching rules with one desired rule (idempotent)
# -------------------------------------------------------------------------------------------------
# Usage:
#   sync_fw_rule [-6] [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]
#
# Args:
#   -6            : OPTIONAL; use ip6tables instead of iptables
#   -q            : OPTIONAL; suppress informational logs (errors still logged)
#   --count       : OPTIONAL; print number of changes (purged + inserted) to stdout
#   <table>       : iptables table
#   <chain>       : chain name
#   "<pattern>"   : ERE to find existing rules to replace (tested against 'iptables -S' lines)
#   "<desired>"   : desired rule arguments (without leading "-A <chain>")
#   [insert_pos]  : OPTIONAL; insert position if adding (default: append)
#
# Behavior:
#   * If exactly one matching rule exists AND equals "-A <chain> <desired>", no change.
#   * Otherwise, purge all matching rules and add the desired one (append or insert at position).
#   * Returns 0 on success; 1 on misuse.
###################################################################################################
sync_fw_rule() {
    local cmd="iptables" fam_label="IPv4" quiet=0 print_count=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -6)       cmd="ip6tables"; fam_label="IPv6"; shift ;;
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            --)       shift; break ;;
            *)        break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local table="${1-}" chain="${2-}" pattern="${3-}" desired="${4-}" ins_pos="${5-}"
    local matches expected line_count desired_count curr_pos
    local cnt=0 n=0

    if [ -z "$table" ] || [ -z "$chain" ] || [ -z "$pattern" ] || [ -z "$desired" ]; then
        log -l err "sync_fw_rule: usage: sync_fw_rule [-6] [-q] [--count] <table> <chain>" \
            "\"<pattern>\" \"<desired args>\" [insert_pos]"
        return 1
    fi

    # Build expected iptables-save-style line
    expected="-A $chain $desired"
    desired_log="$(_spec_to_log "$desired")"

    # Find current matches (avoid SC2046: build argv then quote once)
    set -- "$table $chain" "$pattern"
    [ "$cmd" = ip6tables ] && set -- -6 "$@"
    matches="$(find_fw_rules "$@")"

    if [ -n "$matches" ]; then
        line_count="$(printf '%s' "$matches" | grep -c '^' || true)"
        desired_count="$(printf '%s' "$matches" | grep -Fxc -- "$expected" || true)"

        if [ "$line_count" -eq 1 ] && [ "$desired_count" -eq 1 ]; then
            # Exactly one match and it equals the desired spec
            if [ -n "$ins_pos" ]; then
                # Verify actual rule position among -A entries
                # without passing quoted text via -v to awk
                curr_pos="$(
                    "$cmd" -t "$table" -S "$chain" 2>/dev/null \
                    | awk '$1 == "-A" { i++ } { print i "\t" $0 }' \
                    | grep -F -- "$expected" | head -n1 | awk -F'\t' '{ print $1 }'
                )"
                if [ -n "$curr_pos" ] && [ "$curr_pos" -eq "$ins_pos" ] 2>/dev/null; then
                    _qlog "Rule already present at correct position ($fam_label):" \
                        "table=$table chain=$chain pos=$curr_pos $desired_log"
                    [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
                    return 0
                fi
                # Position differs -> fall through to purge & re-insert
            else
                _qlog "Rule is already present ($fam_label):" \
                    "table=$table chain=$chain $desired_log"
                [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
                return 0
            fi
        fi

        # Purge all matches (build argv to avoid word-splitting issues)
        set --
        [ "$cmd" = ip6tables ] && set -- "$@" -6
        [ "$quiet" -eq 1 ] && set -- "$@" -q
        [ "$print_count" -eq 1 ] && set -- "$@" --count
        set -- "$@" "$table $chain" "$pattern"
        n="$(purge_fw_rules "$@")"
        cnt=$((cnt+n))
    fi

    # Ensure desired rule (append or insert)
    local v6_flag="" q_flag="" cmdargs
    [ "$cmd" = ip6tables ] && v6_flag="-6 "
    [ "$quiet" -eq 1 ] && q_flag="-q "
    cmdargs="${v6_flag}${q_flag}--count \"$table\" \"$chain\""
    if [ -n "$ins_pos" ]; then
        cmdargs="$cmdargs -I \"$ins_pos\""
    fi

    set -f
    eval "set -- $cmdargs $desired"
    set +f
    n="$(ensure_fw_rule "$@")" || n=0
    cnt=$((cnt + ${n:-0}))

    [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
    return 0
}

###################################################################################################
# block_wan_for_host - block a LAN device from using a specific WAN interface
# -------------------------------------------------------------------------------------------------
# Usage:
#   block_wan_for_host <hostname|ip> [wan_id]
#     - wan_id: ASUS WAN index (0 = primary, 1 = secondary). Defaults to 0.
#
# Behavior:
#   * Tries to resolve a single LAN IPv4 (RFC1918). If present, blocks it.
#   * If IPv6 is enabled, resolves all global IPv6 for the host and blocks each
#     (ULAs / link-local are ignored).
#   * Inserts rules at the top of filter / FORWARD:
#       - WAN -> host:  DROP
#       - host -> WAN:  REJECT (icmp-admin-prohibited / icmp6-adm-prohibited)
#   * Succeeds if at least one address family was blocked.
#   * Fails (returns 1) only if neither IPv4 LAN nor global IPv6 could be resolved,
#     or if the WAN interface name is empty.
###################################################################################################
block_wan_for_host() {
    local host="$1" wan_id="${2:-0}"
    local host_ip4="" wan_if v6_list="" ip6
    local any_blocked=0

    # WAN interface
    wan_if="$(nvram get wan${wan_id}_ifname)"
    if [ -z "$wan_if" ]; then
        log -l err "wan${wan_id} interface name is empty; cannot block WAN for host"
        return 1
    fi

    # IPv4: try to resolve a single LAN IPv4; skip silently if none
    host_ip4="$(resolve_lan_ip -q "$host" || true)"
    if [ -n "$host_ip4" ]; then
        # WAN -> host: DROP
        ensure_fw_rule filter FORWARD -I 1 -i "$wan_if" -d "$host_ip4" -j DROP
        # host -> WAN: REJECT (admin prohibited)
        ensure_fw_rule filter FORWARD -I 2 -s "$host_ip4" -o "$wan_if" \
            -j REJECT --reject-with icmp-admin-prohibited
        any_blocked=1
    fi

    # IPv6: only if enabled; block all global v6 addresses (ignore ULA / link-local)
    if [ "$(get_ipv6_enabled)" -eq 1 ]; then
        v6_list="$(resolve_ip -6 -q -g -a "$host" || true)"
        if [ -n "$v6_list" ]; then
            while IFS= read -r ip6; do
                [ -n "$ip6" ] || continue
                # WAN -> host-v6: DROP
                ensure_fw_rule -6 filter FORWARD -I 1 -i "$wan_if" -d "$ip6" -j DROP
                # host-v6 -> WAN: REJECT
                ensure_fw_rule -6 filter FORWARD -I 2 -s "$ip6" -o "$wan_if" \
                    -j REJECT --reject-with icmp6-adm-prohibited
                any_blocked=1
            done <<EOF
$v6_list
EOF
        fi
    fi

    # If nothing was blocked at all, fail gracefully
    if [ "$any_blocked" -eq 0 ]; then
        log -l err "No IPv4 LAN or global IPv6 found for '$host'; nothing to block"
        return 1
    fi

    # Log summary
    if [ -n "$host_ip4" ] && [ -n "$v6_list" ]; then
        log "Blocked WAN for host=$host (ipv4=$host_ip4" \
            "ipv6_global=$(printf '%s' "$v6_list" | tr '\n' ' '))" \
            "on iface=$wan_if (wan_id=$wan_id)"
    elif [ -n "$host_ip4" ]; then
        log "Blocked WAN for host=$host (ipv4=$host_ip4) on iface=$wan_if (wan_id=$wan_id)"
    else
        log "Blocked WAN for host=$host (ipv6_global=$(printf '%s' "$v6_list" | tr '\n' ' '))" \
            "on iface=$wan_if (wan_id=$wan_id)"
    fi
}

###################################################################################################
# allow_wan_for_host - restore WAN access for a previously blocked LAN device
# -------------------------------------------------------------------------------------------------
# Usage:
#   allow_wan_for_host <hostname|ip> [wan_id]
#     - wan_id: ASUS WAN index (0 = primary, 1 = secondary). Defaults to 0.
#
# Behavior:
#   * Tries to resolve a single LAN IPv4; if present, removes IPv4 DROP/REJECT rules.
#   * If IPv6 is enabled, resolves all global IPv6 for the host and removes the
#     corresponding ip6tables rules as well (ULAs / link-local are ignored).
#   * Succeeds if at least one address family was processed.
#   * Fails (returns 1) only if neither IPv4 LAN nor global IPv6 could be resolved,
#     or if the WAN interface name is empty.
###################################################################################################
allow_wan_for_host() {
    local host="$1" wan_id="${2:-0}"
    local host_ip4="" wan_if v6_list="" ip6
    local any_processed=0

    # WAN interface
    wan_if="$(nvram get wan${wan_id}_ifname)"
    if [ -z "$wan_if" ]; then
        log -l err "wan${wan_id} interface name is empty; cannot unblock WAN for host"
        return 1
    fi

    # IPv4: try to resolve a single LAN IPv4; skip silently if none
    host_ip4="$(resolve_lan_ip -q "$host" || true)"
    if [ -n "$host_ip4" ]; then
        ensure_fw_rule filter FORWARD -D -i "$wan_if" -d "$host_ip4" -j DROP
        ensure_fw_rule filter FORWARD -D -s "$host_ip4" -o "$wan_if" \
            -j REJECT --reject-with icmp-admin-prohibited
        any_processed=1
    fi

    # IPv6: only if enabled; remove rules for all global v6 addresses (ignore ULA / link-local)
    if [ "$(get_ipv6_enabled)" -eq 1 ]; then
        v6_list="$(resolve_ip -6 -q -g -a "$host" || true)"
        if [ -n "$v6_list" ]; then
            while IFS= read -r ip6; do
                [ -n "$ip6" ] || continue
                ensure_fw_rule -6 filter FORWARD -D -i "$wan_if" -d "$ip6" -j DROP
                ensure_fw_rule -6 filter FORWARD -D -s "$ip6" -o "$wan_if" \
                    -j REJECT --reject-with icmp6-adm-prohibited
                any_processed=1
            done <<EOF
$v6_list
EOF
        fi
    fi

    # If nothing was processed at all, fail gracefully
    if [ "$any_processed" -eq 0 ]; then
        log -l err "No IPv4 LAN or global IPv6 found for '$host'; nothing to allow"
        return 1
    fi

    # Log summary
    if [ -n "$host_ip4" ] && [ -n "$v6_list" ]; then
        log "Allowed WAN for host=$host (ipv4=$host_ip4" \
            "ipv6_global=$(printf '%s' "$v6_list" | tr '\n' ' '))" \
            "on iface=$wan_if (wan_id=$wan_id)"
    elif [ -n "$host_ip4" ]; then
        log "Allowed WAN for host=$host (ipv4=$host_ip4) on iface=$wan_if (wan_id=$wan_id)"
    else
        log "Allowed WAN for host=$host (ipv6_global=$(printf '%s' "$v6_list" | tr '\n' ' '))" \
            "on iface=$wan_if (wan_id=$wan_id)"
    fi
}

###################################################################################################
# chg - helper: return success if a command prints a non-zero integer
# -------------------------------------------------------------------------------------------------
# Usage:
#   if chg purge_fw_rules --count "raw PREROUTING" "-i $WAN_IF -j KILL$"; then
#       # at least one rule was deleted
#   fi
#
# Behavior:
#   * Executes the given command, captures stdout.
#   * Returns 0 (true) if stdout is a non-zero integer; else returns 1 (false).
#   * Useful with functions that support --count to gate "changed?" decisions.
###################################################################################################
chg() {
    local out
    out="$("$@")" || out=
    case "$out" in
        ''|*[!0-9]*|0) return 1;;
        *)             return 0;;
    esac
}
