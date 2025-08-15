#!/usr/bin/env ash

###################################################################################################
# firewall.sh  - shared firewall functions library for Asuswrt-Merlin shell scripts
# -------------------------------------------------------------------------------------------------
# Public API
# ----------
#   validate_port <N>
#         Validates a single destination port: integer between 1 and 65535 (inclusive).
#         Returns 0 if valid, 1 otherwise.
#
#   validate_ports <spec>
#         Validates a destination port spec: "any", single port (N), comma list (N,N2),
#         dash range (N-M), or mixed list (e.g., 80,443,1000-2000).
#         Returns 0 if valid, 1 otherwise.
#
#   normalize_protos <spec>
#         Normalizes a protocol spec to one of the following: "tcp", "udp", or "tcp,udp".
#         Accepts "any", "tcp", "udp", "tcp,udp", or "udp,tcp".
#         Prints the canonical form and returns 0; non-zero on invalid input.
#
#   fw_chain_exists <table> <chain>
#         Return 0 if the chain exists in the given table, 1 otherwise.
#
#   create_fw_chain [-q] [-f] <table> <chain>
#         Ensure a user-defined chain exists; with -f, flush it if already present.
#         -q suppresses informational logs (errors still logged).
#
#   delete_fw_chain [-q] <table> <chain>
#         Flush and delete a user-defined chain if it exists.
#         -q suppresses informational logs (errors still logged).
#
#   find_fw_rules "<table> <chain>" "<grep -E pattern>"
#         Print matching rules (from 'iptables -t <table> -S <chain>') to stdout,
#         or print nothing if the chain is missing/no matches.
#
#   purge_fw_rules [-q] [--count] "<table> <chain>" "<grep -E pattern>"
#         Remove rules in the specified table/chain that match the regex.
#         With --count, print the number of deleted rules (integer) to stdout.
#         -q suppresses informational logs (errors still logged).
#
#   ensure_fw_rule [-q] [--count] <table> <chain> [-I [pos] | -D] <rule...>
#         Idempotent helper:
#           *  no flag    -> append rule (-A) if it's missing
#           *  -I [pos]   -> insert rule (-I) at position (default 1) if missing
#           *  -D         -> delete rule (-D) if it exists
#         Guarantees the rule appears exactly once (or not at all, for -D).
#         With --count, print 1 to stdout on change (insert/append/delete), else 0.
#         -q suppresses informational logs (errors still logged).
#
#   sync_fw_rule [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]
#         Replace all rules matching <pattern> with a single desired rule (append by default
#         or insert at [insert_pos]). No change if exactly one match equals the desired rule.
#         With --count, print the number of changes (deleted + inserted) to stdout.
#         -q suppresses informational logs (errors still logged).
#
#   block_wan_for_host <hostname|ip> [wan_id]
#         Resolve host to LAN IP and add filter/FORWARD REJECT/DROP rules to block both
#         outbound-to and inbound-from the specified WAN (default wan1).
#
#   allow_wan_for_host <hostname|ip> [wan_id]
#         Resolve host to LAN IP and remove the corresponding REJECT/DROP rules, restoring access.
#
#   chg <command ...>
#         Runs a command and returns success (0) if its stdout is a non-zero
#         integer; useful with --count helpers to test whether anything changed.
#
# Notes
# -----
#   * This library expects common.sh to be sourced first.
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
#   fw_chain_exists <table> <chain>
#
# Args:
#   <table>   : iptables table (e.g., raw | nat | filter | mangle)
#   <chain>   : chain name to verify
#
# Returns:
#   * 0 (success) if the chain exists
#   * 1 (failure) if the chain does not exist or error occurs
###################################################################################################
fw_chain_exists() {
    local table="$1" chain="$2"
    iptables -t "$table" -nL "$chain" >/dev/null 2>&1
}

###################################################################################################
# create_fw_chain - ensure an iptables chain exists; optionally flush if present
# -------------------------------------------------------------------------------------------------
# Usage:
#   create_fw_chain [-q] [-f] <table> <chain>
#
# Args:
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
    local quiet=0 flush=0
    local table chain

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
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
            "create_fw_chain [-q] [-f] <table> <chain>"
        return 1
    fi

    shift 2 || true

    # Chain exists?
    if iptables -t "$table" -S "$chain" >/dev/null 2>&1; then
        if [ "$flush" -eq 1 ]; then
            if iptables -t "$table" -F "$chain" 2>/dev/null; then
                _qlog "Flushed existing chain: table=$table chain=$chain"
                return 0
            else
                log -l err "Failed to flush chain: $table -> $chain"
                return 1
            fi
        fi
        # Exists and no flush requested -> no-op
        _qlog "Chain already exists: table=$table chain=$chain"
        return 0
    fi

    # Create new chain
    if iptables -t "$table" -N "$chain" 2>/dev/null; then
        _qlog "Created new chain: table=$table chain=$chain"
        return 0
    else
        log -l err "Failed to create chain: table=$table chain=$chain"
        return 1
    fi
}

###################################################################################################
# delete_fw_chain - delete an iptables chain (flush, then delete)
# -------------------------------------------------------------------------------------------------
# Usage:
#   delete_fw_chain [-q] <table> <chain>
#
# Args:
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
    local quiet=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -q) quiet=1; shift ;;
            *) break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local table="${1-}" chain="${2-}"

    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "delete_fw_chain: usage: delete_fw_chain <table> <chain>"
        return 1
    fi

    # Chain present?
    if ! iptables -t "$table" -S "$chain" >/dev/null 2>&1; then
        _qlog "Chain not present: $table -> $chain (nothing to delete)"
        return 0
    fi

    # Flush
    iptables -t "$table" -F "$chain" 2>/dev/null || true
    _qlog "Flushed chain: table=$table chain=$chain"

    # Delete
    if ! iptables -t "$table" -X "$chain" 2>/dev/null; then
        log -l err "Failed to delete chain $table -> $chain"
        return 1
    fi

    _qlog "Deleted chain: table=$table chain=$chain"

    return 0
}

###################################################################################################
# find_fw_rules - list rules in a table/chain that match a regex
# -------------------------------------------------------------------------------------------------
# Usage:
#   find_fw_rules "<table> <chain>" "<grep -E pattern>"
#
# Args:
#   <table> <chain>  : e.g., "raw PREROUTING", "nat PREROUTING", "nat WGC1_VSERVER"
#   <pattern>        : extended regex tested against 'iptables -t <table> -S <chain>' lines
#
# Output / Returns:
#   * Prints matching lines verbatim to stdout.
#   * Prints nothing and returns 0 if the chain is missing or no matches.
#   * Returns 1 on misuse (bad args).
###################################################################################################
find_fw_rules() {
    local base="$1" pattern="$2" table chain

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

    # Chain may not exist; treat as empty result
    if ! iptables -t "$table" -S "$chain" >/dev/null 2>&1; then
        return 0
    fi

    iptables -t "$table" -S "$chain" 2>/dev/null | grep -E -- "$pattern" || true
}

###################################################################################################
# purge_fw_rules - remove matching rules from a table/chain
# -------------------------------------------------------------------------------------------------
# Usage:
#   purge_fw_rules [-q] [--count] "<table> <chain>" "<grep -E pattern>"
#
# Args:
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
    local quiet=0 print_count=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            --)       shift; break ;;
            *)        break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local base="${1-}" pattern="${2-}" table chain rules
    local cnt=0

    if [ -z "$base" ] || [ -z "$pattern" ]; then
        log -l err "purge_fw_rules: usage:" \
            "purge_fw_rules [-q] \"<table> <chain>\" \"<pattern>\""
        return 1
    fi

    table=${base%% *}
    chain=${base#* }

    # Chain may not exist; no-op
    if ! iptables -t "$table" -S "$chain" >/dev/null 2>&1; then
        [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
        return 0
    fi

    rules="$(find_fw_rules "$base" "$pattern")"
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

        if iptables -t "$table" -D "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Deleted rule: table=$table chain=$chain $(_spec_to_log "$rest")"
        else
            log -l err "Failed to remove firewall rule: $table $rule"
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
#   ensure_fw_rule [-q] [--count] <table> <chain> [-I [pos] | -D] <rule...>
#
# Args:
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
    local mode="-A" pos=""
    local quiet=0 print_count=0 cnt=0

    # Parse flags
    while :; do
        case "${1-}" in
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            *)        break ;;
        esac
    done

    local table="${1-}" chain="${2-}"
    if [ -z "$table" ] || [ -z "$chain" ]; then
        log -l err "ensure_fw_rule: usage: ensure_fw_rule [-q] [--count]" \
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
            mode="-D"; shift
          ;;
    esac

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    # Existence check (position is irrelevant so we test without it)
    if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        if [ "$mode" = "-D" ]; then
            if iptables -t "$table" -D "$chain" "$@" 2>/dev/null; then
                cnt=$((cnt+1))
                _qlog "Deleted rule: table=$table chain=$chain $(_spec_to_log "$@")"
                [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
                return 0
            else
                log -l err "Failed to delete rule:" \
                    "table=$table chain=$chain $(_spec_to_log "$@")"
                return 1
            fi
        fi
        # Rule already present; no action.
        _qlog "Rule is already present: table=$table chain=$chain $(_spec_to_log "$@")"

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
        if iptables -t "$table" -I "$chain" "$pos" "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Inserted rule at ins_pos=#$pos:" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
        else
            log -l err "Failed to insert rule at ins_pos=#$pos:" \
                "table=$table chain=$chain $(_spec_to_log "$@")"
            return 1
        fi
    else
        if iptables -t "$table" -A "$chain" "$@" 2>/dev/null; then
            cnt=$((cnt+1))
            _qlog "Appended rule: table=$table chain=$chain $(_spec_to_log "$@")"
        else
            log -l err "Failed to append rule:" \
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
#   sync_fw_rule [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]
#
# Args:
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
    local quiet=0 print_count=0

    # Parse flags
    while [ $# -gt 0 ]; do
        case "$1" in
            -q)       quiet=1; shift ;;
            --count)  print_count=1; shift ;;
            --)       shift; break ;;
            *)        break ;;
        esac
    done

    # Helper to conditionally log info
    _qlog() { [ "$quiet" -eq 1 ] || log "$@"; }

    local table="${1-}" chain="${2-}" pattern="${3-}" desired="${4-}" ins_pos="${5-}"
    local matches expected line_count desired_count desired_log qopt="" copt=""
    local cnt=0 n=0

    if [ -z "$table" ] || [ -z "$chain" ] || [ -z "$pattern" ] || [ -z "$desired" ]; then
        log -l err "sync_fw_rule: usage: sync_fw_rule [-q] <table> <chain>" \
            "\"<pattern>\" \"<desired args>\" [insert_pos]"
        return 1
    fi

    [ "$quiet" -eq 1 ] && qopt="-q"
    [ "$print_count" -eq 1 ] && copt="--count"
    desired_log="$(_spec_to_log "$desired")"
    expected="-A $chain $desired"

    # Find current matches
    matches="$(find_fw_rules "$table $chain" "$pattern" || true)"

    if [ -n "$matches" ]; then
        line_count="$(printf '%s' "$matches" | grep -c '^' || true)"
        desired_count="$(printf '%s' "$matches" | grep -Fxc -- "$expected" || true)"

        if [ "$line_count" -eq 1 ] && [ "$desired_count" -eq 1 ]; then
            # Already exactly what we want
            _qlog "Rule is already present: table=$table chain=$chain $desired_log"
            [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"
            return 0
        fi

        n=$(purge_fw_rules $qopt $copt "$table $chain" "$pattern")
        cnt=$((cnt+n))
    fi

    if [ -n "$ins_pos" ]; then
        n=$(ensure_fw_rule $qopt $copt "$table" "$chain" -I "$ins_pos" $desired)
        cnt=$((cnt+n))
    else
        n=$(ensure_fw_rule $qopt $copt "$table" "$chain" $desired)
        cnt=$((cnt+n))
    fi

    [ "$print_count" -eq 1 ] && printf '%s\n' "$cnt"

    return 0
}

###################################################################################################
# block_wan_for_host - block a LAN device from using a specific WAN interface
# -------------------------------------------------------------------------------------------------
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
###################################################################################################
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

###################################################################################################
# allow_wan_for_host - restore WAN access for a previously blocked LAN device
# -------------------------------------------------------------------------------------------------
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
###################################################################################################
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
