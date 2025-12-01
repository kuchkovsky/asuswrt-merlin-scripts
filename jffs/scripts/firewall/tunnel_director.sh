#!/usr/bin/env ash

###################################################################################################
# tunnel_director.sh - outbound ipset-based policy routing for Asuswrt-Merlin
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Provides outbound ipset-based policy routing for selected LAN subnets, directing traffic
#     through WireGuard/OpenVPN clients ("wgcN", "ovpncN") or the WAN ("main") based on
#     destination ipsets (countries or custom lists).
#       - Designed with anti-censorship in mind:
#           * Inclusion policies - tunnel traffic only to censored countries/lists.
#           * Exclusion policies - tunnel everything ("any") but exempt trusted
#             countries/lists back to WAN.
#           * Extended sets capture CDN/hosting ranges registered in blocked countries,
#             reducing leaks and ensuring more complete coverage.
#   * Creates one dedicated chain per rule (TUN_DIR_<idx>) and jumps to it only for that rule's
#     source subnet; optional source exclusions are handled early with RETURN.
#   * Matches destinations against ipsets (countries or custom lists).
#       - For country sets, the script automatically prefers extended ipsets when
#         available (requires GeoLite2). Extended sets include not only directly geolocated
#         networks but also registered-country ranges (broader match), making them ideal
#         for tunnels. If extended sets are not available (e.g., IPdeny provider), the script
#         falls back to standard sets.
#   * Marks matching traffic with a rule-specific fwmark and installs the corresponding
#     policy route.
#   * Tracks configuration via a content hash and validates rule/chain counts. On any change or
#     drift, all TUN_DIR_* chains and associated ip rules are wiped and rebuilt cleanly in order.
#   * Integrates seamlessly with ipset_builder.sh and only proceeds when the required ipsets
#     are available.
#
# Requirements / Notes:
#   * All configuration lives in config.sh (TUN_DIR_RULES variable and chain/routing settings).
#     Review, edit, then run "ipt" (helper alias) to apply changes without rebooting.
#   * At least one VPN client (WireGuard or OpenVPN) must be configured and active in the UI.
#       - NAT must be enabled for the selected VPN clients.
#       - For OpenVPN, "Redirect Internet traffic through tunnel" must be set to
#         "VPN Director / Guest Network" for the selected client(s).
#   * Relies on ipsets produced by ipset_builder.sh. If a referenced set is missing or empty,
#     the affected rule is skipped with a warning while the rest are applied normally.
#   * GeoLite2 country ipsets require MAXMIND_LICENSE_KEY and mounted external storage;
#     sign up for a free account and set the license key if you want to use this database.
#     If the key is unset or storage is unmounted, the script falls back to IPdeny.
#   * By default, Tunnel Director reserves 8 bits of the fwmark (bits 16-23), which allows
#     for up to 255 distinct rules. If you need more, you can adjust TUN_DIR_MARK_MASK and
#     TUN_DIR_MARK_SHIFT in config.sh (see section 10 for details).
#   * IPv4-only for now, as Merlin's VPN implementation does not treat IPv6 as
#     a first-class citizen by default. IPv6 functionality may be considered for
#     implementation in the future.
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
# 0b. Define variables
# -------------------------------------------------------------------------------------------------
# build_tun_dir_rules  - flag: 1 if Tunnel Director rules should be rebuilt
# changes              - flag: 1 if any changes were applied in this run
# warnings             - flag: 1 if non-critical issues were encountered while processing rules
#
# valid_tables_list  - normalized list of allowed routing tables (wgcN, ovpncN, main)
# valid_tables       - same list, space-separated (for fast matching)
# valid_tables_csv   - same list, comma-separated (for logging)
#
# _mark_mask_val        - numeric version of TUN_DIR_MARK_MASK (imported from config.sh)
# _mark_shift_val       - numeric version of TUN_DIR_MARK_SHIFT (imported from config.sh)
# _mark_field_max       - maximum number of TD rules that fit in the mask field
#                         (e.g. 0x00ff0000 >> 16 = 255 rules)
# mark_mask_hex         - lowercase hex string of the mask, for use in iptables commands
###################################################################################################
build_tun_dir_rules=0
changes=0
warnings=0

# -------------------------------------------------------------------------------------------------
# Derived variables
# -------------------------------------------------------------------------------------------------

# Precompute numeric and hex helpers
_mark_mask_val=$((TUN_DIR_MARK_MASK))
_mark_shift_val=$((TUN_DIR_MARK_SHIFT))
_mark_field_max=$((_mark_mask_val >> _mark_shift_val))    # max number of rules in the field
mark_mask_hex="$(printf '0x%x' "$_mark_mask_val")"

# Extract valid routing tables (from rt_tables):
# - wgcN first
# - ovpncN next
# - main always included at the end
# Prevents accidental matches against arbitrary user-defined tables.
valid_tables_list="$(
    awk '$0!~/^#/ && $2 ~ /^wgc[0-9]+$/ { print $2 }' /etc/iproute2/rt_tables | sort
    awk '$0!~/^#/ && $2 ~ /^ovpnc[0-9]+$/ { print $2 }' /etc/iproute2/rt_tables | sort
    printf '%s\n' main
)"

# Single-line, space-separated (for matching)
valid_tables="$(printf '%s\n' "$valid_tables_list" | xargs)"

# CSV version (for logs)
valid_tables_csv="$(printf '%s\n' "$valid_tables_list" | tr '\n' ',' | sed 's/,$//')"

###################################################################################################
# 0c. Define helper functions
# -------------------------------------------------------------------------------------------------
# table_allowed          - checks whether a given routing table is valid (wgcN, ovpncN, or main)
#
# resolve_set_name       - resolves a CSV of ipset keys (countries/custom/combos) into a set name:
#                            * 2-letter country codes are first tried with "_ext"
#                            * combo names are derived with derive_set_name
#                            * prefers *_ext if it exists, else falls back to standard
#                            * returns empty string if no matching ipset is found
#
# get_prerouting_base_pos
#                        - returns the 1-based insert position in mangle/PREROUTING immediately
#                          after the last system iface-mark rule.
#                          These rules look like:
#                            -A PREROUTING -i tun11 -j MARK --set-xmark 0x1/0x1
#                            -A PREROUTING -i wgc1  -j MARK --set-xmark 0x1/0x1
#                          Tunnel Director uses this to anchor its own jumps after the firmware's
#                          interface-marking, so we don't override system bits and ensure a stable
#                          insertion point even if the system changes other rules.
###################################################################################################
table_allowed() {
    # $1 = table (e.g., wgc1)
    case " $valid_tables " in
        *" $1 "*)  return 0 ;;
        *)         return 1 ;;
    esac
}

resolve_set_name() {
    # $1 = comma-separated keys (countries/custom/combos)
    local keys_csv="$1" ext_set std_set

    # Build the *_ext variant CSV: only exact 2-letter tokens get "_ext"
    local ext_csv="" tok IFS_SAVE
    IFS_SAVE=$IFS
    IFS=','; set -- $keys_csv; IFS=$IFS_SAVE
    for tok; do
        [ -n "$tok" ] || continue
        case "$tok" in
            [a-z][a-z]) tok="${tok}_ext" ;;
        esac
        ext_csv="${ext_csv}${ext_csv:+,}$tok"
    done

    ext_set="$(derive_set_name "${ext_csv//,/_}")"

    # Prefer *_ext combo if it exists
    if ipset list "$ext_set" >/dev/null 2>&1; then
        printf '%s\n' "$ext_set"
        return 0
    fi

    std_set="$(derive_set_name "${keys_csv//,/_}")"

    # Fallback to standard combo if it exists
    if ipset list "$std_set" >/dev/null 2>&1; then
        printf '%s\n' "$std_set"
        return 0
    fi

    # Neither exists
    return 0
}

# Return the 1-based insert position after the last system
# iface-mark rule in mangle/PREROUTING.
#
# Matches lines like:
#   -A PREROUTING -i tun11 -j MARK --set-xmark 0x1/0x1
#   -A PREROUTING -i wgc1  -j MARK --set-xmark 0x1/0x1
get_prerouting_base_pos() {
    iptables -t mangle -S PREROUTING 2>/dev/null |
    awk '
        $1 == "-A" {
          i++
          if ( ($0 ~ /-i wgc[0-9]+/ || $0 ~ /-i tun[0-9]+/) &&
               $0 ~ /-j MARK/ && $0 ~ /--set-/ ) {
            last = i
          }
        }
        END { print (last ? last + 1 : 1) }
    '
}

###################################################################################################
# 1. Calculate hashes and set build flag
###################################################################################################

# Create temporary file to hold normalized rule definitions
tun_dir_rules="$(tmp_file)"

# Strip comments and whitespace from rules -> normalized version
strip_comments "$TUN_DIR_RULES" | sed -E 's/[[:blank:]]+//g' > "$tun_dir_rules"

# Hash of an empty ruleset (used for baseline checks)
empty_rules_hash="$(printf '' | compute_hash)"

# Compute current rules hash and load previous one if it exists
new_tun_dir_hash="$(compute_hash "$tun_dir_rules")"
old_tun_dir_hash="$(cat "$TUN_DIR_HASH" 2>/dev/null || printf '%s' "$empty_rules_hash")"

# Compare hashes first
if [ "$new_tun_dir_hash" != "$old_tun_dir_hash" ]; then
    build_tun_dir_rules=1
else
    # If hashes match, verify counts also match to detect drift
    cfg_rows="$(awk 'NF { c++ } END { print c + 0 }' "$tun_dir_rules")"

    # Count TUN_DIR_* chains
    ch_rows="$(
        iptables -t mangle -S 2>/dev/null |
        awk -v pre="$TUN_DIR_CHAIN_PREFIX" '
            $1 == "-N" && $2 ~ ("^" pre "[0-9]+$") { c++ }
            END { print c + 0 }
        '
    )"

    # Count PREROUTING jumps that target TUN_DIR_* (1 per config row expected)
    pr_rows="$(
        iptables -t mangle -S PREROUTING 2>/dev/null |
        awk -v pre="$TUN_DIR_CHAIN_PREFIX" '
            $1 == "-A" {
                for (i = 1; i <= NF - 1; i++) {
                    if ($i == "-j" && $(i + 1) ~ ("^" pre "[0-9]+$")) {
                        c++; break
                    }
                }
            }
            END { print c + 0 }
        '
    )"

    # Count matching ip rule prefs for existing TUN_DIR_* chains
    tun_dir_prefs_file="$(tmp_file)"
    ip_rules_prefs_file="$(tmp_file)"

    # From existing chains TUN_DIR_<idx>, derive the expected ip rule prefs:
    #   expected_pref = TUN_DIR_PREF_BASE + idx
    iptables -t mangle -S 2>/dev/null |
    awk -v pre="$TUN_DIR_CHAIN_PREFIX" -v base="$TUN_DIR_PREF_BASE" '
        $1 == "-N" && $2 ~ ("^" pre "[0-9]+$") {
            sub("^" pre, "", $2)
            print base + $2
        }
    ' > "$tun_dir_prefs_file"


    # ip rule prefs -> leftmost number before the colon
    ip rule 2>/dev/null |
    awk -F: '/^[0-9]+:/ { print $1 }' > "$ip_rules_prefs_file"

    # Count how many TUN_DIR prefs have a matching ip rule pref
    ip_rows="$(
        awk '
            NR == FNR { have[$1] = 1; next }
            have[$1] { c++ }
            END { print c + 0 }
        ' "$ip_rules_prefs_file" "$tun_dir_prefs_file"
    )"

    # If any count differs from the number of config rows, force rebuild
    if [ "$cfg_rows" -ne "$ch_rows" ] \
        || [ "$cfg_rows" -ne "$pr_rows" ] \
        || [ "$cfg_rows" -ne "$ip_rows" ];
    then
        build_tun_dir_rules=1
    fi
fi

###################################################################################################
# 2. Check if ipsets are ready; if not, exit early
###################################################################################################
tun_dir_ipsets_hash="$(cat "$TUN_DIR_IPSETS_HASH" 2>/dev/null || printf '%s' "$empty_rules_hash")"

if [ -s "$tun_dir_rules" ] \
    && [ "$build_tun_dir_rules" -eq 1 ] \
    && [ "$tun_dir_ipsets_hash" != "$new_tun_dir_hash" ];
then
    log "ipsets are not ready for current rules; exiting..."
    exit 0
fi

###################################################################################################
# 3. Build from scratch on any change
###################################################################################################
if [ "$build_tun_dir_rules" -eq 1 ] && [ "$old_tun_dir_hash" != "$empty_rules_hash" ]; then
    log "Configuration has changed; deleting existing rules..."

    # Find all TUN_DIR_* chains in mangle
    chains="$(
        iptables -t mangle -S 2>/dev/null |
        awk '
            $1 == "-N" && $2 ~ /^'"$TUN_DIR_CHAIN_PREFIX"'[0-9]+$/ { print $2 }
        '
    )"

    # Remove PREROUTING jumps, delete chains, drop matching ip rules
    # expected ip rule pref = TUN_DIR_PREF_BASE + <idx>
    while IFS= read -r ch; do
        [ -n "$ch" ] || continue
        idx_num="${ch#"$TUN_DIR_CHAIN_PREFIX"}"
        pref=$((TUN_DIR_PREF_BASE + idx_num))

        purge_fw_rules -q "mangle PREROUTING" "-j ${ch}\$"
        delete_fw_chain -q mangle "$ch"
        ip rule del pref "$pref" 2>/dev/null || true

        log "Removed previous rule: pref=$pref chain=$ch"
    done <<EOF
$chains
EOF
    changes=1
fi

if ! [ -s "$tun_dir_rules" ]; then
    log "No rules are defined"
elif [ "$build_tun_dir_rules" -eq 0 ]; then
    log "Rules are applied and up-to-date"
else
    # Apply all rules in order
    idx=0

    # Figure out where to start (after system iface-mark lines)
    base_pos="$(get_prerouting_base_pos)"

    while IFS=: read -r table src src_excl set set_excl; do
        # Table must be listed in rt_tables as wgcN/ovpncN or main
        if ! table_allowed "$table"; then
            log -l warn "table=$table is not supported" \
                "(must be one of: ${valid_tables_csv:-<none>}); skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # Require non-empty 'src'
        if [ -z "$src" ]; then
            log -l warn "Missing 'src' for table=$table; skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # Support optional interface suffix in the form CIDR%iface (defaults to br0)
        src_iif="br0"
        case "$src" in
            *%*)
                src_iif="${src#*%}"        # part after '%'
                src="${src%%%*}"           # part before '%'
                ;;
        esac

        # Validate interface exists
        if [ -z "$src_iif" ]; then
            log -l warn "Empty interface after '%' in 'src'; skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi
        if [ ! -d "/sys/class/net/$src_iif" ]; then
            log -l warn "Interface '$src_iif' not found; skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # Validate src is a LAN/private CIDR (check base IP before '/')
        src_ip="${src%%/*}"
        if ! is_lan_ip "$src_ip"; then
            log -l warn "src '$src' is not a private RFC1918 subnet; skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # 'set' must be provided (non-empty)
        if [ -z "$set" ]; then
            log -l warn "Missing 'set' for table=$table; skipping rule with idx=$idx"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # Destination matching:
        #   * Support meta ipset "any" -> match ALL destinations (no ipset lookup)
        #   * Otherwise resolve the ipset name (prefers *_ext when available)
        match=""
        if [ "$set" != "any" ]; then
            # Resolve destination ipset with *_ext-first fallback
            dest_set="$(resolve_set_name "$set")"
            if [ -z "$dest_set" ]; then
                log -l warn "No ipset found for set='$set' (neither extended nor standard);" \
                    "skipping rule with idx=$idx"
                warnings=1; idx=$((idx + 1)); continue
            fi
            match="-m set --match-set $dest_set dst"
        fi

        # Optional destination exclusion ipset, also *_ext-first
        if [ -n "$set_excl" ]; then
            orig_excl="$set_excl"
            dest_set_excl="$(resolve_set_name "$orig_excl")"
            if [ -z "$dest_set_excl" ]; then
                log -l warn "No exclusion ipset found for set_excl='$orig_excl'" \
                    "(neither extended nor standard); skipping rule with idx=$idx"
                warnings=1; idx=$((idx + 1)); continue
            fi
            excl="-m set ! --match-set $dest_set_excl dst"
            excl_log=" set_excl=$set_excl"
        else
            excl=""; excl_log=""
        fi

        # Slot is idx + 1 so 0 means "unmarked"
        slot=$((idx + 1))

        # Ensure it fits into our reserved field
        if [ "$slot" -gt "$_mark_field_max" ]; then
            log -l warn "Too many rules for fwmark field (mask=$mark_mask_hex," \
                "shift=$_mark_shift_val): idx=$idx > max=$_mark_field_max; skipping rule"
            warnings=1; idx=$((idx + 1)); continue
        fi

        # Compute masked mark value
        _mark_val=$((slot << _mark_shift_val))
        mark_val_hex="$(printf '0x%x' "$_mark_val")"

        # Compute routing pref and per-rule chain name
        pref=$((TUN_DIR_PREF_BASE + idx))
        chain="${TUN_DIR_CHAIN_PREFIX}${idx}"

        # Create/flush the per-rule chain
        create_fw_chain -q -f mangle "$chain"

        # Source exclusions: RETURN early (preserve order); validate each is private
        if [ -n "$src_excl" ]; then
            IFS_SAVE=$IFS
            IFS=','; set -- $src_excl; IFS=$IFS_SAVE
            for ex; do
                [ -n "$ex" ] || continue
                ex_ip="${ex%%/*}"
                if ! is_lan_ip "$ex_ip"; then
                    log -l warn "src_excl='$ex' is not a private RFC1918 subnet;" \
                        "skipping rule with idx=$idx"
                    warnings=1; continue
                fi
                ensure_fw_rule -q mangle "$chain" -s "$ex" -j RETURN
            done
            src_exc_log=" src_excl=$src_excl"
        else
            src_exc_log=""
        fi

        # Set ONLY our field (masked), leave other apps' bits intact
        ensure_fw_rule -q mangle "$chain" $match $excl \
            -j MARK --set-xmark "$mark_val_hex/$mark_mask_hex"

        # Jump from PREROUTING only if our field is still zero (first-match-wins)
        # Preserve config order
        insert_pos=$((base_pos + idx))
        sync_fw_rule -q mangle PREROUTING "-j $chain$" \
            "-s $src -i $src_iif -m mark --mark 0x0/$mark_mask_hex -j $chain" "$insert_pos"

        # Unique ip rule at this pref
        ip rule del pref "$pref" 2>/dev/null || true
        ip rule add pref "$pref" fwmark "$mark_val_hex/$mark_mask_hex" \
            lookup "$table" >/dev/null 2>&1 || true

        log "Added rule: table=$table pref=$pref fw_mark=${mark_val_hex}/${mark_mask_hex}" \
            "chain=$chain iface=$src_iif src=$src${src_exc_log} set=$set${excl_log}"

        changes=1; idx=$((idx + 1))
    done < "$tun_dir_rules"
fi

# Save hash for the current run
printf '%s\n' "$new_tun_dir_hash" > "$TUN_DIR_HASH"

###################################################################################################
# 4. Finalize
###################################################################################################
if [ "$changes" -eq 0 ]; then
    # Exit silently if no changes were applied
    exit 0
elif [ "$warnings" -eq 0 ]; then
    log "All changes have been applied successfully"
else
    log -l warn "Completed with warnings; please check logs for details"
fi
