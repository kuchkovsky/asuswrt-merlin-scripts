#!/usr/bin/env ash

###################################################################################################
# ipset_builder.sh - ipset builder for geo, custom and combo sets
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Builds per-country ipsets from GeoLite2 (preferred for better accuracy) when
#     MAXMIND_LICENSE_KEY is set in config.sh and external storage is mounted;
#     otherwise falls back to IPdeny. Only countries referenced in WAN_FW_RULES
#     and TUN_DIR_RULES are built.
#   * Creates named custom ipsets from inline CIDR blocks (comments allowed) or
#     nested URL sources (FireHOL, AbuseIPDB etc.) listed in CUSTOM_IPSETS;
#     a predefined FireHOL Level 1 set is bundled for baseline protection.
#   * Optionally aggregates CIDRs with mapCIDR (create -> aggregate -> apply).
#     The toolchain (BusyBox static for unzip + mapCIDR) is auto-bootstrapped
#     into $IPS_BDR_DIR/bin when storage is mounted. Aggregation is auto-disabled
#     when mapCIDR or external storage is unavailable.
#   * Generates "combo" sets (list:set) that union existing sets so firewall
#     rules can match a single key instead of many.
#   * Truncates and replaces a custom set name or combo set name with a 24-char hash
#     if its name exceeds 31 characters. This keeps the firewall fully operational,
#     but makes logs harder to read. For this reason, shorter and more descriptive names
#     are recommended whenever possible, so that syslog output stays human-readable.
#   * Restores sets from cached dump files for fast boot; -u forces a fresh
#     download / rebuild even if a dump is present. SHA-256 hashes are stored
#     per custom block to skip rebuilds if list definitions haven't changed
#     (does not apply to country sets).
#   * Uses an atomic 'create -> swap -> destroy' flow for zero-downtime updates.
#   * Optional temporary killswitch (-k) blocks the configured WAN ports
#     until all ipsets are ready.
#   * Optionally adds a short post-boot delay (see BOOT_WAIT_DELAY in config.sh).
#     This prevents the router from being hammered while it is still starting
#     and gives external modems time to finish their long cold-start so
#     download-based rule sources are reachable.
#   * On download, build, or storage failure:
#       - Sets a flag file and schedules a 10-minute cron retry carrying the
#         same flags.
#       - Sends a single "failure" email; on the next success, removes the
#         cron job and sends a "resolved" notice.
#   * Runs wan_firewall.sh and/or tunnel_director.sh if requested via switches
#     so iptables rules referencing these ipsets go live immediately.
#
# Usage:
#   ipset_builder.sh           # normal run (restore when possible)
#   ipset_builder.sh -k        # enable temporary killswitch during build
#   ipset_builder.sh -u        # force update of all ipsets (countries + custom)
#   ipset_builder.sh -uc       # force update of custom ipsets only; skip countries
#   ipset_builder.sh -w        # launch wan_firewall.sh after build
#   ipset_builder.sh -t        # launch tunnel_director.sh after build
#   ipset_builder.sh -k -u -w  # combinations of the above
#
# Requirements / Notes:
#   * All important variables live in config.sh. Review, edit, then run "ipw"
#     (helper alias) to apply changes without rebooting.
#   * GeoLite2 requires MAXMIND_LICENSE_KEY and mounted external storage;
#     sign up for a free account and set the license key if you want to use this database.
#     If the key is unset or storage is unmounted, the script falls back to IPdeny.
#   * Aggregation requires external binaries and external storage; BusyBox and mapCIDR
#     are installed under $IPS_BDR_DIR/bin if external storage is available.
#   * amtm email must be configured on the router beforehand.
#   * IPv4 only; extend to IPv6 as required.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2018
# shellcheck disable=SC2019
# shellcheck disable=SC2086
# shellcheck disable=SC2153

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Parse args
###################################################################################################
killswitch=0
update=0
update_custom=0
start_wan_fw=0
start_tun_dir=0

while [ $# -gt 0 ]; do
    case "$1" in
        -k)  killswitch=1;      shift ;;
        -u)  update=1;          shift ;;
        -uc) update_custom=1;   shift ;;
        -w)  start_wan_fw=1;    shift ;;
        -t)  start_tun_dir=1;   shift ;;
        *)                      break ;;
    esac
done

# Precedence: -u overrides -uc (if both given)
if [ "$update" -eq 1 ] && [ "$update_custom" -eq 1 ]; then
    update_custom=0
fi

###################################################################################################
# 0b. Load utils and shared variables
###################################################################################################
. /jffs/scripts/utils/common.sh
. /jffs/scripts/utils/firewall.sh

DIR="$(get_script_dir)"
. "$DIR/config.sh"
. "$DIR/fw_shared.sh"

acquire_lock  # avoid concurrent runs

###################################################################################################
# 0c. Define constants & variables
###################################################################################################

# Active WAN interface
WAN_IF=$(get_active_wan_if)

# Paths for binaries
BIN_DIR="$IPS_BDR_DIR/bin"
BUSYBOX_BIN="$BIN_DIR/busybox"
MAPCIDR_BIN="$BIN_DIR/mapcidr"

# Paths for dumps
DUMP_DIR="$IPS_BDR_DIR/dumps"
COUNTRY_DUMP_DIR="$DUMP_DIR/countries"
CUSTOM_DUMP_DIR="$DUMP_DIR/custom"

# Email sender utility
EMAIL_SENDER='/jffs/scripts/utils/send_email.sh'

# GeoLite2 downloads
GEOLITE2_COUNTRY_URL="https://download.maxmind.com/app/geoip_download\
?edition_id=GeoLite2-Country-CSV&license_key=${MAXMIND_LICENSE_KEY}&suffix=zip"

# IPdeny downloads
IPDENY_COUNTRY_BASE_URL='https://www.ipdeny.com/ipblocks/data/aggregated'
IPDENY_COUNTRY_FILE_SUFFIX='-aggregated.zone'

# Cron job for retries
RETRY_CRON_TAG='retry_ipset_builder'  # tag
RETRY_CRON_SCHEDULE='*/10 * * * *'    # schedule (every 10 minutes)

# Mutable runtime flags
external_storage=0  # external storage is available
busybox_ready=0     # BusyBox binary is ready
mapcidr_ready=0     # mapCIDR is ready
agg_disabled=0      # aggregation disabled this run
warnings=0          # non-critical issues encountered

# Explicitly export home directory for root (required by mapCIDR)
export HOME=/root

###################################################################################################
# 0d. Define helper functions
# -------------------------------------------------------------------------------------------------
# Killswitch / storage helpers:
#   is_killswitch_enabled    - true if killswitch=1 and KILLSWITCH_RULES is non-empty
#   is_mount_prefix            - true if path starts with /mnt/ or /tmp/mnt/
#   is_mounted                 - resolve /mnt -> /tmp/mnt and verifies device is mounted
#
# Retry / notification flow:
#   create_retry_and_notify    - add 10-min cron retry and send failure email
#   delete_retry_and_notify    - remove retry cron job and send success email
#   on_failure                 - log, flag, schedule retry, notify, and exit 1
#   if_recovered               - log recovery, cancel retry, clear flags, notify
#
# Small utilities:
#   semver                     - extract X.Y.Z from a string (first match)
#
# Network fetch:
#   fetch_to_files             - curl API result check for app versions -> RES/ERR files;
#                                returns 0/1/2 (ok / fail / keep installed)
#   download_file              - curl file download with error logging;
#                                supports --label for nicer names
#
# Tool bootstrapping:
#   arch                       - detect router architecture (aarch64/armv7 for GNU or arm64/arm)
#   init_busybox               - ensure latest busybox.static in $BIN_DIR (for unzip, etc.)
#   init_mapcidr               - ensure latest mapCIDR in $BIN_DIR (uses BusyBox unzip)
#
# Geo data:
#   use_geolite2               - check if MAXMIND_LICENSE_KEY is set and external storage
#                                is mounted, so GeoLite2 DB can be used
#   generate_geolite2_country_files
#                             - download GeoLite2 Country CSV; emit per-country *.zone
#
# ipset helpers:
#   ipset_exists               - test if an ipset exists
#   get_ipset_count            - fast header-only entry count
#
# Parsing / printing:
#   clean_ipv4_line            - strip comments/whitespaces; validate IPv4/CIDR; print cleaned line
#   print_cidrs_from_file      - emit valid CIDRs from a file
#   print_cidrs_from_url       - download a URL, then emit valid CIDRs (for nesting)
#   print_create_ipset         - emit 'create' (hash:net, with size/limit)
#   print_add_entry            - emit one 'add' line
#   print_swap_and_destroy     - emit swap+destroy for atomic updates
#
# Persistence:
#   save_dump                  - ipset save -> dump file
#   restore_dump               - atomic restore: tmp clone + swap if dump exists
#   save_hashes                - compute normalized hashes of WAN_FW_RULES and TUN_DIR_RULES,
#                                then save them
#
# Build pipeline:
#   aggregate                  - optional aggregation via mapCIDR when available;
#                                returns count of aggregated entries
#   build_ipset <set> <src> <dump> [--label "name"] [--no-agg]
#                              - source: URL or file (file may contain nested URLs)
#                              - triggers 'aggregate'
#                              - always applies via restore script; saves new dump
###################################################################################################

killswitch_rules=$(strip_comments "$KILLSWITCH_RULES" | sed -E 's/[[:blank:]]+//g')

is_killswitch_enabled() {
    [ "$killswitch" -eq 1 ] && [ -n "$killswitch_rules" ]
}

is_mount_prefix() {
    case "$1" in
        /mnt/*|/tmp/mnt/*) return 0 ;;  # it means we store data on external storage
        *)                 return 1 ;;  # not external storage, probably JFFS
    esac
}

is_mounted() {
    local dir="$1" real_dir prefix_base rest id mount_point

    case "$dir" in
        /mnt/*)
            # alias -> map /mnt/st5/... to /tmp/mnt/st5/...
            real_dir="/tmp$dir"
            ;;
        /tmp/mnt/*)
            # original mount point without alias -> /tmp/mnt/st5/...
            real_dir="$dir"
            ;;
        *)
            # not an external storage - return
            return 1
            ;;
    esac

    # Our real mounts all live under /tmp/mnt
    prefix_base="/tmp/mnt"

    # Strip off /tmp/mnt/ to get st5/whatever...
    rest="${real_dir#"$prefix_base"/}"

    # Grab just the first component, e.g., st5
    id="${rest%%/*}"

    # Return error if the storage ID is missing
    [ -z "$id" ] && return 1

    # Build the mount point path
    mount_point="$prefix_base/$id"

    # Look for that exact mount point in /proc/mounts
    grep -qs "[[:space:]]${mount_point}[[:space:]]" /proc/mounts
}

create_retry_and_notify() {
    # Create the job only if it isn't already there
    if ! cru l | grep -q "[[:space:]]#${RETRY_CRON_TAG}#\$"; then
        local retry_args="" cron_cmd

        # Recreate the original flag set for the cron command
        [ "$killswitch" -eq 1 ] && retry_args="$retry_args -k"
        [ "$update" -eq 1 ] && retry_args="$retry_args -u"
        [ "$update_custom" -eq 1 ] && retry_args="$retry_args -uc"
        [ "$start_wan_fw" -eq 1 ] && retry_args="$retry_args -w"
        [ "$start_tun_dir" -eq 1 ] && retry_args="$retry_args -t"

        # Cron command, tagged so we can find / remove it later
        cron_cmd="$RETRY_CRON_SCHEDULE $(get_script_path)${retry_args}"

        # Add cron job
        cru a "${RETRY_CRON_TAG}" "${cron_cmd}"

        log -l notice "Scheduled cron retry job '${RETRY_CRON_TAG}' (${cron_cmd})"
    fi

    # Bail if an alert was already sent for this failure
    [ -f "$ALERT_EMAIL_SENT_FLAG" ] && return 0

    local msg="$1"

    # Decide which explanatory message to include
    if [ -f "$STORAGE_NOT_MOUNTED_FLAG" ]; then
        msg="${msg}. Please attach the disk or verify the USB connection."
    elif [ -f "$BUILD_FAILED_FLAG" ]; then
        msg="${msg}. Please check the logs for details."
    else
        msg="$msg required for ipset building. Please check the HTTP status code;"
        msg="$msg possible causes include a network problem, a wrong URL,"
        msg="$msg or API rate limits."
    fi

    # Send error email in the background
    (
        sleep 30;
        "$EMAIL_SENDER" \
            "🔴 Firewall State Notification" \
            "$msg\n\n" \
            "This will affect the functionality of WAN Firewall and Tunnel Director.\n\n" \
            "A cron job has been scheduled to retry every 10 minutes.";
        touch "$ALERT_EMAIL_SENT_FLAG"
    ) &

    return 0
}

delete_retry_and_notify() {
    # If retry job exists
    if cru l | grep -q "[[:space:]]#${RETRY_CRON_TAG}#\$"; then
        cru d "$RETRY_CRON_TAG"  # delete it
        log -l notice "Removed cron retry job '$RETRY_CRON_TAG'"

        local msg

        # Decide which explanatory message to include
        if [ -f "$STORAGE_NOT_MOUNTED_FLAG" ]; then
            msg="Storage at $IPS_BDR_DIR has been mounted successfully."
        else
            msg="All ipset downloads have completed successfully."
        fi

        # Send success email in the background
        (
            "$EMAIL_SENDER" \
                "🟢 Firewall State Notification" \
                "$msg\n\n" \
                "Automatic retry cron job has been removed."
        ) &
    fi
}

on_failure() {
    local msg="$1"  flag="$2"

    log -l err "$msg"
    touch "$flag"

    create_retry_and_notify "$msg"

    log -l notice "Exiting due to error; will retry later..."
    exit 1
}

if_recovered() {
    local flag="$1" msg="$2"

    if [ -f "$flag" ]; then
        log -l notice "$msg"
        delete_retry_and_notify

        rm -f "$flag" "$ALERT_EMAIL_SENT_FLAG"
    fi
}

semver() { sed -nE 's/.*?([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -1; }

fetch_to_files() {
    local res="$1" err="$2" url="$3" api_name="$4" bin_name="$5" existing="$6"

    if curl -fsSL "$url" -o "$res" 2>"$err"; then
        return 0
    fi

    log -l warn "$api_name request failed - $(cat "$err")"
    if [ -x "$existing" ]; then
        log -l warn "Could not check latest $bin_name; keeping installed version"
        return 2
    else
        log -l warn "Could not check latest $bin_name and none installed; aggregation will be disabled"
        return 1
    fi
}

download_file() {
    local url="$1" file="$2"
    shift 2
    local label="" args="" http_code short_label

    # Pull out our meta flag (--label). Keep all other args for curl
    while [ $# -gt 0 ]; do
        case "$1" in
            --label) shift; label="$1" ;;
            *) args="$args '$(printf "%s" "$1" | sed "s/'/'\\\\''/g")'" ;;
        esac
        shift
    done

    if [ -n "$label" ]; then
        # If a human-friendly label was explicitly provided, use it directly
        short_label="$label"
    else
        # Otherwise, default to using the URL itself as the verbose label
        label="$url"

        # Build a proper short_label:
        # - last non-empty path segment
        # - drop trailing slash if no query
        # - keep query and prepend "/?" when present (e.g., "aslookup/?q=ASN")
        local u path query base         # declare variables
        u=${url#*://}                   # remove the scheme (http://, https://, etc.)
        case $u in
            */*) rest=${u#*/} ;;        # if there's at least one '/', drop the host part
            *)   rest= ;;               # otherwise, no path - clear "rest"
        esac
        path=${rest%%\?*}               # path without query string
        query=${rest#"$path"}           # either "" or the query part (starting with '?')
        path=${path%/}                  # remove trailing slash from path
        base=${path##*/}                # get the last path segment (after last '/')

        if [ -n "$base" ]; then
            # Normal case: we have a non-empty last segment - append query if present
            short_label="$base${query:+/}$query"
        else
            # Edge case: no last segment (e.g., URL ends with '/'), so use host instead
            # Append query if present
            short_label="${u%%/*}${query:+/}$query"
        fi
    fi

    log "Downloading '$label'..."

    # -sS: silent but show errors
    # -G : move any -d data to query string (always GET)
    # -w : capture HTTP status code
    set -f
    if ! http_code=$(eval "curl -sS -G $args -o \"\$file\" -w \"%{http_code}\" \"$url\""); then
        http_code=000
    fi
    set +f

    # Default to 000 if empty (transport/DNS error)
    [ -n "$http_code" ] || http_code=000

    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        log "Successfully downloaded '$short_label'"
    else
        rm -f "$file"
        on_failure \
            "Failed to download file '$short_label' (HTTP $http_code)" \
            "$DOWNLOAD_FAILED_FLAG"
    fi
}

arch() {
    local f="${1:-gnu}"; f="${f#-}"
    local m; m="$(uname -m)"

    case "$m" in
        aarch64|arm64)
            case "$f" in
                gnu) printf '%s\n' 'aarch64' ;;
                *)   printf '%s\n' 'arm64'   ;;
            esac
            ;;
        armv7l|armv7)
            case "$f" in
                gnu) printf '%s\n' 'armv7' ;;
                *)   printf '%s\n' 'arm'   ;;
            esac
            ;;
        *)
            log -l err "Unknown CPU architecture: $m"
            exit 1
            ;;
    esac
}

init_busybox() {
    local base_url rel_marker
    local installed_ver="" installed_rel="" remote_ver="" remote_rel=""
    local file_name apk_file compressed_bin
    local res err tmp rc

    base_url="https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/$(arch)/"
    rel_marker="$BIN_DIR/.busybox-static-release"

    log "Ensuring the latest BusyBox version is installed into BIN_DIR='$BIN_DIR'..."

    mkdir -p "$BIN_DIR"
    res=$(tmp_file); err=$(tmp_file)

    if ! fetch_to_files "$res" "$err" "$base_url" "Alpine CDN" "BusyBox" "$BUSYBOX_BIN"; then
        rc=$?
        [ "$rc" -eq 2 ] && return 0 || return 1
    fi

    # Parse the newest busybox-static-*.apk from the index (there should be only one)
    file_name="$(sed -nE 's@.*href="(busybox-static-[^"]+\.apk)".*@\1@p' "$res" | head -1)"
    if [ -z "$file_name" ]; then
        log -l warn "Could not find busybox-static in the Alpine Linux repo"
        return 1
    fi

    # Extract version (e.g., 1.37.0) and release (e.g., r18) from file_name
    remote_ver="$(printf '%s' "$file_name" | sed -nE 's/^busybox-static-([0-9.]+)-r[0-9]+\.apk$/\1/p')"
    remote_rel="r$(printf '%s' "$file_name" | sed -nE 's/^busybox-static-[0-9.]+-r([0-9]+)\.apk$/\1/p')"

    # Read installed version (BusyBox prints "BusyBox vX.Y.Z ...").
    # If we already have BusyBox with unzip and exact same version+release, we're done
    if [ -x "$BUSYBOX_BIN" ]; then
        installed_ver="$("$BUSYBOX_BIN" 2>&1 | semver)"
        [ -f "$rel_marker" ] && installed_rel="$(cat "$rel_marker" 2>/dev/null)"

        if [ "$installed_ver" = "$remote_ver" ] && [ "$installed_rel" = "$remote_rel" ]; then
            log "BusyBox is installed and up-to-date (v${installed_ver} ${installed_rel})"
            busybox_ready=1
            return 0
        else
            log "The installed BusyBox v${installed_ver} ${installed_rel} is outdated. Starting update..."
        fi
    else
        log "BusyBox is not installed. Starting installation..."
    fi

    # Download & extract into tmp dir
    tmp="$(tmp_dir)"
    apk_file="$tmp/$file_name"
    download_file "${base_url}${file_name}" "$apk_file"

    log "Extracting and installing BusyBox binary from apk..."

    # Find the bin path (bin/busybox.static) inside the apk (a gzipped tar)
    compressed_bin="$(tar -tzf "$apk_file" | grep -E '(^|/)bin/busybox\.static$' | head -1)"
    if [ -z "$compressed_bin" ]; then
        log -l warn "APK does not contain bin/busybox.static"
        return 1
    fi

    # Extract that compressed bin to stdout and write to our destination
    if ! tar -xzf "$apk_file" "$compressed_bin" -O > "$BUSYBOX_BIN"; then
        log -l warn "Failed to extract '$apk_file'"
        return 1
    fi

    # Make BusyBox executable
    chmod 755 "$BUSYBOX_BIN"

    # Save the release version info
    printf '%s\n' "$remote_rel" > "$rel_marker"

    # Verify that BusyBox is executable
    if ! "$BUSYBOX_BIN" --help >/dev/null 2>&1; then
        log -l warn "Installed BusyBox is not executable"
        return 1
    fi

    log "Successfully installed BusyBox v${remote_ver} ${remote_rel}"
    rm -rf "$tmp"
    busybox_ready=1

    return 0
}

init_mapcidr() {
    local repo="projectdiscovery/mapcidr"
    local remote_tag="" remote_ver="" installed_ver=""
    local zip_name zip_url zip_file
    local res err tmp rc

    log "Ensuring the latest mapCIDR version is installed into BIN_DIR='$BIN_DIR'..."

    mkdir -p "$BIN_DIR"
    res=$(tmp_file); err=$(tmp_file)

    if ! fetch_to_files "$res" "$err" "https://api.github.com/repos/${repo}/releases/latest" \
        "GitHub API" "mapCIDR" "$MAPCIDR_BIN";
    then
        rc=$?
        [ "$rc" -eq 2 ] && return 0 || return 1
    fi

    # Parse version
    remote_tag="$(sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$res" | head -1)"
    if [ -z "$remote_tag" ]; then
        log -l warn "Could not parse latest tag from GitHub response"
        return 1
    fi
    remote_ver="${remote_tag#v}"

    # Read installed version. If we already have the same version, we're done
    if [ -x "$MAPCIDR_BIN" ]; then
        installed_ver="$("$MAPCIDR_BIN" -version 2>&1 | semver)"

        if [ "$installed_ver" = "$remote_ver" ]; then
            log "mapCIDR is installed and up-to-date (v${installed_ver})"
            mapcidr_ready=1
            return 0
        else
            log "The installed mapCIDR v${installed_ver} is outdated. Starting update..."
        fi
    else
        log "mapCIDR is not installed. Starting installation..."
    fi

    if [ "$busybox_ready" -eq 0 ]; then
        log "Extraction of mapCIDR archive requires a newer version of BusyBox" \
            "than the built-in one; ensuring availability..."

        init_busybox || return 1
    fi

    # Download & extract into tmp dir
    tmp="$(tmp_dir)"
    zip_name="mapcidr_${remote_ver}_linux_$(arch -go).zip"
    zip_url="https://github.com/$repo/releases/download/$remote_tag/$zip_name"
    zip_file="$tmp/mapcidr.zip"
    download_file "$zip_url" "$zip_file" -L

    log "Extracting and installing mapCIDR binary from ZIP..."

    # Use our BusyBox to unzip just the mapcidr binary
    if ! "$BUSYBOX_BIN" unzip -p "$zip_file" mapcidr > "$tmp/mapcidr"; then
        log -l warn "Failed to extract '$zip_file'"
        return 1
    fi

    # Move the binary to the permanent bin folder
    mv -f "$tmp/mapcidr" "$MAPCIDR_BIN"

    # Make mapCIDR executable
    chmod 755 "$MAPCIDR_BIN"

    # Verify that mapCIDR is executable
    if ! TMPDIR="$tmp" "$MAPCIDR_BIN" -version >/dev/null 2>&1; then
        log -l warn "Installed mapCIDR is not executable"
        return 1
    fi

    log "Successfully installed mapCIDR v${remote_ver}"

    # Delete custom tmp dir
    rm -rf "$tmp"
    mapcidr_ready=1

    return 0
}

_gen_geolite2_cc_data() {
    local scratch_dir="$1" loc_csv="$2" blk_csv="$3" out_dir="$4"
    local cc_csv="${5:-}" ext_match="${6:-0}"
    local ext_suffix="" ext_log=""
    local IFS_SAVE cc cc_uc cc_lc ids_file target

    [ -n "$cc_csv" ] || return 0

    if [ "$ext_match" -eq 1 ]; then
        ext_suffix="_ext"
        ext_log="extended "
    fi

    IFS_SAVE=$IFS
    IFS=,; set -- $cc_csv; IFS=$IFS_SAVE

    for cc; do
        [ -n "$cc" ] || continue

        log "Generating ${ext_log}zone file: '${cc}${ext_suffix}'..."

        cc_uc=$(printf '%s' "$cc" | LC_ALL=C tr 'a-z' 'A-Z')
        cc_lc=$(printf '%s' "$cc" | LC_ALL=C tr 'A-Z' 'a-z')
        ids_file="${scratch_dir}/ids.${cc_uc}"
        target="${out_dir}/${cc_lc}${ext_suffix}.zone"

        # Collect all location IDs for the ISO (field 5 in Locations)
        awk -F',' -v cc="$cc_uc" '
            NR == 1 { next }
            $5 == cc { gsub(/"|\r/, ""); id[$1] = 1 }
            END { for (i in id) print i }
        ' "$loc_csv" > "$ids_file"

        # One awk; ext=0 -> (g||rep), ext=1 -> (g||rep||reg)
        awk -F',' -v ext="$ext_match" '
            NR == FNR { id[$1] = 1; next }          # wanted IDs
            NR == 1   { next }                      # skip Blocks header
            {
                gsub(/"|\r/, "")
                net = $1         # network
                g   = $2         # geoname_id
                reg = $3         # registered_country_geoname_id
                rep = $4         # represented_country_geoname_id
                if (id[g] || id[rep] || (ext && id[reg])) print net
            }
        ' "$ids_file" "$blk_csv" > "$target"
    done
}

use_geolite2() {
  [ -n "$MAXMIND_LICENSE_KEY" ] && [ "$external_storage" -eq 1 ]
}

generate_geolite2_country_files() {
    local cc_list="${1:-}" cc_ext_list="${2:-}"
    local tmp out zip loc_zipped blk_zipped loc_csv blk_csv

    tmp="$(tmp_dir)"; out="$(tmp_dir)"

    # Download the GeoLite2 Country CSV ZIP
    zip="${tmp}/geolite2-country.zip"
    download_file "$GEOLITE2_COUNTRY_URL" "$zip" --label "GeoLite2 Country DB" -L

    if [ "$busybox_ready" -eq 0 ]; then
        log "Extraction of GeoLite2 archive requires a newer version of BusyBox" \
            "than the built-in one; ensuring availability..."
        init_busybox || return 1
    fi

    # Find required CSVs inside the archive
    loc_zipped="$(
        "$BUSYBOX_BIN" unzip -l "$zip" 2>/dev/null |
        awk '/GeoLite2-Country-Locations-en\.csv$/ { print $NF; exit }'
    )"
    blk_zipped="$(
        "$BUSYBOX_BIN" unzip -l "$zip" 2>/dev/null |
        awk '/GeoLite2-Country-Blocks-IPv4\.csv$/ { print $NF; exit }'
    )"

    if [ -z "$loc_zipped" ] || [ -z "$blk_zipped" ]; then
        log -l warn "Required CSV files were not found in ZIP" \
            "(loc='$loc_zipped' blk='$blk_zipped')"
        return 1
    fi

    log "Unzipping CSV files..."
    loc_csv="${tmp}/locations.csv"
    blk_csv="${tmp}/blocks.csv"
    "$BUSYBOX_BIN" unzip -p "$zip" "$loc_zipped" > "$loc_csv"
    "$BUSYBOX_BIN" unzip -p "$zip" "$blk_zipped" > "$blk_csv"

    # Build standard & extended sets in one pass
    _gen_geolite2_cc_data  "$tmp" "$loc_csv" "$blk_csv" "$out" "$cc_list" 0
    _gen_geolite2_cc_data  "$tmp" "$loc_csv" "$blk_csv" "$out" "$cc_ext_list" 1

    rm -rf "$tmp"

    log "Successfully generated zone files for GeoLite2"
    printf '%s\n' "$out"
    return 0
}

ipset_exists() {
    ipset list -n "$1" >/dev/null 2>&1
}

get_ipset_count() {
    ipset list "$1" 2>/dev/null |
        awk '/Number of entries:/ { print $4; exit } ' || true
}

clean_ipv4_line() {
    # 1. Remove everything after first # or ;
    local l=${1%%[\#;]*}

    # 2. Drop any CR
    l=${l//$'\r'/}

    # 3. Trim leading whitespace
    l=${l#"${l%%[![:space:]]*}"}

    # 4. Trim trailing whitespace
    l=${l%"${l##*[![:space:]]}"}

    # 5. If empty or not a valid IPv4 or CIDR, bail out
    if [ -z "$l" ] || ! printf '%s\n' "$l" |
        grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$'
    then
        return 1
    fi

    # Otherwise emit it and succeed
    printf '%s\n' "$l"
    return 0
}

print_cidrs_from_file() {
    local file="$1"

    while IFS= read -r line; do
        clean_ipv4_line "$line" || continue
    done < "$file"
}

print_cidrs_from_url() {
    local blob="$1"; shift
    local file url args_lines old_IFS
    local no_clean=0 kept_nl=""

    file=$(tmp_file)

    # Strip only the function-level --no-clean flag; forward all other args unchanged.
    # Keep them as newline-separated tokens to preserve spaces
    while [ $# -gt 0 ]; do
        if [ "$1" = "--no-clean" ]; then
            no_clean=1
        else
            kept_nl="${kept_nl}${kept_nl:+
}$1"
        fi
        shift
    done

    # Tokenize a curl-style "blob" into one argument per line without invoking a shell.
    # Supports:
    #   - Unquoted words, 'single-quoted', and "double-quoted" segments.
    #   - Whitespace outside quotes splits tokens.
    #   - Backslash escaping:
    #       * Outside quotes: "\" escapes the next char verbatim.
    #       * Inside double quotes: "\" escapes the next char (e.g., \" to keep a quote).
    #       * Inside single quotes: backslashes are literal (no escapes).
    #   - Quotes are not included in the output; only their contents are emitted.
    #   - No expansions are performed (no $VAR, $(...), `...`, or globbing).
    # Behavior: walks the string character-by-character with a tiny state machine:
    #   in_s=in single quotes, in_d=in double quotes, esc=backslash pending; builds token t.
    args_lines=$(
        awk -v s="$blob" '
            BEGIN {
              in_s = 0; in_d = 0; esc = 0; t = ""
              for (i = 1; i <= length(s); i++) {
                  c = substr(s, i, 1)

                  # If previous char was backslash (outside quotes), take this one verbatim
                  if (esc) { t = t c; esc = 0; continue }

                  # Inside single quotes: only a closing '\'' ends the segment; no escapes.
                  if (in_s) {
                      if (c == "'\''") in_s = 0; else t = t c; continue
                  }

                  # Inside double quotes: \" (or any backslash+char) preserves that char; " ends
                  if (in_d) {
                      if (c == "\\") { i++; if (i <= length(s)) t = t substr(s, i, 1); continue }
                      if (c == "\"") { in_d = 0; continue }
                      t = t c; continue
                  }

                  # Unquoted section
                  if (c == "\\") { esc = 1; continue }     # start an escape for next char
                  if (c == "\"") { in_d = 1; continue }    # enter double quotes
                  if (c == "'\''") { in_s = 1; continue }  # enter single quotes

                  # Whitespace outside quotes splits tokens
                  if (c ~ /[ \t]/) { if (length(t)) { print t; t = "" } continue }

                  # Regular character
                  t = t c
              }
              # Emit the final token if any
              if (length(t)) print t
            }
        '
    )

    # Load tokens into $1..$N using newline as the only splitter
    old_IFS=$IFS
    IFS='
'
    set -- $args_lines
    IFS=$old_IFS

    if [ $# -lt 1 ]; then
        log -l warn "Empty URL blob - skipped"
        rm -f "$file"
        return 1
    fi

    url=$1; shift

    # Append the kept function-level args (e.g., --label ...), excluding --no-clean
    if [ -n "$kept_nl" ]; then
        old_IFS=$IFS
        IFS='
'
        set -- "$@" $kept_nl
        IFS=$old_IFS
    fi

    # url is the full, possibly-unquoted URL (supports &, ?, ;, etc.)
    # "$@" are the remaining curl args (e.g., -d plaintext -d ipVersion=4 -H "Key: <Key>")
    download_file "$url" "$file" "$@"

    # Output either raw (no-clean) or normalized CIDR list
    if [ "$no_clean" -eq 1 ]; then
        cat "$file"
    else
        print_cidrs_from_file "$file"
    fi

    rm -f "$file"
}

# Round up to the next power of two (>= 1)
_next_pow2() {
    local n=${1:-1} p=1

    [ "$n" -lt 1 ] && n=1

    while [ "$p" -lt "$n" ]; do
        p=$((p<<1))
    done

    printf '%s\n' "$p"
}

# Size from element count:
# - target load ~ 0.75 -> buckets ~ ceil(4 * n / 3)
# - round buckets to next pow2
# - floor at 1024 for safety
_calc_ipset_size() {
    local n=${1:-0} floor=1024 buckets

    buckets=$(((4 * n + 2) / 3))
    [ "$buckets" -lt "$floor" ] && buckets=$floor

    _next_pow2 "$buckets"
}

print_create_ipset() {
    local set="$1" cnt="$2" size

    size="$(_calc_ipset_size "$cnt")"

    printf 'create %s hash:net family inet hashsize %s maxelem %s\n' \
        "$set" "$size" "$size"
}

print_add_entry() { printf 'add %s %s\n' "$1" "$2"; }

print_swap_and_destroy() {
    printf 'swap %s %s\n' "$1" "$2"
    printf 'destroy %s\n' "$1"
}

save_dump() { ipset save "$1" > "$2"; }

restore_dump() {
    local set="$1" dump="$2" cnt rc=0

    # If forcing update or dump missing, signal caller to rebuild
    if [ "$update" -eq 1 ] || [ "$update_custom" -eq 1 ] || [ ! -f "$dump" ]; then
        return 1
    fi

    if ipset_exists "$set"; then
        # Existing set: restore into a temp clone, then swap
        local tmp_set="${set}_tmp" restore_script
        restore_script=$(tmp_file)
        ipset destroy "$tmp_set" 2>/dev/null || true

        {
            sed -e "s/^create $set /create $tmp_set /" \
                -e "s/^add $set /add $tmp_set /" "$dump"
            print_swap_and_destroy "$tmp_set" "$set"
        } > "$restore_script"

        ipset restore -! < "$restore_script" || rc=$?
        rm -f "$restore_script"
    else
        # Set doesn't exist yet - restore directly
        ipset restore -! < "$dump" || rc=$?
    fi

    # Check restore code for any failures
    if [ "$rc" -ne 0 ]; then
        log -l warn "Restore failed for ipset '$set'; will rebuild"
        return 1
    fi

    cnt=$(get_ipset_count "$set")

    log "Restored ipset '$set' from dump ($cnt entries)"

    return 0
}

save_hashes() {
    local wan_fw_rules tun_dir_rules

    wan_fw_rules=$(tmp_file)
    tun_dir_rules=$(tmp_file)

    strip_comments "$WAN_FW_RULES" | sed -E 's/[[:blank:]]+//g' > "$wan_fw_rules"
    strip_comments "$TUN_DIR_RULES" | sed -E 's/[[:blank:]]+//g' > "$tun_dir_rules"

    printf '%s\n' "$(compute_hash "$wan_fw_rules")" > "$WAN_FW_IPSETS_HASH"
    printf '%s\n' "$(compute_hash "$tun_dir_rules")" > "$TUN_DIR_IPSETS_HASH"
}

aggregate() {
    local set="$1" cidr_list="$2" no_agg="$3" cnt=0

    if [ "$external_storage" -eq 1 ] && [ "$agg_disabled" -eq 0 ] && [ "$no_agg" -eq 0 ]; then
        # Enable CIDR aggregation if mapCIDR is successfully installed
        if [ "$mapcidr_ready" -eq 0 ]; then
            if init_mapcidr; then
                log "CIDR aggregation is enabled"
                mapcidr_ready=1
            else
                log -l warn "CIDR aggregation is disabled"
                agg_disabled=1
                printf '%s\n' "$cnt"
                return 1
            fi
        fi

        log "Aggregating CIDRs for ipset '$set'..."
        local cidr_list_agg tmp

        # Create a tmp file for aggregated CIDRs
        cidr_list_agg=$(tmp_file)

        # Create a custom tmp dir for mapCIDR (allows easy cleanup later)
        tmp="$(tmp_dir)"

        # -a: aggregate, -silent: quiet output
        if TMPDIR="$tmp" "$MAPCIDR_BIN" -a -silent < "$cidr_list" > "$cidr_list_agg"; then
            mv "$cidr_list_agg" "$cidr_list"
            cnt=$(wc -l < "$cidr_list")
            log "Number of CIDRs for ipset '$set' after aggregation: $cnt"
        else
            log -l warn "Failed to aggregate CIDRs for ipset '$set'"
            warnings=1
        fi

        # Delete custom tmp dir
        rm -rf "$tmp"
    fi

    printf '%s\n' "$cnt"
    return 0
}

build_ipset() {
    local set="$1" src="$2" dump="$3"
    shift 3

    # Optional flags
    local label="" no_agg=0 no_clean=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --label)    shift; label="$1" ;;
            --no-agg)   no_agg=1   ;;
            --no-clean) no_clean=1 ;;
        esac
        shift
    done

    local target_set cidr_list cidr_list_agg restore_script
    local cnt=0 cnt_agg=0 rc=0

    log "Parsing CIDRs for ipset '$set'..."

    # Decide whether we need a temporary set (for "hot" updates) or in‐place create
    if ipset_exists "$set"; then
        target_set="${set}_tmp"
        ipset destroy "$target_set" 2>/dev/null || true
    else
        target_set="$set"
    fi

    # Build the list of CIDRs into a temp file
    cidr_list=$(tmp_file)
    {
        case "$src" in
            http://*|https://*)
                # Single URL source: download and print CIDRs (one per line)
                clean_opt=""
                [ "$no_clean" -eq 1 ] && clean_opt="--no-clean"
                print_cidrs_from_url "$src" --label "$label" $clean_opt
                ;;
            *)
                if [ "$no_clean" -eq 1 ]; then
                    # Clean file (like country zone) - no normalization needed
                    cat "$src"
                else
                    # Generic file: each line may be a CIDR or another URL to expand
                    while IFS= read -r line; do
                        case "$line" in
                            http://*|https://*)
                                print_cidrs_from_url "$line"
                                ;;
                            *)
                                # Normalize/validate and emit the CIDR if valid
                                clean_ipv4_line "$line" || continue
                                ;;
                        esac
                    done < "$src"
                fi
                ;;
        esac
    } > "$cidr_list"

    cnt=$(wc -l < "$cidr_list")
    log "Total number of CIDRs for ipset '$set': $cnt"

    # Optional aggregation pass (requires mapCIDR)
    cnt_agg=$(aggregate "$set" "$cidr_list" "$no_agg") || true
    [ "$cnt_agg" -ne 0 ] && cnt="$cnt_agg"

    log "Converting CIDRs for ipset '$set' to ipset-restore format..."

    # Generate an ipset-restore script for a single atomic apply
    restore_script=$(tmp_file)
    {
        # 1. Create target set
        print_create_ipset "$target_set" "$cnt"

        # 2. Add all CIDRs
        while IFS= read -r line; do
            print_add_entry "$target_set" "$line"
        done < "$cidr_list"

        # 3. If updating an existing set: swap temp -> live, then destroy temp
        if [ "$target_set" != "$set" ]; then
            print_swap_and_destroy "$target_set" "$set"
        fi
    } > "$restore_script"

    # Apply it all at once, ignoring duplicates
    log "Applying changes for ipset '$set'..."
    ipset restore -! < "$restore_script" || rc=$?
    rm -f "$restore_script"
    rm -f "$cidr_list"

    # Check restore code for any failures
    if [ "$rc" -ne 0 ]; then
        on_failure \
            "Failed to build ipset '$set'" \
            "$BUILD_FAILED_FLAG"
    fi

    # Save the new dump, count entries, and log final status
    cnt=$(get_ipset_count "$set")
    save_dump "$set" "$dump"

    if [ "$target_set" = "$set" ]; then
        log "Created new ipset '$set' ($cnt entries)"
    else
        log "Updated existing ipset '$set' ($cnt entries) via swap"
    fi

    if [ "$cnt" -eq 0 ]; then
        log -l warn "ipset '$set' is empty; file format may be wrong or you reached API limits"
        warnings=1
    fi
}

###################################################################################################
# 0e. Run initialization checks (flags, uptime, mounts, directories)
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Validate killswitch configuration
# -------------------------------------------------------------------------------------------------
if [ "$killswitch" -eq 1 ] && [ -z "$killswitch_rules" ]; then
    log -l warn "You requested killswitch with the '-k' flag," \
        "but KILLSWITCH_RULES are empty. Please configure them or remove the '-k' flag"
    warnings=1
fi

# -------------------------------------------------------------------------------------------------
# Apply killswitch if requested
# -------------------------------------------------------------------------------------------------
if is_killswitch_enabled; then
    killswitch_rule_count=0

    # Create a new chain or flush the existing one
    create_fw_chain -f raw "$KILLSWITCH_CHAIN"

    # Populate drop rules
    while IFS=: read -r ports protos; do
        case "$ports" in
            any)
                log -l warn "'any' is not supported for killswitch ports." \
                    "You need to explicitly specify ports for blocking"
                warnings=1
                continue
                ;;
            *[,-]*)
                port_spec="-m multiport --dports ${ports//-/:}"
                ;;
            *)
                port_spec="--dport $ports"
                ;;
        esac

        [ "$protos" = "any" ] && protos="tcp,udp"

        for proto in ${protos//,/ }; do
            ensure_fw_rule -q raw "$KILLSWITCH_CHAIN" -p "$proto" $port_spec -j DROP

            log "Added DROP rule -> $KILLSWITCH_CHAIN: proto=$proto ports=$ports"

            killswitch_rule_count=$((killswitch_rule_count + 1))
        done
    done <<EOF
$killswitch_rules
EOF

    # Insert jump once
    ensure_fw_rule -q raw PREROUTING -I 1 -i "$WAN_IF" -j "$KILLSWITCH_CHAIN"
    log "Inserted jump: raw PREROUTING iface=$WAN_IF -> $KILLSWITCH_CHAIN"

    if [ "$killswitch_rule_count" -ne 0 ]; then
        ports=$(
            printf '%s\n' "$killswitch_rules" |
            awk -F: '$1 != "any" && !seen[$1]++ { if (n++) printf ","; printf "%s", $1 }'
        )
        log "Killswitch is ON: blocking $WAN_IF on ports $ports"
    else
        log -l warn "Killswitch is OFF due to errors; please review your rules"
    fi
fi

# -------------------------------------------------------------------------------------------------
# Defer if system just booted
# -------------------------------------------------------------------------------------------------
if [ "$BOOT_WAIT_DELAY" -ne 0 ] && \
    ! awk -v min="$MIN_BOOT_TIME" '{ exit ($1 < min) }' /proc/uptime;
then
    log "Uptime < ${MIN_BOOT_TIME}s, sleeping ${BOOT_WAIT_DELAY}s..."
    sleep "$BOOT_WAIT_DELAY"
fi

# -------------------------------------------------------------------------------------------------
# Ensure the storage is ready
# -------------------------------------------------------------------------------------------------
if is_mount_prefix "$IPS_BDR_DIR"; then
    if is_mounted "$IPS_BDR_DIR"; then
        external_storage=1
    else
        on_failure \
            "The storage for IPS_BDR_DIR=$IPS_BDR_DIR is not mounted" \
            "$STORAGE_NOT_MOUNTED_FLAG"
    fi
fi

# Ensure the dump directories are created
mkdir -p "$COUNTRY_DUMP_DIR" "$CUSTOM_DUMP_DIR"

# -------------------------------------------------------------------------------------------------
# Let user know if update was requested
# -------------------------------------------------------------------------------------------------
if [ "$update" -eq 1 ]; then
    log "Update requested: forcing rebuild of all ipsets and dumps"
elif [ "$update_custom" -eq 1 ]; then
    log "Custom-only update requested: forcing rebuild of custom ipsets; skipping countries"
fi

###################################################################################################
# 1. Build per-country ipsets
###################################################################################################

# All two-letter ISO country codes, lowercase
ALL_COUNTRY_CODES='
ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt
bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh
er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht
hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls
lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni
nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg
sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug
um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
'

# Parse country codes from rules:
# - Reads the rules text and strips comments/blank lines using strip_comments.
# - Splits fields on both ':' and ',' (-F '[:,]').
# - By default scans fields 4..NF. Adjust start_field/end_field per caller.
# - For each candidate token:
#     * Strips whitespace
#     * Accepts only two-letter lowercase strings
#     * Validates against ALL_COUNTRY_CODES
# - Collects valid codes in a set, ensuring uniqueness.
# - Emits the final list of country codes, sorted and deduped.
parse_country_codes() {
    local rules="$1"
    local start_field="${2:-4}"
    local end_field="${3:-0}"

    strip_comments "$rules" |
    awk -F '[:,]' -v valid="$ALL_COUNTRY_CODES" -v SF="$start_field" -v EF="$end_field" '
        BEGIN {
            # Build lookup of valid country codes
            n = split(valid, arr, "[[:space:]\r\n]+")
            for (i = 1; i <= n; i++) if (arr[i] != "") V[arr[i]] = 1
        }
        {
            # Scan requested field range (inclusive)
            s = (SF > 0 ? SF : 1)
            e = (EF > 0 ? EF : NF)

            # Fields s..e contain key-lists; collect country tokens
            for (i = s; i <= e; i++) {
                c = $i
                gsub(/[[:space:]]*/, "", c)   # strip all whitespace
                if (c ~ /^[a-z]{2}$/ && V[c]) seen[c] = 1
            }
        }
        END {
            for (c in seen) print c
        }
    ' | sort
}

wan_fw_cc=$(parse_country_codes "$WAN_FW_RULES" 4)
tun_dir_cc=$(parse_country_codes "$TUN_DIR_RULES" 4)

if [ -z "$wan_fw_cc$tun_dir_cc" ]; then
    log "Step 1: no country references in WAN_FW_RULES or TUN_DIR_RULES; skipping build"
elif [ "$update_custom" -eq 1 ]; then
    log "Step 1: custom-only update requested; skipping build of country ipsets"
else
    # Decide provider & dump suffix
    if use_geolite2; then
        log "Step 1: building country ipsets using GeoLite2 provider..."
        PROVIDER="GeoLite2"; DUMP_SUFFIX="-geolite2.dump"
    else
        log "Step 1: building country ipsets using IPdeny provider..."
        PROVIDER="IPdeny"; DUMP_SUFFIX="-ipdeny.dump"
    fi

    # For IPdeny, also fold in TUN_DIR_RULES countries into standard sets
    # (since it doesn't provide extended data)
    if [ "$PROVIDER" = "IPdeny" ] && [ -n "$tun_dir_cc" ]; then
        std_cc=$(printf '%s\n%s\n' "$wan_fw_cc" "$tun_dir_cc" | sort -u)
    else
        std_cc="$wan_fw_cc"
    fi

    # Figure out which standard sets are missing, and try to restore them
    if [ "$update" -eq 1 ]; then
        missing_std="$(printf '%s\n' "$std_cc" | xargs)"
    else
        log "Attempting to restore $PROVIDER dumps for country sets (if any)..."
        missing_std=""
        for cc in $std_cc; do
            dump="${COUNTRY_DUMP_DIR}/${cc}${DUMP_SUFFIX}"
            restore_dump "$cc" "$dump" || missing_std="$missing_std $cc"
        done
        missing_std="$(printf '%s\n' "$missing_std" | xargs)"
    fi

    # For GeoLite2, try to restore both standard and extended sets (if any)
    if [ "$PROVIDER" = "GeoLite2" ]; then
        # Build list of extended set names (cc_ext) and find which are missing
        if [ "$update" -eq 1 ]; then
            missing_ext="$(printf '%s\n' "$tun_dir_cc" | xargs)"
        else
            log "Attempting to restore GeoLite2 dumps for extended country sets (if any)..."
            missing_ext=""
            for cc in $tun_dir_cc; do
                cc_ext="${cc}_ext"
                dump="${COUNTRY_DUMP_DIR}/${cc_ext}${DUMP_SUFFIX}"
                restore_dump "$cc_ext" "$dump" || missing_ext="$missing_ext $cc"
            done
            missing_ext="$(printf '%s\n' "$missing_ext" | xargs)"
        fi
    else
        missing_ext=""
    fi

    # Build phase
    if [ -z "$missing_std$missing_ext" ]; then
        log "All ${PROVIDER} dumps restored; nothing to rebuild"
    else
        case "$PROVIDER" in
            GeoLite2)
                # Prepare proper log message
                msg=""
                if [ -n "$missing_std" ]; then
                    msg="'$missing_std'"
                fi
                if [ -n "$missing_ext" ]; then
                    ext_fmt=""
                    set -- $missing_ext
                    for cc; do
                        ext_fmt="${ext_fmt}${ext_fmt:+ }${cc}_ext"
                    done
                    msg="${msg:+$msg and }'$ext_fmt'"
                fi

                log "Building GeoLite2 ipsets for $msg"

                # Build both kinds in a single ZIP pass
                std_csv="${missing_std// /,}"
                ext_csv="${missing_ext// /,}"

                if countries_dir=$(generate_geolite2_country_files "$std_csv" "$ext_csv"); then
                    # Standard sets
                    for cc in $missing_std; do
                        file="${countries_dir}/${cc}.zone"
                        dump="${COUNTRY_DUMP_DIR}/${cc}${DUMP_SUFFIX}"

                        build_ipset "$cc" "$file" "$dump" --no-clean
                    done

                    # Extended sets
                    for cc in $missing_ext; do
                        cc_ext="${cc}_ext"
                        file="${countries_dir}/${cc_ext}.zone"
                        dump="${COUNTRY_DUMP_DIR}/${cc_ext}${DUMP_SUFFIX}"

                        build_ipset "$cc_ext" "$file" "$dump" --no-clean
                    done

                    rm -rf "$countries_dir"
                else
                    on_failure "Failed to build zone files for GeoLite2" "$BUILD_FAILED_FLAG"
                fi
                ;;
            IPdeny)
                # Only standard lists exist with IPdeny
                log "Building IPdeny ipsets for '${missing_std}'"

                for cc in $missing_std; do
                    url="${IPDENY_COUNTRY_BASE_URL}/${cc}${IPDENY_COUNTRY_FILE_SUFFIX}"
                    dump="${COUNTRY_DUMP_DIR}/${cc}${DUMP_SUFFIX}"

                    build_ipset "$cc" "$url" "$dump" \
                        --label "${cc}${IPDENY_COUNTRY_FILE_SUFFIX}" --no-agg --no-clean
                done
                ;;
        esac
    fi
fi

###################################################################################################
# 2. Build custom ipsets
###################################################################################################

# Handle blocks inside CUSTOM_IPSETS
process_custom_block() {
    local set="$1" blockfile="$2"
    local sha_file="$CUSTOM_DUMP_DIR/$set.sha256"
    local dump_file="$CUSTOM_DUMP_DIR/$set.dump"

    local new_hash old_hash
    new_hash=$(compute_hash "$blockfile")
    old_hash=$(cat "$sha_file" 2>/dev/null || printf '')

    if [ "$new_hash" = "$old_hash" ] && restore_dump "$set" "$dump_file"; then
        return 0  # dump is restored
    fi

    # Either the block changed, or restore_dump failed -> rebuild
    build_ipset "$set" "$blockfile" "$dump_file"

    # Record the new hash for next time
    printf '%s\n' "$new_hash" > "$sha_file"
}

custom_ipsets="$(strip_comments "$CUSTOM_IPSETS")"

if [ -z "$custom_ipsets" ]; then
    log "Step 2: no custom ipsets defined; skipping build"
else
    log "Step 2: building custom ipsets..."
    cur_set="" tmp_lines=""

    while IFS= read -r line; do
        case "$line" in
            [A-Za-z0-9_]*:)    # header line, e.g., "blk:" or "rly:"
                short_label=${line%:}

                # Finish previous block
                if [ -n "$cur_set" ]; then
                    process_custom_block "$cur_set" "$tmp_lines"
                fi

                # Start new block with normalized name
                cur_set="$(derive_set_name "$short_label")"

                # Guard: custom set names must not collide with reserved country sets (cc or cc_ext)
                label_lc="$(printf '%s' "$short_label" | tr 'A-Z' 'a-z')"
                if printf '%s\n' "$label_lc" | grep -Eq '^[a-z]{2}(_ext)?$'; then
                    cc_base="${label_lc%_ext}"
                    if printf '%s' "$ALL_COUNTRY_CODES" |
                        grep -Eq "(^|[[:space:]])${cc_base}([[:space:]]|$)";
                    then
                        log -l warn "Custom ipset name '$short_label' conflicts with reserved country set" \
                            "'${cc_base}' ('${cc_base}_ext' reserved as well); skipping block"
                        cur_set=""; tmp_lines=""; warnings=1
                        continue
                    fi
                fi

                tmp_lines=$(tmp_file)
                ;;
            *)                 # data line (CIDR or URL) -> append to current block file
                if [ -n "$cur_set" ]; then
                    printf '%s\n' "$line" >> "$tmp_lines"
                fi
                ;;
        esac
    done <<EOF
$custom_ipsets
EOF

    if [ -n "$cur_set" ]; then
        process_custom_block "$cur_set" "$tmp_lines"
    fi
fi

###################################################################################################
# 3. Build combined ipsets
###################################################################################################

# Parse combo ipsets from rules:
# - Reads the rules text and strips comments/blank lines using strip_comments.
# - Inspects only fields 4 & 5 (KEYS and EXCLUDES).
# - Emits only fields that contain a comma (i.e., real "combos" such as "blk,cn,ir").
# - Strips internal whitespace so logically identical combos dedupe cleanly.
# - When ext_flag=1, exact two-letter country tokens are converted to "<cc>_ext".
# - ext_flag: pass 1 to prefer extended country data, but it is honored only if GeoLite2
#             is available; otherwise it is forced to 0.
# - Output: one combo per line, tokens comma-separated, sorted/deduped by caller for stability.
parse_combo_from_rules() {
    # $1 = rules text (variable contents), $2 = ext_flag (0 standard, 1 extended)
    local rules_text="$1" ext_flag="${2:-0}"

    # Use standard ipsets if GeoLite2 is not available
    if [ "$ext_flag" -eq 1 ] && ! use_geolite2; then
        ext_flag=0
    fi

    strip_comments "$rules_text" |
    awk -F':' -v ext="$ext_flag" '
        function emit_combo(field,    f,n,a,i,t,out) {
            f = field
            gsub(/[[:space:]]/, "", f)
            if (f ~ /,/) {
                n = split(f, a, ",")
                out = ""
                for (i = 1; i <= n; i++) {
                    t = a[i]
                    if (ext == 1 && t ~ /^[a-z]{2}$/) t = t "_ext"
                    out = out (out ? "," : "") t
                }
                print out
            }
        }
        { emit_combo($4); emit_combo($5) }
    ' | sort -u
}

wan_fw_combo_ipsets="$(parse_combo_from_rules "$WAN_FW_RULES" 0)"
tun_dir_combo_ipsets="$(parse_combo_from_rules "$TUN_DIR_RULES" 1)"

# Union, drop empties, unique
combo_ipsets="$(
    printf '%s\n' "${wan_fw_combo_ipsets:-}" "${tun_dir_combo_ipsets:-}" |
    awk 'NF' | sort -u
)"

# Returns 0 when every expected combo ipset exists
all_combo_present() {
    local line set
    for line in $combo_ipsets; do
        set="$(derive_set_name "${line//,/_}")"
        ipset_exists "$set" || return 1
    done
    return 0
}

if [ -z "$combo_ipsets" ]; then
    log "Step 3: no combo ipsets are required; skipping build"
elif all_combo_present; then
    log "Step 3: all combo ipsets are already present; skipping build"
else
    log "Step 3: building combo ipsets..."
    while IFS= read -r line; do
        set="$(derive_set_name "${line//,/_}")"

        # Skip if combo already exists
        if ipset_exists "$set"; then
            log "Combo ipset '$set' already exists; skipping"
            continue
        fi

        ipset create "$set" list:set

        # Add members; track if at least one was added (no-empty-set guarantee)
        added=0
        for key in ${line//,/ }; do
            member="$(derive_set_name "${key}")"

            if ! ipset_exists "$member"; then
                log -l warn "Combo ipset '$set': member ipset '$member' not found; skipping." \
                    "Ensure this member exists (country or custom) and previous steps succeeded"
                warnings=1
                continue
            fi

            if ipset add "$set" "$member" 2>/dev/null; then
                added=$((added + 1))
            fi
        done

        if [ "$added" -eq 0 ]; then
            # Enforce: no empty ipsets
            ipset destroy "$set" 2>/dev/null || true
            log -l warn "Combo ipset '$set' had no valid members and was not created; skipping"
            warnings=1
            continue
        fi

        log "Created combo ipset '$set'"
    done <<EOF
$combo_ipsets
EOF
fi

###################################################################################################
# 4. Finalize
###################################################################################################
if [ "$warnings" -eq 0 ]; then
    log "All ipsets have been created or updated successfully"
else
    log -l warn "Completed with warnings; please check logs for details"
fi

# Save hashes for the currently processed set of rules
save_hashes

# Start WAN Firewall if requested
if [ "$start_wan_fw" -eq 1 ]; then
    "$DIR/wan_firewall.sh"
fi

# Start Tunnel Director if requested
if [ "$start_tun_dir" -eq 1 ]; then
    "$DIR/tunnel_director.sh"
fi

# Clear storage error flag
if_recovered \
    "$STORAGE_NOT_MOUNTED_FLAG" \
    "Previously unmounted storage has been attached successfully"

# Clear download error flag
if_recovered \
    "$DOWNLOAD_FAILED_FLAG" \
    "Previously failed downloads have completed successfully"

# Clear build error flag
if_recovered \
    "$BUILD_FAILED_FLAG" \
    "Previously failed build has been completed successfully"

# Turn off killswitch if it was enabled
if is_killswitch_enabled; then
    # Remove all matching jump rules (even duplicates) to fully unblock traffic
    purge_fw_rules -q "raw PREROUTING" "-i $WAN_IF -j $KILLSWITCH_CHAIN$"

    # Delete the killswitch chain itself
    delete_fw_chain -q raw "$KILLSWITCH_CHAIN"

    log "Killswitch is OFF: all $WAN_IF ingress is allowed"
fi
