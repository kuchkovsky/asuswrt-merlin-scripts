#!/usr/bin/env ash

###################################################################################################
# ipset_builder.sh - ipset builder for geo, custom and combo sets
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Builds per-country ipsets from GeoLite2 (preferred for better accuracy) when
#     MAXMIND_LICENSE_KEY is set in config.sh and external storage is mounted;
#     otherwise falls back to IPdeny. For IPv4, countries referenced in WAN_FW_RULES
#     and TUN_DIR_RULES are built; for IPv6, countries referenced in WAN_FW_V6_RULES
#     are built. When GeoLite2 is available, both standard (cc / cc6) and extended
#     (cc_ext / cc6_ext) sets are supported.
#   * Creates named custom ipsets from inline CIDR blocks (comments allowed) or
#     nested URL sources (FireHOL, AbuseIPDB etc.) listed in CUSTOM_IPSETS and
#     CUSTOM_V6_IPSETS; a predefined FireHOL Level 1 set is bundled for baseline
#     protection.
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
#   * Optional temporary killswitch (-k) blocks the configured WAN ports (IPv4/IPv6)
#     until all ipsets are ready; the IPv6 path is auto-disabled when firmware IPv6
#     is off.
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
#   * Dual-stack aware: builds IPv4 by default and IPv6 when firmware IPv6 is enabled;
#     IPv6 paths are automatically skipped when disabled.
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

# IPv6 status
IPV6_ENABLED="$(get_ipv6_enabled)"

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
IPDENY_COUNTRY_V6_BASE_URL='https://www.ipdeny.com/ipv6/ipaddresses/aggregated/'
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
#   is_killswitch_enabled      - family-aware (-6) check; true when killswitch=1 and rules exist;
#                                IPv6 path auto-disabled if firmware IPv6 is off
#   is_mount_prefix            - true if path starts with /mnt/ or /tmp/mnt/
#   is_mounted                 - resolve /mnt -> /tmp/mnt and verify the device is mounted
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
#   fetch_to_files             - curl API/result helper -> RES/ERR files; returns 0/1/2
#                                (ok / fail / keep installed)
#   download_file              - curl download with error logging; supports --label for nicer names
#
# Tool bootstrapping:
#   arch                       - detect router architecture (aarch64/armv7 for GNU or arm64/arm)
#   init_busybox               - ensure latest busybox.static in $BIN_DIR (for unzip, etc.)
#   ensure_busybox_ready       - idempotent wrapper around init_busybox
#   init_mapcidr               - ensure latest mapCIDR in $BIN_DIR (uses BusyBox unzip)
#   ensure_mapcidr_ready       - enable aggregation when external storage & mapCIDR are available
#
# Geo data:
#   use_geolite2               - true if MAXMIND_LICENSE_KEY is set and external storage is mounted
#                                (enables GeoLite2 over IPdeny)
#   generate_geolite2_country_files
#                              - download GeoLite2 Country CSV; emit per-country *.zone
#   _gen_geolite2_cc_data      - internal: build per-ISO zone files (IPv4/IPv6; std/extended)
#
# ipset helpers:
#   ipset_exists               - test if an ipset exists
#   get_ipset_count            - fast header-only entry count
#
# Parsing / printing:
#   clean_ip_line              - strip comments/whitespace; validate IPv4/IPv6 CIDR; print cleaned
#   print_cidrs_from_file      - emit valid CIDRs from a file (supports -6)
#   print_cidrs_from_url       - download a URL (curl-like blob, quoted args ok); emits cleaned
#                                CIDRs unless --no-clean; supports -6 and --label
#   print_create_ipset         - emit 'create' (hash:net, auto-sized via _calc_ipset_size)
#   print_add_entry            - emit one 'add' line
#   print_swap_and_destroy     - emit swap+destroy for atomic updates
#
# Sizing helpers:
#   _next_pow2                 - round up to the next power of two (>=1)
#   _calc_ipset_size           - derive hashsize/maxelem from element count (target load ~0.75)
#
# Persistence:
#   save_dump                  - ipset save -> dump file
#   restore_dump               - atomic restore: tmp clone + swap if dump exists
#   save_hashes                - compute normalized hashes of WAN (v4/v6) and TUN (v4) rule blobs,
#                                then save
#
# Build pipeline:
#   aggregate                  - optional aggregation via mapCIDR when available; returns count
#   build_ipset                - build set from URL or file (nested URLs ok), optionally aggregate,
#                                apply via restore script, and save new dump
###################################################################################################
killswitch_rules=$(strip_comments "$KILLSWITCH_RULES" | sed -E 's/[[:blank:]]+//g')
killswitch_v6_rules=$(strip_comments "$KILLSWITCH_V6_RULES" | sed -E 's/[[:blank:]]+//g')

is_killswitch_enabled() {
    local use_v6=0
    [ "${1-}" = "-6" ] && { use_v6=1; shift; }

    if [ "$use_v6" -eq 1 ]; then
        [ "$killswitch" -eq 1 ] && [ -n "$killswitch_v6_rules" ]
    else
        [ "$killswitch" -eq 1 ] && [ -n "$killswitch_rules" ]
    fi
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
        local u path query base rest    # declare variables
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

ensure_busybox_ready() {
    [ "$busybox_ready" -eq 1 ] && return 0
    init_busybox || return 1
    busybox_ready=1
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
            return 0
        else
            log "The installed mapCIDR v${installed_ver} is outdated. Starting update..."
        fi
    else
        log "mapCIDR is not installed. Starting installation..."
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

    return 0
}

ensure_mapcidr_ready() {
    [ "$external_storage" -eq 1 ] || return 1
    [ "$agg_disabled" -eq 0 ]     || return 1
    [ "$mapcidr_ready" -eq 1 ]    && return 0

    if [ "$busybox_ready" -eq 0 ]; then
        log "Extraction of mapCIDR archive requires a newer version of BusyBox" \
            "than the built-in one; ensuring availability..."

        ensure_busybox_ready || return 1
    fi

    if init_mapcidr; then
        log "CIDR aggregation is enabled"
        mapcidr_ready=1
        return 0
    else
        log -l warn "CIDR aggregation is disabled"
        agg_disabled=1
        return 1
    fi
}

_gen_geolite2_cc_data() {
    local scratch_dir="$1" loc_csv="$2" blk_csv="$3" out_dir="$4"
    local cc_csv="${5:-}" ext_match="${6:-0}" ipfam="${7:-v4}"
    local ext_suffix="" ext_log="" fam_suffix="" fam_label=""
    local IFS_SAVE cc cc_uc cc_lc ids_file target

    [ -n "$cc_csv" ] || return 0

    if [ "$ext_match" -eq 1 ]; then
        ext_suffix="_ext"
        ext_log="extended "
    fi

    case "$ipfam" in
        v6) fam_suffix="6"; fam_label="IPv6" ;;
        *)  fam_suffix="";  fam_label="IPv4" ;;
    esac

    IFS_SAVE=$IFS
    IFS=,; set -- $cc_csv; IFS=$IFS_SAVE

    for cc; do
        [ -n "$cc" ] || continue

        cc_uc=$(printf '%s' "$cc" | LC_ALL=C tr 'a-z' 'A-Z')
        cc_lc=$(printf '%s' "$cc" | LC_ALL=C tr 'A-Z' 'a-z')

        # Scratch file with family suffix (ids.US for v4, ids6.US for v6)
        ids_file="${scratch_dir}/ids${fam_suffix}.${cc_uc}"

        # Output filename: <cc><6><_ext>.zone  e.g., us6.zone, us6_ext.zone
        target="${out_dir}/${cc_lc}${fam_suffix}${ext_suffix}.zone"

        log "Generating ${ext_log}zone file (${fam_label}): '$(basename "$target")'..."

        # Collect all location IDs for the ISO (field 5 in Locations)
        awk -F',' -v cc="$cc_uc" '
            NR == 1 { next }
            $5 == cc { gsub(/"|\r/, ""); id[$1] = 1 }
            END { for (i in id) print i }
        ' "$loc_csv" > "$ids_file"

        # Filter block CSV by those location IDs.
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
    local cc_list="${1:-}" cc_ext_list="${2:-}" fam_filter="${3:-both}"
    local tmp out zip loc_zipped blk4_zipped blk6_zipped loc_csv blk4_csv blk6_csv
    local want_v4=0 want_v6=0 have_v4=0 have_v6=0

    case "$fam_filter" in
        v4)   want_v4=1 ;;
        v6)   want_v6=1 ;;
        both) want_v4=1; want_v6=1 ;;
        *)    return 1  ;;
    esac

    tmp="$(tmp_dir)"; out="$(tmp_dir)"

    zip="${tmp}/geolite2-country.zip"
    download_file "$GEOLITE2_COUNTRY_URL" "$zip" --label "GeoLite2 Country DB" -L

    loc_zipped="$("$BUSYBOX_BIN" unzip -l "$zip" 2>/dev/null |
        awk '/GeoLite2-Country-Locations-en\.csv$/ { print $NF; exit }')"
    [ -n "$loc_zipped" ] || { log -l warn "Locations CSV not found in ZIP"; return 1; }

    # Probe blocks we actually need
    [ "$want_v4" -eq 1 ] && blk4_zipped="$("$BUSYBOX_BIN" unzip -l "$zip" 2>/dev/null |
        awk '/GeoLite2-Country-Blocks-IPv4\.csv$/ { print $NF; exit }')"
    [ "$want_v6" -eq 1 ] && blk6_zipped="$("$BUSYBOX_BIN" unzip -l "$zip" 2>/dev/null |
        awk '/GeoLite2-Country-Blocks-IPv6\.csv$/ { print $NF; exit }')"

    [ "$want_v4" -eq 1 ] && [ -z "$blk4_zipped" ] && want_v4=0
    [ "$want_v6" -eq 1 ] && [ -z "$blk6_zipped" ] && want_v6=0

    if [ "$want_v4" -eq 0 ] && [ "$want_v6" -eq 0 ]; then
        log -l warn "No usable Blocks CSV found in ZIP"
        return 1
    fi

    log "Unzipping CSV files..."
    loc_csv="${tmp}/locations.csv"; "$BUSYBOX_BIN" unzip -p "$zip" "$loc_zipped" > "$loc_csv"

    if [ "$want_v4" -eq 1 ]; then
        blk4_csv="${tmp}/blocks4.csv"
        "$BUSYBOX_BIN" unzip -p "$zip" "$blk4_zipped" > "$blk4_csv"
        have_v4=1
    fi
    if [ "$want_v6" -eq 1 ]; then
        blk6_csv="${tmp}/blocks6.csv"
        "$BUSYBOX_BIN" unzip -p "$zip" "$blk6_zipped" > "$blk6_csv"
        have_v6=1
    fi

    # Build only the requested family
    if [ "$have_v4" -eq 1 ]; then
        _gen_geolite2_cc_data "$tmp" "$loc_csv" "$blk4_csv" "$out" "$cc_list" 0 v4
        _gen_geolite2_cc_data "$tmp" "$loc_csv" "$blk4_csv" "$out" "$cc_ext_list" 1 v4
    fi
    if [ "$have_v6" -eq 1 ]; then
        _gen_geolite2_cc_data "$tmp" "$loc_csv" "$blk6_csv" "$out" "$cc_list" 0 v6
        _gen_geolite2_cc_data "$tmp" "$loc_csv" "$blk6_csv" "$out" "$cc_ext_list" 1 v6
    fi

    rm -rf "$tmp"

    if [ "$have_v4" -eq 1 ] && [ "$have_v6" -eq 1 ]; then
        log "Successfully generated IPv4 and IPv6 zone files for GeoLite2"
    elif [ "$have_v4" -eq 1 ]; then
        log "Successfully generated IPv4 zone files for GeoLite2"
    elif [ "$have_v6" -eq 1 ]; then
        log "Successfully generated IPv6 zone files for GeoLite2"
    else
        log -l err "No zone files were generated (check ZIP)"
        return 1
    fi

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

clean_ip_line() {
    local use_v6=0
    [ "$1" = "-6" ] && { use_v6=1; shift; }

    # 1. Strip comments starting at first # or ;
    local l=${1%%[\#;]*}

    # 2. Drop any CR
    l=${l//$'\r'/}

    # 3. Trim leading/trailing whitespace
    l=${l#"${l%%[![:space:]]*}"}   # left trim
    l=${l%"${l##*[![:space:]]}"}   # right trim

    # 4. Empty? -> reject
    [ -n "$l" ] || return 1

    # 5. Choose regex & flags; very permissive by design
    # IPv4: dotted-quad with optional /NN
    # IPv6: requires >= 2 colons; allows hex, colons, dots (IPv4-mapped), optional /NNN
    local regex g_flags
    if [ "$use_v6" -eq 1 ]; then
        regex='^[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*(/[0-9]{1,3})?$'
        g_flags='-Eiq'   # extended, case-insensitive, quiet
    else
        regex='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$'
        g_flags='-Eq'    # extended, quiet
    fi

    # 6. Validate shape
    printf '%s\n' "$l" | grep $g_flags -- "$regex" >/dev/null || return 1

    # 7. Emit cleaned value
    printf '%s\n' "$l"
    return 0
}

print_cidrs_from_file() {
    local v6_flag=""
    [ "$1" = "-6" ] && { v6_flag="-6"; shift; }

    local file="$1"

    # Expand clean_flag only if set; avoids per-iteration branching
    while IFS= read -r line; do
        clean_ip_line $v6_flag "$line" || continue
    done < "$file"
}

print_cidrs_from_url() {
    local use_v6=0 v6_flag=""
    [ "$1" = "-6" ] && { use_v6=1; v6_flag="-6"; shift; }

    local no_clean=0 blob file url args_lines kept_nl="" old_IFS
    file=$(tmp_file)

    # First positional is the "blob" (curl-like arg string)
    local have_blob=0
    if [ $# -gt 0 ]; then
        blob="$1"
        shift
        have_blob=1
    fi
    if [ "$have_blob" -ne 1 ]; then
        log -l warn "Empty URL blob - skipped"
        rm -f "$file"
        return 1
    fi

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
    set -f
    set -- $args_lines
    set +f
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

    # Output raw or normalized CIDR list
    if [ "$no_clean" -eq 1 ]; then
        cat "$file"
    else
        print_cidrs_from_file $v6_flag "$file"
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
    local fam="inet"
    [ "$1" = "-6" ] && { fam="inet6"; shift; }

    local set_name="$1" cnt="${2:-0}" size
    size="$(_calc_ipset_size "$cnt")"

    printf 'create %s hash:net family %s hashsize %s maxelem %s\n' \
        "$set_name" "$fam" "$size" "$size"
}

print_add_entry() { printf 'add %s %s\n' "$1" "$2"; }

print_swap_and_destroy() {
    printf 'swap %s %s\n' "$1" "$2"
    printf 'destroy %s\n' "$1"
}

save_dump() { ipset save "$1" > "$2"; }

restore_dump() {
    local set_name="$1" dump="$2" cnt rc=0

    # If forcing update or dump missing, signal caller to rebuild
    if [ "$update" -eq 1 ] || [ "$update_custom" -eq 1 ] || [ ! -f "$dump" ]; then
        return 1
    fi

    if ipset_exists "$set_name"; then
        # Existing set: restore into a temp clone, then swap
        local tmp_set="${set_name}_tmp" restore_script
        restore_script=$(tmp_file)
        ipset destroy "$tmp_set" 2>/dev/null || true

        {
            sed -e "s/^create $set_name /create $tmp_set /" \
                -e "s/^add $set_name /add $tmp_set /" "$dump"
            print_swap_and_destroy "$tmp_set" "$set_name"
        } > "$restore_script"

        ipset restore -! < "$restore_script" || rc=$?
        rm -f "$restore_script"
    else
        # Set doesn't exist yet - restore directly
        ipset restore -! < "$dump" || rc=$?
    fi

    # Check restore code for any failures
    if [ "$rc" -ne 0 ]; then
        log -l warn "Restore failed for ipset '$set_name'; will rebuild"
        return 1
    fi

    cnt=$(get_ipset_count "$set_name")

    log "Restored ipset '$set_name' from dump ($cnt entries)"

    return 0
}

save_hashes() {
    local wan_fw_rules wan_fw_v6_rules
    local tun_dir_rules

    wan_fw_rules=$(tmp_file)
    wan_fw_v6_rules=$(tmp_file)
    tun_dir_rules=$(tmp_file)

    strip_comments "$WAN_FW_RULES"    | sed -E 's/[[:blank:]]+//g' > "$wan_fw_rules"
    strip_comments "$WAN_FW_V6_RULES" | sed -E 's/[[:blank:]]+//g' > "$wan_fw_v6_rules"
    strip_comments "$TUN_DIR_RULES"   | sed -E 's/[[:blank:]]+//g' > "$tun_dir_rules"

    printf '%s\n' "$(compute_hash "$wan_fw_rules")"    > "$WAN_FW_IPSETS_HASH"
    printf '%s\n' "$(compute_hash "$wan_fw_v6_rules")" > "$WAN_FW_V6_IPSETS_HASH"
    printf '%s\n' "$(compute_hash "$tun_dir_rules")"   > "$TUN_DIR_IPSETS_HASH"
}

aggregate() {
    local set_name="$1" cidr_list="$2" no_agg="$3" cnt=0

    if [ "$external_storage" -eq 1 ] && [ "$agg_disabled" -eq 0 ] && [ "$no_agg" -eq 0 ]; then
        # Enable CIDR aggregation if mapCIDR is successfully installed
        if [ "$mapcidr_ready" -eq 0 ]; then
            printf '%s\n' "$cnt"
            return 1
        fi

        log "Aggregating CIDRs for ipset '$set_name'..."
        local cidr_list_agg tmp

        # Create a tmp file for aggregated CIDRs
        cidr_list_agg=$(tmp_file)

        # Create a custom tmp dir for mapCIDR (allows easy cleanup later)
        tmp="$(tmp_dir)"

        # -a: aggregate, -silent: quiet output
        if TMPDIR="$tmp" "$MAPCIDR_BIN" -a -silent < "$cidr_list" > "$cidr_list_agg"; then
            mv "$cidr_list_agg" "$cidr_list"
            cnt=$(wc -l < "$cidr_list")
            log "Number of CIDRs for ipset '$set_name' after aggregation: $cnt"
        else
            log -l warn "Failed to aggregate CIDRs for ipset '$set_name'"
            warnings=1
        fi

        # Delete custom tmp dir
        rm -rf "$tmp"
    fi

    printf '%s\n' "$cnt"
    return 0
}

build_ipset() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "$1" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local set_name="$1" src="$2" dump="$3"
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

    local target_set cidr_list restore_script
    local cnt=0 cnt_agg=0 rc=0

    log "Parsing CIDRs for ipset '$set_name' ($fam_label)..."

    # Decide whether we need a temporary set (for "hot" updates) or in-place create
    if ipset_exists "$set_name"; then
        target_set="${set_name}_tmp"
        ipset destroy "$target_set" 2>/dev/null || true
    else
        target_set="$set_name"
    fi

    # Build the list of CIDRs into a temp file
    cidr_list=$(tmp_file)
    {
        case "$src" in
            http://*|https://*)
                # Single URL source: download and print CIDRs (one per line)
                clean_opt=""
                [ "$no_clean" -eq 1 ] && clean_opt="--no-clean"
                print_cidrs_from_url $v6_flag "$src" --label "$label" $clean_opt
                ;;
            *)
                if [ "$no_clean" -eq 1 ]; then
                    # Pre-cleaned (e.g., zone file) - emit as-is
                    cat "$src"
                else
                    # Generic file: each line may be a CIDR or another URL to expand
                    while IFS= read -r line; do
                        case "$line" in
                            http://*|https://*)
                                print_cidrs_from_url $v6_flag "$line"
                                ;;
                            *)
                                # Normalize/validate and emit the CIDR if valid
                                clean_ip_line $v6_flag "$line" || continue
                                ;;
                        esac
                    done < "$src"
                fi
                ;;
        esac
    } > "$cidr_list"

    cnt=$(wc -l < "$cidr_list")
    log "Total number of CIDRs for ipset '$set_name' ($fam_label): $cnt"

    # Optional aggregation pass
    ensure_mapcidr_ready || true
    cnt_agg=$(aggregate "$set_name" "$cidr_list" "$no_agg") || true
    [ "$cnt_agg" -ne 0 ] && cnt="$cnt_agg"

    log "Converting CIDRs for ipset '$set_name' to ipset-restore format ($fam_label)..."

    # Generate an ipset-restore script for a single atomic apply
    restore_script=$(tmp_file)
    {
        # 1. Create target set
        print_create_ipset $v6_flag "$target_set" "$cnt"

        # 2. Add all CIDRs
        while IFS= read -r line; do
            print_add_entry "$target_set" "$line"
        done < "$cidr_list"

        # 3. If updating an existing set: swap temp -> live, then destroy temp
        if [ "$target_set" != "$set_name" ]; then
            print_swap_and_destroy "$target_set" "$set_name"
        fi
    } > "$restore_script"

    # Apply it all at once, ignoring duplicates
    log "Applying changes for ipset '$set_name' ($fam_label)..."
    ipset restore -! < "$restore_script" || rc=$?
    rm -f "$restore_script" "$cidr_list"

    # Check restore code for any failures
    if [ "$rc" -ne 0 ]; then
        on_failure "Failed to build ipset '$set_name' ($fam_label)" "$BUILD_FAILED_FLAG"
    fi

    # Save the new dump, count entries, and log final status
    cnt=$(get_ipset_count "$set_name")
    save_dump "$set_name" "$dump"

    if [ "$target_set" = "$set_name" ]; then
        log "Created new ipset '$set_name' ($fam_label, $cnt entries)"
    else
        log "Updated existing ipset '$set_name' ($fam_label, $cnt entries) via swap"
    fi

    if [ "$cnt" -eq 0 ]; then
        log -l warn "ipset '$set_name' ($fam_label) is empty;" \
            "file format may be wrong or you reached API limits"
        warnings=1
    fi
}

###################################################################################################
# 0e. Run initialization checks (flags, uptime, mounts, directories)
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Validate killswitch configuration
# -------------------------------------------------------------------------------------------------
validate_killswitch() {
    local use_v6=0 fam_label="IPv4"
    [ "$1" = "-6" ] && { use_v6=1; fam_label="IPv6"; shift; }

    local rules="$1" rules_var="$2"

    if [ "$killswitch" -eq 1 ] && [ -z "$rules" ]; then
        log -l warn "You requested ${fam_label} killswitch with the '-k' flag," \
            "but ${rules_var} rules are empty. Please configure them or remove the '-k' flag"
        warnings=1
    fi
}

# Validate killswitch for each protocol
validate_killswitch "$killswitch_rules" "KILLSWITCH_RULES"
[ "$IPV6_ENABLED" -eq 1 ] && validate_killswitch -6 "$killswitch_v6_rules" "KILLSWITCH_V6_RULES"

# -------------------------------------------------------------------------------------------------
# Apply killswitch if requested
# -------------------------------------------------------------------------------------------------
apply_killswitch() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "$1" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local ports protos proto port_spec rule_count=0
    local chain="$1" rules="$2"

    # Create/flush chain
    create_fw_chain $v6_flag -f raw "$chain"

    # Populate DROP rules
    while IFS=: read -r ports protos; do
        case "$ports" in
            any)
                log -l warn "'any' is not supported for killswitch ports ($fam_label)." \
                    "Explicitly specify ports to block"
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
            ensure_fw_rule $v6_flag -q raw "$chain" -p "$proto" $port_spec -j DROP
            log "Added DROP rule ($fam_label) -> $chain: proto=$proto ports=$ports"
            rule_count=$((rule_count + 1))
        done
    done <<EOF
$rules
EOF

    # Jump from PREROUTING once (idempotent)
    ensure_fw_rule $v6_flag -q raw PREROUTING -I 1 -i "$WAN_IF" -j "$chain"
    log "Inserted jump ($fam_label): raw PREROUTING iface=$WAN_IF -> $chain"

    # Summary
    if [ "$rule_count" -ne 0 ]; then
        local uniq_ports
        uniq_ports=$(
            printf '%s\n' "$rules" |
            awk -F: '$1 != "any" && !seen[$1]++ { if (n++) printf ","; printf "%s", $1 }'
        )
        log "Killswitch ($fam_label) is ON: blocking $WAN_IF on ports $uniq_ports"
    else
        log -l warn "Killswitch ($fam_label) is OFF due to errors; please review your rules"
    fi
}

# Apply killswitch for each protocol
is_killswitch_enabled && apply_killswitch "$KILLSWITCH_CHAIN" "$killswitch_rules"
[ "$IPV6_ENABLED" -eq 1 ] && is_killswitch_enabled -6 && \
    apply_killswitch -6 "$KILLSWITCH_CHAIN" "$killswitch_v6_rules"

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
#   * IPv4 (default): accepts "cc", ignores "cc6"
#   * IPv6 (-6): accepts "cc6" (strips the '6'), ignores bare "cc"
#   * Strips comments/blank lines via strip_comments.
#   * Tokenizes on ":" and "," but ignores ":" inside square brackets (IPv6 literals stay intact).
#   * Scans fields start_field..end_field (defaults: 4..NF).
#   * Normalizes tokens (trim whitespace), accepts only /^[a-z]{2}6?$/
#     (i.e., 'cc' for IPv4, 'cc6' for IPv6),
#     and validates against ALL_COUNTRY_CODES.
#   * Collects unique matches and emits sorted country codes (one per line).
parse_country_codes() {
    local use_v6=0
    [ "${1-}" = "-6" ] && { use_v6=1; shift; }

    local rules="$1" start_field="${2:-4}" end_field="${3:-0}"

    strip_comments "$rules" |
    awk -v valid="$ALL_COUNTRY_CODES" -v SF="$start_field" -v EF="$end_field" -v v6="$use_v6" '
        function add_code(tok, base, suf) {
            gsub(/[[:space:]]+/, "", tok)

            # Accept cc or cc6 only
            if (tok ~ /^[a-z]{2}6?$/) {
                base = substr(tok, 1, 2)
                suf  = (length(tok) == 3 ? substr(tok, 3, 1) : "")

                # Family gate:
                #  - v6 == 1  -> require suffix "6"
                #  - v6 == 0  -> require no suffix
                if ((v6 && suf != "6") || (!v6 && suf == "6")) return
                if (V[base]) seen[base] = 1
            }
        }
        BEGIN {
            # Build validation set from ALL_COUNTRY_CODES
            n = split(valid, arr, /[[:space:]\r\n]+/)
            for (i = 1; i <= n; i++) if (arr[i] != "") V[arr[i]] = 1
        }
        {
            # Split on ":" or "," outside [...]
            depth = 0; tok = ""; nf2 = 0
            for (i = 1; i <= length($0); i++) {
                c = substr($0, i, 1)
                if (c == "[") depth++
                else if (c == "]" && depth > 0) depth--
                if ((c == ":" || c== ",") && depth == 0) {
                    f[++nf2] = tok; tok = ""
                }
                else tok = tok c
            }
            f[++nf2] = tok

            s = (SF > 0 ? SF : 1); e = (EF > 0 ? EF : nf2)
            for (i = s; i <=e; i++) add_code(tolower(f[i]))

            for (i = 1; i <= nf2; i++) delete f[i]
        }
        END { for (c in seen) print c }
    ' | sort
}

build_country_ipsets() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "$1" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local wan_rules="$1" tun_rules="${2-}"

    # Parse country codes
    local wan_cc tun_cc=""
    wan_cc="$(parse_country_codes $v6_flag "$wan_rules" 4)"
    [ -n "$tun_rules" ] && tun_cc="$(parse_country_codes $v6_flag "$tun_rules" 4)"

    # Nothing to do?
    if [ -z "$wan_cc$tun_cc" ]; then
        log "Step 1 ($fam_label): no country references; skipping build"
        return 0
    fi
    if [ "$update_custom" -eq 1 ]; then
        log "Step 1 ($fam_label): custom-only update; skipping country ipsets"
        return 0
    fi

    # Provider & dump suffix
    local provider dump_suffix
    if use_geolite2; then
        provider="GeoLite2"; dump_suffix="-geolite2.dump"
    else
        provider="IPdeny"; dump_suffix="-ipdeny.dump"
    fi

    log "Step 1 ($fam_label): building country ipsets using $provider..."

    # Standard vs extended lists
    local std_cc missing_std="" missing_ext="" set_suffix=""
    [ "$use_v6" -eq 1 ] && set_suffix="6"

    if [ "$provider" = "IPdeny" ] && [ -n "$tun_cc" ]; then
        std_cc="$(printf '%s\n%s\n' "$wan_cc" "$tun_cc" | sort -u)"
    else
        std_cc="$wan_cc"
    fi

    # Try restoring dumps first (unless forced update)
    if [ "$update" -eq 1 ]; then
        missing_std="$(printf '%s\n' "$std_cc" | xargs)"
        [ "$provider" = "GeoLite2" ] && missing_ext="$(printf '%s\n' "$tun_cc" | xargs)"
    else
        log "Attempting to restore $provider dumps for standard country sets (if any)..."
        local cc dump set_std
        for cc in $std_cc; do
            set_std="${cc}${set_suffix}"
            dump="${COUNTRY_DUMP_DIR}/${set_std}${dump_suffix}"
            restore_dump "$set_std" "$dump" || missing_std="$missing_std $cc"
        done
        missing_std="$(printf '%s\n' "$missing_std" | xargs)"

        if [ "$provider" = "GeoLite2" ] && [ -n "$tun_cc" ]; then
            log "Attempting to restore GeoLite2 dumps for extended country sets (if any)..."
            local set_ext
            for cc in $tun_cc; do
                set_ext="${cc}${set_suffix}_ext"
                dump="${COUNTRY_DUMP_DIR}/${set_ext}${dump_suffix}"
                restore_dump "$set_ext" "$dump" || missing_ext="$missing_ext $cc"
            done
            missing_ext="$(printf '%s\n' "$missing_ext" | xargs)"
        fi
    fi

    # All good?
    if [ -z "$missing_std$missing_ext" ]; then
        log "All ${provider} dumps restored; nothing to rebuild"
        return 0
    fi

    # Build phase
    case "$provider" in
        GeoLite2)
            # Status line with real set names
            local msg="" cc sn=""
            if [ -n "$missing_std" ]; then
                sn=""
                for cc in $missing_std; do
                    sn="${sn}${sn:+ }${cc}${set_suffix}"
                done
                msg="'$sn'"
            fi
            if [ -n "$missing_ext" ]; then
                local ext_fmt="" x
                for x in $missing_ext; do
                    ext_fmt="${ext_fmt}${ext_fmt:+ }${x}${set_suffix}_ext"
                done
                msg="${msg:+$msg and }'$ext_fmt'"
            fi
            log "Building GeoLite2 ipsets for $msg"

            local std_csv="${missing_std// /,}"
            local ext_csv="${missing_ext// /,}"

            local fam_for_gen="v4"
            [ "$use_v6" -eq 1 ] && fam_for_gen="v6"

            ensure_busybox_ready || \
                on_failure "Failed to initialize BusyBox for GeoLite2 extraction" \
                "$BUILD_FAILED_FLAG"

            if countries_dir="$(generate_geolite2_country_files "$std_csv" "$ext_csv" "$fam_for_gen")"; then
                # Standard sets
                for cc in $missing_std; do
                    set_std="${cc}${set_suffix}"

                    build_ipset $v6_flag "$set_std" "${countries_dir}/${cc}${set_suffix}.zone" \
                        "${COUNTRY_DUMP_DIR}/${set_std}${dump_suffix}" --no-clean
                done
                # Extended sets
                for cc in $missing_ext; do
                    set_ext="${cc}${set_suffix}_ext"

                    build_ipset $v6_flag "$set_ext" "${countries_dir}/${cc}${set_suffix}_ext.zone" \
                        "${COUNTRY_DUMP_DIR}/${set_ext}${dump_suffix}" --no-clean
                done
                rm -rf "$countries_dir"
            else
                on_failure "Failed to build zone files for GeoLite2" "$BUILD_FAILED_FLAG"
            fi
            ;;
        IPdeny)
            # Only standard lists exist with IPdeny
            local sn_list="" cc
            for cc in $missing_std; do
                sn_list="${sn_list}${sn_list:+ }${cc}${set_suffix}"
            done
            log "Building IPdeny ipsets for '${sn_list}'"

            local url_base
            url_base=$([ "$use_v6" -eq 1 ] && printf '%s' "$IPDENY_COUNTRY_V6_BASE_URL" \
                || printf '%s' "$IPDENY_COUNTRY_BASE_URL")

            for cc in $missing_std; do
                set_std="${cc}${set_suffix}"
                url="${url_base%/}/${cc}${IPDENY_COUNTRY_FILE_SUFFIX}"
                dump="${COUNTRY_DUMP_DIR}/${set_std}${dump_suffix}"

                build_ipset $v6_flag "$set_std" "$url" "$dump" \
                    --label "${cc}${IPDENY_COUNTRY_FILE_SUFFIX}" --no-agg --no-clean
            done
            ;;
    esac
}

# Build ipsets for each protocol
build_country_ipsets "$WAN_FW_RULES" "$TUN_DIR_RULES"
[ "$IPV6_ENABLED" -eq 1 ] && build_country_ipsets -6 "$WAN_FW_V6_RULES"

###################################################################################################
# 2. Build custom ipsets
###################################################################################################

# Handle blocks inside CUSTOM_IPSETS
process_custom_block() {
    local use_v6=0 v6_flag=""
    [ "${1-}" = "-6" ] && { use_v6=1; v6_flag="-6"; shift; }

    local set_name="$1" block_file="$2"
    local sha_file="$CUSTOM_DUMP_DIR/$set_name.sha256"
    local dump_file="$CUSTOM_DUMP_DIR/$set_name.dump"

    local new_hash old_hash
    new_hash=$(compute_hash "$block_file")
    old_hash=$(cat "$sha_file" 2>/dev/null || printf '')

    if [ "$new_hash" = "$old_hash" ] && restore_dump "$set_name" "$dump_file"; then
        return 0  # dump is restored
    fi

    # Rebuild with the correct family
    build_ipset $v6_flag "$set_name" "$block_file" "$dump_file"

    # Record the new hash for next time
    printf '%s\n' "$new_hash" > "$sha_file"
}

# Collect normalized set names (as created by derive_set_name) from a custom rules blob
_collect_custom_set_names() {
    local rules="$1" line short_label set_name

    while IFS= read -r line; do
        case "$line" in
            [A-Za-z0-9_]*:)
                short_label=${line%:}
                set_name="$(derive_set_name "$short_label")"
                printf '%s\n' "$set_name"
                ;;
        esac
    done <<EOF
$rules
EOF
}

# Reserved country-set name guard (reject names like us, us_ext, us6, us6_ext)
_is_reserved_country_set_label() {
    # Input: short label (not derived), lower-cased
    # Accept as reserved when it matches:
    #   cc | cc_ext | cc6 | cc6_ext, where cc in ALL_COUNTRY_CODES
    local lbl_lc="$1" base

    case "$lbl_lc" in
        [a-z][a-z]|[a-z][a-z]_ext|[a-z][a-z]6|[a-z][a-z]6_ext)
            base="${lbl_lc%_ext}"
            base="${base%6}"
            if printf '%s' "$ALL_COUNTRY_CODES" |
                grep -Eq "(^|[[:space:]])${base}([[:space:]]|$)";
            then
                return 0
            fi
            ;;
    esac

    return 1
}

# Process custom ipsets for each protocol
process_custom_ipsets() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local rules="$1"
    local skip_names="${2-}"
    [ -n "$rules" ] || return 0

    log "Step 2 ($fam_label): building custom ipsets..."

    local cur_set="" tmp_lines="" line short_label
    while IFS= read -r line; do
        case "$line" in
            [A-Za-z0-9_]*:)
                short_label=${line%:}

                # Finish previous block
                if [ -n "$cur_set" ]; then
                    process_custom_block $v6_flag "$cur_set" "$tmp_lines"
                fi

                # Reject reserved names like cc, cc_ext, cc6, cc6_ext
                if _is_reserved_country_set_label \
                    "$(printf '%s' "$short_label" | tr 'A-Z' 'a-z')";
                then
                    log -l warn "Custom ipset name '$short_label' conflicts" \
                        "with reserved country sets; skipping block"
                    cur_set=""; tmp_lines=""; warnings=1
                    continue
                fi

                cur_set="$(derive_set_name "$short_label")"

                # Avoid name overlap between CUSTOM_IPSETS and CUSTOM_V6_IPSETS
                if [ -n "$skip_names" ] && printf '%s\n' "$skip_names" |
                    grep -Fxq -- "$cur_set";
                then
                    log -l warn "Custom $fam_label ipset '$short_label' resolves to '$cur_set'," \
                        "which conflicts with the other family; skipping block"
                    cur_set=""; tmp_lines=""; warnings=1
                    continue
                fi

                tmp_lines=$(tmp_file)
                ;;
            *)
                [ -n "$cur_set" ] && printf '%s\n' "$line" >> "$tmp_lines"
                ;;
        esac
    done <<EOF
$rules
EOF

    [ -n "$cur_set" ] && process_custom_block $v6_flag "$cur_set" "$tmp_lines"
}

# Build custom ipsets
build_custom_ipsets() {
    local custom_ipsets custom_v6_ipsets
    local have_v4=0 have_v6=0
    local v4_sets v6_sets overlap=""

    custom_ipsets="$(strip_comments "$CUSTOM_IPSETS")"
    custom_v6_ipsets="$(strip_comments "$CUSTOM_V6_IPSETS")"

    [ -n "$custom_ipsets" ] && have_v4=1
    if [ "$IPV6_ENABLED" -eq 1 ] && [ -n "$custom_v6_ipsets" ]; then
        have_v6=1
    fi

    if [ "$have_v4" -eq 0 ] && [ "$have_v6" -eq 0 ]; then
        if [ -z "$custom_v6_ipsets" ] || [ "$IPV6_ENABLED" -eq 1 ]; then
            log "Step 2: no custom ipsets defined; skipping build"
        fi
        return 0
    fi

    if [ "$have_v4" -eq 1 ] && [ "$have_v6" -eq 1 ]; then
        # Gather normalized set names only when both families are in play
        v4_sets="$(_collect_custom_set_names "$custom_ipsets" | sort -u)"
        v6_sets="$(_collect_custom_set_names "$custom_v6_ipsets" | sort -u)"
        overlap="$(printf '%s\n%s\n' "$v4_sets" "$v6_sets" | sort | uniq -d)"

        if [ -n "$overlap" ]; then
            # Just validate & warn; IPv6 side will skip the overlapping names
            log -l warn "Custom IPv4 and IPv6 ipsets share set name(s):" \
                "$(printf '%s' "$overlap" | tr '\n' ' ')" \
                "- IPv6 blocks with these names will be skipped"
            warnings=1
        fi
    fi

    # Build IPv4, then IPv6 (skip overlapping names on the IPv6 pass)
    [ "$have_v4" -eq 1 ] && process_custom_ipsets "$custom_ipsets"
    [ "$have_v6" -eq 1 ] && process_custom_ipsets -6 "$custom_v6_ipsets" "$overlap"

    return 0
}

build_custom_ipsets

###################################################################################################
# 3. Build combined ipsets
###################################################################################################

# Parse combo ipsets from rules (IPv4/IPv6 aware, bracket-safe):
# - Usage: parse_combo_from_rules [-6] "<rules_text>" [ext_flag]
#   * -6        : treat as IPv6; map "cc6" -> "cc6" or "cc6_ext"
#   * rules_text: the rules variable content
#   * ext_flag  : 0 = standard sets, 1 = prefer extended (honored only if GeoLite2 is available)
# - Behavior:
#   * Strips comments/blanks via strip_comments.
#   * Splits the line into fields on ':' but ignores ':' inside [...] (IPv6 literals).
#   * Considers only fields 4 and 5 (KEYS and EXCLUDES).
#   * Emits only fields that contain a comma (true combos like "blk,cn,ir").
#   * Strips internal whitespace; outputs comma-joined tokens.
#   * Bare two-letter country codes become:
#       - IPv4: "cc" or "cc_ext"
#       - IPv6: "cc6" or "cc6_ext"
#   * Output is sorted & deduped.
parse_combo_from_rules() {
    local use_v6=0
    [ "${1-}" = "-6" ] && { use_v6=1; shift; }

    local rules_text="$1" ext_flag="${2:-0}"

    # Use standard sets if GeoLite2 is not available
    [ "$ext_flag" -eq 1 ] && ! use_geolite2 && ext_flag=0

    strip_comments "$rules_text" |
    awk -v ext="$ext_flag" -v v6="$use_v6" '
        # Split on ":" but ignore ":" inside square brackets (for IPv6 literals)
        function split_br_aware(s, a, i, c, br, f, n) {
            br = 0; n = 0; f = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "[")      { br++; f = f c }
                else if (c == "]") { if (br > 0) br--; f = f c }
                else if (c == ":" && br == 0) { a[++n] = f; f = "" }
                else { f = f c }
            }
            a[++n] = f
            return n
        }

        function emit_combo(field, f, n, a, i, t, out) {
            f = field
            gsub(/[[:space:]]/, "", f)
            if (f ~ /,/) {
                n = split(f, a, ",")
                out = ""
                for (i = 1; i <= n; i++) {
                    t = a[i]

                    # Map country codes
                    if (t ~ /^[a-z]{2}$/) {
                        if (v6) t = t (ext ? "6_ext" : "6");
                        else    if (ext) t = t "_ext";
                    } else if (v6 && ext && t ~ /^[a-z]{2}6$/) {
                        # User already wrote cc6;
                        # upgrade to cc6_ext if ext_flag=1
                        t = t "_ext";
                    }
                    out = out (out ? "," : "") t
                }
                print out
            }
        }

        {
            n = split_br_aware($0, F)
            if (n >= 4) emit_combo(F[4])
            if (n >= 5) emit_combo(F[5])
        }
    ' | sort -u
}

# Helper: returns 0 when every expected combo ipset exists
_all_combo_present_for() {
    # $1 = newline-separated combos (tokens comma-separated)
    local list="$1" line set_name

    for line in $list; do
        set_name="$(derive_set_name "${line//,/_}")"
        ipset_exists "$set_name" || return 1
    done

    return 0
}

# Build all combo ipsets for one family per run
build_combo_ipsets() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    local wan_rules="$1" tun_rules="${2-}"

    # Parse combos: WAN uses standard sets; TUN prefers extended (when available)
    local wan_combo tun_combo="" combo_ipsets

    wan_combo="$(parse_combo_from_rules $v6_flag "$wan_rules" 0)"
    [ -n "$tun_rules" ] && tun_combo="$(parse_combo_from_rules $v6_flag "$tun_rules" 1)"

    # Union, drop empties, unique
    combo_ipsets="$(
        printf '%s\n' "${wan_combo:-}" "${tun_combo:-}" |
        awk 'NF' | sort -u
    )"

    if [ -z "$combo_ipsets" ]; then
        log "Step 3 ($fam_label): no combo ipsets are required; skipping build"
        return 0
    fi

    if _all_combo_present_for "$combo_ipsets"; then
        log "Step 3 ($fam_label): all combo ipsets are already present; skipping build"
        return 0
    fi

    log "Step 3 ($fam_label): building combo ipsets..."
    local line set_name key member added

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        set_name="$(derive_set_name "${line//,/_}")"

        # Skip if combo already exists
        if ipset_exists "$set_name"; then
            log "Combo ipset '$set_name' already exists; skipping"
            continue
        fi

        ipset create "$set_name" list:set

        # Add members; track if at least one was added (no-empty-set guarantee)
        added=0
        for key in ${line//,/ }; do
            member="$(derive_set_name "${key}")"

            if ! ipset_exists "$member"; then
                log -l warn "Combo ipset '$set_name': member ipset '$member' not found; skipping." \
                    "Ensure this member exists (country/custom) and previous steps succeeded"
                warnings=1
                continue
            fi

            if ipset add "$set_name" "$member" 2>/dev/null; then
                added=$((added + 1))
            fi
        done

        if [ "$added" -eq 0 ]; then
            # Enforce: no empty ipsets
            ipset destroy "$set_name" 2>/dev/null || true
            log -l warn "Combo ipset '$set_name' had no valid members and was not created; skipping"
            warnings=1
            continue
        fi

        log "Created combo ipset '$set_name'"
    done <<EOF
$combo_ipsets
EOF
}

# Build ipsets for each protocol
build_combo_ipsets "$WAN_FW_RULES" "$TUN_DIR_RULES"
[ "$IPV6_ENABLED" -eq 1 ] && build_combo_ipsets -6 "$WAN_FW_V6_RULES"

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
[ "$start_wan_fw" -eq 1 ] && "$DIR/wan_firewall.sh"

# Start Tunnel Director if requested
[ "$start_tun_dir" -eq 1 ] && "$DIR/tunnel_director.sh"

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
disable_killswitch() {
    local use_v6=0 v6_flag="" fam_label="IPv4"
    [ "${1-}" = "-6" ] && { use_v6=1; v6_flag="-6"; fam_label="IPv6"; shift; }

    # Only act if killswitch for this family is currently enabled
    is_killswitch_enabled $v6_flag || return 0

    # Remove all matching jump rules (even duplicates)
    set -- "raw PREROUTING" "-i $WAN_IF -j $KILLSWITCH_CHAIN$"
    [ "$use_v6" -eq 1 ] && set -- -6 "$@"
    set -- -q "$@"
    purge_fw_rules "$@"

    # Delete the killswitch chain itself
    set -- raw "$KILLSWITCH_CHAIN"
    [ "$use_v6" -eq 1 ] && set -- -6 "$@"
    set -- -q "$@"
    delete_fw_chain "$@"

    log "$fam_label killswitch is OFF: all $WAN_IF ingress is allowed"
}

# Disable killswitch for each protocol
disable_killswitch
[ "$IPV6_ENABLED" -eq 1 ] && disable_killswitch -6

exit 0
