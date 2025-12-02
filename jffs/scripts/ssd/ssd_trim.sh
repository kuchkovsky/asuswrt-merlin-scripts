#!/usr/bin/env ash

###################################################################################################
# ssd_trim.sh - safely enable TRIM on USB SSDs connected to ASUS routers
# -------------------------------------------------------------------------------------------------
# Why this script is needed:
#   By default, ASUS firmware does not provide any automated or reliable method to issue
#   TRIM (discard) to USB-attached SSDs. This is true even though the kernel and
#   filesystems themselves support TRIM.
#
#   In practice, this default behavior means:
#     * The firmware never runs fstrim automatically.
#     * Many USB-SATA/NVMe adapters expose SSDs with provisioning_mode="full"/"partial",
#       which blocks UNMAP, so even manually running fstrim often provides no trim at all.
#     * Some USB bridges fail on large discard operations and return misleading errors
#       such as "Remote I/O error".
#
#   Without TRIM, an SSD cannot reclaim freed space internally. Over time this leads to:
#     * degraded write performance,
#     * increased write amplification,
#     * unnecessary wear on the drive.
#
# What this script does:
#   This script turns TRIM into a fully automated, reliable process on ASUS routers. It:
#     1) Detects all USB-backed mounts under /tmp/mnt (or a specific label when provided).
#     2) Validates each device is eligible:
#           - not excluded via EXCLUDED_SSD_LABELS,
#           - formatted as ext2/ext3/ext4,
#           - not explicitly disabled via nvram.
#     3) Fixes USB bridge behavior by forcing provisioning_mode="unmap" so the kernel
#        is allowed to send TRIM/UNMAP commands through the USB stack.
#     4) Runs fstrim and automatically adapts to problematic USB bridges:
#          * If fstrim works normally -> nothing is cached; defaults are fine.
#          * If fstrim reports "Operation not supported":
#                -> The device is marked as unsupported.
#                   nvram: discard_max_bytes = 0   (permanently skipped in future runs)
#          * If fstrim reports "Remote I/O error":
#                -> The script retries using write_same_max_bytes (a safe hardware-provided limit).
#                -> If the retry works: this value is cached in nvram and used next time.
#                -> If it still fails: the disk is marked unsupported (discard_max_bytes = 0).
#
#   Every disk that requires a custom discard_max_bytes value is tracked via a stable
#   nvram key derived from its USB identity:
#       ${SSD_NV_PREFIX}<disk-id>_discard_max_bytes
#
#   This ensures predictable behavior on every boot and avoids repeated redetection.
#
# Usage:
#   ssd_trim.sh           -> scans all USB mounts under /tmp/mnt and trims any suitable SSDs
#   ssd_trim.sh <LABEL>   -> trims only the specified mount /tmp/mnt/<LABEL> (if eligible)
#
# Requirements / Notes:
#   * The USB storage device must use ext2, ext3, or ext4 - other filesystems either do not
#     support TRIM or the router firmware does not expose discard functionality for them.
#   * The script should be invoked periodically (cron) to maintain SSD performance.
#   * nvram entries created by this script are persistent across reboots.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2227

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Load utils and configuration
###################################################################################################
. /jffs/scripts/utils/common.sh

DIR="$(get_script_dir)"
. "$DIR/config.sh"

acquire_lock  # avoid concurrent runs

###################################################################################################
# 0b. Define constants and variables
###################################################################################################
# Optional label filter: if set, only /tmp/mnt/<LABEL> will be considered.
LABEL_FILTER="${1:-}"

# Prefix for per-disk nvram keys; may be overridden in config.sh
SSD_NV_PREFIX="${SSD_NV_PREFIX:-ssd_trim_}"

# Track whether we changed any nvram values this run
nvram_dirty=0

###################################################################################################
# 0c. Define helper functions
###################################################################################################

# -------------------------------------------------------------------------------------------------
# is_label_excluded - check if label is excluded
# -------------------------------------------------------------------------------------------------
is_label_excluded() {
    # $1 = label string
    local lbl="$1"
    local excluded="${EXCLUDED_SSD_LABELS:-}"

    [ -z "$excluded" ] && return 1

    printf '%s\n' "$excluded" | grep -qx "$lbl"
}

# -------------------------------------------------------------------------------------------------
# get_disk_id_key - derive a stable disk key for nvram
# -------------------------------------------------------------------------------------------------
# Tries, in order:
#   1) USB idVendor + idProduct + serial from USB parent
#   2) SCSI-level serial from /sys/block/$disk/device/serial
#   3) vendor + model from /sys/block/$disk/device/{vendor,model}
#
# Returns a short, sanitized id string suitable for nvram keys, e.g.:
#   04e8_4001_1234567890AB
#   Samsung_SSD_T7
# -------------------------------------------------------------------------------------------------
get_disk_id_key() {
    # $1 = disk name, e.g. "sdb"
    local disk="$1"
    local dev_path="/sys/block/$disk/device"
    local usb_path idv idp ser scsi_ser vendor model raw key

    usb_path=$(readlink -f "$dev_path" 2>/dev/null || printf '')

    # 1) Walk up to the USB parent with idVendor/idProduct/serial
    while [ -n "$usb_path" ] && [ "$usb_path" != "/" ] && [ ! -f "$usb_path/idVendor" ]; do
        usb_path=${usb_path%/*}
    done

    if [ -f "$usb_path/idVendor" ]; then
        idv=$(cat "$usb_path/idVendor" 2>/dev/null || printf '')
        idp=$(cat "$usb_path/idProduct" 2>/dev/null || printf '')
        ser=$(cat "$usb_path/serial" 2>/dev/null || printf '')

        if [ -n "$idv" ] && [ -n "$idp" ]; then
            raw="${idv}_${idp}"
            [ -n "$ser" ] && raw="${raw}_${ser}"
        fi
    fi

    # 2) If still empty, try SCSI serial
    if [ -z "$raw" ] && [ -f "$dev_path/serial" ]; then
        scsi_ser=$(cat "$dev_path/serial" 2>/dev/null || printf '')
        [ -n "$scsi_ser" ] && raw="$scsi_ser"
    fi

    # 3) If still empty, fallback to vendor+model
    if [ -z "$raw" ]; then
        vendor=$(cat "$dev_path/vendor" 2>/dev/null || printf '')
        model=$(cat "$dev_path/model"  2>/dev/null || printf '')
        if [ -n "$vendor$model" ]; then
            raw="${vendor}_${model}"
        fi
    fi

    # Last resort: use disk name itself
    [ -z "$raw" ] && raw="$disk"

    # Sanitize to [A-Za-z0-9_] and trim
    key=$(printf '%s' "$raw" | tr -c 'A-Za-z0-9_' '_' | cut -c1-40)

    printf '%s\n' "$key"
}

# -------------------------------------------------------------------------------------------------
# filesystem_supports_trim - check if filesystem is eligible for TRIM
# -------------------------------------------------------------------------------------------------
# Checks only:
#   * filesystem type (must be ext2/ext3/ext4)
#
# Returns 0 if filesystem is supported, 1 otherwise.
# -------------------------------------------------------------------------------------------------
filesystem_supports_trim() {
    local part="$1"
    local fstype="$2"
    local context="$3"

    case "$fstype" in
        ext2|ext3|ext4)
            return 0
            ;;
        *)
            log "Skipping partition=${part} (unsupported filesystem=${fstype};" \
                "only ext2, ext3, ext4 are supported) for ${context}"
            return 1
            ;;
    esac
}

# -------------------------------------------------------------------------------------------------
# ensure_unmap_for_disk - ensure provisioning_mode="unmap" for a given disk
# -------------------------------------------------------------------------------------------------
# For each:
#   /sys/block/$disk/device/scsi_disk/*/provisioning_mode
# switches "full"/"partial"/"disabled" to "unmap".
#
# Arguments:
#   $1 - disk name (e.g. "sda")
#
# Logs only when a change is made.
# Returns:
#   0 - success (at least one provisioning_mode exists and all ended as "unmap")
#   1 - failure (no provisioning_mode files found, or a write failed)
# -------------------------------------------------------------------------------------------------
ensure_unmap_for_disk() {
    local disk="$1"
    local pm cur found errors

    found=0
    errors=0

    for pm in /sys/block/"$disk"/device/scsi_disk/*/provisioning_mode; do
        [ -f "$pm" ] || continue
        found=1

        cur=$(cat "$pm" 2>/dev/null || printf '')

        if [ "$cur" != "unmap" ]; then
            if echo unmap > "$pm" 2>/dev/null; then
                log "Set 'unmap' (was '${cur:-unknown}') -> $pm"
            else
                log -l err "Could not write 'unmap' -> $pm"
                errors=1
            fi
        fi
    done

    # If nothing found or any error, treat as failure
    [ "$found" -eq 0 ] && return 1
    [ "$errors" -ne 0 ] && return 1

    return 0
}

# -------------------------------------------------------------------------------------------------
# run_fstrim_with_fallback - fstrim with nvram-backed fallback for a disk+mount
# -------------------------------------------------------------------------------------------------
# Arguments:
#   $1 - disk        (e.g. "sdb")
#   $2 - mountpoint  (e.g. "/tmp/mnt/st5")
#   $3 - context     (rich string for logging)
#   $4 - nv_key      (per-disk nvram key)
#   $5 - nv_val      (current nvram value: "", "0", or number >0)
#
# Behaviour:
#   * If nv_val > 0:
#       - Apply it to discard_max_bytes and run fstrim.
#   * If nv_val == "":
#       - Run fstrim with current kernel defaults.
#
#   On error:
#     * "Operation not supported":
#         - Mark disk as unsupported: nvram key -> 0.
#     * "Remote I/O error":
#         - If no override was used yet:
#             + Try discard_max_bytes = write_same_max_bytes.
#             + On success: store this value in nvram and reuse next time.
#             + On failure: mark disk as unsupported (nvram = 0).
#         - If override was already used:
#             + Mark disk as unsupported (nvram = 0).
# -------------------------------------------------------------------------------------------------
run_fstrim_with_fallback() {
    local disk="$1"
    local mp="$2"
    local context="$3"
    local nv_key="$4"
    local nv_val="$5"

    local used_override=0
    local output ws_bytes bytes

    # If we already have a cached working value, apply it first
    if [ -n "$nv_val" ]; then
        used_override=1
        if echo "$nv_val" > "/sys/block/$disk/queue/discard_max_bytes" 2>/dev/null; then
            log "Using cached discard_max_bytes=${nv_val} for /dev/${disk} (nvram key=${nv_key})"
        else
            log -l warn "Could not apply cached discard_max_bytes=${nv_val} for /dev/${disk}"
        fi
    fi

    log "Running fstrim on ${mp}..."
    if output=$(fstrim -v "$mp" 2>&1); then
        log "fstrim succeeded: $output"

        # Detect if any bytes were actually trimmed (parse last numeric field)
        bytes=$(
            printf '%s\n' "$output" |
                awk '{
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /^[0-9]+$/) last = $i
                    }
                } END {
                    if (last == "") last = 0
                    print last + 0
                }'
        )
        [ "$bytes" -gt 0 ] && trim_effective=1

        return 0
    fi

    # Simplified / explicit error reason logging
    case "$output" in
        *"Remote I/O error"*)
            log -l err "fstrim failed on ${mp}: Remote I/O error"
            ;;
        *"Operation not supported"*)
            log -l err "fstrim failed on ${mp}: Operation not supported"
            ;;
        *)
            log -l err "fstrim failed on ${mp}: $output"
            ;;
    esac

    case "$output" in
        *"Operation not supported"*)
            nvram set "${nv_key}=0"
            nvram_dirty=1
            log -l warn "Disabling TRIM for /dev/${disk} (${context}) after" \
                "\"Operation not supported\" error; nvram ${nv_key}=0"
            return 1
            ;;
        *"Remote I/O error"*)
            # Only try the write_same_max_bytes fallback once (when no override yet)
            if [ "$used_override" -eq 0 ]; then
                ws_bytes=$(
                    cat "/sys/block/$disk/queue/write_same_max_bytes" 2>/dev/null \
                        || printf ''
                )
                case "$ws_bytes" in
                    ''|*[!0-9]*|0)
                        nvram set "${nv_key}=0"
                        nvram_dirty=1
                        log -l warn "No usable write_same_max_bytes for /dev/${disk};" \
                            "disabling TRIM (nvram ${nv_key}=0)"
                        return 1
                        ;;
                esac

                if echo "$ws_bytes" > "/sys/block/$disk/queue/discard_max_bytes" 2>/dev/null; then
                    log "Retrying fstrim on ${mp} with discard_max_bytes=${ws_bytes}" \
                        "(fallback from write_same_max_bytes)..."

                    if output=$(fstrim -v "$mp" 2>&1); then
                        log "fstrim succeeded with fallback" \
                            "discard_max_bytes=${ws_bytes}: $output"

                        nvram set "${nv_key}=$ws_bytes"
                        nvram_dirty=1

                        log "Cached fallback discard_max_bytes=${ws_bytes}" \
                            "in nvram key ${nv_key} for /dev/${disk}"
                        return 0
                    fi

                    log -l err "fstrim still failed on ${mp} with fallback" \
                        "discard_max_bytes=${ws_bytes}: $output"
                else
                    log -l warn "Could not apply fallback" \
                        "discard_max_bytes=${ws_bytes} for /dev/${disk}"
                fi
            fi

            # Fallback either not attempted or failed: disable this disk for TRIM
            nvram set "${nv_key}=0"
            nvram_dirty=1
            log -l warn "Disabling TRIM for /dev/${disk} (${context}) after" \
                "Remote I/O error; nvram ${nv_key}=0"
            return 1
            ;;
        *)
            # Unknown error: leave nvram as-is, just fail
            return 1
            ;;
    esac
}

###################################################################################################
# 1. TRIM mode: operate on mounted filesystems under /tmp/mnt
###################################################################################################
log_msg="Scanning /proc/mounts for USB-backed filesystems under /tmp/mnt"
[ -n "$LABEL_FILTER" ] && log_msg="${log_msg} (label filter: ${LABEL_FILTER})"
log "$log_msg"

trimmed=0
trim_failed=0
trim_effective=0

# Read /proc/mounts line by line: device, mountpoint, fstype, ...
while read -r dev m fstype rest; do
    case "$m" in
        /tmp/mnt/*)
            label="${m#/tmp/mnt/}"

            # If a specific label is requested, skip others
            if [ -n "$LABEL_FILTER" ] && [ "$label" != "$LABEL_FILTER" ]; then
                continue
            fi

            # 1) Skip excluded labels (user-configured)
            if [ -n "$label" ] && is_label_excluded "$label"; then
                log "Skipping label=${label} mount=${m} (excluded via EXCLUDED_SSD_LABELS)"
                continue
            fi

            # Map device (/dev/sdXN) to its /sys representation
            part_name="${dev#/dev/}"          # sda1
            disk_name="${part_name%%[0-9]*}"  # sda
            sys_part="/sys/block/${disk_name}/${part_name}"

            # Require this to be a partition and exist in /sys
            [ -f "$sys_part/partition" ] || continue

            # Climb from partition to the underlying device node and verify USB
            p=$(readlink -f "${sys_part%/*}/device" 2>/dev/null) || continue
            while [ "$p" != "/" ] && [ ! -f "$p/idVendor" ]; do
                p=${p%/*}
            done
            [ -f "$p/idVendor" ] || continue

            vid=$(cat "$p/idVendor" 2>/dev/null || printf '')
            [ -n "$vid" ] || continue

            manufacturer=$(
                sed -E '/^[[:space:]]*$/d' "$p/manufacturer" 2>/dev/null || printf ''
            )

            # Build rich context (we'll reuse it for all checks)
            context="label=${label} mount=${m} part=${dev} fs=${fstype} vendor_id=${vid}"
            [ -n "$manufacturer" ] && context="${context} vendor_name=${manufacturer}"

            # 2) Filesystem support check (TRIM only on ext2/ext3/ext4)
            if ! filesystem_supports_trim "$dev" "$fstype" "$context"; then
                continue
            fi

            # 3) Derive per-disk nvram key & value (after cheap filters)
            disk_id=$(get_disk_id_key "$disk_name")
            nv_key="${SSD_NV_PREFIX}${disk_id}_discard_max_bytes"
            nv_val=$(nvram get "$nv_key" 2>/dev/null || printf '')

            # Normalize nvram value
            case "$nv_val" in
                '') nv_val='' ;;
                0)
                    log "Skipping drive=/dev/${disk_name}" \
                        "(disabled via nvram: ${nv_key}=0) for ${context}"
                    continue
                    ;;
                *[!0-9]*)
                    # Garbage; treat as unset
                    nv_val=''
                    ;;
            esac

            log "Detected SSD candidate: ${context}"

            # 4) Ensure UNMAP; if this fails, mark disk as unsupported & skip
            if ! ensure_unmap_for_disk "$disk_name"; then
                nvram set "${nv_key}=0"
                nvram_dirty=1
                log -l warn "Device /dev/${disk_name} does not expose a usable" \
                    "provisioning_mode; disabling TRIM (nvram ${nv_key}=0) for ${context}"
                continue
            fi

            # 5) Run TRIM with nvram-backed fallback strategy
            if run_fstrim_with_fallback "$disk_name" "$m" "$context" "$nv_key" "$nv_val"; then
                trimmed=1
            else
                trim_failed=1
            fi
            ;;
    esac
done < /proc/mounts

###################################################################################################
# 2. Final status & nvram commit
###################################################################################################
if [ "$trimmed" -eq 0 ] && [ "$trim_failed" -eq 0 ]; then
    msg="No suitable USB-backed mountpoints"
    if [ -n "$LABEL_FILTER" ]; then
        msg="${msg} found for label=${LABEL_FILTER}"
    else
        msg="${msg} detected under /tmp/mnt"
    fi

    log "${msg}; nothing to trim. Supported filesystems: ext2, ext3, ext4"
    exit 0
fi

[ "$nvram_dirty" -eq 1 ] && nvram commit
[ "$trim_failed" -eq 1 ] && exit 1

if [ "$trim_effective" -eq 1 ]; then
    log "Successfully trimmed all selected SSD mountpoints"
else
    log "No SSD mountpoints required trimming"
fi
