#!/usr/bin/env ash

#######################################################################################
# ssd_unmap.sh - set USB SSD provisioning_mode to "unmap"
# -------------------------------------------------------------------------------------
# Background:
#   Most USB-attached SSDs expose /sys/.../provisioning_mode as "full" or
#   "partial" by default. In those modes the kernel won't pass discard (TRIM)
#   as SCSI UNMAP to the device, so fstrim becomes a no-op and the SSD never
#   learns about freed blocks. Switching the mode to "unmap" enables proper
#   TRIM/UNMAP passthrough, keeping write performance steady and minimizing wear.
#
# What this script does:
#   * Scans /sys/devices for USB devices whose idVendor matches SSD_VENDOR_ID
#     (default 04e8 for Samsung; override via CLI).
#   * For each match, locates its provisioning_mode file and sets it to "unmap"
#     if it isn't already, logging successes and failures.
#
# Usage:
#   ssd_unmap.sh         # target Samsung
#   ssd_unmap.sh 0781    # target SanDisk (example vendor ID)
#######################################################################################

# -------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------
# shellcheck disable=SC2227

# -------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------
set -euo pipefail

#######################################################################################
# 0a. Load utils
#######################################################################################
. /jffs/scripts/utils/common.sh

#######################################################################################
# 0b. Define constants & variables
#######################################################################################
SSD_VENDOR_ID="${1:-04e8}"
SYS_DEVICE_ROOT='/sys/devices/'

#######################################################################################
# 1. Find every idVendor file that matches our vendor ID
#######################################################################################
log "Searching ${SYS_DEVICE_ROOT} for idVendor=${SSD_VENDOR_ID}..."

vendor_files=$(
    find "$SYS_DEVICE_ROOT" -name idVendor 2>/dev/null \
        -exec grep -l "^${SSD_VENDOR_ID}$" {} \;
)

if [ -z "$vendor_files" ]; then
    log -l err "No USB devices found with idVendor=${SSD_VENDOR_ID}"
    exit 1
fi

#######################################################################################
# 2. Derive the parent device directories (strip trailing /idVendor)
#######################################################################################
device_dirs="$(printf '%s\n' "$vendor_files" | sed 's#/idVendor$##')"

#######################################################################################
# 3. Within those devices, find every provisioning_mode file
#######################################################################################
prov_mode_files="$(
    printf '%s\n' "$device_dirs" |
    xargs -r -I{} find "{}" -name provisioning_mode 2>/dev/null
)"

if [ -z "$prov_mode_files" ]; then
    log -l err "No provisioning_mode files found for devices" \
        "with idVendor=${SSD_VENDOR_ID}"
    exit 1
fi

#######################################################################################
# 4. Write "unmap" into each provisioning_mode file
#######################################################################################
changed=0
failed=0

for file in $prov_mode_files; do
    cur="$(cat "$file" 2>/dev/null || true)"

    if [ "$cur" != "unmap" ]; then
        if printf '%s\n' unmap > "$file" 2>/dev/null; then
            log "Set 'unmap' (was '${cur:-unknown}') -> $file"
            changed=1
        else
            log -l err "Could not write -> $file"
            failed=1
        fi
    else
        log "Already 'unmap' -> $file"
    fi
done

#######################################################################################
# 5. Report success if no errors were hit; otherwise exit with a non-zero status
#######################################################################################
[ "$failed" -eq 1 ] && exit 1

if [ "$changed" -eq 1 ]; then
    log "Successfully updated all devices"
else
    log "All devices are up-to-date"
fi
