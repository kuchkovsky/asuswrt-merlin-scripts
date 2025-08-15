#!/usr/bin/env ash

#######################################################################################
# ssd_trim.sh - run fstrim on a USB SSD
# -------------------------------------------------------------------------------------
# Background:
#   TRIM lets the filesystem inform the SSD about unused blocks, helping
#   the drive maintain high write performance and reduce wear over time.
#
# What this script does:
#   * Runs 'fstrim -v' on SSD mount point to trigger a TRIM operation.
#
# Usage:
#   ssd_trim.sh <LABEL>    # filesystem label (e.g., st5) mounted at /tmp/mnt/<LABEL>
#
# Requirements / Notes:
#   * Requires provisioning_mode='unmap' (see ssd_unmap.sh), otherwise TRIM is ignored.
#   * Intended to be called periodically from cron to maintain USB drive performance.
#######################################################################################

# -------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------
set -euo pipefail

#######################################################################################
# 0a. Load utils
#######################################################################################
. /jffs/scripts/utils/common.sh

#######################################################################################
# 0b. Parse args & define constants
# -------------------------------------------------------------------------------------
# SSD_VOLUME_LABEL   - SSD volume label assigned via tune2fs
# SSD_MOUNT_POINT    - expected mount path for the SSD under '/tmp/mnt'
#######################################################################################
SSD_VOLUME_LABEL="${1:-}"

if [ -z "$SSD_VOLUME_LABEL" ]; then
    log -l err "Please specify the SSD volume label"
    exit 1
fi

SSD_MOUNT_POINT="/tmp/mnt/$SSD_VOLUME_LABEL"

#######################################################################################
# 1. Run fstrim on SSD_MOUNT_POINT
#######################################################################################
if awk -v m="$SSD_MOUNT_POINT" '$2 == m { f = 1; exit } END { exit(!f) }' /proc/mounts;
then
    log "Running fstrim on $SSD_MOUNT_POINT..."

    # Capture output and exit status from fstrim
    if output=$(fstrim -v "$SSD_MOUNT_POINT" 2>&1); then
        log "fstrim succeeded: $output"
    else
        log -l err "$output"
        exit 2
    fi
else
    # Mount point missing - likely the drive is unplugged; treat as non-fatal
    log "Mount point $SSD_MOUNT_POINT not found - skipping"
fi
