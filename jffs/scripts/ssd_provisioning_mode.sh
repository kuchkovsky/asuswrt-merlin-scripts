#!/bin/sh
#
# ssd_provisioning_mode.sh — flip USB SSD(s) to "unmap"
# -------------------------------------------------------------------------------
# Background
#   Most USB-attached SSDs expose /sys/.../provisioning_mode as full or
#   partial by default. In those modes the Linux fstrim command cannot
#   pass TRIM/UNMAP down to the drive, so the filesystem never informs the
#   SSD about freed blocks. Setting the file to unmap enables proper
#   TRIM support, letting routine fstrim jobs keep the drive's write speed
#   consistent and minimise wear.
#
# What this script does:
#   * Scans /sys/devices/ for every USB device whose idVendor equals
#     SSD_VENDOR_ID (default 04e8 = Samsung; override with CLI arg).
#   * For each match, writes the string "unmap" into its provisioning_mode
#     file (if writable).
#   * Logs successes and failures to syslog with tag 'ssd_provisioning_mode'.
#
# Usage examples:
#     ssd_provisioning_mode.sh           # targets Samsung USB SSDs
#     ssd_provisioning_mode.sh 0781      # targets SanDisk (example vendor ID)
#
# -------------------------------------------------------------------------------

set -e                            # abort script on any error

SSD_VENDOR_ID="${1:-04e8}"        # optional CLI override for idVendor
SYS_DEVICE_ROOT='/sys/devices/'

# Logger — writes the message to syslog (tag: ssd_provisioning_mode) and stderr
log() { logger -s -t ssd_provisioning_mode "$1"; }

#################################################################################
# 1) Find every idVendor file that matches our vendor ID
#################################################################################
log "Searching ${SYS_DEVICE_ROOT} for idVendor=${SSD_VENDOR_ID}..."

VENDOR_FILES=$(
    find "$SYS_DEVICE_ROOT" -name idVendor 2>/dev/null \
         -exec grep -l "^${SSD_VENDOR_ID}$" {} \;
)

[ -n "$VENDOR_FILES" ] || {
    log "No USB devices found with idVendor=${SSD_VENDOR_ID}."
    exit 1
}

#################################################################################
# 2) Derive the parent device directories (strip trailing /idVendor)
#################################################################################
DEVICE_DIRS=$(echo "$VENDOR_FILES" | sed 's|/idVendor$||')

#################################################################################
# 3) Within those devices, find every provisioning_mode file
#################################################################################
PROV_MODE_FILES=$(find $DEVICE_DIRS -name provisioning_mode 2>/dev/null)

[ -n "$PROV_MODE_FILES" ] || {
    log "No provisioning_mode files found for devices with idVendor=${SSD_VENDOR_ID}."
    exit 1
}

#################################################################################
# 4) Write "unmap" into each provisioning_mode file
#################################################################################
FAIL=0
for f in $PROV_MODE_FILES; do
    if echo unmap > "$f" 2>/dev/null; then
        log "Set unmap -> $f"
    else
        log "ERROR: could not write $f"
        FAIL=1
    fi
done

#################################################################################
# 5) Report success if no errors were hit; otherwise exit with a non-zero status
#################################################################################
[ "$FAIL" -eq 0 ] && log "Successfully updated all devices." || exit 1
