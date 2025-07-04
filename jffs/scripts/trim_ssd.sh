#!/bin/sh
#
# trim_ssd.sh — fstrim helper for a USB SSD on Asuswrt-Merlin
# -------------------------------------------------------------------------------
# • Assumes the drive is mounted at $SSD_MOUNT_POINT (see variable below).
# • Runs `fstrim -v` so the kernel passes TRIM/UNMAP to the SSD, reclaiming
#   space and keeping write speeds high.
# • Intended to be called from cron, e.g. via:
#       cru a trim_ssd "0 3 * * 0 /jffs/scripts/trim_ssd.sh"
# • Pair this with ssd_provisioning_mode.sh, which sets provisioning_mode to
#   "unmap"; otherwise the SSD may ignore TRIM commands.
# -------------------------------------------------------------------------------

set -e                        # abort script on any error

SSD_MOUNT_POINT='/mnt/st5'    # where the SSD is expected to be mounted

# Logger — writes the message to syslog (tag: trim_ssd) and stderr
log() { logger -s -t trim_ssd "$1"; }

# --------------------------------  Main Logic  ---------------------------------
if [ -d "$SSD_MOUNT_POINT" ]; then
    log "Running fstrim on $SSD_MOUNT_POINT..."

    # Capture output and exit status from fstrim
    if OUTPUT=$(fstrim -v "$SSD_MOUNT_POINT" 2>&1); then
        log "fstrim succeeded: $OUTPUT"  # success path
    else
        log "ERROR: $OUTPUT"             # fstrim failed → log & propagate error
        exit 1
    fi
else
    # Mount point missing — likely the drive is unplugged; treat as non-fatal
    log "Mount point $SSD_MOUNT_POINT not found. Skipping."
fi
