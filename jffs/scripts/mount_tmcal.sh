#!/bin/sh
#
# mount_tmcal.sh — inject custom Traffic Monitor tweak
# ----------------------------------------------------------------------------
# The stock ASUS GUI (tmcal.js) reports Current/Average/Maximum values
# in KB/s – MB/s (bytes). This add-on snippet  /jffs/tmcal.js.add
# rewrites those table functions so the numbers show Kb/s – Mb/s (bits).
#
# It does not modify the SVG history graph; only the table values are
# affected. This script concatenates the original file with the add-on and
# bind-mounts the result over /www/tmcal.js each boot.
# ----------------------------------------------------------------------------

SRC_ORIG="/www/tmcal.js"
SRC_ADD="/jffs/tmcal.js.add"
TMP_JS="/tmp/tmcal_custom.js"

# Abort if the extra file is missing
[ -f "$SRC_ADD" ] || { echo "Error: $SRC_ADD not found" >&2; exit 1; }

# Build the combined script
cat "$SRC_ORIG" "$SRC_ADD" > "$TMP_JS"

# Bind-mount the new file over the original
mount -o bind "$TMP_JS" "$SRC_ORIG"
