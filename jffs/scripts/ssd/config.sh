###################################################################################################
# config.sh - configuration for ssd_trim.sh (USB SSD TRIM/UNMAP handler)
# -------------------------------------------------------------------------------------------------
# Defines filesystem labels excluded from automatic provisioning_mode="unmap" and fstrim calls.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2034

###################################################################################################
# 1. Excluded SSD filesystem labels
# -------------------------------------------------------------------------------------------------
# A newline-separated list of filesystem labels that should be skipped entirely by ssd_trim.sh.
#
# If a mounted filesystem has a label listed here, ssd_trim.sh will NOT:
#   * enable provisioning_mode="unmap",
#   * attempt TRIM (fstrim),
#   * apply nvram fallback logic.
#
# Use this when:
#   * you have backup drives or external disks you prefer untouched,
#   * the device is managed manually,
#   * the disk behaves poorly with TRIM and you want to disable all handling explicitly.
#
# Matching is exact (case-sensitive). Blank lines are ignored.
#
# Examples:
#   EXCLUDED_SSD_LABELS='backup'
#
#   EXCLUDED_SSD_LABELS='
#     st5
#     backup
#   '
#
#   # Default: do not exclude anything
#   EXCLUDED_SSD_LABELS=''
###################################################################################################
EXCLUDED_SSD_LABELS=''

###################################################################################################
# 2. Make configuration constants read-only
# -------------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
###################################################################################################
readonly EXCLUDED_SSD_LABELS
