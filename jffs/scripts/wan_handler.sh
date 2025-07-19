#!/usr/bin/env ash
#
# wan_handler.sh  –  full WAN-event logic for Asuswrt-Merlin
# -------------------------------------------------------------------------------
# Tested only with ASUS's built-in Dual WAN feature
# (primary Ethernet + USB LTE dongle as secondary WAN).
# It has not been validated with third-party Dual WAN scripts.
#
# Invoked by the thin /jffs/scripts/wan-event launcher with:
#     $1 = WAN number  (1 = secondary/backup WAN)
#     $2 = event       (connected | disconnected)
#
# Major components
# ----------------
# * notify_when_settled – sends email only after the router
#   has been up ≥ 3 min, preventing false alerts while the modem
#   is still booting after a power outage.
# * Optional LAN device firewall toggling (block/allow a host's WAN access).
# * Flag file handling so that /jffs/scripts/firewall-start can
#   reapply the block rule after a firewall restart or reboot
#   while the primary WAN is still down.
#
# -------------------------------------------------------------------------------

#################################################################################
# Early exit – ignore primary WAN events
#################################################################################
BACKUP_WAN_ID=1
[ "$1" = "$BACKUP_WAN_ID" ] || exit 0

#################################################################################
# User-defined variables
#################################################################################
MAIN_WAN_ISP="PrimaryISP"   # <-- edit: name of your main / primary WAN provider
BACKUP_WAN_ISP="BackupISP"  # <-- edit: name of your backup / failover provider

MIN_UPTIME=180              # seconds router must be up before mailing
MAIL_DELAY=30               # seconds wait before sending mail

#################################################################################
# Paths to files
#################################################################################
UPTIME_FILE="/proc/uptime"
EMAIL_SCRIPT="/jffs/scripts/send_email.sh"
BACKUP_WAN_FLAG="/tmp/backup_wan.enabled"

#################################################################################
#  Helper: send mail only after the router has "settled"
#################################################################################
#    WAN-not-ready logic:
#    After a cold boot the modem feeding the primary WAN often needs
#    a minute or two to finish initialising.  During that window the
#    router may briefly report "primary WAN down / secondary WAN up".
#    To avoid false alarms we:
#       1. Read /proc/uptime (seconds since boot).
#       2. Bail out if uptime < $MIN_UPTIME.
#       3. Otherwise wait $MAIL_DELAY seconds, then mail.
notify_when_settled() {
    local subject="$1" body="$2"
    awk -v min="$MIN_UPTIME" '{ exit ($1 < min) }' "$UPTIME_FILE" || return 0
    (sleep "$MAIL_DELAY"; "$EMAIL_SCRIPT" "$subject" "$body") &
}

###############################################################################
# Load shared helpers
###############################################################################
. /jffs/scripts/util.sh   # brings in block/allow_wan_for_host

#################################################################################
# Main state machine – backup WAN only
#################################################################################
WAN0_PRIMARY_FLAG="$(nvram get wan0_primary)"
WAN1_PRIMARY_FLAG="$(nvram get wan1_primary)"

case "$2" in
  connected)    # primary WAN down -> using backup
    if [ "$WAN0_PRIMARY_FLAG" = 0 ] && [ "$WAN1_PRIMARY_FLAG" = 1 ]; then
        touch "$BACKUP_WAN_FLAG"
        block_wan_for_host hostname    # <-- edit: delete this line if you only want email alerts,
                                       # or replace 'hostname' with the device to block
        notify_when_settled "🔴 WAN State Notification" \
          "$MAIN_WAN_ISP connection is not available. I switched to $BACKUP_WAN_ISP."
    fi
    ;;
  disconnected) # primary WAN restored
    if [ "$WAN0_PRIMARY_FLAG" = 1 ] && [ "$WAN1_PRIMARY_FLAG" = 0 ]; then
        rm -f "$BACKUP_WAN_FLAG"
        allow_wan_for_host hostname    # <-- edit: delete this line if you only want email alerts,
                                       # or replace 'hostname' with the device to unblock
        notify_when_settled "🟢 WAN State Notification" \
          "$MAIN_WAN_ISP connection is available again. I switched back from $BACKUP_WAN_ISP."
    fi
    ;;
esac
