#!/usr/bin/env ash

###################################################################################################
# wan_failover.sh - Dual WAN failover handler for Asuswrt-Merlin
# -------------------------------------------------------------------------------------------------
# What this script does:
#   * Automatically reacts when your router switches between the main internet connection
#     (primary WAN) and the backup link (secondary WAN, e.g., LTE modem).
#   * Sends "primary down / restored" email notifications, but only after the router
#     has been up >= 3 min - preventing false alerts while the modem is still booting
#     after a power outage.
#   * Optionally blocks selected LAN devices from using the backup link (for example,
#     preventing a torrent box from consuming expensive LTE data), and unblocks them
#     when the main link returns.
#   * Maintains a "secondary WAN active" flag so that block rules are automatically
#     reapplied if the firewall restarts while the main WAN is still down.
#
# Usage:
#   Called automatically by wan-event or firewall-start with:
#     $1 -> WAN number (0 = primary, 1 = secondary) or WAN interface name (e.g., eth10 = secondary)
#     $2 -> event ("connected" | "disconnected" | "fw_started")
#
# Requirements / Notes:
#   * Designed to work with the Dual WAN feature built into ASUS firmware.
#     Compatibility with third-party Dual WAN solutions has not been tested.
#   * amtm email must be configured on the router beforehand.
#   * All configurable variables are defined inside this script - adjust them before use.
#     The most important ones are IPS names (for notifications) and the list
#     of LAN hosts for blocking.
#   * The script only manages failover notifications and optional host blocking - it does not
#     handle general firewall settings, QoS, or VPN routing.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Abort script on any error
# -------------------------------------------------------------------------------------------------
set -euo pipefail

###################################################################################################
# 0a. Define constants & variables
# -------------------------------------------------------------------------------------------------
# PRIMARY_WAN_ID      - index of the primary WAN (e.g., 0 = Ethernet)
# SECONDARY_WAN_ID    - index of the secondary WAN (e.g., 1 = USB LTE)
#
# PRIMARY_WAN_ISP     - name of the primary WAN provider (used in notifications)
# SECONDARY_WAN_ISP   - name of the secondary WAN provider
#
# HOSTS_TO_BLOCK      - newline-separated list of LAN hosts to block from using the secondary WAN
#                       during failover. If empty, no blocking occurs.
#
# MIN_BOOT_TIME       - minimum router uptime (in seconds) before sending mail;
#                       avoids false alerts during cold boot / modem init
# MAIL_DELAY          - delay (in seconds) before sending mail after event;
#                       avoids connection issues after WAN change
#
# EMAIL_SENDER        - helper used to send email notifications
# SECONDARY_WAN_FLAG  - presence of this file signals that secondary WAN is active
###################################################################################################
PRIMARY_WAN_ID=0
SECONDARY_WAN_ID=1

PRIMARY_WAN_ISP="PrimaryISP"       # <-- edit: name of your main / primary WAN provider
SECONDARY_WAN_ISP="SecondaryISP"   # <-- edit: name of your failover / secondary provider

HOSTS_TO_BLOCK='
'

MIN_BOOT_TIME=180
MAIL_DELAY=30

EMAIL_SENDER='/jffs/scripts/utils/send_email.sh'
SECONDARY_WAN_FLAG='/tmp/secondary_wan.enabled'

###################################################################################################
# 0b. Early exit - ignore events not for the secondary WAN (by ID or interface name)
###################################################################################################
[ "$1" = "$SECONDARY_WAN_ID" ] \
    || [ "$1" = "$(nvram get wan${SECONDARY_WAN_ID}_ifname)" ] \
    || exit 0

###################################################################################################
# 0c. Load utils
###################################################################################################
. /jffs/scripts/utils/common.sh
. /jffs/scripts/utils/firewall.sh

###################################################################################################
# 0d. Define helper functions
###################################################################################################

# -------------------------------------------------------------------------------------------------
# notify_when_settled - helper to send email only after the router has settled
# -------------------------------------------------------------------------------------------------
# Purpose:
#   Prevents false WAN alerts during early boot:
#     * After a cold boot, modems often take 1-2 minutes to initialize.
#     * During that period, the router may briefly switch to the secondary WAN,
#       triggering a misleading "primary WAN down" alert.
#
# Behavior:
#   1. Reads /proc/uptime to check system uptime.
#   2. If uptime < MIN_BOOT_TIME, exits silently (no email).
#   3. Otherwise, waits MAIL_DELAY seconds, then sends email via EMAIL_SENDER.
#
# Usage:
#   notify_when_settled "<subject>" "<body part 1>" [<body part 2> ...]
#     * All arguments after the subject are passed to EMAIL_SENDER as body.
# -------------------------------------------------------------------------------------------------
notify_when_settled() {
    local subject="$1"  # first arg = subject
    shift               # $@ now contains the whole body, word-for-word

    awk -v min="$MIN_BOOT_TIME" '{ exit ($1 < min) }' /proc/uptime || return 0
    (sleep "$MAIL_DELAY"; "$EMAIL_SENDER" "$subject" "$@") &
}

# -------------------------------------------------------------------------------------------------
# apply_host_action - apply per-host WAN policy on failover / restore
# -------------------------------------------------------------------------------------------------
# Purpose:
#   Iterates over HOSTS_TO_BLOCK and applies a per-host WAN action on the secondary WAN.
#   For each host, invokes block_wan_for_host or allow_wan_for_host based on ACTION.
#
# Behavior:
#   1. Validates ACTION is 'block' or 'allow'; otherwise logs an error and returns 1.
#   2. Reads HOSTS_TO_BLOCK through strip_comments to drop blanks and '#' comments.
#   3. For each remaining host token, calls:
#        "${ACTION}_wan_for_host" "$host" "$SECONDARY_WAN_ID"
#
# Inputs:
#   $1 (ACTION)            : 'block' | 'allow'
#
# Usage:
#   apply_host_action block     # on failover (secondary WAN became active)
#   apply_host_action allow     # on restore  (primary WAN became active again)
# -------------------------------------------------------------------------------------------------
apply_host_action() {
    local action="$1" host

    case "$action" in
        block|allow) ;;
        *)
            log -l err "apply_host_action: invalid action '$action'" \
                "(expected 'block' or 'allow')"
            return 1
            ;;
    esac

    for host in $(strip_comments "$HOSTS_TO_BLOCK"); do
        "${action}_wan_for_host" "$host" "$SECONDARY_WAN_ID" || true
    done
}

###################################################################################################
# 1. Process WAN events
# -------------------------------------------------------------------------------------------------
# Behavior:
#   * On 'connected': primary WAN is down and router switched to backup.
#       - Sets a flag file ($SECONDARY_WAN_FLAG)
#       - Blocks WAN access for selected LAN hosts
#       - Sends notification after boot-settle check
#
#   * On 'fw_started': primary WAN is down and firewall (re)started.
#       - Reapplies WAN block for selected LAN hosts (if failover flag is set)
#
#   * On 'disconnected': primary WAN is restored and router switches back.
#       - Removes the flag file
#       - Reallows WAN access for the previously blocked hosts
#       - Sends notification after boot-settle check
###################################################################################################
PRIMARY_WAN_ACTIVE="$(nvram get wan${PRIMARY_WAN_ID}_primary)"
SECONDARY_WAN_ACTIVE="$(nvram get wan${SECONDARY_WAN_ID}_primary)"

case "$2" in
    connected)     # primary WAN down -> using backup
        if [ "$PRIMARY_WAN_ACTIVE" = 0 ] && [ "$SECONDARY_WAN_ACTIVE" = 1 ]; then
            touch "$SECONDARY_WAN_FLAG"
            apply_host_action block

            notify_when_settled "🔴 WAN State Notification" \
                "$PRIMARY_WAN_ISP connection is not available." \
                "I switched to $SECONDARY_WAN_ISP."
        fi
        ;;
    fw_started)    # firewall (re)started while secondary is active
        if [ -f "$SECONDARY_WAN_FLAG" ]; then
            apply_host_action block
        fi
        ;;
    disconnected)  # primary WAN restored
        if [ "$PRIMARY_WAN_ACTIVE" = 1 ] && [ "$SECONDARY_WAN_ACTIVE" = 0 ]; then
            rm -f "$SECONDARY_WAN_FLAG"
            apply_host_action allow

            notify_when_settled "🟢 WAN State Notification" \
                "$PRIMARY_WAN_ISP connection is available again." \
                "I switched back from $SECONDARY_WAN_ISP."
        fi
        ;;
esac
