#!/usr/bin/env ash

##############################################################################################
# fw_shared.sh - INTERNAL shared library for ipset_builder.sh, wan_firewall.sh,
#                and tunnel_director.sh
# --------------------------------------------------------------------------------------------
# Purpose:
#   Provides helper functions and state file paths shared by the scripts.
#   User configuration belongs in config.sh - not here.
##############################################################################################

# --------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# --------------------------------------------------------------------------------------------
# shellcheck disable=SC2018
# shellcheck disable=SC2019
# shellcheck disable=SC2034

##############################################################################################
# 1. Functions
# --------------------------------------------------------------------------------------------
# derive_set_name <name> - return lowercased <name> if ≤31 chars;
#                          otherwise return a stable 24-char SHA-256 prefix alias,
#                          and log a notice about the rename
##############################################################################################
derive_set_name() {
    local set="$1" max=31 set_lc hash

    set_lc=$(printf '%s' "$set" | tr 'A-Z' 'a-z')

    # Fits already? Return as-is
    if [ "${#set_lc}" -le "$max" ]; then
        printf '%s\n' "$set_lc"
        return 0
    fi

    hash="$(printf '%s' "$set_lc" | compute_hash | cut -c1-24)"

    log -l notice "Assigned alias='$hash' for set='$set_lc'" \
        "because set name exceeds $max chars"

    printf '%s\n' "$hash"
}

##############################################################################################
# 2. State files (flags & hashes)
# --------------------------------------------------------------------------------------------
# All paths live under /tmp and persist only until reboot. They coordinate behavior between
# ipset_builder.sh, wan_firewall.sh, and tunnel_director.sh - detecting when rules/sets
# need rebuilding and ensuring scripts apply idempotently.
#
# IPS_BUILDER_DIR           - base dir for IPSet Builder state
# WAN_FW_IPSETS_HASH        - SHA-256 marker after a successful build/apply of WAN Firewall
#                             ipsets
# TUN_DIR_IPSETS_HASH       - SHA-256 marker after a successful build/apply of Tunnel Director
#                             ipsets
# STORAGE_NOT_MOUNTED_FLAG  - flag indicating external storage is missing
# DOWNLOAD_FAILED_FLAG      - flag indicating a file download failed
# BUILD_FAILED_FLAG         - flag indicating ipset build failed
# ALERT_EMAIL_SENT_FLAG     - throttle flag to avoid duplicate failure alerts via email
#
# WAN_FIREWALL_DIR          - base dir for WAN Firewall state
# WAN_FW_RULES_HASH         - last applied SHA-256 hash of normalized WAN Firewall rules
# DOS_PROT_RULES_HASH       - last applied SHA-256 hash of normalized DoS Protection rules
#
# TUN_DIRECTOR_DIR          - base dir for Tunnel Director state
# TUN_DIR_HASH              - last applied SHA-256 hash of normalized Tunnel Director rules
##############################################################################################
IPS_BUILDER_DIR="/tmp/ipset_builder"
WAN_FW_IPSETS_HASH="$IPS_BUILDER_DIR/wan_fw_ipsets.sha256"
TUN_DIR_IPSETS_HASH="$IPS_BUILDER_DIR/tun_dir_ipsets.sha256"
STORAGE_NOT_MOUNTED_FLAG="$IPS_BUILDER_DIR/ipsets_storage.not_mounted"
DOWNLOAD_FAILED_FLAG="$IPS_BUILDER_DIR/ipsets_download.failed"
BUILD_FAILED_FLAG="$IPS_BUILDER_DIR/ipsets_build.failed"
ALERT_EMAIL_SENT_FLAG="$IPS_BUILDER_DIR/ipsets_alert_email.sent"

WAN_FIREWALL_DIR='/tmp/wan_firewall'
WAN_FW_RULES_HASH="$WAN_FIREWALL_DIR/wan_fw_rules.sha256"
DOS_PROT_RULES_HASH="$WAN_FIREWALL_DIR/dos_prot_rules.sha256"

TUN_DIRECTOR_DIR="/tmp/tunnel_director"
TUN_DIR_HASH="$TUN_DIRECTOR_DIR/tun_dir_rules.sha256"

##############################################################################################
# 3. Create dirs & make all configuration constants read-only
# --------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
##############################################################################################
mkdir -p "$IPS_BUILDER_DIR" "$WAN_FIREWALL_DIR" "$TUN_DIRECTOR_DIR"

readonly \
    IPS_BUILDER_DIR WAN_FW_IPSETS_HASH TUN_DIR_IPSETS_HASH \
    STORAGE_NOT_MOUNTED_FLAG DOWNLOAD_FAILED_FLAG \
    BUILD_FAILED_FLAG ALERT_EMAIL_SENT_FLAG \
    WAN_FIREWALL_DIR WAN_FW_RULES_HASH DOS_PROT_RULES_HASH \
    TUN_DIRECTOR_DIR TUN_DIR_HASH
