#!/usr/bin/env ash

##############################################################################################
# wf_ib_shared.sh - INTERNAL shared library for wan_firewall.sh and ipset_builder.sh
# --------------------------------------------------------------------------------------------
# Purpose:
#   Provides helper functions and state file paths shared by both scripts.
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
    local set="$1" max=31 hash

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
# wan_firewall.sh and ipset_builder.sh (e.g., detecting when rules/sets need rebuilding).
#
# WAN_FW_FLAG_DIR          - base dir for wan_firewall state
# DOS_RULES_HASH           - last applied SHA-256 hash of normalized DoS rules
# IPSET_RULES_HASH         - last applied SHA-256 hash of normalized ipset rules
#
# IPS_BDR_FLAG_DIR         - base dir for ipset_builder state
# IPSETS_CREATED_HASH      - SHA-256 marker written after a successful build/apply of ipsets
# STORAGE_NOT_MOUNTED_FLAG - flag indicating external storage is missing
# DOWNLOAD_FAILED_FLAG     - flag when any file download failed
# BUILD_FAILED_FLAG        - flag when building ipsets failed
# ALERT_EMAIL_SENT_FLAG    - throttle flag to avoid duplicate failure emails
##############################################################################################
WAN_FW_FLAG_DIR='/tmp/wan_firewall'
DOS_RULES_HASH="$WAN_FW_FLAG_DIR/dos_rules.sha256"
IPSET_RULES_HASH="$WAN_FW_FLAG_DIR/ipset_rules.sha256"

IPS_BDR_FLAG_DIR="$WAN_FW_FLAG_DIR/ipset_builder"
IPSETS_CREATED_HASH="$IPS_BDR_FLAG_DIR/ipsets_created.sha256"
STORAGE_NOT_MOUNTED_FLAG="$IPS_BDR_FLAG_DIR/ipsets_storage.not_mounted"
DOWNLOAD_FAILED_FLAG="$IPS_BDR_FLAG_DIR/ipsets_download.failed"
BUILD_FAILED_FLAG="$IPS_BDR_FLAG_DIR/ipsets_build.failed"
ALERT_EMAIL_SENT_FLAG="$IPS_BDR_FLAG_DIR/ipsets_alert_email.sent"

##############################################################################################
# 3. Create dirs & make all configuration constants read-only
# --------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
##############################################################################################
mkdir -p "$WAN_FW_FLAG_DIR" "$IPS_BDR_FLAG_DIR"

readonly \
    DOS_RULES_HASH IPSET_RULES_HASH \
    IPSETS_CREATED_HASH STORAGE_NOT_MOUNTED_FLAG \
    DOWNLOAD_FAILED_FLAG BUILD_FAILED_FLAG ALERT_EMAIL_SENT_FLAG
