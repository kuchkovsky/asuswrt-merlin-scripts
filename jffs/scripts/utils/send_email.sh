#!/usr/bin/env ash

###############################################################################
# send_email.sh - lightweight email notification helper for Asuswrt-Merlin
# -----------------------------------------------------------------------------
# What it does:
#   * Sends a single email using the router's amtm email configuration.
#   * Concatenates all body arguments with spaces into the final message body.
#
# Usage:
#   send_email.sh "<subject>" "<body part 1>" [<body part 2> ...]
#
# Requirements:
#   * amtm email must be configured on the router beforehand.
###############################################################################

# -----------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -----------------------------------------------------------------------------
# shellcheck disable=SC1090
# shellcheck disable=SC2086
# shellcheck disable=SC2154

# -----------------------------------------------------------------------------
# Abort script on any error
# -----------------------------------------------------------------------------
set -euo pipefail

###############################################################################
# 0a. Load utils
###############################################################################
. /jffs/scripts/utils/common.sh

###############################################################################
# 0b. Define constants
###############################################################################
AMTM_EMAIL_DIR="/jffs/addons/amtm/mail"
AMTM_EMAIL_CONF="$AMTM_EMAIL_DIR/email.conf"
AMTM_EMAIL_PW_ENC="$AMTM_EMAIL_DIR/emailpw.enc"

# Wait time (seconds) before retrying email after network failure
RETRY_DELAY=60

###############################################################################
# 0c. Ensure email is configured
###############################################################################
if [ ! -r "$AMTM_EMAIL_CONF" ] || [ ! -r "$AMTM_EMAIL_PW_ENC" ]; then
    log -l err "Email is not configured in amtm. Please configure it first"
    exit 1
fi

# Load amtm variables:
#   SMTP       - mail server host
#   PORT       - mail server port
#   PROTOCOL   - "smtp" or "smtps"
#   SSL_FLAG   - none or "--insecure"
#   emailPwEnc - encrypted password
#   TO_NAME, TO_ADDRESS, FROM_ADDRESS, USERNAME
. "$AMTM_EMAIL_CONF"

###############################################################################
# 0d. Parse args & define variables
###############################################################################
SUBJECT="${1-}"                       # first argument = email subject
shift                                 # drop $1, so $@ now starts with the body

# Remaining arguments = message body.
# Join them with spaces and translate \n etc. using printf '%b'
BODY=$(printf '%b' "$*")

# Validate subject
if [ -z "${SUBJECT//[[:space:]]/}" ]; then
    log -l err "Email subject is empty. Please provide an argument"
    exit 2
fi

# Validate body
if [ -z "${BODY//[[:space:]]/}" ]; then
    log -l err "Email body is empty. Please provide at least one body argument"
    exit 2
fi

# Decrypt password
PASSWORD="$(/usr/sbin/openssl aes-256-cbc "$emailPwEnc" \
    -d -in "$AMTM_EMAIL_PW_ENC" -pass pass:ditbabot,isoi 2>/dev/null)"

###############################################################################
# 1. Build the message
###############################################################################
TMP_MAIL=$(tmp_file)

FROM_NAME="ASUS $(nvram get model)"   # router name shown in "From:"

{
    printf 'From: "%s"<%s>\n'       "$FROM_NAME" "$FROM_ADDRESS"
    printf 'To: "%s"<%s>\n'         "$TO_NAME" "$TO_ADDRESS"
    printf 'Subject: %s\n'          "$SUBJECT"
    printf 'Date: %s\n'             "$(date -R)"
    printf '\nHey there,\n\n%s\n\n' "$BODY"
    printf '--------------------\n'
    printf 'Best regards,\nYour friendly router\n'
} > "$TMP_MAIL"

###############################################################################
# 2. Send over SMTP using curl
###############################################################################
for try in 1 2 3; do
    if /usr/sbin/curl -sS --url "${PROTOCOL}://${SMTP}:${PORT}" \
            --mail-from "$FROM_ADDRESS" \
            --mail-rcpt "$TO_ADDRESS" \
            --upload-file "$TMP_MAIL" \
            --ssl-reqd \
            --crlf \
            --user "$USERNAME:$PASSWORD" \
            $SSL_FLAG;
    then
        log "Email sent to $TO_ADDRESS: $SUBJECT"
        break
    fi

    if [ "$try" -lt 3 ]; then
        log -l warn "Email send failed, retrying in ${RETRY_DELAY}s... (attempt $try/3)"
        sleep "$RETRY_DELAY"
    else
        log -l err "Failed to send email to $TO_ADDRESS: $SUBJECT after 3 attempts"
        exit 3
    fi
done
