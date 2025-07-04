#!/usr/bin/env ash
#
# send_email.sh — lightweight email helper for Asuswrt-Merlin
# -----------------------------------------------------------------------------
# • Requires that **amtm email** is already configured. The script reads
#   `/jffs/addons/amtm/mail/email.conf` plus the encrypted password file.
#
# • Usage:
#     send_email.sh  "Subject text"  "Body text"
#
# -----------------------------------------------------------------------------

set -e  # abort script on any error

# Logger — writes the message to syslog (tag: send_email) and stderr
log() { logger -s -t send_email "$1"; }

###############################################################################
# Paths supplied by amtm
###############################################################################
AMTM_EMAIL_DIR="/jffs/addons/amtm/mail"
AMTM_EMAIL_CONF="$AMTM_EMAIL_DIR/email.conf"
AMTM_EMAIL_PW_ENC="$AMTM_EMAIL_DIR/emailpw.enc"

###############################################################################
# Ensure email is configured
###############################################################################
if [ ! -r "$AMTM_EMAIL_CONF" ] || [ ! -r "$AMTM_EMAIL_PW_ENC" ]; then
    log "ERROR: email is not configured in amtm. Please configure it first."
    exit 1
fi

# Load amtm variables:
#   SMTP       – mail server host
#   PORT       – mail server port
#   PROTOCOL   – "smtp" or "smtps"
#   SSL_FLAG   – none or "--insecure"
#   emailPwEnc - encrypted password
#   TO_NAME, TO_ADDRESS, FROM_ADDRESS, USERNAME
#
# shellcheck disable=SC1090
. "$AMTM_EMAIL_CONF"

###############################################################################
# Decrypt password
###############################################################################
# shellcheck disable=SC2154
PASSWORD="$(/usr/sbin/openssl aes-256-cbc "$emailPwEnc" \
    -d -in "$AMTM_EMAIL_PW_ENC" -pass pass:ditbabot,isoi 2>/dev/null)"

###############################################################################
# Build the message
###############################################################################
TMP_MAIL="/tmp/mail_$$.txt"     # $$ = PID → unique per run
trap 'rm -f "$TMP_MAIL"' EXIT   # always clean up

FROM_NAME="ASUS $(nvram get model)"
SUBJECT="$1"
BODY="$2"

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
# Send over SMTP using curl
###############################################################################
# shellcheck disable=SC2086
if /usr/sbin/curl --url "${PROTOCOL}://${SMTP}:${PORT}" \
    --mail-from "$FROM_ADDRESS" \
    --mail-rcpt "$TO_ADDRESS" \
    --upload-file "$TMP_MAIL" \
    --ssl-reqd \
    --crlf \
    --user "$USERNAME:$PASSWORD" \
    $SSL_FLAG
then
    log "Email sent to $TO_ADDRESS: $SUBJECT"
else
    log "ERROR sending email to $TO_ADDRESS: $SUBJECT"
    exit 1
fi
