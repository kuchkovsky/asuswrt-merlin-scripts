###################################################################################################
# config.sh - shared configuration for SDN scripts
# -------------------------------------------------------------------------------------------------
# Defines bridge interfaces excluded from automatic IPv6 assignment and firewall configuration.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2034

###################################################################################################
# 1. Excluded interfaces for SDN IPv6 auto-assignment
# -------------------------------------------------------------------------------------------------
# * Lists bridge interfaces that should be skipped when assigning IPv6 /64 subnets.
# * Useful if you want to keep certain SDNs IPv4-only, or manage their IPv6 configuration via
#   the built-in SDN settings (stateful DHCPv6 mode) or manually.
# * The main LAN (br0) is always excluded automatically, so it should not be listed here.
#
# Example:
#   EXCLUDED_IFACES='br54 br56'
###################################################################################################
EXCLUDED_IFACES=''

###################################################################################################
# 2. Make all public configuration constants read-only
# -------------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
###################################################################################################
readonly EXCLUDED_IFACES
