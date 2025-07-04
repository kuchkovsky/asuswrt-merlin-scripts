#!/usr/bin/env ash
#
# wgc_port_forwarding.sh — adds port forwarding support for the WireGuard client
# ---------------------------------------------------------------------------------
# The Asuswrt UI can forward ports **only to the WAN interface**;
# it offers no option to forward traffic that enters a WireGuard client tunnel
# (`wgcX`) to LAN hosts. This helper script fills that gap:
#
#   1. Creates a dedicated DNAT chain tied to the WG client interface.
#   2. Reads PORT_FWD_MAPPINGS (one rule per line, TCP by default or UDP if
#      specified) and inserts matching iptables rules for both WG and LAN
#      ingress.
#
# ---------------------------------------------------------------------------------

###################################################################################
# User-defined variables
###################################################################################

# PORT_FWD_MAPPINGS — list of port forwarding rules, **one per line**:
#   EXT_PORT:DST_IP:DST_PORT[:PROTO]
#     EXT_PORT   external port seen on the WG interface
#     DST_IP     internal host that will receive the traffic
#     DST_PORT   port on the internal host
#     PROTO      tcp | udp   (optional, defaults to tcp)
PORT_FWD_MAPPINGS='
80:192.168.50.20:80
443:192.168.50.20:443:tcp
51820:192.168.50.30:51820:udp
'

WG_CLIENT_IP='10.0.0.2'         # IP of this router inside the WG subnet
LAN_IF='br0'                    # LAN bridge
WGC_IF='wgc1'                   # WireGuard client interface

# iptables chain used for DNAT. Interface-specific and always in UPPERCASE.
CHAIN="$(echo "$WGC_IF" | tr 'a-z' 'A-Z')_VSERVER"

###################################################################################
# Load shared helpers
###################################################################################
. /jffs/scripts/util.sh

###################################################################################
# 1) Chain creation & hook into PREROUTING (WG traffic)
###################################################################################
iptables -t nat -N "$CHAIN" 2>/dev/null         # harmless if it already exists
ensure_fw_rule nat PREROUTING -d "$WG_CLIENT_IP/32" -j "$CHAIN"

###################################################################################
# 2) DNAT rules defined in PORT_FWD_MAPPINGS
###################################################################################
echo "$PORT_FWD_MAPPINGS" | while IFS=: read -r EXT_PORT DST_IP DST_PORT PROTO; do
    [ -n "$EXT_PORT" ] || continue               # skip blank/empty lines
    PROTO=${PROTO:-tcp}                          # default protocol

    for IFACE in "$WGC_IF" "$LAN_IF"; do
        ensure_fw_rule nat "$CHAIN" \
            -p "$PROTO" -i "$IFACE" --dport "$EXT_PORT" \
            -j DNAT --to-destination "${DST_IP}:${DST_PORT}"
    done
done
