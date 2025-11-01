#!/usr/bin/env ash

###################################################################################################
# config.sh - shared configuration for ipset_builder.sh, wan_firewall.sh,
#             and tunnel_director.sh
# -------------------------------------------------------------------------------------------------
# APPLYING CHANGES:
#   * Changes to this file do not take effect until reloaded.
#   * You can reload in one of the following ways:
#       - Run "ipw" (helper alias) - reloads wan_firewall.sh without reboot.
#       - Run "ipt" (helper alias) - reloads tunnel_director.sh without reboot.
#       - Reboot the router - slower, but also works.
#   * Both "ipw" and "ipt" automatically run ipset_builder.sh first to build/refresh
#     required ipsets, then trigger the corresponding script.
###################################################################################################

# -------------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# -------------------------------------------------------------------------------------------------
# shellcheck disable=SC2034

###################################################################################################
# 1. Download & dump path for IPSet Builder
# -------------------------------------------------------------------------------------------------
# * If IPS_BDR_DIR points to external storage (e.g., /mnt/...):
#     - BusyBox and mapCIDR are bootstrapped into $IPS_BDR_DIR/bin,
#       enabling GeoLite2 country ipset generation and CIDR aggregation.
# * If IPS_BDR_DIR is on internal flash (e.g., /jffs/...):
#     - these binaries are not installed;
#       the builder falls back to IPdeny feeds, and aggregation is disabled.
# * Dump files (saved ipset snapshots) are stored under $IPS_BDR_DIR/dumps.
# * Using external storage for IPS_BDR_DIR:
#     - preserves the router's internal flash (JFFS).
#     - provides sufficient space for both binaries and dump files.
#
# IMPORTANT: It's highly recommended to change this path to your external storage
# (e.g., '/mnt/st5/ipset_builder').
###################################################################################################
IPS_BDR_DIR='/jffs/ipset_builder'

###################################################################################################
# 2. MaxMind License Key for GeoLite2
# -------------------------------------------------------------------------------------------------
# * GeoLite2 provides one of the most accurate and frequently updated country-to-IP
#   mappings available for free. It is derived from MaxMind's commercial GeoIP2
#   database, which is used by many enterprises, CDNs, and security providers.
#   Accuracy comes from:
#     - Multiple data sources: ISP-provided allocation data, WHOIS records,
#       global BGP routing tables, and geolocation hints from large-scale
#       anonymous telemetry (browser, mobile, app data).
#     - Continuous verification: IP ranges are actively cross-checked and
#       corrected when ownership or routing changes occur.
#     - Weekly updates: reduces stale mappings that occur in less-maintained
#       datasets.
#   By contrast, many other free feeds (e.g., IPdeny) rely primarily on registration
#   country rather than observed routing and location, which can misclassify IPs
#   from large cloud/CDN providers (e.g., Cloudflare) and reduce accuracy.
#
# * GeoLite2 CSV downloads require a valid MAXMIND_LICENSE_KEY.
#   To obtain one:
#     1. Sign up for a free account: https://www.maxmind.com/en/geolite2/signup
#     2. Log in and go to "Manage license keys" in your account settings.
#     3. Generate and copy the key, then paste it into this variable.
#
# * If MAXMIND_LICENSE_KEY is unset or empty, the script will fall back to
#   IPdeny country feeds (less accurate, but fine for some cases).
###################################################################################################
MAXMIND_LICENSE_KEY=''

###################################################################################################
# 3. Custom ipsets (IPv4 & IPv6)
# -------------------------------------------------------------------------------------------------
# Define named ipsets, each containing inline CIDRs and/or remote sources.
#
# Variables:
#   CUSTOM_IPSETS     - IPv4 definitions
#   CUSTOM_V6_IPSETS  - IPv6 definitions
#
# Format:
#   <set_name>:
#     * Inline CIDR entries (e.g., 1.2.3.4/32 or 2001:db8::/32),
#       optionally followed by comments (#).
#     * Remote URLs (http/https) returning plain-text CIDR lists:
#         - You may append curl options (-H, -d, etc.) to support headers, API keys, etc.
#         - Each URL is downloaded, validated, and merged into the target ipset.
#
# Naming guidance:
#   * Prefer 3-letter names for IPv4 sets and 4-letter names with a "6" suffix for IPv6
#     (not strictly required). Two-letter names and their IPv6 counterparts ending in "6"
#     are commonly reserved for country codes. Shorter names help stay within the ipset
#     name length limit, especially when multiple sets are combined into a single combo set.
#   * If a set name or a generated combo set name exceeds 31 characters, it will be
#     automatically truncated and replaced with a 24-character hash. This ensures the
#     firewall remains fully operational, but makes logs harder to read. For this reason,
#     shorter and more descriptive names are recommended whenever possible, so that
#     syslog output stays human-readable.
#
# Default list (IPv4):
#   * "blk" baseline blocking uses FireHOL Level 1 - a curated aggregate
#     blacklist providing maximum protection with minimal false positives.
#     Suitable for basic protection on all internet-facing servers, routers,
#     and firewalls.
#     This list includes:
#       - Bogon networks (unroutable/reserved IPs).
#       - Known attack sources (e.g., brute-force attempts, worms, scanners).
#       - Spam and abuse sources.
#     Internally, firehol_level1 aggregates several well-vetted feeds, including:
#       * dshield - sources of recent network attacks.
#       * feodo - IPs related to Feodo/Dridex malware infrastructure.
#       * fullbogons - unallocated and reserved address space.
#       * spamhaus_drop - IPs controlled by known spam and cybercrime operators.
#       * spamhaus_edrop - extended list of botnet and malware infrastructure.
#     Designed to avoid overly aggressive or controversial sources, reducing
#     the risk of false positives while still blocking a wide range of threats.
#
# Default list (IPv6):
#   * "blk6" baseline blocking uses two well-established, continuously
#     maintained sources:
#       * fullbogons-ipv6 - published by Team Cymru, listing all IPv6
#         address ranges that are either unallocated or reserved by IANA
#         and therefore should never appear in global routing tables.
#         Blocking these prevents spoofing and misconfigured traffic.
#       * dropv6 - published by Spamhaus, listing IPv6 ranges controlled
#         by known spammers, malware distributors, and botnet C2 networks.
#         It focuses on permanent, well-confirmed sources of abuse.
#     This combination is intentionally conservative, avoiding overblocking
#     while still filtering invalid or hostile IPv6 space that has no
#     legitimate use on the public internet.
#
# Recommended additions for stronger IPv4 security (uncomment the lines in "blk"):
#   * FireHOL Level 2 & 3 - broader threat coverage than Level 1.
#       - Level 2: aggregates multiple blocklists tracking active attacks
#         seen in roughly the last 48 hours, including:
#           * blocklist_de - reported attack sources.
#           * dshield_1d - sources of network attacks in the past day.
#           * greensnow - IPs engaged in scanning and abuse.
#         Focuses on active attackers, aggressive crawlers, and bots.
#         Suitable for blocking current threats while keeping false positives low.
#       - Level 3: more aggressive; aggregates additional blocklists tracking
#         attacks, spyware, and viruses over a longer time window (up to 30 days),
#         including:
#           * bruteforceblocker - repeated SSH brute-force sources.
#           * ciarmy - general attack sources.
#           * dshield_30d - attackers seen in the last month.
#           * myip - malware C2s and infected hosts.
#           * vxvault - known malware distribution sites.
#         Provides wider coverage but may include less strictly vetted sources,
#         slightly increasing the risk of false positives.
#   * AbuseIPDB - a high-quality, crowd-sourced abuse database containing the
#       latest 10,000 most-reported IPs, ordered by confidence score and recency.
#       - This feed (free plan) includes exclusively IPs with a 100% abuse
#         confidence score - meaning they have been repeatedly reported by
#         multiple trusted users for the same malicious activity (e.g., SSH
#         bruteforce, spam, scanning, malware C2).
#       - Results are refreshed daily and sorted by highest confidence first,
#         then most recent report, ensuring that the worst and most persistent
#         offenders appear at the top.
#       Setup:
#         1. Register for a free API key: https://www.abuseipdb.com/register?plan=free
#         2. Replace YOUR_API_KEY in the corresponding CUSTOM_IPSETS line.
#   * IPsum - a daily updated aggregate list compiled from ~30 trusted
#       threat intelligence sources, each reporting IPs involved in abusive or
#       malicious activity (e.g., SSH bruteforce, spam, scanning, malware C2).
#       - Level 2 (file '2.txt' in the URL): an IP must appear in at least 2
#         independent sources within the same day to be included, greatly
#         reducing false positives while retaining broad coverage.
#       - Level 3 (file '3.txt' in the URL): lighter version where IPs must
#         appear in at least 3 sources, further reducing false positives while
#         providing slightly lower coverage. Recommended if you notice
#         overblocking or want smaller ipsets for performance reasons.
#   * bds_atif - extra public threat intelligence feeds.
#   * cybercrime - curated feed of IPs linked to cybercriminal activity.
#   * etn_aggressive - blacklist of aggressive IPs maintained by Etnetera.
#       Listed in the Suricata IPS update rule source.
#
# Recommended additions for stronger IPv6 security (uncomment the lines in "blk6"):
#   * blocklist.de - aggregates actively abusive IPv6 hosts reported worldwide.
#   * AbuseIPDB - community-driven IPv6 abuse intelligence feed.
# See detailed descriptions of these lists in the corresponding IPv4 section above.
#
# Note:
#   All data sources listed under the same set name are aggregated using mapCIDR
#   (if available), so overlapping entries are deduplicated automatically
#   without impacting performance.
#
# Examples (IPv4):
#
#   # A high-priority passlist for WAN Firewall rules
#   # (overrides any blocklists or DoS Protection rules)
#   pss:
#     4.5.6.7                         # your VPS IPv4
#     11.12.13.14                     # your friend's home IPv4
#
#   # A custom list for other purposes
#   lst:
#     1.2.3.4/32                       # personal IPv4
#     https://example.com/list.txt    -H "Authorization: Bearer TOKEN"
#
# Examples (IPv6):
#
#   # A high-priority passlist for WAN Firewall rules
#   # (overrides any blocklists or DoS Protection rules)
#   pss6:
#     2001:db8:1:1::20                 # example VPS IPv6
#     2001:db8:1:1::30                 # example friend's home IPv6
#
#   # A custom list for other purposes
#   lst6:
#     2001:db8:2:1::42/128             # personal IPv6
#     https://example.com/list-v6.txt  -H "Authorization: Bearer TOKEN"
###################################################################################################
CUSTOM_IPSETS='
blk:
  https://iplists.firehol.org/files/firehol_level1.netset

  # Uncomment the URLs below for enhanced protection;
  # Replace YOUR_API_KEY for AbuseIPDB
  # https://iplists.firehol.org/files/firehol_level2.netset
  # https://iplists.firehol.org/files/firehol_level3.netset
  # https://api.abuseipdb.com/api/v2/blacklist -d plaintext -d ipVersion=4 -H "Key: YOUR_API_KEY"
  # https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt
  # https://iplists.firehol.org/files/bds_atif.ipset
  # https://iplists.firehol.org/files/cybercrime.ipset
  # https://security.etnetera.cz/feeds/etn_aggressive.txt
'

CUSTOM_V6_IPSETS='
blk6:
  https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
  https://www.spamhaus.org/drop/dropv6.txt

  # Uncomment the URLs below for enhanced protection;
  # Replace YOUR_API_KEY for AbuseIPDB
  https://lists.blocklist.de/lists/all.txt
  https://api.abuseipdb.com/api/v2/blacklist -d plaintext -d ipVersion=6 -H "Key: YOUR_API_KEY"
'

###################################################################################################
# 4. Killswitch rules (IPv4 & IPv6)
# -------------------------------------------------------------------------------------------------
# Temporarily block WAN ingress on specified ports:protos pairs during the first
# ipset initialization phase (e.g., after system boot), before filtering is active.
# This prevents exposure to unfiltered traffic while sets are still being built.
#
# IPv4 and IPv6 rules are defined separately in KILLSWITCH_RULES and
# KILLSWITCH_V6_RULES. Both lists share the same syntax and behavior.
#
# One rule per line (blank lines are ignored; # comments are allowed).
#
# Format:
#   ports:protos
#     * ports  -> can be a single number (e.g., 80), a comma-separated list (e.g., 80,443,123),
#                 or a dash-style range (e.g., 1000-2000)
#     * protos -> can be "tcp", "udp", or "any" (matches both tcp and udp)
#
# Examples:
#   80:tcp        # HTTP
#   123:udp       # NTP
#   443:any       # HTTPS with HTTP/3 support (both tcp and udp)
#   20-21:tcp     # FTP data/control
#   53,853:udp    # DNS and DoT
#
# Note:
#   "any" (as a port placeholder) and automatic port discovery are NOT supported
#   for killswitch ports. The killswitch must operate deterministically and
#   immediately, without relying on runtime inspection of existing firewall
#   rules or the current system state. For this reason, you must explicitly
#   list every port you want to block.
###################################################################################################
KILLSWITCH_RULES='
'

KILLSWITCH_V6_RULES='
'

###################################################################################################
# 5. WAN Firewall rules (ipset-based; IPv4 & IPv6)
# -------------------------------------------------------------------------------------------------
# One rule per line (blank lines are ignored; # comments are allowed).
#
# Format:
#   mode:ports:protos:set[,set...]:set_excl[,set_excl...][:minutes][:ip_count]
#
#   Country codes:
#     For country-based filtering, 'set' (or 'set_excl') can include ISO-3166-1 alpha-2
#     country codes (e.g., "us", "ca", "de") corresponding to the GeoLite2 or IPdeny datasets.
#     See the full list here (A-2 column, lowercase):
#       https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes
#     Codes must be lowercase and separated by commas when specifying multiple.
#     For IPv6 rules, country-based set names must include the "6" suffix (e.g., "us6", "de6").
#
#   mode     -> pass  | allow | block | log
#                pass  :  unconditional allow - traffic matching the listed set
#                         keys is immediately accepted and further firewall
#                         processing stops, skipping DoS Protection rules as well.
#                         Excludes (if any) are skipped from the match.
#                         Use only for highly trusted IPs (e.g., personal servers
#                         or a friend's home IP). This prevents them from being
#                         affected by any false positives in the blocklists, so
#                         place pass rules at the very top, as ordering determines
#                         priority.
#
#                allow :  allowlist - traffic matching the listed set keys is
#                         accepted and sent for further processing via DoS Protection
#                         rules (if enabled); anything else for the same proto/port
#                         is dropped. Excludes (if any) are skipped from the match.
#
#                block :  blocklist - traffic matching the listed set keys is
#                         dropped, unless matched by exclude sets (if given).
#                         All other traffic is left untouched.
#
#                log   :  log-only - matching traffic is logged.
#                         Excludes may be used to skip logging for trusted IPs.
#                         Intended mainly for debugging and abuse investigation.
#                         Supports the meta ipset key "any" to match all IPs
#                         (useful for logging all requests). Logging rate can be
#                         tuned with the 'minutes' and 'ip_count' arguments
#                         (see below).
#
#   ports    -> a single port          (e.g., 123)
#               a comma-separated list (e.g., 80,443)
#               a port range           (e.g., 1000-2000)
#               or the keyword  any    (matches all forwarded ports)
#
#   protos   -> tcp | udp | tcp,udp | any (alias for tcp,udp)
#
#   set      -> lowercase identifiers of pre-built <key> ipsets (main match set),
#               comma-separated, or "any" to match all IPs (supported only in
#               the "log" mode)
#
#   set_excl -> optional; set keys to exclude from matching (same format as keys);
#               leave blank if no exclusions
#
#   minutes  -> optional; only used for log mode; log rate limit window in minutes;
#               defaults to 5 if omitted
#
#   ip_count -> optional; only used for log mode; number of unique IPs to log per
#               window; defaults to 1 if omitted
#
# Logging:
#   When a rule in "log" mode matches, packets are logged. Logs are prefixed
#   with either "ips_" for IPv4 or "ips6_" for IPv6 and sent to syslog.
#   You can view them in the GUI (System Log -> General Log) or via CLI:
#       grep 'ips' /tmp/syslog.log
#   The prefix format is:
#     ips[6]_<ports>_<t|u>_<set>[_<set_excl>]
#   Examples: ips_80,443_t_blk   ips6_22_t_blk_exc1
#     - 6           -> present for IPv6 logs
#     - <ports>     -> original port spec (single, list, or range string)
#     - <t|u>       -> first letter of protocol (tcp/udp)
#     - <set>       -> keys list joined with underscores (e.g., blk,cn -> blk_cn)
#     - <set_excl>  -> optional; exclude keys joined with underscores (if any)
#
# Ordering:
#   Rules are inserted into iptables in the exact order they appear here.
#   Put high-priority or broad rules first (e.g., 'pass', 'block:any:any:...', or
#   wide 'allow' rules) so that subsequent, more specific rules are not shadowed
#   by earlier catch-all ACCEPT or DROP actions.
#
# Port ranges:
#   Recommended: if possible, forward only ports <= 32767 in the ASUS GUI, avoiding
#   higher port numbers. Ports >= 32768 are commonly used as ephemeral source ports by
#   major operating systems (Linux, macOS, iOS, Windows, Android). Staying at or below 32767
#   reduces edge cases where reply traffic from outbound connections might reuse the same
#   numbers as your forwarded services, keeping matching in raw PREROUTING unambiguous.
#
# Examples:
#   pass:any:any:pss                     # unconditionally allow matches from pss
#   block:any:any:blk,cn,kp              # drop traffic from blocklist, CN or KP
#   block:any:any:blk,cn,kp:exc1,exc2    # same as above, but skip exc1/2
#   allow:80,443:any:rly,us              # allow rly/US, drop others on ports 80/443
#   allow:1000-2000:tcp:ca               # allow CA, drop others on TCP ports 1000-2000
#   log:123:udp:any                      # log all NTP with 5 min window, 1 IP
#   log:123:udp:us::2:4                  # log US NTP with 2 min window, 4 IPs
###################################################################################################
WAN_FW_RULES='
block:any:any:blk
'

WAN_FW_V6_RULES='
block:any:any:blk6
'

###################################################################################################
# 6. DoS Protection rules (flood / DoS rate-limit; IPv4 & IPv6)
# -------------------------------------------------------------------------------------------------
# One rule per line (blank lines are ignored; # comments are allowed).
#
# Format:
#   mode:port:proto:above[:burst][:minutes][:log_count]
#     * mode      -> per_ip    (hashlimit-mode srcip)
#                    per_port  (hashlimit-mode dstport)
#     * port      -> destination port number
#     * proto     -> tcp | udp
#     * above     -> packets/sec threshold to begin throttling (hashlimit-above)
#     * burst     -> optional allowance before throttling kicks in (hashlimit-burst);
#                    defaults to 3 if omitted
#     * minutes   -> optional tracking window; defaults to 5 if omitted
#                    - drives hashlimit-htable-expire = minutes * 60000 ms
#                    - also feeds the per-IP logging rate
#     * log_count -> optional per_ip only; max log entries per offending IP
#                    across the window. Ignored (with a warning) for per_port mode.
#                    If omitted, defaults to 1 for per_ip
#
# Per-mode details:
#   * per_ip (srcip)
#       - Throttles each source IP independently.
#       - Logging additionally capped via '-m limit' using a rate derived from
#         (log_count / minutes) with a fixed burst of 1.
#         Example: 5 logs over 10 minutes = "1 per 2 minutes".
#       - Defaults: minutes=5, log_count=1, burst=3 -> about 3 log/IP every 5 minutes.
#
#   * per_port (dstport)
#       - Throttles aggregate traffic to the destination port.
#       - Logging is already constrained by the second hashlimit;
#         log_count is ignored here.
#       - Defaults: minutes=5, burst=3 -> about 3 log every 5 minutes for all IPs.
#
# Logging:
#   When a rule's threshold is exceeded, matching packets are logged. Logs are prefixed
#   with either "dos_" for IPv4 or "dos6_" for IPv6 and sent to syslog.
#   You can view them in the GUI (System Log -> General Log) or via CLI:
#       grep 'dos' /tmp/syslog.log
#   The prefix format is:
#     dos[6]_<ip|port>_<port>_<t|u>
#   Examples: dos_ip_443_t   dos6_port_123_u
#     - 6           -> present for IPv6 logs
#     - <ip|port>   -> threshold mode (per_ip or per_port)
#     - <port>      -> destination port (e.g., 443)
#     - <t|u>       -> first letter of protocol (tcp/udp)
#
# IMPORTANT:
#   * Put per_ip rules before overlapping per_port rules so individual sources are
#     throttled first and the per_port limiter acts only as a safety net.
#   * For IPv6 rules, define them separately in DOS_PROT_V6_RULES; both follow the
#     same syntax and semantics as IPv4.
#
# Reference for iptables hashlimit module options:
# https://ipset.netfilter.org/iptables-extensions.man.html#lbAY
#
# Examples:
#   per_ip:123:udp:100            # per_ip on UDP/123, burst defaults to 3
#   per_ip:123:udp:100:500        # per_ip on UDP/123 with explicit burst=500
#   per_ip:80:tcp:200:400:10:5    # per_ip with explicit window and per-rule log cap
#                                 # (5 logs across 10 minutes)
#   per_port:123:udp:3333         # per_port, burst defaults to 3 (log_count ignored)
###################################################################################################
DOS_PROT_RULES='
'

DOS_PROT_V6_RULES='
'

###################################################################################################
# 7. Tunnel Director rules (ipset-based; IPv4-only)
# -------------------------------------------------------------------------------------------------
# One rule per line (blank lines are ignored; # comments are allowed).
#
# Format:
#   table:src[%iface][:src_excl[,src_excl...]]:set[,set...][:set_excl[,set_excl...]]
#     * table    -> routing table name (must exist in /etc/iproute2/rt_tables,
#                   or be the special main table).
#                   Allowed: wgcN, ovpncN, main
#                   Example: wgc1, ovpnc2, main
#                   NOTE: see below for details on routing tables.
#
#     * src      -> LAN source subnet (CIDR) whose traffic is eligible
#                   Must be a private RFC1918 subnet.
#                   Example: 192.168.50.0/24, 192.168.50.2/32
#
#     * iface    -> optional; bind the rule to a specific LAN ingress interface.
#                   If omitted, defaults to "br0" (the main LAN bridge).
#                   Useful for routers with SDN (Self-Defined Network), which can
#                   define multiple LAN bridges (main LAN + VLANs).
#                   Example: br0, br52
#
#     * src_excl -> optional; comma-separated list of subnets to exclude from the source.
#                   Example: 192.168.50.10/32,192.168.50.20/32
#
#   * set        -> comma-separated list of ipset keys (countries or custom), or the
#                   special meta ipset "any" which matches all traffic regardless of
#                   destination. When using "any", destination checks are skipped entirely.
#                   Examples: us,ubl,any
#                   NOTE: see below for details on country sets.
#
#     * set_excl -> optional; comma-separated ipset keys to exclude from destination match.
#                   Example: ca_excl
#
# VPN/WAN routing tables:
#   * WireGuard: use wgcN (N = client number in the ASUS GUI;
#     up to 5 clients in Asuswrt-Merlin: wgc1..wgc5).
#       - NAT must be enabled for the client in the ASUS GUI.
#   * OpenVPN: use ovpncN (N = client number in the ASUS GUI;
#     up to 5 clients in Asuswrt-Merlin: ovpnc1..ovpnc5).
#       - NAT must be enabled for the client in the ASUS GUI.
#       - "Redirect Internet traffic through tunnel" must be set to
#         "VPN Director / Guest Network" for the selected client.
#   * WAN (direct routing): use main.
#
# Standard vs extended country sets:
#   * There are two types of country sets used under the hood:
#       - Standard sets  -> include networks where the GeoLite2 block's geoname_id
#                           or represented_country_geoname_id matches the country.
#       - Extended sets  -> include everything from the standard set, plus networks
#                           where the registered_country_geoname_id matches.
#                           These sets carry the "_ext" suffix internally,
#                           but you should still write plain 2-letter codes (e.g., "us").
#                           Tunnel Director automatically prefers "us_ext" when
#                           available, falling back to "us" if not.
#   * Why it matters:
#       - Standard sets are tighter and follow the geolocation used by MaxMind.
#         Best for blocking (to avoid pulling in global infra like CDNs).
#       - Extended sets are broader: they also include ranges registered in
#         that country, even if traffic geolocates elsewhere. This typically adds
#         hosting, ISP, or CDN ranges that are registered in the country,
#         even if geolocation places them elsewhere. Best for tunnels, where you
#         want to capture "all traffic associated with a country", not just strictly
#         geolocated blocks.
#   * Availability: extended sets require GeoLite2 (MAXMIND_LICENSE_KEY and
#     external storage). With IPdeny provider, only standard sets exist.
#   * IMPORTANT: Do not specify "_ext" manually. Always use plain country codes
#     (e.g., "us"). The script substitutes to "us_ext" automatically if present.
#
# Ordering:
#   Rules are inserted into routing tables (starting at 16384) and iptables
#   in the exact order they appear here. Put high-priority rules first,
#   so that subsequent, more specific rules are not shadowed by earlier catch-all rules.
#
# Examples:
#   1. Inclusion policy (send all traffic from the main LAN via VPN, but only
#      when destinations are in certain ipsets, excluding one LAN device):
#        wgc1:192.168.50.0/24:192.168.50.10/32:us,ubl
#        -> Route all devices in 192.168.50.0/24 via wgc1, but only
#           for destinations in the US and in the custom ipset "ubl".
#           Device 192.168.50.10 is excluded and always routed via WAN.
#
#   2. Exclusion policy (send a specific VLAN device via VPN, except for some countries):
#        wgc1:192.168.52.10/32%br52::any:us,ca
#        -> Route all traffic from device 192.168.52.10 (on VLAN br52) via wgc1
#           for all destinations, but exclude the US and Canada.
#           Packets to US/CA bypass the tunnel and follow normal WAN routing.
###################################################################################################
TUN_DIR_RULES='
'

###################################################################################################
# 8. Timing logic
# -------------------------------------------------------------------------------------------------
# Controls boot-time delay to avoid running the IPSet Builder stack during early startup.
#
# * MIN_BOOT_TIME   - minimum system uptime (in seconds) considered "just after boot".
#                     If uptime is less than this, a delay is triggered.
# * BOOT_WAIT_DELAY - pause duration (in seconds) before proceeding when the above
#                     condition is met. You can set it to 0 to disable the boot delay
#                     completely (not recommended).
#
# Why this matters:
#   - Ensures the network stack and WAN link are fully initialized after a cold start
#     (some modems take time to sync and provide connectivity).
#   - Allows IPSet Builder to fetch or update external files (e.g., ipset lists)
#     before rules are applied, avoiding failures from missing dependencies.
#   - Reduces CPU and I/O contention during boot, preventing IPSet Builder
#     from slowing down other critical router services starting in parallel.
#
# Tuning:
#   The default values provide a safe balance. Advanced users may decrease
#   BOOT_WAIT_DELAY (e.g., to ~30 seconds) if their network stack comes up quickly.
#   Setting it to 0 disables the delay entirely, which is possible but not recommended.
#
# Note:
#   If the killswitch flag (-k) is enabled, it is applied before the pause
#   to block unfiltered traffic during the wait period.
###################################################################################################
MIN_BOOT_TIME=120
BOOT_WAIT_DELAY=60

###################################################################################################
# 9. hashlimit tuning
# -------------------------------------------------------------------------------------------------
# Controls the size and behavior of the hashlimit tracking table used for rate limiting.
#
# * HTABLE_SIZE - number of buckets (should be a power of 2 for optimal hashing).
# * HTABLE_MAX  - maximum number of tracked entries (oldest are evicted if exceeded).
#
# This determines how many distinct sources (e.g., IPs or ports) can be concurrently
# tracked by hashlimit rules. Set high enough to handle peak concurrent clients.
###################################################################################################
HTABLE_SIZE=131072
HTABLE_MAX=131072

###################################################################################################
# 10. Firewall chain & routing constants
# -------------------------------------------------------------------------------------------------
# Defines the iptables chain names and routing constants used by the WAN Firewall,
# Tunnel Director, and IPSet Builder.
#
#   * VSERVER_CHAIN        - contains the router's port-forwarding rules as managed
#                            by the ASUS firmware (GUI-configured).
#   * KILLSWITCH_CHAIN     - temporarily drops all inbound traffic during the initial
#                            ipset build to prevent unfiltered exposure.
#   * FILTERING_CHAIN      - main entry point for inbound filtering logic; hooked into
#                            raw PREROUTING immediately after the killswitch (if active).
#   * IPSET_CHAIN          - subchain dedicated to ipset-based filtering
#                            (geo-blocking, custom lists, threat feeds).
#
#   * TUN_DIR_CHAIN_PREFIX - prefix for Tunnel Director per-rule chains created in mangle,
#                            e.g., TUN_DIR_16384, TUN_DIR_16385, ...
#   * TUN_DIR_PREF_BASE    - base preference number for Tunnel Director ip rules.
#                            Each rule increments from here (e.g., 16384, 16385, ...).
#                            The base of 16384 is chosen deliberately so that
#                            Tunnel Director rules have lower priority than Asuswrt-Merlin's
#                            VPN Director rules or ASUS SDN policies, ensuring
#                            they don't override system-level routing decisions.
#   * TUN_DIR_MARK_MASK    - bitmask of the nfmark field owned by Tunnel Director.
#                            Default: 0x00ff0000 (bits 16–23).
#                            This reserves an 8-bit "slot field" inside the 32-bit mark.
#                            Slot 0 = "unmarked by TD"; slots 1..255 = rule IDs.
#                            We always write marks with --set-xmark <value>/<mask>, so only
#                            these bits change; other applications' bits are preserved.
#   * TUN_DIR_MARK_SHIFT   - left shift applied when encoding the slot into the field above.
#                            Default: 16, aligning slot N to value (N << 16), i.e.
#                            0x00010000, 0x00020000, ... 0x00ff0000.
#
# Detailed explanation about Tunnel Director marks (advanced info, usually not required
# for normal operation, and can be safely skipped if not relevant):
#   * How first-match-wins and coexistence with other marks is ensured:
#       - PREROUTING jumps into each TUN_DIR_* chain are guarded with:
#           -m mark --mark 0x0/TUN_DIR_MARK_MASK
#         so a chain is only evaluated if TD's slot field is still zero.
#       - When a rule matches, the slot is set via:
#           --set-xmark <slot<<SHIFT>/<MASK>
#         which fills only TD's bits, leaving all other nfmark bits intact
#         (QoS, vendor flags, DPI, etc.). Since later jumps see a non-zero slot,
#         they are skipped -> first match wins.
#   * Why these defaults:
#       - Bits 16–23 are rarely used by firmware features on Asuswrt-Merlin,
#         while bit 0 is often used by system rules.
#         Reserving bits 16–23 provides a safe, isolated 8-bit field
#         that supports up to 255 Tunnel Director rules without collisions.
#   * When to change MARK_MASK/SHIFT (advanced):
#       - If >255 rules are required, choose a wider contiguous field
#         (e.g., 0x0fff0000 with SHIFT=16).
#       - If another component already uses bits 16–23, move TD's field
#         elsewhere (e.g., 0x0000ff00 with SHIFT=8).
#       - REQUIREMENTS:
#           * MASK must be contiguous (e.g., 0x0000ff00, not disjoint).
#           * SHIFT must equal the number of trailing zero bits in MASK.
#           * Reapply/rebuild rules after changing.
#
# Note:
#   All chains except VSERVER_CHAIN are created and maintained automatically
#   by these scripts.
###################################################################################################
VSERVER_CHAIN='VSERVER'
KILLSWITCH_CHAIN='VSERVER_KILLSWITCH'
FILTERING_CHAIN='WAN_FILTERING'
IPSET_CHAIN='IPSET_FILTERING'

TUN_DIR_CHAIN_PREFIX='TUN_DIR_'
TUN_DIR_PREF_BASE=16384
TUN_DIR_MARK_MASK=0x00ff0000
TUN_DIR_MARK_SHIFT=16

###################################################################################################
# 11. Make all public configuration constants read-only
# -------------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
###################################################################################################
readonly \
    IPS_BDR_DIR \
    MAXMIND_LICENSE_KEY \
    CUSTOM_IPSETS CUSTOM_V6_IPSETS \
    KILLSWITCH_RULES KILLSWITCH_V6_RULES \
    WAN_FW_RULES WAN_FW_V6_RULES \
    DOS_PROT_RULES DOS_PROT_V6_RULES \
    TUN_DIR_RULES \
    MIN_BOOT_TIME BOOT_WAIT_DELAY \
    HTABLE_SIZE HTABLE_MAX \
    VSERVER_CHAIN KILLSWITCH_CHAIN FILTERING_CHAIN IPSET_CHAIN \
    TUN_DIR_CHAIN_PREFIX TUN_DIR_PREF_BASE
