#!/usr/bin/env ash

##############################################################################################
# config.sh - shared configuration for wan_firewall.sh and ipset_builder.sh
# --------------------------------------------------------------------------------------------
# APPLYING CHANGES:
#   Any modification to this file will NOT take effect until reloaded.
#   You can apply changes in either of two ways:
#     * Run 'ipb' (helper alias) - recommended (reloads without reboot).
#     * Reboot the router - slower, but also works.
##############################################################################################

# --------------------------------------------------------------------------------------------
# Disable unneeded shellcheck warnings
# --------------------------------------------------------------------------------------------
# shellcheck disable=SC2034

##############################################################################################
# 1. Download & dump path
# --------------------------------------------------------------------------------------------
# * If DATA_DIR points to external storage (e.g. /mnt/...):
#     - BusyBox and mapCIDR are bootstrapped into $DATA_DIR/bin,
#       enabling GeoLite2 country ipset generation and CIDR aggregation.
# * If DATA_DIR is on internal flash (e.g. /jffs/...):
#     - these binaries are not installed;
#       GeoLite2 falls back to IPdeny feeds, and aggregation is disabled.
# * Dump files (saved ipset snapshots) are stored under $DATA_DIR/dumps.
# * Using external storage for DATA_DIR:
#     - preserves the router's internal flash (JFFS).
#     - provides sufficient space for both binaries and dump files.
#
# IMPORTANT: It's highly recommended to change this path to your external storage
# (e.g. '/mnt/st5/wan_firewall').
##############################################################################################
DATA_DIR='/jffs/wan_firewall'

##############################################################################################
# 2. MaxMind License Key for GeoLite2
# --------------------------------------------------------------------------------------------
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
##############################################################################################
MAXMIND_LICENSE_KEY=''

##############################################################################################
# 3. Custom ipsets
# --------------------------------------------------------------------------------------------
# Define named ipsets, each containing inline CIDRs and/or remote sources.
#
# Format:
#   <set_name>:
#     * Inline CIDR entries (e.g. 1.2.3.4/32), optionally followed by comments (#).
#     * Remote URLs (http/https) returning plain-text CIDR lists:
#       - You may append curl options (e.g. -H, -d) to support headers, API keys, etc.
#
# Naming guidance:
#   * Prefer 3-letter set names (not strictly required). Two-letter names are commonly
#     used for country codes, and short names help stay within the total ipset name
#     length limit when multiple ipsets are combined into a single combo set.
#   * If a set name or a generated combo set name exceeds 31 characters, it will be
#     automatically truncated and replaced with a 24-character hash. This ensures the
#     firewall remains fully operational, but makes logs harder to read. For this reason,
#     shorter and more descriptive names are recommended whenever possible, so that
#     syslog output stays human-readable.
#
# Default list:
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
# Recommended additions for stronger security (uncomment the lines in "blk"):
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
# Note:
#   All data sources listed under the same set name are aggregated using mapCIDR
#   (if available), so overlapping entries are deduplicated automatically
#   without impacting performance.
#
# Examples:
#
#   # A high-priority passlist for IPSET_RULES
#   # (overrides any blocklists or DoS rules)
#   pss:
#     4.5.6.7                         # your VPS IP
#     11.12.13.14                     # your friend's home IP
#
#   # A custom list for other purposes
#   lst:
#     1.2.3.4/32                       # personal IP
#     https://example.com/list.txt    -H "Authorization: Bearer TOKEN"
##############################################################################################
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

##############################################################################################
# 4. ipset rules
# --------------------------------------------------------------------------------------------
# One rule per line (blank lines are ignored). Format:
#   mode:ports:protos:keys[,keys...]:excludes[,excludes...][:minutes][:ip_count]
#
#   Country codes:
#     For country-based filtering, 'keys' (or 'excludes') can include ISO-3166-1 alpha-2
#     country codes (e.g. us, ca, de) corresponding to the GeoLite2 or IPdeny datasets.
#     See the full list here (A-2 column, lowercase):
#       https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes
#     Codes must be lowercase and separated by commas when specifying multiple.
#
#   mode     -> pass  | allow | block | log
#                pass  :  unconditional allow - traffic matching the listed set
#                         keys is immediately accepted and further firewall
#                         processing stops, skipping DoS rules as well.
#                         Excludes (if any) are skipped from the match.
#                         Use only for highly trusted IPs (e.g. personal servers
#                         or a friend's home IP). This prevents them from being
#                         affected by any false positives in the blocklists, so
#                         place pass rules at the very top, as ordering determines
#                         priority.
#
#                allow :  allowlist - traffic matching the listed set keys is
#                         accepted and sent for further processing via DoS rules
#                         (if enabled); anything else for the same proto/port
#                         is dropped. Excludes (if any) are skipped from the match.
#
#                block :  blocklist - traffic matching the listed set keys is
#                         dropped, unless matched by exclude sets (if given).
#                         All other traffic is left untouched.
#
#                log   :  log-only - matching traffic is logged.
#                         Excludes may be used to skip logging for trusted IPs.
#                         Intended mainly for debugging and abuse investigation.
#                         Supports the meta ipset key 'any' to match all IPs
#                         (useful for logging all requests). Logging rate can be
#                         tuned with the 'minutes' and 'ip_count' arguments
#                         (see below).
#
#   ports    -> a single port          (e.g. 123)
#               a comma-separated list (e.g. 80,443)
#               a port range           (e.g. 1000-2000)
#               or the keyword  any    (matches all forwarded ports)
#
#   protos   -> tcp | udp | tcp,udp | any (alias for tcp,udp)
#
#   keys     -> lowercase identifiers of pre-built <key> ipsets (main match set),
#               comma-separated
#
#   excludes -> optional; set keys to exclude from matching (same format as keys);
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
#   with 'ips_' and go to syslog. View them in the GUI (System Log ->
#   General Log) or via CLI: `grep ips_ /tmp/syslog.log`.
#   The prefix format is:
#     ips_<ports>_<t|u>_<set>[_<excl_set>]
#   Examples: ips_80,443_t_blk   ips_22_t_blk_exc1
#     - <ports>     -> original port spec (single, list, or range string)
#     - <t|u>       -> first letter of protocol (tcp/udp)
#     - <set>       -> keys list joined with underscores (e.g., blk,cn -> blk_cn)
#     - <excl_set>  -> optional; exclude keys joined with underscores (if any)
#
# Ordering:
#   Rules are inserted into iptables in the exact order they appear here.
#   Put high-priority or broad rules first (e.g. 'pass', 'block:any:any:...', or
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
##############################################################################################
IPSET_RULES='
block:any:any:blk
'

##############################################################################################
# 5. Killswitch rules
# --------------------------------------------------------------------------------------------
# Temporarily block WAN ingress on specified ports:protos pairs during the first
# ipset initialization phase (e.g. after system boot), before filtering is active.
# This prevents exposure to unfiltered traffic while sets are still being built.
#
# Format:
#   ports:protos
#     * ports  -> can be a single number (e.g. 80), a comma-separated list (e.g. 80,443,123),
#                 or a dash-style range (e.g. 1000-2000)
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
######################################################################################
KILLSWITCH_RULES='
'

##############################################################################################
# 6. Flood / DoS rate-limit
# --------------------------------------------------------------------------------------------
# One rule per line (blank lines are ignored; comments are allowed).
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
#   When a rule's threshold is crossed, matching packets are logged. Logs are
#   prefixed with 'dos_' and go to syslog. View them in the GUI (System Log ->
#   General Log) or via CLI: `grep dos_ /tmp/syslog.log`.
#   The prefix format is:
#     dos_<ip|port>_<port>_<t|u>
#   Examples: dos_ip_443_t   dos_port_123_u
#     - <ip|port>  -> per_ip or per_port mode
#     - <port>     -> destination port (e.g., 443)
#     - <t|u>      -> first letter of protocol (tcp/udp)
#
# IMPORTANT:
#   * Put per_ip rules before overlapping per_port rules so individual sources are
#     throttled first and the per_port limiter acts only as a safety net.
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
##############################################################################################
DOS_RULES='
'

##############################################################################################
# 7. Timing logic
# --------------------------------------------------------------------------------------------
# Controls boot-time delay to avoid running the ipset builder stack during early startup.
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
#   - Allows the ipset builder to fetch or update external files (e.g. ipset lists)
#     before rules are applied, avoiding failures from missing dependencies.
#   - Reduces CPU and I/O contention during boot, preventing ipset builder
#     from slowing down other critical router services starting in parallel.
#
# Tuning:
#   The default values provide a safe balance. Advanced users may decrease
#   BOOT_WAIT_DELAY (e.g. to ~30 seconds) if their network stack comes up quickly.
#   Setting it to 0 disables the delay entirely, which is possible but not recommended.
#
# Note:
#   If the killswitch flag (-k) is enabled, it is applied before the pause
#   to block unfiltered traffic during the wait period.
##############################################################################################
MIN_BOOT_TIME=120
BOOT_WAIT_DELAY=60

##############################################################################################
# 8. hashlimit tuning
# --------------------------------------------------------------------------------------------
# Controls the size and behavior of the hashlimit tracking table used for rate limiting.
#
# * HTABLE_SIZE - number of buckets (should be a power of 2 for optimal hashing).
# * HTABLE_MAX  - maximum number of tracked entries (oldest are evicted if exceeded).
#
# This determines how many distinct sources (e.g. IPs or ports) can be concurrently
# tracked by hashlimit rules. Set high enough to handle peak concurrent clients.
##############################################################################################
HTABLE_SIZE=65536
HTABLE_MAX=262144

##############################################################################################
# 9. ipset hash:net tuning
# --------------------------------------------------------------------------------------------
# Controls memory allocation and capacity for hash:net ipsets (used for CIDR-based sets).
#
# * IPSET_HASH_SIZE  - number of hash buckets (should be a power of 2 for efficient lookup).
# * IPSET_MAX_ELEM   - maximum number of CIDR entries allowed in the set.
#
# Sizing rationale:
#   - Largest current country set ("ru") contains ~13k CIDRs after aggregation.
#   - Values provide ample headroom for growth, including large custom blocklists.
#   - Still safely below the kernel's default global limit (16 million elements).
##############################################################################################
IPSET_HASH_SIZE=65536
IPSET_MAX_ELEM=131072

##############################################################################################
# 10. Firewall chain names
# --------------------------------------------------------------------------------------------
# Defines the iptables chain names used for inbound filtering.
#
# * VSERVER_CHAIN    - chain containing the router's port-forwarding rules as
#                      managed by the ASUS firmware (GUI-configured).
# * KILLSWITCH_CHAIN - temporarily drops all inbound traffic during initial ipset
#                      build to prevent unfiltered exposure.
# * FILTERING_CHAIN  - main entry point for inbound filtering logic; hooked into
#                      raw PREROUTING immediately after the killswitch (if active).
# * IPSET_CHAIN      - subchain dedicated to ipset-based filtering (geo-blocking,
#                      custom lists, threat feeds).
#
# All chains - except for VSERVER_CHAIN - are created and maintained automatically
# by this script.
##############################################################################################
VSERVER_CHAIN='VSERVER'
KILLSWITCH_CHAIN='VSERVER_KILLSWITCH'
FILTERING_CHAIN='VSERVER_FILTERING'
IPSET_CHAIN='IPSET_FILTERING'

##############################################################################################
# 11. Make all public configuration constants read-only
# --------------------------------------------------------------------------------------------
# Prevents accidental modification of critical config values at runtime.
##############################################################################################
readonly \
    DATA_DIR \
    MAXMIND_LICENSE_KEY \
    CUSTOM_IPSETS \
    IPSET_RULES \
    KILLSWITCH_RULES \
    DOS_RULES \
    MIN_BOOT_TIME BOOT_WAIT_DELAY \
    HTABLE_SIZE HTABLE_MAX \
    IPSET_HASH_SIZE IPSET_MAX_ELEM \
    VSERVER_CHAIN KILLSWITCH_CHAIN FILTERING_CHAIN IPSET_CHAIN
