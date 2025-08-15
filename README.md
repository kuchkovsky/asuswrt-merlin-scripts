# Asuswrt-Merlin Script Collection

A set of shell scripts that extend the functionality of routers running **[Asuswrt-Merlin](https://www.asuswrt-merlin.net/)**.
Each script lives in `/jffs/scripts` and integrates with Merlin's built-in hook system
(`services-start`, `nat-start`, `wgclient-start`, etc.).

> **Firmware requirement**: these scripts depend on Merlin's custom script framework and
  will **not** run on stock ASUS firmware.


## General Information & Disclaimers

* Scripts are provided **as-is**; review the code before deployment.
* The code and configuration files are extensively commented - *read them carefully* to understand
  how each script works and how to adapt it to your environment. In most cases, you'll find all the
  details you need directly inside the script headers or `config.sh`.
* Adjust IPs, subnets, filesystem labels, and USB vendor IDs to match your own setup. If you remove
  a script you don't use, also delete any references to it in related hook or event-handler files.
* **`send_email.sh`** (used by WAN failover, startup notifications, and ipset builder retry alerts)
  requires that email is preconfigured in **`amtm`** before running these scripts.
* Network-related scripts are IPv4-only since my ISP doesn't support IPv6 yet.
  I'll add IPv6 support once I can properly test it.

## Prerequisites

1. **Flash Asuswrt-Merlin** to your router.
2. **Enable SSH** (*Administration → System → Enable SSH = "LAN only"*). Strongly recommended to use key-based auth
   (ed25519 or RSA) and a non-default port.
3. **Enable custom scripts/configs** (*Administration → System → Enable JFFS custom scripts and configs = "Yes"*).
4. **Clone the repository** to your local machine:
```bash
git clone https://github.com/kuchkovsky/asuswrt-merlin-scripts.git
```


## Uploading the updated scripts to your router
Before applying these steps, make sure you've reviewed the scripts described in the next sections
and adjusted their configuration to fit your own environment. Once configured, follow these commands
to safely upload and activate them on your router:
```sh
# On your machine
cd asuswrt-merlin-scripts

# Backup your router's current /jffs directory
# (recommended before overwriting anything)
scp -O -r admin@<router-ip>:/jffs/ jffs_backup/

# ⚠️ WARNING:
# The next command will overwrite files in /jffs on your router
# with those from your local jffs directory.
# It is strongly recommended to merge configs first:
#   - Compare jffs_backup/configs/* with your local jffs/configs/*
#   - Compare jffs_backup/scripts/* with your local jffs/scripts/*
# Merge any differences into your local jffs before proceeding.
scp -O -r jffs/* admin@<router-ip>:/jffs/

# On your router (SSH session)
chmod -R a+rx /jffs/scripts
reboot
```


## Table of Contents

1. [Inbound WAN Firewall (ipset-based blocking & DoS-protection)](#1-inbound-wan-firewall-ipset-based-blocking--dos-protection)
2. [Tunnel Director (ipset-based policy routing)](#2-tunnel-director-ipset-based-policy-routing)
3. [WireGuard Client Port Forwarder](#3-wireguard-client-port-forwarder)
4. [Dual WAN email notifications & optional LAN host blocking](#4-dual-wan-email-notifications--optional-lan-host-blocking)
5. [Automatic USB SSD trimming](#5-automatic-usb-ssd-trimming)
6. [nextdns-cli integration for SDNs & automatic updates](#6-nextdns-cli-integration-for-sdns--automatic-updates)
7. [Traffic Monitor table patch (Kb/s & Mb/s)](#7-traffic-monitor-table-patch-kbs--mbs)
8. [Router startup notification](#8-router-startup-notification)
9. [Shared utilities](#9-shared-utilities)


## 1. Inbound WAN Firewall (ipset-based blocking & DoS-protection)

> **Prerequisites:**
> 1. Designed for use only when port forwarding is enabled - it has no effect otherwise.
> 2. The WAN interface must receive a **public IP directly** (no double NAT).
> 3. Country blocking with [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
>    requires a `MAXMIND_LICENSE_KEY` and external USB storage; otherwise,
>    [IPdeny](https://www.ipdeny.com/ipblocks/) will be used.
> 4. The CIDR aggregation feature requires external USB storage for the
>    [mapCIDR](https://github.com/projectdiscovery/mapcidr) binary;
>    otherwise, IP ranges won't be aggregated.

* [**`wan_firewall.sh`**](jffs/scripts/firewall/wan_firewall.sh) - **high-performance inbound firewall for Asuswrt-Merlin**
  that applies only the TCP/UDP ports you actually forward in the GUI. It provides **country blocking,
  malicious IP filtering, spoofed traffic protection, and optional per-IP/per-port DoS rate limiting**
  before packets hit DNAT, conntrack, or routing - protecting your public services with minimal overhead.
  
  **By default, it uses [FireHOL Level 1](https://iplists.firehol.org/?ipset=firehol_level1) as a baseline**
  against spoofed traffic and common attack sources for minimal false positives. **Includes predefined but commented-out
  rules for stronger protection** (FireHOL Level 2/3, AbuseIPDB, IPsum, etc.) that you can enable as needed.
  
  Features **ipset aggregation** using [mapCIDR](https://github.com/projectdiscovery/mapcidr) for maximum performance
  (handled by the [`ipset_builder.sh`](jffs/scripts/firewall/ipset_builder.sh) module - see details below),
  and **fully customizable rules** for the forwarded ports. An **optional killswitch** prevents your services
  from being exposed before the initial ipset build/restore completes on system boot.
  
  On download or ipset build failure, **retries via cron and sends email alerts**;
  on success, cancels retries and sends a resolution notification.

  #### Main features
  * **Bogon traffic drop**  
    - Discards spoofed traffic from reserved/unroutable IPv4 ranges (RFC 6890, 1918, 3927, 6598, etc.) before conntrack,
      saving CPU and avoiding table pollution.
  * **Country blocking with high-accuracy [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)**  
    - Uses [MaxMind's](https://www.maxmind.com/en/home) free [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
      database (weekly updates, multi-source verification) for some of the most accurate country-to-IP mappings available.  
    - Falls back to [IPdeny](https://www.ipdeny.com/ipblocks/) feeds if you don't set a `MAXMIND_LICENSE_KEY`.  
    - Blocks entire countries from reaching your forwarded ports - useful for cutting off high-risk regions entirely.
  * **Custom ipsets for malicious source blocking**  
    - Pulls in threat intelligence feeds you choose **directly from URLs** - e.g. AbuseIPDB, IPsum, DShield, Greensnow.
      Can also use **custom hardcoded IP lists** defined directly in the configuration file.
    - Supports downloads from **any source**, including the **API key protected ones** by allowing you to specify
      custom `curl` arguments like headers, so you can integrate paid or authenticated feeds without modifying the script. 
    - Ships with [**FireHOL Level 1**](https://iplists.firehol.org/?ipset=firehol_level1) enabled as a baseline:
      curated bogon, abuse, and attack-source list designed for minimal false positives.  
    - Includes [predefined](jffs/scripts/firewall/config.sh) (commented out by default) high-impact feeds for stronger protection:
      * [**FireHOL Level 2**](https://iplists.firehol.org/?ipset=firehol_level2) - broader threat coverage,
        focusing on active attacks from the last ~48 hours (blocklist_de, dshield_1d, greensnow).  
      * [**FireHOL Level 3**](https://iplists.firehol.org/?ipset=firehol_level3) - even more aggressive,
        covering up to ~30 days of attack, spyware, and malware activity (bruteforceblocker, ciarmy,
        dshield_30d, myip, vxvault).  
      * [**AbuseIPDB**](https://www.abuseipdb.com) - daily feed of the 10,000 most-reported abusive IPs
        with 100% confidence scores.  
      * [**IPsum**](https://github.com/stamparm/ipsum) - aggregate of ~30 trusted threat feeds;
        Level 2/3 variants require IPs to appear in at least 2 or 3 sources to reduce false positives.  
      * [**bds_atif**](https://iplists.firehol.org/?ipset=bds_atif) - public threat intelligence feeds
        targeting malicious activity.  
      * [**cybercrime**](https://iplists.firehol.org/?ipset=cybercrime) - curated list of IPs linked
        to cybercriminal infrastructure.  
      * [**etn_aggressive**](https://security.etnetera.cz/feeds/etn_aggressive.txt) - aggressive IP blacklist
        maintained by [Etnetera](https://www.etnetera.cz/en/security) and commonly used by
        [Suricata IDS/IPS](https://docs.rocknsm.io/services/suricata/#enabling-feeds),
        listing abusive and scanning hosts.
    - Example rules:
      ```
      # Each set starts with a name ending with a colon
      blk:
        https://iplists.firehol.org/files/firehol_level1.netset

      # Multiple sources can be combined into one set
      mal:
        https://example.com/malware_feed.txt
        https://another-feed.com/list.txt -H "Authorization: Bearer API_KEY"
        1.2.3.4/32     # inline CIDR entry
    
      # You can define a passlist for highly-trusted sources
      pss:
        4.5.6.7        # your VPS IP
        11.12.13.14    # your friend's home IP
      ```
  * **Flexible ipset-based WAN Firewall rules**  
    - Defines filtering behavior using a clear rule format:  
      **`mode:ports:protos:set[,set...]:set_excl[,set_excl...][:minutes][:ip_count]`**  
      where:  
      - `mode` → `pass`, `allow`, `block`, or `log`  
      - `ports` → one or more ports or ranges (`80,443`, `1000-2000`)  
      - `protos` → `tcp`, `udp`, or `any`  
      - `set` → one or more country or custom ipsets  
      - `set_excl` → optional sets to exempt from a match  
      - `minutes` / `ip_count` → optional logging controls (for `log` rules only)  
    - Behavior of modes:  
      - **`pass`** → unconditionally allow trusted sources and bypass all further filtering (including DoS rate limits).  
      - **`allow`** → permit traffic only from the listed sets; drop all others for the specified ports/protocols.  
      - **`block`** → drop traffic from the listed sets unless explicitly excluded.  
      - **`log`** → record matching traffic for analysis without dropping it. Adjustable logging frequency via `minutes`
        (time window) and `ip_count` (max logs per IP). Packets are logged to syslog with
        the `ips_` prefix (`ips_80,443_t_blk`, `ips_22_t_blk_exc1`).  
    - Features:  
      - **Excludes** let you carve out trusted or special-case sets within a broader rule.
      - **Rule order matters**: place broad/global rules (e.g., passlists, global blocks) before more specific matches.  
    - Example rules:  
      ```
      pass:any:any:pss                     # unconditionally allow matches from pss
      block:any:any:blk,cn,kp              # drop traffic from blocklist, CN or KP
      block:any:any:blk,cn,kp:exc1,exc2    # same as above, but exempt exc1/2
      allow:80,443:any:rly,us              # allow rly/US, drop others on 80/443
      allow:1000-2000:tcp:ca               # allow CA on TCP 1000-2000
      log:123:udp:any                      # log all NTP with 5 min window, 1 IP
      log:123:udp:us::2:4                  # log US NTP with 2 min window, 4 IPs
      ```
  * **Optional per-IP / per-port DoS Protection**  
    - Adds selective throttling against high-rate connection attempts using the `xt_hashlimit` module.  
    - Defines rate-limiters using a clear rule format:  
      **`mode:port:proto:above[:burst][:minutes][:log_count]`**  
      where:  
      - `mode` → limiter mode (`per_ip` or `per_port`)  
          * **`per_ip`** → limits new connection rates per source IP (`--hashlimit-mode srcip`),
          ideal against individual abusive hosts.  
          * **`per_port`** → limits aggregate new connection rates to a destination port (`--hashlimit-mode dstport`),
          useful as a global safety net.  
      - `port` → destination port  
      - `proto` → `tcp` or `udp`  
      - `above` → packets-per-second threshold that triggers throttling  
      - `burst` → optional number of packets allowed before throttling begins (default: 3)  
      - `minutes` → optional tracking window (default: 5 minutes)  
      - `log_count` → optional, `per_ip` only; max logs per offending IP per window (default: 1)  
    - Logging:  
      - Offending packets are logged to syslog with the `dos_` prefix (`dos_ip_443_t`, `dos_port_123_u`).  
      - Logging is automatically rate-limited to prevent log floods.  
    - Best practice:  
      - Place **`per_ip`** rules before any overlapping **`per_port`** rules so attackers are throttled
        individually before aggregate limits apply.  
    - Example rules:  
      ```
      per_ip:123:udp:100            # per_ip on UDP/123, burst defaults to 3
      per_ip:123:udp:100:500        # per_ip on UDP/123 with explicit burst=500
      per_ip:80:tcp:200:400:10:5    # per_ip with explicit window and per-rule log cap
                                    # (5 logs across 10 minutes)
      per_port:123:udp:3333         # per_port, burst defaults to 3 (log_count ignored)
      ```
  * **Dynamic targeting & early filtering**  
    - Auto-detects forwarded ports from the GUI and filters only those.  
    - All filtering happens in the `raw` table for earliest possible drop.
  * **Smart rule tracking & idempotence**  
    - Computes hashes of current vs. desired rule sets.  
    - Applies changes only when needed, avoiding redundant reloads and keeping the firewall stable.

  #### Why it matters
  * **Blocks entire threat regions** at the packet edge - before services see the traffic.  
  * **Reduces attack surface** by excluding known malicious IPs and unneeded countries.  
  * **Saves CPU cycles** by avoiding unnecessary conntrack entries and DNAT processing.  
  * **Minimizes false positives** - rules apply *only* to your WAN-exposed services.

  #### Integration
  * Runs on `nat-start` to auto-refresh rules after GUI changes.
  * If `ipset_builder.sh` killswitch is active, WAN firewall rules are inserted after it
    so no traffic leaks before sets are ready.

* [**`ipset_builder.sh`**](jffs/scripts/firewall/ipset_builder.sh) - **ipset builder module** used by `wan_firewall.sh`.

  #### Capabilities
  * Builds per-country ipsets from [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
    (preferred) or [IPdeny](https://www.ipdeny.com/ipblocks/).
  * Fetches and maintains custom ipsets from inline CIDRs or remote lists (HTTP/HTTPS).
  * Bundles [FireHOL Level 1](https://iplists.firehol.org/?ipset=firehol_level1) for safe baseline protection;
    can optionally add Level 2/3, AbuseIPDB, IPsum, and other feeds for stronger security.
  * **Deduplicates and aggregates** with [mapCIDR](https://github.com/projectdiscovery/mapcidr) if available
    (auto-installs if external storage is present).
  * Generates combo sets to match multiple sources in a single rule.
  * Restores from cached dumps for fast boot; SHA-256 hashes skip rebuilds if custom ipset definitions are unchanged.
  * **Optional killswitch (`-k`)**:
    - Temporarily blocks WAN ingress on specified `ports:protos` pairs during the first ipset initialization phase
      (e.g., right after boot), before any filtering rules are active. It's automatically removed after the
      successful build of all ipsets.
    - Prevents your forwarded ports from being exposed to unfiltered traffic while ipsets
      are still downloading and building.
    - `ports` can be a single number (e.g. 80), a comma-separated list (e.g. 80,443,123),
      or a dash-style range (e.g. 1000-2000)
    - `protos` can be `tcp`, `udp`, or `any` (matches both).
    - Example rules:
      ```
      80:tcp        # HTTP
      123:udp       # NTP
      443:any       # HTTPS with HTTP/3 support (both tcp and udp)
      20-21:tcp     # FTP data/control
      53,853:udp    # DNS and DoT
      ```
  * On build failure, **retries via cron and sends email alerts**; on success, removes retries and notifies resolution.
  * Runs `wan_firewall.sh` if requested via switches so iptables rules referencing these ipsets go live immediately.

* [**`config.sh`**](jffs/scripts/firewall/config.sh) - shared configuration file for both `wan_firewall.sh` and `ipset_builder.sh`.  
  **Review and adjust it** to match your environment before running the scripts.

* [**`fw_shared.sh`**](jffs/scripts/firewall/fw_shared.sh) - internal shared library for
  the firewall-related scripts.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion.
  It triggers the initial ipset build and schedules periodic refresh via cron (daily for country sets
  and twice daily for custom feeds), then starts WAN Firewall.

* [**`nat-start`**](jffs/scripts/nat-start) - Asuswrt-Merlin hook that reapplies firewall rules
  after every NAT reload.

* [**`profile.add`**](jffs/configs/profile.add) - Asuswrt-Merlin custom shell profile config. 
  Defines a helper alias so you can edit `config.sh` and reapply firewall changes instantly
  by simply typing `ipw`, without rebooting.

### Notes
* All configuration lives in [`config.sh`](jffs/scripts/firewall/config.sh).
  Review before use - it also contains extended docs for every option.
* Change `IPS_BDR_DIR` in [`config.sh`](jffs/scripts/firewall/config.sh) to external storage
  if possible - required for [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
  country ipset generation and CIDR aggregation, as these features rely on additional binaries
  that are only bootstrapped when using external storage. Otherwise, the script will fall back to
  [IPdeny](https://www.ipdeny.com/ipblocks/) feeds and disable CIDR aggregation.
* Set `MAXMIND_LICENSE_KEY` in [`config.sh`](jffs/scripts/firewall/config.sh) for country blocking with
  [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/); otherwise the script
  falls back to [IPdeny](https://www.ipdeny.com/ipblocks/). The `config.sh` file contains instructions
  on how to sign up for a free license key.
* Define your rule sets in [`config.sh`](jffs/scripts/firewall/config.sh) -
  e.g. `CUSTOM_IPSETS`, `IPSET_RULES`, `DOS_RULES`, and `KILLSWITCH_RULES`.
  These determine the firewall's behavior.
* No Entware dependency - all required external binaries are downloaded and managed automatically by the script.
* This script is designed to operate on inbound traffic only, specifically targeting ports that are publicly
  exposed to the WAN. It intentionally does not filter or inspect outbound traffic. The rationale is threefold:
  - Limiting filtering to inbound services minimizes the risk of false positives that could disrupt legitimate
    local or client-initiated connections.
  - It improves performance by reducing the number of packets that must be inspected,
    which is especially important on consumer-grade router hardware.
  - There is no compelling reason to apply ipset-based blocking to outbound traffic,
    as user activity protection on the internet is better handled by higher-level tools
    like [AdGuard](https://adguard.com/en/welcome.html) or [NextDNS](https://nextdns.io),
    which offer more accurate domain-level filtering, improved privacy protection, and easier management.
* Recommended: if possible, **forward only ports ≤ 32767** in the ASUS GUI, avoiding higher port numbers.
  Ports ≥ 32768 are commonly used as ephemeral *source* ports by major operating systems
  (Linux, macOS, iOS, Windows, Android). Staying at or below **32767** reduces edge cases where
  reply traffic from outbound connections might reuse the same numbers as your forwarded services,
  keeping matching in `raw PREROUTING` unambiguous.

## 2. Tunnel Director (ipset-based policy routing)

> **Prerequisites:**
> 1. At least one **VPN client (WireGuard or OpenVPN)** must be configured and active in Asuswrt-Merlin.  
>    - NAT must be enabled for the selected VPN clients in the ASUS GUI.
>    - For OpenVPN, "Redirect Internet traffic through tunnel" must be set to
>      "VPN Director / Guest Network" for the selected client(s).
> 2. Country ipsets with [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
>    require a `MAXMIND_LICENSE_KEY` and external USB storage; otherwise,
>    [IPdeny](https://www.ipdeny.com/ipblocks/) will be used.

* [**`tunnel_director.sh`**](jffs/scripts/firewall/tunnel_director.sh) - **outbound, ipset-based policy routing for
  Asuswrt-Merlin**. It lets you route selected LAN subnets through specific tunnels (WireGuard/OpenVPN) or the WAN
  based on **where traffic is going** (countries or custom ipsets).  
  **Perfect for anti-censorship use cases:** you can **force all traffic to or from entire countries or custom ipsets
  through a censorship-resistant VPN**, or invert the logic with meta ipset `any` - **send everything through the VPN
  except selected countries**.

  #### Main features
  * **Tight integration with [`ipset_builder.sh`](jffs/scripts/firewall/ipset_builder.sh)**  
    - Reuses the same IPSet Builder script as the WAN Firewall, avoiding code duplication.  
    - Automatically downloads, normalizes, and builds the required ipsets based on your defined rules.
  * **Flexible ipset-based rules**  
    - Defines routing behavior using a clear rule format:  
      **`table:src[%iface][:src_excl[,src_excl...]]:set[,set...][:set_excl[,set_excl...]]`**  
      where:  
      - `table` → routing table: `wgcN` (WireGuard client), `ovpncN` (OpenVPN client), or `main` (WAN).  
      - `src` → LAN source subnet (RFC1918, e.g., `192.168.50.0/24`, `192.168.50.2/32`). 
      - `iface` → optional; bind the rule to a specific LAN ingress interface (e.g., `br0`, `br52`);
        defaults to `br0` (the main LAN bridge).
      - `src_excl` → optional; comma-separated list of LAN subnets to exclude from matching.  
      - `set` → one or more destination ipset keys (countries or custom lists).  
        * Special keyword **`any`** matches all destinations (no ipset filtering).  
        * For country codes, the script automatically prefers [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
          extended set if available, falling back to standard country set otherwise.  
      - `set_excl` → optional; comma-separated ipsets to exclude from the match.  
    - Features:
      - **Excludes** - carve out exceptions at both the source (LAN devices/subnets) and destination (countries/ipsets).
      - **Meta ipset `any`** - match *all traffic* without ipset filtering, enabling simple policies like 
        "send everything through VPN except X" or "only send Y through VPN" - without relying on VPN Director.
      - **Rule order matters** - rules are applied sequentially. Place broad/global catch-alls before more
        specific rules to avoid shadowing.
    - Example rules:  
      ```
      # 1. Inclusion policy (send all traffic from the main LAN via VPN, but only
      # when destinations are in certain ipsets, excluding one LAN device):
      wgc1:192.168.50.0/24:192.168.50.10/32:us,ubl
      #  -> Route all devices in 192.168.50.0/24 via wgc1, but only
      #     for destinations in the US and in the custom ipset "ubl".
      #     Device 192.168.50.10 is excluded and always routed via WAN.
      
      # 2. Exclusion policy (send a specific VLAN device via VPN, except for some countries):
      wgc1:192.168.52.10/32%br52::any:us,ca
      # -> Route all traffic from device 192.168.52.10 (on VLAN br52) via wgc1
      #    for all destinations, but exclude the US and Canada.
      #    Packets to US/CA bypass the tunnel and follow normal WAN routing.
      ```
  * **Country-aware destination matching (extended vs. standard sets)**  
    - When [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) is available, the script
      automatically prefers *extended country sets*, which include both geolocated networks and registered-country
      ranges. This broader coverage is ideal for tunneling around national firewalls and CDN edge infrastructure.  
    - If [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) is not available, the script
      falls back to *standard country sets* from [IPdeny](https://www.ipdeny.com/ipblocks/), which are
      registration-based only (grouping IP blocks by the country where they are registered with the regional
      internet registries). Unlike GeoLite2, these sets do not reflect actual geolocation, so they may
      over- or under-match in cases such as CDNs or hosting providers with globally distributed infrastructure.
  * **Smart rule tracking & idempotence**  
    - Uses content hashes to detect when the configured rules differ from the currently applied state.  
    - Automatically validates rule counts (chains, `PREROUTING` jumps, and ip rules) to detect drift.  
    - Rebuilds rules only when necessary, ensuring clean updates without redundant reloads.  
    - Keeps Tunnel Director stable and predictable by preventing duplicate or half-applied policies.

  #### Why it matters (and how it helps against censorship)
  * **Unblock entire countries/regions at once**  
    - If a country's services are throttled/blocked on your direct WAN, route all traffic destined to that country via
      a VPN table (e.g., `wgc1`). This transparently covers websites, apps, CDNs, microservices, and API hosts without
      per-domain tinkering.  
    - Extended sets ([GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)) also include
      registered-in-country ranges used by global clouds/CDNs, ensuring that you capture not only geolocated IPs
      but also infrastructure *owned by* that country. This reduces the risk of missing endpoints that matter
      for the target region's internet ecosystem.

  * **Granular exceptions & flexible policies**  
    - Keep most traffic on the fast direct WAN, but selectively tunnel specific countries or content categories
      (e.g., news, social media, messaging) through VPN.  
    - Or invert the policy: tunnel *everything* through VPN by default (using `any`), then carve out exceptions
      for trusted countries back to WAN (`main`). This balances privacy and performance.  
    - Per-source rules let you apply different censorship-bypass strategies per subnet or even per-device.

  * **Resilient to domain/IP churn**  
    - Country-based ipsets are automatically downloaded and refreshed by the builder; you don't chase hostnames or
      play whack-a-mole with changing IPs.  
    - New endpoints in the target region are picked up automatically on the next update cycle, so policies remain
      effective even if services move to new CDNs or hosting providers.

* [**`config.sh`**](jffs/scripts/firewall/config.sh) - shared configuration file for both `tunnel_director.sh` and `ipset_builder.sh`.  
  **Review and adjust it** to match your environment before running the scripts.

* [**`fw_shared.sh`**](jffs/scripts/firewall/fw_shared.sh) - internal shared library for
  the firewall-related scripts.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion.
  It triggers the initial ipset build and schedules periodic refresh via cron (daily for country sets
  and twice daily for custom feeds), then starts Tunnel Director.

* [**`firewall-start`**](jffs/scripts/firewall-start) - Asuswrt-Merlin hook that reapplies Tunnel Director rules
  automatically whenever the firewall restarts.

* [**`profile.add`**](jffs/configs/profile.add) - Asuswrt-Merlin custom shell profile config. 
  Defines a helper alias so you can edit `config.sh` and reapply tunnel changes instantly
  by simply typing `ipt`, without rebooting.

## 3. WireGuard Client Port Forwarder
> **Prerequisites:**
> 1. Your **AllowedIPs** in the WireGuard config should include the tunnel subnet (e.g. `10.0.0.0/24`)
>    and any optional public subnets, **but not** your LAN range (`192.168.0.0/16`).
>    Use [this tool](https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/)
>    to calculate only the **AllowedIPs** you really need.
> 2. Go to **VPN → VPN Client → WireGuard → Select client instance → [your instance] → Inbound Firewall**,
>    set it to **Allow**, and click **Apply**; otherwise, services running on the router will not be
>    accessible to other WireGuard peers.

* [**`wgc_port_forwarder.sh`**](jffs/scripts/wireguard/wgc_port_forwarder.sh) - the ASUS GUI forwards ports
  only to the WAN interface. **This script adds equivalent port forwarding for the WireGuard client tunnel** (`wgcX`).

  * Creates two NAT chains:
    * **`<WGC_IF>_VSERVER`** - hooked from `PREROUTING` for traffic to the router's  **`WG_CLIENT_IP`**.
    * **`<WGC_IF>_VSERVER_RULES`** - holds interface-agnostic DNAT rules.
  * Inserts per-interface jumps (WireGuard + LAN) from `_VSERVER` into `_VSERVER_RULES` to reduce duplicate rules
    and keep lookups cheap. The LAN jump makes forwarded ports reachable locally on the WG client IP (e.g. `10.0.0.2`)
    from devices on the home LAN - useful for services that reference the WG IP.
  * Reads a simple mapping list **`ext_ports:protos:int_ip[:int_port]`** and installs DNAT rules.  
    - `ext_ports` supports comma lists and ranges (e.g. `80,443,81-85`).  
    - `protos` is required: `tcp` | `udp` | `tcp,udp` | `any` (alias for `tcp,udp`).  
    - If multiple ports / ranges are used, `int_port` must be omitted (ports are preserved).  
    - Logs each action and warns about unsupported combinations.
  * Tracks rule sets by computing hashes, applying changes only when needed. This ensures
    idempotence and avoids unnecessary firewall reloads.

* [**`nat-start`**](jffs/scripts/nat-start) - Asuswrt-Merlin hook that reapplies the rules after every NAT reload.

* [**`wgc_route.sh`**](jffs/scripts/wireguard/wgc_route.sh) - toggles static routes for your WireGuard client on `wgcN`.
  Configure `WG_CLIENT_NUMBER` and `WG_CLIENT_SUBNETS` (one or more CIDRs, e.g. `10.0.0.0/24`) inside the script
  so LAN hosts can reply to any tunnel peer. The script is idempotent - routes are only added or removed when needed.

* [**`wgclient-start`**](jffs/scripts/wgclient-start) / [**`wgclient-stop`**](jffs/scripts/wgclient-stop) -
  Asuswrt-Merlin hooks that call `wgc_route.sh` with `add` or `del`, ensuring routes exist only while the client is up.

* [**`profile.add`**](jffs/configs/profile.add) - Asuswrt-Merlin custom shell profile config. 
  Defines a helper alias so you can edit the configuration and reapply port forwarding changes instantly
  by simply typing `wpf`, without rebooting.


## 4. Dual WAN email notifications & optional LAN host blocking

> **Prerequisites / Notes:**
> 1. **Dual WAN** must be enabled in the UI and configured in **failover** mode with automatic **failback**.
> 2. Tested only with official Asuswrt Dual WAN in the failover / failback mode,
>    using an Ethernet port as the primary WAN and a USB LTE dongle as the secondary WAN.
>    Third-party Dual WAN implementations were **not** evaluated.

* [**`wan_failover.sh`**](jffs/scripts/misc/wan_failover.sh) - **monitors ASUS Dual WAN events and
  alerts you when the primary ISP connection goes down or is restored**.
  * Waits until the router has been up for at least 3 minutes before sending an email, preventing false alerts
    immediately after a power outage when the primary link may still be initializing.
  * **Optionally blocks selected LAN devices** from using the backup link (for example, stopping a torrent box from
    consuming expensive LTE data), and unblocks them when the main link returns.

* [**`wan-event`**](jffs/scripts/wan-event) - Asuswrt-Merlin hook that triggers the script whenever
  a WAN interface goes up or down.

* [**`firewall-start`**](jffs/scripts/firewall-start) - Asuswrt-Merlin hook that reapplies the LAN-hosts
  block if the firewall is restarted while the secondary WAN is active.
  
## 5. Automatic USB SSD trimming

**Why?** ASUS routers don't enable SSD trimming by default, and most USB SSDs ship with
provisioning mode **`full`** or **`partial`**. In those modes, Linux silently ignores `fstrim`,
so the drive never learns which blocks are free. Switching the attribute to **`unmap`**
enables proper TRIM/UNMAP and keeps write speeds consistent.
**These scripts enable full TRIM support for USB SSDs on ASUS routers**.

* [**`ssd_unmap.sh`**](jffs/scripts/ssd/ssd_unmap.sh) - scans `/sys/devices/` for USB devices whose
  `idVendor` matches `SSD_VENDOR_ID` (default: `04e8` for Samsung) and writes
  `unmap` into each `provisioning_mode` file it finds (if needed).

* [**`ssd_trim.sh`**](jffs/scripts/ssd/ssd_trim.sh) - runs `fstrim -v /tmp/mnt/<LABEL>` and logs the result.

* [**`pre-mount`**](jffs/scripts/pre-mount) - Asuswrt-Merlin hook that automatically applies
  the provisioning mode fix when a drive with the specified label is connected.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook that sets up
  a weekly cron job to run `ssd_trim.sh`.

### Required steps - run on the router once
  **1) Identify your vendor ID and partition path**

  ```sh
  for d in /sys/block/sd*/sd*; do
    [ -f "$d/partition" ] || continue            # keep partitions only
    part=/dev/${d##*/}                           # /dev/sdXN
    p=$(readlink -f "${d%/*}/device")            # climb to USB device node
    while [ "$p" != "/" ] && [ ! -f "$p/idVendor" ]; do p=${p%/*}; done
    [ -f "$p/idVendor" ] && printf '%s -> %s (%s)\n'         "$(cat "$p/idVendor")" "$part"         "$(cat "$p/manufacturer" 2>/dev/null)"
  done | sort -u
  ```

  Sample output:

  ```
  04e8 -> /dev/sda1 (Samsung)
  0781 -> /dev/sdb1 (SanDisk)
  ```

  Take the hex ID (`04e8`) and note the correct partition.

  **2) Supply your vendor ID (only if it isn't Samsung)** 
  
  Edit [`pre-mount`](jffs/scripts/pre-mount) and add your own `idVendor`
as the first argument.  Leave the line untouched if you use a Samsung SSD
(`idVendor = 04e8`).

  ```sh
/jffs/scripts/ssd_unmap.sh 0781   # 0781 = SanDisk (example)
  ```
  **3) Label the filesystem**

Pick any label you like (e.g. `st5`, `ssd`).

  ```sh
tune2fs -L st5 /dev/sda1   # specify your label and the device partition
  ```

**4) Keep the label in sync with the `pre-mount` hook**

Edit [`pre-mount`](jffs/scripts/pre-mount) and set:

```sh
SSD_VOLUME_LABEL='st5'   # use the exact label you assigned with tune2fs
```

**5) Keep the label in sync with the `services-start` hook**

Edit [`services-start`](jffs/scripts/services-start) and update the cron job definition argument:

```sh
cru a trim_ssd "0 4 * * 0 /jffs/scripts/ssd/ssd_trim.sh st5"   # use the exact label you assigned with tune2fs
```

## 6. nextdns-cli integration for SDNs & automatic updates
> **Prerequisites:**  
> 1. [SDN](https://www.asus.com/support/faq/1053195/) integration is supported only on
>    [VLAN-capable router models](https://www.asus.com/support/faq/1049415/) running Asuswrt-Merlin
>    3006.\* or later. Routers without SDN ignore the `dnsmasq-sdn.postconf` file.  
> 2. Install and configure
>    [**`nextdns-cli`**](https://github.com/nextdns/nextdns/wiki/AsusWRT-Merlin)
>    before adding these scripts.

* **`dnsmasq-sdn.postconf`** - **enables `nextdns-cli` for every
  [SDN (Self-Defined Network)](https://www.asus.com/support/faq/1053195/)**, not just the main LAN.
  To enable NextDNS for SDN, simply run **on the router** once:  
  ```sh
  ln -s /jffs/scripts/dnsmasq.postconf /jffs/scripts/dnsmasq-sdn.postconf
  ```
  > **Note:** `dnsmasq.postconf` is created automatically by `nextdns-cli`. We just symlink it under
  > `dnsmasq-sdn.postconf` so SDNs use it too.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion
  that adds a weekly cron entry to update the `nextdns-cli` binary.


## 7. Traffic Monitor table patch (Kb/s & Mb/s)

* [**`tmcal.js.add`**](jffs/tmcal.js.add) - overrides a function in ASUS `tmcal.js`
  so the **Traffic Monitor table shows throughput in kilobits/megabits per second (Kb/s & Mb/s)**
  instead of bytes per second. It simply multiplies the raw byte values by **8**, aligning with
  units used by tools like Speedtest, making the numbers easier to compare with real-world bandwidth tests.

* [**`mount_tmcal.sh`**](jffs/scripts/misc/mount_tmcal.sh) - concatenates the stock JS file
  with the patch and bind-mounts the result over `/www/tmcal.js`.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion
  that triggers `mount_tmcal.sh`.


Once the `tmcal.js` overlay is mounted, the **Traffic Analyzer → Traffic Monitor** table switches
from showing KB/s & MB/s to Kb/s & Mb/s:

![Traffic-Monitor table now shows Mb/s](docs/img/tm_table_patched.png)


## 8. Router startup notification

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion
  that triggers **startup notification email 60 seconds after the router comes online**.
  Serves as an indirect power outage alert: if you receive the message without having rebooted
  the router yourself, it likely means power was lost and then restored.


## 9. Shared utilities

Helper scripts shared by other modules.

**Purpose** - provide common building blocks (a lightweight email notifier, structured logging, per-script locking,
  temp files/dirs with auto-cleanup, SHA-256 hashing, comment stripping/normalization, port/protocol validation
  & normalization, idempotent `iptables` helpers, selective WAN-blocking utilities) so feature scripts stay short,
  focused, and easy to maintain.

### Components:

 * [**`send_email.sh`**](jffs/scripts/utils/send_email.sh) - small wrapper used by other scripts (e.g., WAN failover and startup notifications) to send status emails.

 * [**`common.sh`**](jffs/scripts/utils/common.sh) **library**

   | Function                        | What it does                                                                                                                                                                                            | Typical use-case                                                                              |
   |---------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
   | `uuid4`                         | Generates a kernel-provided random UUIDv4 string from `/proc/sys/kernel/random/uuid`.                                                                                                                   | Create unique temp names, job IDs, or correlation IDs in logs.                                |
   | `compute_hash [<file>\|-]`      | SHA-256 helper: hashes a file (when path is given) or stdin (no arg/`-`); prints the 64-char lowercase digest only.                                                                                     | Change detection (e.g., ruleset/config hashing) and cache keys; works cleanly in pipelines.   |
   | `get_script_path`               | Returns the absolute path to the running script, resolving symlinks (falls back to `$0` if needed).                                                                                                     | Locate the script itself (e.g., `. "$(get_script_path)"`).                                    |
   | `get_script_dir`                | Returns the directory containing the current script (absolute, no trailing slash).                                                                                                                      | Locate sibling files (e.g., `. "$(get_script_dir)/config.sh"`).                               |
   | `get_script_name [-n]`          | Returns the script's filename; `-n` strips the extension.                                                                                                                                               | Derive a log tag, lock name, or temp file prefix.                                             |
   | `log [-l <level>] <message...>` | Lightweight syslog wrapper (facility `user`). Logs to both syslog and stderr; supports priorities: `debug\|info\|notice\|warn\|err\|crit\|alert\|emerg`. Adds readable prefixes for non-default levels. | Uniform logging across scripts; easy grepping in `/tmp/syslog.log`.                           |
   | `acquire_lock [<name>]`         | Takes a non-blocking lock under `/var/lock/<name>.lock` (defaults to script name). Exits early if another instance is running; holds lock until process exit.                                           | Prevent concurrent runs of cron- or hook-driven scripts.                                      |
   | `tmp_file`                      | Creates a UUID-named temp file in `/tmp`, tracks it for auto-cleanup on exit via trap. Prints the path.                                                                                                 | Scratch files that should be deleted automatically.                                           |
   | `tmp_dir`                       | Creates a UUID-named temp directory in `/tmp`, tracked for auto-cleanup on exit via trap. Prints the path.                                                                                              | Staging directories for downloads, extracts, or generated assets.                             |
   | `is_lan_ip <ipv4>`              | Returns `0` if the IPv4 is private (RFC-1918: `10/8`, `172.16/12`, `192.168/16`), `1` otherwise.                                                                                                        | Quick guard before applying LAN-only logic or validations.                                    |
   | `resolve_ip <host-or-ip>`       | Resolves a literal IP, `/etc/hosts` alias, or DNS name to a single IPv4 (LAN or WAN). Prints the IP; non-zero on failure.                                                                               | Turn a hostname into an address when public/private doesn't matter.                           |
   | `resolve_lan_ip <host-or-ip>`   | Like `resolve_ip`, but requires the result be RFC-1918; errors out otherwise.                                                                                                                           | Safely resolve devices that must be on your LAN (e.g., firewall rules targeting local hosts). |
   | `get_active_wan_if`             | Returns the interface name of the currently active WAN (checks `wanN_primary` flags; falls back to `wan0_ifname`).                                                                                      | Pick the correct egress interface for WAN-specific rules or diagnostics.                      |
   | `strip_comments [<text>]`       | Trims lines, drops blanks and `#` comments (including inline), normalizes input. Reads from the argument if provided, otherwise stdin; prints cleaned lines.                                            | Preprocess rule blocks (e.g., `CUSTOM_IPSETS`, `IPSET_RULES`, `DOS_RULES`) before parsing.    |
   | `is_pos_int <value>`            | Returns success (`0`) if `<value>` is a positive integer (>= 1); returns `1` otherwise.                                                                                                                 | Validate numeric config such as `minutes`, `above`, `burst`, `log_count`.                     |

 * [**`firewall.sh`**](jffs/scripts/utils/firewall.sh) **library**

   | Function                                                                                | What it does                                                                                                                                                                                                                                                                   | Typical use-case                                                                                                                                                    |
   |-----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | `validate_port <N>`                                                                     | Validates a single TCP/UDP port: must be an integer between `1` and `65535`. Returns `0` if valid, `1` otherwise.                                                                                                                                                              | Sanity-check user-provided port numbers before passing them into `iptables` or higher-level parsing.                                                                |
   | `validate_ports <spec>`                                                                 | Validates a destination port spec: `"any"`, single port (`N`), comma list (`N,N2`), dash range (`N-M`), or mixed list (e.g., `80,443,1000-2000`). Returns `0` if valid, `1` otherwise.                                                                                         | Sanity-check rule port fields before building iptables args.                                                                                                        |
   | `normalize_protos <spec>`                                                               | Normalizes a protocol spec to one of: `tcp`, `udp`, or `tcp,udp`. Accepts `any`, `tcp`, `udp`, `tcp,udp`, or `udp,tcp`; prints the canonical form and returns `0` (non-zero on invalid input).                                                                                 | Convert user config to canonical proto strings used when generating iptables rules (`-p` / multiport).                                                              |
   | `fw_chain_exists <table> <chain>`                                                       | Returns `0` if the chain exists in the table, else `1`.                                                                                                                                                                                                                        | Quick guard checks before creating, deleting, or syncing rules.                                                                                                     |
   | `create_fw_chain [-q] [-f] <table> <chain>`                                             | Ensures a user-defined chain exists; with `-f` flushes it if already present. `-q` suppresses info logs.                                                                                                                                                                       | Initialize or reset per-script chains (e.g., `RAW_FILTERING`, `WGC1_RULES`).                                                                                        |
   | `delete_fw_chain [-q] <table> <chain>`                                                  | Flushes and deletes a user-defined chain if it exists (no-op if missing). `-q` suppresses info logs.                                                                                                                                                                           | Clean teardown during script disable/uninstall or rebuilds.                                                                                                         |
   | `find_fw_rules "<table> <chain>" "<grep -E pattern>"`                                   | Prints matching `iptables -S` lines for the given table/chain and regex; prints nothing if chain missing.                                                                                                                                                                      | Inspect current state, drive higher-level sync/purge operations.                                                                                                    |
   | `purge_fw_rules [-q] [--count] "<table> <chain>" "<grep -E pattern>"`                   | Deletes all rules in the specified table/chain that match the regex. With `--count`, prints number of deletions. `-q` suppresses info logs.                                                                                                                                    | Remove stale/duplicate jump blocks or old rule variants in bulk.                                                                                                    |
   | `ensure_fw_rule [-q] [--count] <table> <chain> [-I [pos] \| -D] <rule...>`              | Idempotent rule manager: appends (`-A`) if missing, inserts at position (`-I [pos]`, default 1) if missing, or deletes (`-D`) if present. Skips duplicates and avoids invalid deletes. With `--count`, prints `1` on change, else `0`. `-q` suppresses info logs.              | Reliable single-rule management without manual `-C/-A/-I/-D` dance; used throughout all firewall scripts.                                                           |
   | `sync_fw_rule [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]` | Reconciles a rule set to exactly one desired rule: if one matching rule already equals the desired spec → no change; otherwise purge all matches and add the desired rule (append or insert at `insert_pos`). With `--count`, prints total changes. `-q` suppresses info logs. | Keep `PREROUTING` jump blocks or chain heads in a single authoritative form (e.g., TCP/UDP multiport jumps).                                                        |
   | `block_wan_for_host <hostname\|ip> [wan_id]`                                            | Resolves the host to a LAN IP, finds the WAN egress interface, and inserts `DROP`/`REJECT` rules in `filter FORWARD` to block both *to* and *from* that WAN (defaults to secondary WAN `wan_id=1`).                                                                            | Keep a chatty device off an expensive LTE backup link; enforce parental controls by cutting a child's device off the internet via scripts/automations.              |
   | `allow_wan_for_host <hostname\|ip> [wan_id]`                                            | Resolves the host to a LAN IP, locates the WAN egress interface, and removes the corresponding `DROP`/`REJECT` rules to restore WAN access (defaults to `wan_id=1`).                                                                                                           | Restore internet access when primary WAN is back; lift temporary parental blocks.                                                                                   |
   | `chg <command ...>`                                                                     | Helper that returns success (`0`) if the wrapped command's stdout is a non-zero integer; otherwise returns failure. Useful with functions that support `--count`.                                                                                                              | Gate "did anything change?" flows: `if chg purge_fw_rules --count ...; then do_something; fi` or aggregate change detection across multiple ensure/sync operations. |


## License

This project is distributed under the [GNU General Public License v3.0](https://github.com/kuchkovsky/asuswrt-merlin-scripts/blob/main/LICENSE).
