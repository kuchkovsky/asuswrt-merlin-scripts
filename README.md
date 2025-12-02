# Asuswrt-Merlin Script Collection

A set of shell scripts that extend the functionality of routers running **[Asuswrt-Merlin](https://www.asuswrt-merlin.net/)**.
Each script lives in `/jffs/scripts` and integrates with Merlin's built-in hook system
(`services-start`, `firewall-start`, `wgclient-start`, etc.).

> **Firmware requirement**: these scripts depend on Merlin's custom script framework and
  will **not** run on stock ASUS firmware.


## General Information & Disclaimers

* Scripts are provided **as-is**; review the code before deployment.
* Deployment is straightforward: always upload the `scripts/utils` folder (it contains the
  shared libraries) and the files mentioned in the section of the script you want to deploy
  (e.g., `scripts/services-start`, `scripts/firewall/ipset_builder.sh`). Edit the configs
  locally before uploading them.
* The code and configuration files are extensively commented - it's recommended to review them
  to understand how each component works and how to adapt it to your environment. In most cases,
  you'll find all the details you need directly inside the script headers or in `config.sh`.
* Adjust IPs, subnets, filesystem labels, and USB vendor IDs to match your own setup. If you remove
  a script you don't use, also delete any references to it in related hook or event-handler files.
* **`send_email.sh`** (used by WAN failover, startup notifications, and ipset builder retry alerts)
  requires that email is preconfigured in **`amtm`** before running these scripts.
* Most network-related scripts are dual-stack and support both IPv4 and IPv6 where applicable.

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
and adjusted their configuration to fit your own environment, removing the scripts you don't need.
Once configured, follow these commands to safely upload and activate them on your router:
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

1. [Automatic USB SSD TRIM](#1-automatic-usb-ssd-trim)
2. [Inbound WAN Firewall (ipset-based blocking & DoS Protection)](#2-inbound-wan-firewall-ipset-based-blocking--dos-protection)
3. [Tunnel Director (ipset-based policy routing)](#3-tunnel-director-ipset-based-policy-routing)
4. [WireGuard Client Port Forwarder](#4-wireguard-client-port-forwarder)
5. [Dual WAN email notifications & optional LAN host blocking](#5-dual-wan-email-notifications--optional-lan-host-blocking)
6. [IPv6 SLAAC and RA support for SDN networks](#6-ipv6-slaac-and-ra-support-for-sdn-networks)
7. [nextdns-cli integration for SDNs & automatic updates](#7-nextdns-cli-integration-for-sdns--automatic-updates)
8. [Static IPv6 routes to LAN hosts](#8-static-ipv6-routes-to-lan-hosts)
9. [Router startup notification](#9-router-startup-notification)
10. [Shared utilities](#10-shared-utilities)

## 1. Automatic USB SSD TRIM

> **Prerequisites:**
> 1. The USB storage must be formatted with an **ext2, ext3, or ext4** filesystem.  
>    Other filesystems are not supported for TRIM by this script.
> 2. TRIM must be **supported and correctly exposed** by both the SSD and its USB bridge/enclosure.  
>    This script will try to work around common limitations (e.g., broken UNMAP, buggy discard handling),
>    but success is not guaranteed. If you run into issues, feel free to contact me via **SNBForums**
>    or open a **GitHub issue** for further investigation.

By default, ASUS firmware does not provide a built-in and reliable way to issue TRIM for USB-attached SSDs.  
Even though Linux and ext-based filesystems support TRIM, the stock behavior often means that:
- `fstrim` is never run automatically,
- many USB-SATA/NVMe bridges expose SSDs with `provisioning_mode=full` or `partial`, which blocks UNMAP,
- some adapters fail on larger discard operations with kernel errors such as `"Remote I/O error"`.

In practice, this can result in USB SSDs never being trimmed, leading over time to reduced write
performance, increased write amplification, and unnecessary wear.  
The script in this section provides **automated, safe TRIM handling** for USB SSDs on Asuswrt-Merlin.

* **[`ssd_trim.sh`](jffs/scripts/ssd/ssd_trim.sh)** - automated TRIM handler for USB SSDs.  
  This script turns TRIM into a regular maintenance task handled entirely on the router side. It:
  - scans all USB-backed mountpoints under `/tmp/mnt` (or a single label if specified),
  - skips excluded labels, unsupported filesystems, and disks that were permanently disabled due to previous errors,
  - enforces `provisioning_mode="unmap"` on eligible devices so the kernel can send TRIM/UNMAP commands,
  - runs `fstrim` and detects whether any space was actually reclaimed,
  - handles problematic USB adapters by:
    - retrying with `write_same_max_bytes` as a safe upper bound,
    - caching per-disk working `discard_max_bytes` values in **nvram**,
    - permanently disabling TRIM only for devices that cannot be made to work reliably.

  All per-disk decisions are stored under stable nvram keys derived from the device's USB identity,
  so behavior remains consistent across reboots without manual tuning.

* **[`config.sh`](jffs/scripts/ssd/config.sh)** - configuration for `ssd_trim.sh`.  
  This file centralizes user-facing settings:
  - defines filesystem labels to exclude from automatic TRIM via `EXCLUDED_SSD_LABELS`,
  - allows adjustments without editing the main script,
  - is sourced by `ssd_trim.sh` on every run, so changes take effect immediately.

  To completely skip a given disk, assign it a label and add that label to `EXCLUDED_SSD_LABELS`.

* [**`services-start`**](jffs/scripts/services-start) - scheduled trimming via cron.  
  The `services-start` hook installs a periodic cron job (weekly by default) that runs `ssd_trim.sh`,
  ensuring that connected USB SSDs are trimmed regularly without manual intervention.

> **Note:**  
> If the script permanently disabled a disk (for example due to repeated TRIM errors) and you
> want to re-enable it for testing or debugging, simply remove the corresponding nvram flag:
>
> ```sh
> nvram unset ssd_trim_<disk-id>_discard_max_bytes
> nvram commit
> ```
>
> You can find the exact `<disk-id>` in the script log - it appears whenever the device is
> skipped. For example:
>
> ```
> ssd_trim: Skipping drive=/dev/sdb (disabled via nvram: ssd_trim_24a9_205a_24092311730058_discard_max_bytes=0) ...
> ```
>
> After unsetting the key, the drive will be treated as a fresh candidate on the next run.

## 2. Inbound WAN Firewall (ipset-based blocking & DoS Protection)

> **Prerequisites:**
> 1. Designed for use only when IPv4 port forwarding is enabled or IPv6 services
>    are allowed in the firewall for external access - it has no effect otherwise.
> 2. The WAN interface must receive a **public IP directly** (no double NAT).
> 3. For IPv6-based blocking to function, your ISP must support IPv6,
>    and it must be enabled in the router's settings.
> 4. Country blocking with [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
>    requires a `MAXMIND_LICENSE_KEY` and external USB storage; otherwise,
>    [IPdeny](https://www.ipdeny.com/ipblocks/) will be used.
> 5. The CIDR aggregation feature requires external USB storage for the
>    [mapCIDR](https://github.com/projectdiscovery/mapcidr) binary;
>    otherwise, IP ranges won't be aggregated.

* [**`wan_firewall.sh`**](jffs/scripts/firewall/wan_firewall.sh) - **high-performance inbound firewall for Asuswrt-Merlin**
  that applies only to the TCP/UDP ports you forward or allow for external access in the GUI
  and **supports both IPv4 and IPv6**. It provides **country blocking, malicious IP filtering,
  spoofed traffic protection, and optional per-IP/per-port DoS rate limiting** -
  all applied before packets hit DNAT, conntrack, or routing, protecting your public services
  with minimal overhead.
  
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
    - Discards spoofed traffic from reserved/unroutable IPv4 and IPv6 ranges before conntrack,
      saving CPU and avoiding table pollution.
  * **Country blocking with high-accuracy [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)**  
    - Uses [MaxMind's](https://www.maxmind.com/en/home) free [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
      database (weekly updates, multi-source verification) for some of the most accurate country-to-IP mappings available.  
    - Falls back to [IPdeny](https://www.ipdeny.com/ipblocks/) feeds if you don't set a `MAXMIND_LICENSE_KEY`.  
    - Blocks entire countries from reaching your forwarded ports - useful for cutting off high-risk regions entirely.
    - Fully supports IPv6 ranges, as well as the IPv4 ones.
  * **Custom ipsets for malicious source blocking**  
    - Pulls in threat intelligence feeds you choose **directly from URLs** - e.g. AbuseIPDB, IPsum, DShield, Greensnow.
      Can also use **custom hardcoded IP lists** defined directly in the configuration file.
    - Supports downloads from **any source**, including the **API key protected ones** by allowing you to specify
      custom `curl` arguments like headers, so you can integrate paid or authenticated feeds without modifying the script. 
    - For IPv4, ships with [**FireHOL Level 1**](https://iplists.firehol.org/?ipset=firehol_level1) enabled as a baseline:
      curated bogon, abuse, and attack-source list designed for minimal false positives.  
    - For IPv6, it uses two reputable, continuously maintained sources -
      [**Team Cymru fullbogons**](https://www.team-cymru.com/bogon-reference-http),
      which lists all unallocated or reserved IPv6 ranges to block invalid traffic, and
      [**Spamhaus DROPv6**](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), which targets well-known
      abusive networks such as spam, malware, and botnet hosts - together providing a clean, safe IPv6 baseline
      with minimal risk of overblocking.  
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
        4.5.6.7        # your VPS IPv4
        11.12.13.14    # your friend's home IPv4
      
      pss6:
        2a12:abcd::10  # your VPS IPv6
        2a12:abcd::30  # your friend's home IPv6
      ```
  * **Flexible ipset-based WAN Firewall rules**  
    - Defines IPv4/IPv6 filtering behavior using a clear rule format:  
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
        the `ips_` (or `ips6_` for IPv6) prefix (`ips_80,443_t_blk`, `ips6_22_t_blk_exc1`).  
    - Features:  
      - **Excludes** let you carve out trusted or special-case sets within a broader rule.
      - **Rule order matters**: place broad/global rules (e.g., passlists, global blocks) before more specific matches.  
    - Example rules:  
      ```
      pass:any:any:pss                     # unconditionally allow matches from pss
      block:any:any:blk,cn,kp              # drop IPv4 traffic from blocklist, CN or KP
      block:any:any:blk,cn,kp:exc1,exc2    # same as above, but exempt exc1/2
      block:any:any:blk6,cn6,kp6           # drop IPv6 traffic from blocklist, CN or KP
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
      - Offending packets are logged to syslog with the `dos_` (or `dos6_` for IPv6) prefix
        (`dos_ip_443_t`, `dos6_port_123_u`).  
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
    - Auto-detects forwarded or publicly allowed ports from the GUI and filters only those -
      both IPv4 and IPv6.
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
  * Runs on `firewall-start` to auto-refresh rules after GUI changes.
  * If `ipset_builder.sh` killswitch is active, both IPv4 and IPv6 WAN rules are inserted afterward,
    ensuring no unfiltered traffic leaks before ipsets are restored.

* [**`ipset_builder.sh`**](jffs/scripts/firewall/ipset_builder.sh) - **ipset builder module** used by `wan_firewall.sh`.

  #### Capabilities
  * Builds per-country IPv4 and IPv6 ipsets from [GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
    (preferred) or [IPdeny](https://www.ipdeny.com/ipblocks/),
    depending on availability and router configuration.
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
    - When IPv6 is enabled, the killswitch also applies to IPv6 firewall chains.
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
  It triggers the initial ipset build and schedules periodic refresh via cron
  (daily for country sets and twice daily for custom feeds), then starts WAN Firewall.

* [**`firewall-start`**](jffs/scripts/firewall-start) - Asuswrt-Merlin hook that reapplies
  firewall rules after every firewall reload.

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

## 3. Tunnel Director (ipset-based policy routing)

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

## 4. WireGuard Client Port Forwarder

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
    * **`<WGC_IF>_VSERVER`** - hooked from `PREROUTING` for traffic to the router's **`WG_CLIENT_IP`**.
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


## 5. Dual WAN email notifications & optional LAN host blocking

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

## 6. IPv6 SLAAC and RA support for SDN networks

> **Prerequisites:**
> 1. [SDN](https://www.asus.com/support/faq/1053195/) is supported only on
>    [VLAN-capable router models](https://www.asus.com/support/faq/1049415/) running Asuswrt-Merlin
>    3006.\* or later.
> 2. Your ISP must delegate a **/48**, **/56**, or **/60** IPv6 prefix to your router.  
>    If the WAN PD is **/64**, there are no free /64 subnets available for SDN bridges.
> 3. **Enable IPv6 globally** in the router's Web UI:  
>    *Advanced Settings → IPv6*  
>    You can select any IPv6 mode except Passthrough.
> 4. **Disable IPv6** for each SDN in the GUI.  
>    The scripts automatically handle IPv6 addressing and Router Advertisements (RA).

ASUS firmware currently lacks proper support for **stateless IPv6 autoconfiguration (SLAAC)** on
**[SDN (Self-Defined Network)](https://www.asus.com/support/faq/1053195/)** bridges. The built-in `dnsmasq` service
only enables **stateful DHCPv6** for SDNs, not stateless autoconfiguration. As a result, when IPv6 is enabled
for SDN interfaces in the GUI, the firmware reconfigures all internal subnets - including the main LAN - from
`/64` to `/72`. This breaks SLAAC entirely, since most client devices require a `/64` prefix to self-generate
global IPv6 addresses. Consequently, IPv6 connectivity fails completely for clients that don't support DHCPv6.

When your ISP provides a **delegated prefix (PD)** (for example, `/56`), the main LAN correctly receives
a `/64` only **as long as SDN IPv6 remains disabled**. Once enabled, however, the firmware slices the entire PD
into smaller `/72` segments, effectively breaking SLAAC on all networks - including the main LAN.

The scripts below work together to **restore full IPv6 functionality** on all SDN bridges.  
They automatically allocate proper `/64` subnets from the delegated prefix, enable Router Advertisements (RA)
for **SLAAC**, and configure a secure firewall policy that allows outbound traffic while maintaining
isolation between SDNs and the router.

**Note:** the scripts configure IPv6 on all SDN bridges by default. If you want to exclude specific bridges,
upload all required files listed below, then run the **`sls`** command on the router (a helper alias)
to list SDN names and their bridges:
> ```
> kuchkovsky@rt:/tmp/home/root# sls
> name=Guest br=br54 sdn_idx=3
> name=IoT   br=br56 sdn_idx=5
> ```
Next, edit [`config.sh`](jffs/scripts/sdn/config.sh) and set `EXCLUDED_IFACES` to skip the selected bridges.

* [**`sdn_v6_br.sh`**](jffs/scripts/sdn/sdn_v6_br.sh) - assigns stable, per-bridge `/64` prefixes.
  * Reads the **WAN delegated prefix (PD)** and computes unique `/64` subnets for each SDN bridge.  
  * Assigns each bridge its own router address (e.g. `<prefix>::1/64`).
  * Keeps subnet numbering stable between reboots or config changes.  
  * Supports PD sizes `/48`, `/56`, and `/60` (skips `/64` since there's nothing to carve).  
  * **Example:**  
    ```
    WAN PD = 2001:db8:abcd:1000::/56  
    br0  (idx=0) → 2001:db8:abcd:1000::/64  
    br54 (idx=1) → 2001:db8:abcd:1001::/64  
    br56 (idx=2) → 2001:db8:abcd:1002::/64
    ```

* [**`sdn_v6_dnsmasq.sh`**](jffs/scripts/sdn/sdn_v6_dnsmasq.sh) - enables Router Advertisements and SLAAC.  
  * Automatically appends the required `dnsmasq` directives for each SDN instance.  
  * Ensures that clients receive IPv6 configuration via **SLAAC**, not stateful DHCPv6.  
  * Advertises DNS (RDNSS) via RA, so clients can resolve hostnames automatically.  
  * Runs automatically through the `dnsmasq-sdn.postconf` hook - no manual execution required.

* [**`sdn_v6_firewall.sh`**](jffs/scripts/sdn/sdn_v6_firewall.sh) - enables and secures IPv6 connectivity
  for SDN bridges.  
  * Establishes full IPv6 forwarding support, allowing SDN clients to reach the internet via the router.  
  * Permits essential local services - DNS (UDP/53) and DHCPv6 (UDP/547) - for address configuration.  
  * Blocks direct access to the router's global IPv6 addresses and isolates SDN bridges from each other.  
  * Prevents unsolicited inbound ICMPv6 (ping) traffic from the Internet to internal networks.

* [**`sdn_v6_shared.sh`**](jffs/scripts/sdn/sdn_v6_shared.sh) - internal helper library shared
  by all SDN IPv6 scripts.

* [**`config.sh`**](jffs/scripts/sdn/config.sh) - shared configuration.  
  * Lists excluded bridges (if you want some SDNs to stay IPv4-only).  
  * The main LAN (`br0`) is always excluded automatically.  
  * All scripts respect this configuration file.

* [**`dhcpc-event`**](jffs/scripts/dhcpc-event) - Asuswrt-Merlin system hook invoked on DHCP events.
  Triggers `sdn_v6_br.sh` whenever the WAN interface receives a new IPv6 prefix delegation (PD).

* [**`dnsmasq-sdn.postconf`**](jffs/scripts/dnsmasq-sdn.postconf) - Asuswrt-Merlin hook executed after
  SDN `dnsmasq` configuration is generated. Calls `sdn_v6_dnsmasq.sh` to enable Router Advertisements (RA)
  and SLAAC on SDN instances.

* [**`firewall-start`**](jffs/scripts/firewall-start) - Asuswrt-Merlin hook triggered after each firewall reload.
  Runs `sdn_v6_firewall.sh` to reapply IPv6 forwarding and isolation rules for all SDN bridges.

* [**`profile.add`**](jffs/configs/profile.add) - Asuswrt-Merlin custom shell profile config.
  Defines a helper alias `sls` that lists all SDN networks and their corresponding bridges,
  allowing you to quickly identify the bridge name you may want to exclude in your configuration.

## 7. nextdns-cli integration for SDNs & automatic updates

> **Prerequisites:**  
> 1. [SDN](https://www.asus.com/support/faq/1053195/) is supported only on
>    [VLAN-capable router models](https://www.asus.com/support/faq/1049415/) running Asuswrt-Merlin
>    3006.\* or later. Routers without SDN ignore the `dnsmasq-sdn.postconf` file.  
> 2. Install and configure
>    [**`nextdns-cli`**](https://github.com/nextdns/nextdns/wiki/AsusWRT-Merlin)
>    before adding these scripts.

* **`dnsmasq-sdn.postconf`** - extends `nextdns-cli` integration to all
  [**SDN (Self-Defined Network)**](https://www.asus.com/support/faq/1053195/) instances, not just the main LAN.  
  The script directly invokes `dnsmasq.postconf`, which is generated automatically by `nextdns-cli`,
  ensuring that SDN networks also benefit from NextDNS filtering and DoH configuration.

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion
  that adds a weekly cron entry to update the `nextdns-cli` binary.

## 8. Static IPv6 routes to LAN hosts

> **Prerequisites:**
> 1. Your ISP must delegate a **/48**, **/56**, or **/60** IPv6 prefix to your router.  
>    A /64 prefix is insufficient for routing additional subnets to LAN hosts.
> 2. **Enable IPv6 globally** in the router's Web UI:  
>    *Advanced Settings → IPv6*  
>    You can select any IPv6 mode except Passthrough.

ASUS firmware currently provides no GUI support for **IPv6 static routes**, making it impossible
to route additional IPv6 subnets (e.g., dedicated `/64`s) to specific LAN hosts or downstream routers.  
This script fills that gap by allowing you to define and automatically maintain **static IPv6 routes**
using link-local next-hops - the correct and reliable method for on-link IPv6 routing.

It is particularly useful for setups where a device such as a **Docker host**, **hypervisor**, or
**secondary router** manages its own downstream subnet. You can carve one or more subnets from your
delegated prefix (PD) and route them to that device, allowing it to manage those addresses natively.

* [**`v6_static_routes.sh`**](jffs/scripts/misc/v6_static_routes.sh) - defines and maintains static IPv6
  routes to LAN hosts.
  * Reads rule definitions from the `STATIC_ROUTE_RULES` variable, where each line follows  
    the format `iface|link_local|static_route`.  
    Example:
    ```
    br0|fe80::1234:56ff:fe78:9abc|2a10:abcd:1234:aa10::/64
    ```
  * Validates each rule:
    - Ensures the interface exists.  
    - Verifies that the next-hop address is link-local (`fe80::/10`).
  * Applies routes idempotently:
    - Skips routes that already exist with the same parameters.  
    - Replaces or removes conflicting entries automatically.
  * Supports **any valid IPv6 prefix size** (`/48`-`/128`), though `/64` is typical for host subnets.  
  * Uses link-local next-hops to avoid dependence on global SLAAC or DHCPv6 addresses.  
  * Logs all actions, warnings, and errors for full transparency.

* [**`dhcpc-event`**](jffs/scripts/dhcpc-event) - Asuswrt-Merlin system hook invoked on DHCP events.
  Triggers `v6_static_routes.sh` whenever the WAN interface receives a new IPv6 prefix delegation (PD).  

> **Tip:**  
> Avoid using the first few subnets from your delegated prefix if you also use
> [`sdn_v6_br.sh`](jffs/scripts/sdn/sdn_v6_br.sh) for SDN networks, since that script assigns
> lower-indexed subnets automatically and may cause overlap.

## 9. Router startup notification

* [**`services-start`**](jffs/scripts/services-start) - Asuswrt-Merlin hook invoked on boot completion
  that triggers **startup notification email 60 seconds after the router comes online**.
  Serves as an indirect power outage alert: if you receive the message without having rebooted
  the router yourself, it likely means power was lost and then restored.

## 10. Shared utilities

Helper scripts shared by other modules.

**Purpose** - provide common building blocks (a lightweight email notifier, structured logging, per-script locking,
  temp files/dirs with auto-cleanup, SHA-256 hashing, comment stripping/normalization, port/protocol validation
  & normalization, idempotent `iptables` helpers, selective WAN-blocking utilities) so feature scripts stay short,
  focused, and easy to maintain.

### Components:

 * [**`send_email.sh`**](jffs/scripts/utils/send_email.sh) - small wrapper used by other scripts (e.g., WAN failover and startup notifications) to send status emails.

 * [**`common.sh`**](jffs/scripts/utils/common.sh) **library**

   | Function                                    | What it does                                                                                                                                                                                            | Typical use-case                                                                                |
   |---------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
   | `uuid4`                                     | Generates a kernel-provided random UUIDv4 string from `/proc/sys/kernel/random/uuid`.                                                                                                                   | Create unique temp names, job IDs, or correlation IDs in logs.                                  |
   | `compute_hash [<file>\|-]`                  | SHA-256 helper: hashes a file (when path is given) or stdin (no arg/`-`); prints the 64-char lowercase digest only.                                                                                     | Change detection (e.g., ruleset/config hashing) and cache keys; works cleanly in pipelines.     |
   | `get_script_path`                           | Returns the absolute path to the running script, resolving symlinks (falls back to `$0` if needed).                                                                                                     | Locate the script itself (e.g., `. "$(get_script_path)"`).                                      |
   | `get_script_dir`                            | Returns the directory containing the current script (absolute, no trailing slash).                                                                                                                      | Locate sibling files (e.g., `. "$(get_script_dir)/config.sh"`).                                 |
   | `get_script_name [-n]`                      | Returns the script's filename; `-n` strips the extension.                                                                                                                                               | Derive a log tag, lock name, or temp file prefix.                                               |
   | `log [-l <level>] <msg...>`                 | Lightweight syslog wrapper (facility `user`). Logs to both syslog and stderr; supports priorities: `debug\|info\|notice\|warn\|err\|crit\|alert\|emerg`. Adds readable prefixes for non-default levels. | Uniform logging across scripts; easy grepping in `/tmp/syslog.log`.                             |
   | `acquire_lock [<name>]`                     | Takes a non-blocking lock under `/var/lock/<name>.lock` (defaults to script name). Exits early if another instance is running; holds the lock until process exit.                                       | Prevent concurrent runs of cron- or hook-driven scripts.                                        |
   | `tmp_file`                                  | Creates a UUID-named temp file in `/tmp`, tracked for auto-cleanup on exit via trap. Prints the path.                                                                                                   | Scratch files that should be deleted automatically.                                             |
   | `tmp_dir`                                   | Creates a UUID-named temp directory in `/tmp`, tracked for auto-cleanup on exit via trap. Prints the path.                                                                                              | Staging directories for downloads, extracts, or generated assets.                               |
   | `is_lan_ip [-6] <ip>`                       | Returns `0` if the address is private (IPv4 RFC1918 or IPv6 ULA/link-local), `1` otherwise.                                                                                                             | Quick guard before applying LAN-only logic or validations.                                      |
   | `resolve_ip [-6] [-q] [-g] [-a] <host\|ip>` | Resolves a host or literal IP to one or more addresses. Supports IPv4/IPv6 selection, global/public filtering, quiet mode, and returning all matches.                                                   | Generic resolver for hostnames; used when family/publicity doesn't matter.                      |
   | `resolve_lan_ip [-6] [-q] [-a] <host\|ip>`  | Like `resolve_ip`, but requires results to be private/LAN (IPv4 RFC1918, IPv6 ULA/link-local).                                                                                                          | Safely resolve LAN-only devices (e.g., internal firewall targets).                              |
   | `get_ipv6_enabled`                          | Prints `1` if IPv6 is enabled in NVRAM (`ipv6_service` != `disabled`), else `0`.                                                                                                                        | Conditional logic for dual-stack scripts (skip IPv6 logic when disabled).                       |
   | `get_active_wan_if`                         | Returns the interface name of the currently active WAN (`wanN_primary` flag; falls back to `wan0_ifname`).                                                                                              | Pick the correct egress interface for WAN-specific rules or diagnostics.                        |
   | `strip_comments [<text>]`                   | Trims lines, drops blanks and `#` comments (including inline), normalizes input. Reads from argument if provided, otherwise stdin; prints cleaned lines.                                                | Preprocess multi-line configs (e.g., `CUSTOM_IPSETS`, `IPSET_RULES`, `DOS_RULES`) before parse. |
   | `is_pos_int <value>`                        | Returns success (`0`) if `<value>` is a positive integer (≥ 1); returns `1` otherwise.                                                                                                                  | Validate numeric config such as `minutes`, `above`, `burst`, `log_count`.                       |

 * [**`firewall.sh`**](jffs/scripts/utils/firewall.sh) **library**

   | Function                                                                                     | What it does                                                                                                                                                                     | Typical use-case                                                                               |
   |----------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
   | `validate_port <N>`                                                                          | Validates a single TCP/UDP port: must be an integer between `1` and `65535`. Returns `0` if valid, `1` otherwise.                                                                | Sanity-check user-provided port numbers before using them in `iptables` or parsing routines.   |
   | `validate_ports <spec>`                                                                      | Validates a port specification: accepts `"any"`, single ports (`N`), comma lists (`N,N2`), dash ranges (`N-M`), or mixed forms (e.g., `80,443,1000-2000`). Returns `0` if valid. | Validate destination port fields in rule definitions before constructing CLI args.             |
   | `normalize_protos <spec>`                                                                    | Normalizes protocol spec to `tcp`, `udp`, or `tcp,udp`. Accepts `any`, `tcp`, `udp`, `tcp,udp`, `udp,tcp`; prints canonical form, returns `0` if valid.                          | Convert user configs into canonical proto lists used by multiport rules.                       |
   | `fw_chain_exists [-6] <table> <chain>`                                                       | Returns `0` if `<chain>` exists in `<table>` (`iptables` or `ip6tables`), else `1`.                                                                                              | Guard before creating or deleting user-defined chains.                                         |
   | `create_fw_chain [-6] [-q] [-f] <table> <chain>`                                             | Ensures a chain exists; with `-f`, flushes it if present. `-6` selects `ip6tables`; `-q` suppresses info logs.                                                                   | Initialize or reset per-script chains (e.g., `WAN_FILTERING`, `WGC1_RULES`).                   |
   | `delete_fw_chain [-6] [-q] <table> <chain>`                                                  | Flushes and deletes a user-defined chain if present. No-op if absent.                                                                                                            | Clean teardown or script disable/uninstall routines.                                           |
   | `find_fw_rules [-6] "<table> <chain>" "<pattern>"`                                           | Lists all rules in `<table>/<chain>` matching a regex. Prints nothing if none.                                                                                                   | Inspect active rules to drive higher-level sync/purge logic.                                   |
   | `purge_fw_rules [-6] [-q] [--count] "<table> <chain>" "<pattern>"`                           | Deletes all rules matching `<pattern>` in `<table>/<chain>`. With `--count`, prints number of deletions.                                                                         | Bulk cleanup of outdated jumps or stale variants before reinsertion.                           |
   | `ensure_fw_rule [-6] [-q] [--count] <table> <chain> [-I [pos] \| -D] <rule...>`              | Idempotent rule manager: append, insert, or delete rules safely. Skips duplicates; `--count` prints `1` if a change occurred.                                                    | Core helper for consistent single-rule management throughout all firewall scripts.             |
   | `sync_fw_rule [-6] [-q] [--count] <table> <chain> "<pattern>" "<desired args>" [insert_pos]` | Reconciles a rule set to exactly one desired rule: if matches differ, purges all and inserts one canonical rule. Supports IPv6 and positional inserts.                           | Maintain a single authoritative jump (e.g., `PREROUTING` jump to `WAN_FIREWALL`).              |
   | `block_wan_for_host <hostname\|ip> [wan_id]`                                                 | Resolves the host to its LAN IPv4 and (if IPv6 enabled) all global IPv6 addresses. Inserts DROP/REJECT rules in `filter/FORWARD` for both directions. Defaults to `wan_id=0`.    | Temporarily isolate a LAN device from a specific WAN (e.g., LTE backup, parental control).     |
   | `allow_wan_for_host <hostname\|ip> [wan_id]`                                                 | Resolves LAN IPv4 and global IPv6, removes the corresponding DROP/REJECT rules to restore connectivity. Defaults to `wan_id=0`.                                                  | Restore WAN access previously blocked by `block_wan_for_host`.                                 |
   | `chg <command ...>`                                                                          | Runs a command and returns success (`0`) if its stdout is a non-zero integer - useful with `--count` helpers.                                                                    | Gate logic like `if chg purge_fw_rules ...; then do_something; fi` for clean change detection. |

## License

This project is distributed under the [GNU General Public License v3.0](https://github.com/kuchkovsky/asuswrt-merlin-scripts/blob/main/LICENSE).
