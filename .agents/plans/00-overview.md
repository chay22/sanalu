# Sanalu - System Overview & Architecture Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** Seamless self-bootstrapping: `sanalu run` automatically creates all missing directories, database files, and config templates on startup. No separate installation command to remember.

**Goal:** Build `sanalu`, an ultra-lightweight, high-performance security daemon in Rust that replaces fail2ban. It automatically discovers Nginx and SSH logs on Ubuntu 22/24 (and Debian 11/12), applies zero-conflict `nftables` bans locally without manual firewall configuration, and synchronizes with Cloudflare Free WAF Security Rules (under the strict 4,000-character expression limit with LRU ban rotation, ASN filtering, and geo-fencing).

---

## Target Platform Baseline & Execution Requirements

- **Privilege Requirement:** **`root` access is mandatory** on boot for live packet filtering and reading protected system logs (`/var/log/nginx`, `journald`). Non-root execution is prohibited on first boot and allowed **only** with `--dry-run` for local log simulation.
- **Operating System Baseline:** Modern Linux distributions using **`systemd`** and **`nftables`**:
  - **Tier 1 (Tested & Targeted):** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS.
  - **Compatible:** Debian 11 (Bullseye), Debian 12 (Bookworm).
- **Kernel & Networking Requirements:** Linux kernel $\ge 5.4$ with `nf_tables` enabled (default on Ubuntu 20+ and Debian 11+).
- **Firewall Coexistence:** `sanalu` operates exclusively in its own namespace (`table inet sanalu`). Even if the host uses `iptables-nft`, UFW, or Docker, `sanalu` runs at `prerouting priority -100` before those chains, with **zero table collisions** and zero interference.
- **Web Server:** Nginx using standard Debian/Ubuntu directory structures (`/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/`, `/etc/nginx/conf.d/`, and `/var/log/nginx/`). Supports any backend service (Rust, Go, Node.js/Bun, Python, PHP, static).
- **SSH Service:** OpenSSH (`sshd`), ingesting events natively via `systemd-journald` (`_COMM=sshd` or `UNIT=ssh.service`), with fallback to `/var/log/auth.log` when rsyslog is active (Ubuntu 22).

---

## Strict 3-Stage Evaluation Pipeline

Every incoming log event is evaluated in strict descending order of authority. A check never bypasses an earlier stage:

```
[ Incoming Request ]
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 1: IP & ASN / Country Filter (Highest Authority)      │
│ 1. IP in Whitelist? -> ALLOW (bypass everything)            │
│ 2. IP in Banned List? -> DROP / IGNORE                      │
│ 3. ASN in Blocked ASNs? -> BAN immediately                  │
│ 4. ASN in Restricted ASNs from unallowed region? -> BAN     │
└─────────────────────────────────────────────────────────────┘
        │ (Passed Stage 1)
        ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 2: User-Agent & Bot Category Filter                   │
│ 1. Is it a blocked bot category (scanners, AI, bad SEO)?    │
│ 2. Is it a blocked generic tool (Java, perl, python, etc.)? │
│    -> If YES: BAN immediately.                              │
│    (An attacker using zgrab on any path is BANNED here;     │
│     allowed endpoints DO NOT bypass Stage 2).               │
└─────────────────────────────────────────────────────────────┘
        │ (Passed Stage 2)
        ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 3: Path & Query Probe Filter (Polyglot / Generic)     │
│ 1. Matches `allowed_endpoints` regex/prefix? -> ALLOW       │
│ 2. Matches known exploit probes (.env, .git, /adminer,      │
│    phpunit, /telescope, path traversal `..`, `%00`)?        │
│    -> BAN immediately.                                      │
│ 3. Matches sensitive dumps (.bak, .swp, .key, .pem, .sql)?  │
│    -> BAN immediately.                                      │
│ 4. Standard application routes (API, SPA, dynamic routes)?  │
│    -> ALLOW.                                                │
└─────────────────────────────────────────────────────────────┘
```

---

## Architecture & Storage (`redb`)

1. **Self-Bootstrapping Runtime (`sanalu run`)**:
   - Spawning `sanalu run` under systemd automatically initializes `/var/lib/sanalu/` and `sanalu.redb` if missing.
   - If `/etc/sanalu/sanalu.toml` is absent, it writes the default template and starts with safe defaults.
   - Zero manual setup commands.
2. **Embedded Persistent Storage (`redb`)**:
   - Single database file at `/var/lib/sanalu/sanalu.redb`.
   - Stores:
     - `bans`: Active IP bans, escalation tiers, timestamps, reasons.
     - `offenses`: History of repeat offenders for tiered escalation.
     - `whitelist`: Whitelisted IPs / CIDRs.
     - `blocked_categories`: Runtime bot categories to block.
     - `blocked_asns`: Runtime blocked ASNs.
     - `allowed_regions`: Runtime allowed country codes for restricted ASNs.
     - `cloudflare`: Cached active WAF rule expression and LRU rotation state.
3. **Runtime Mutability via CLI**:
   - Whitelist, blocked categories, blocked ASNs, and allowed regions can be modified on the fly via CLI subcommands without restarting the daemon.
4. **Event-Driven Cloudflare Sync with Batch Window (`sync_batch_seconds`)**:
   - When new bans occur, they are applied to `nftables` in 0ms.
   - Cloudflare sync is triggered with a **5 to 10 second batch window** (`sync_batch_seconds`) to coalesce multiple attacks into a single API update, respecting Cloudflare rate limits while stopping traffic at the edge before bandwidth is consumed.
   - Zero polling when no attacks occur.
5. **Debian Packaging (`.deb`) & Production Systemd Service**:
   - Packaged as a standard `.deb` with a high-performance systemd unit file removing kernel/OS limits (`LimitNOFILE=1048576`, `TasksMax=infinity`, `OOMScoreAdjust=-500`).

---

## Minimal Configuration Specification (`sanalu.toml`)

```toml
[general]
whitelist = [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
db_path = "/var/lib/sanalu/sanalu.redb"
ip_db_path = "/var/lib/sanalu/ip_asn_geo.bin"

[nginx]
enabled = true
find_time = "10m"
max_retry = 1
ban_tiers = ["15m", "1h", "24h", "permanent"]
probe_instant_ban = true
allowed_endpoints = [
    "^/api/.*",
    "^/health$",
    "^/metrics$",
    "^/webhooks/.*",
    "^/ws/.*"
]

[ssh]
enabled = true
find_time = "10m"
max_retry = 3
ban_tiers = ["1h", "24h", "permanent"]
scanner_instant_ban = true

[bots]
blocked_categories = [
    "scanners",
    "ai",
    "aggressive_seo",
    "generic_tools"
]

[asn_rules]
enabled = true
# These ASNs are blocked if originating outside allowed_regions:
restricted_asns = [
    15169, # Google
    16509, # Amazon AWS
    14061, # DigitalOcean
    31898, # Oracle Cloud
    13238, # Tencent
    13335  # Cloudflare
]
allowed_regions = ["ID", "MY", "SG", "US", "PH", "JP"]
# Unconditionally blocked ASNs:
blocked_asns = []

[cloudflare]
enabled = false
api_token = ""
zone_id = ""
rule_name = "sanalu_auto_block"
action = "block"
max_rule_chars = 3950
sync_batch_seconds = 5
```

---

## Detailed Plans Index

1. [01-autodiscovery-and-nftables.md](file:///code/rust/sanalu/plans/01-autodiscovery-and-nftables.md): Platform baseline, root verification, Nginx `log_format` discovery, and zero-config `nftables` engine.
2. [02-bot-and-threat-intelligence.md](file:///code/rust/sanalu/plans/02-bot-and-threat-intelligence.md): 3-stage pipeline, bot categories, polyglot exploit probes, and runtime category management.
3. [03-asn-geoip-and-cloudflare.md](file:///code/rust/sanalu/plans/03-asn-geoip-and-cloudflare.md): Registration-free IP/ASN/Geo database, regional ASN rules, batched Cloudflare sync, and 4,000-char rotation.
4. [04-log-monitoring-and-tier-engine.md](file:///code/rust/sanalu/plans/04-log-monitoring-and-tier-engine.md): Async Inotify/journald tailers, multi-format Nginx & SSH parsers, and tiered ban escalation.
5. [05-cli-and-daemon-design.md](file:///code/rust/sanalu/plans/05-cli-and-daemon-design.md): CLI interface (`category`, `asn`, `region`, `whitelist`), embedded `redb` storage, `.deb` packaging, and unrestricted systemd unit.
6. [06-implementation-milestones.md](file:///code/rust/sanalu/plans/06-implementation-milestones.md): Bite-sized development milestones, test suites using `references/` real logs, and `sentrux` quality gates.
