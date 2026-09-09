# sanalu

**Ultra-lightweight, high-performance Linux security daemon in Rust.**

`sanalu` is a modern, high-performance Linux security daemon designed to protect web servers and SSH endpoints in real time. It applies instant, zero-conflict packet drops via native `nftables`, provides 3-stage threat intelligence, and synchronizes active bans to Cloudflare's Free Tier WAF within a 4,000-character budget.

---

## Key Highlights

- **Blazing Performance**: Pure Rust (2024 edition). Sub-millisecond log processing with zero runtime dependencies (no Python, no JVM, no external database).
- **Zero-Conflict Firewall**: Operates inside an isolated `table inet sanalu` at `prerouting priority -100`. It drops malicious packets before connection tracking (`conntrack`) and never interferes with UFW, Firewalld, or Docker iptables rules.
- **CIDR & Single IP Support**: Drops both individual attackers (`198.51.100.22`) and entire malicious subnets (`192.0.2.0/24`) using native `nftables` interval sets.
- **3-Stage Threat Intelligence**:
  1. **Instant Probe Banning**: Immediate drops for path traversals, `.env`, `.git`, WordPress exploits, and known web vulnerability scanners.
  2. **SSH Scanner & Brute-Force Detector**: Distinguishes automated network port scanners from authentication failures.
  3. **Bot & ASN Reputation**: Filters malicious user agents, aggressive scrapers, and suspicious cloud/datacenter ASNs.
- **Dynamic Escalation**: Multi-tier ban durations (`15m` &rarr; `1h` &rarr; `24h` &rarr; `permanent`) with sliding offense time-windows.
- **Cloudflare Free Tier WAF Sync**: Automatically compiles active threats into a single Cloudflare WAF rule expression under 4,000 characters using LRU eviction and regional ASN clauses.
- **0ms Diagnostics**: `sanalu check <ip/cidr>` provides immediate root-cause inspection without scrolling through thousands of ban records.
- **Self-Contained Storage**: Embedded ACID key-value storage using [`redb`](https://github.com/cberner/redb) with zero external database configuration.

---

## Defense-in-Depth Architecture

`sanalu` implements a dual-layer, zero-conflict defense model:

1. **Edge CDN Defense (Cloudflare Free Tier WAF)**
   - Syncs active local attackers to Cloudflare's edge before traffic ever touches your origin server.
   - Fits within Cloudflare Free Tier's 4,000-character single-rule budget using LRU eviction and IP/ASN aggregation.
   - Prevents bandwidth saturation and frees server resources from processing malicious requests.

2. **Kernel Ingress Drop (`prerouting priority -100`)**
   - Packets reaching the origin server are dropped at the earliest possible packet hook in `nftables`.
   - Dropped before Linux connection tracking (`conntrack`), preventing state-table exhaustion attacks.
   - Fully isolated inside `table inet sanalu`, ensuring zero interference with UFW, Firewalld, or Docker iptables rules.

3. **High-Performance Embedded Storage (`redb`)**
   - Embedded atomic B-Tree with ACID durability and zero external database overhead.
   - Zero-copy reads via memory-mapped architecture without disk thrashing or lock contention.
   - Enables sub-millisecond status checks and 0ms IP diagnostics (`sanalu check <ip>`).

---

## Prerequisites & System Requirements

`sanalu` is purpose-built for modern Linux servers and depends on two core system components:

1. **`nftables` (Required Firewall Backend)**
   - `sanalu` enforces packet drops exclusively through native Linux `nftables` via an isolated table (`table inet sanalu`).
   - Legacy `iptables` and `ipset` are **not supported**.
   - The `nft` command-line utility must be installed:
     - **Ubuntu / Debian**: `sudo apt update && sudo apt install nftables`
     - **RHEL / Rocky / AlmaLinux**: `sudo dnf install nftables`
     - **Arch Linux**: `sudo pacman -S nftables`
     - Verify installation: `nft --version`

2. **`systemd` (Service Lifecycle & Background Daemon)**
   - Production deployment as a background daemon relies on `systemd`.
   - When run with root privileges, `sanalu` automatically bootstraps `/etc/systemd/system/sanalu.service` and registers with `systemctl`.
   - Handles auto-start on boot, daemon supervision, and logging via `journalctl -u sanalu -f`.
   - *(Note: You can run `sanalu run` directly in the foreground for testing or custom process supervision, but background service management assumes `systemd`).*

3. **Linux Kernel & Privileges**
   - Linux kernel 5.4+ with `nftables` interval and timeout sets support (`flags interval, timeout;`).
   - Root privileges (`sudo`) are required to apply kernel firewall rules and register systemd units.

---

## Installation

### Option 1: Precompiled Binary (Zero-Setup, Recommended)

Download the standalone binary for Linux x86_64 and run it. **No setup or wizard required** — `sanalu run` auto-detects your server environment, log files, creates config/database, and activates firewall protection in milliseconds:

```bash
# 1. Download and extract precompiled binary
curl -LO https://github.com/chay22/sanalu/releases/latest/download/sanalu-linux-x86_64.tar.gz
tar -xzf sanalu-linux-x86_64.tar.gz

# 2. Install to system PATH
sudo install -m 755 sanalu /usr/bin/sanalu

# 3. Simply run it! (Everything is automatically bootstrapped and detected)
sudo sanalu run
```

On first run, `sanalu` automatically does all the heavy lifting in < 5ms:
- **Auto-discovers** all active Nginx access/error logs and SSH authentication sources
- **Auto-bootstraps** `/etc/sanalu/sanalu.toml` (if not already present)
- **Auto-initializes** `/var/lib/sanalu/sanalu.redb` with secure permissions (`0700`)
- **Auto-configures** kernel firewall rules (`table inet sanalu` in `nftables`)
- **Auto-installs** shell tab-completions into `/etc/bash_completion.d/sanalu`

### Option 2: Debian / Ubuntu Package (`.deb`)

```bash
sudo dpkg -i sanalu_*_amd64.deb
sudo systemctl enable --now sanalu
```

### Option 3: Build from Source

Requirements: Rust 1.85+ and `nftables`.

```bash
git clone https://github.com/chay22/sanalu.git
cd sanalu
cargo build --release
sudo install -m 755 target/release/sanalu /usr/bin/sanalu
```

---

## Systemd Service Setup

`sanalu` automatically bootstraps its own systemd service unit into `/etc/systemd/system/sanalu.service` when run with root privileges. You do not need to download or copy any extra files:

```bash
# Enable and start the background daemon
sudo systemctl enable --now sanalu

# View live daemon logs
sudo journalctl -u sanalu -f
```

---

## Quick Command Reference

```bash
# Check service and ban status
sanalu status

# Diagnose an IP or CIDR subnet (0ms root-cause lookup)
sanalu check 198.51.100.22
sanalu check 192.0.2.0/24

# List active bans (with automatic terminal paging)
sanalu ban list
sanalu ban list --all
sanalu ban list --plain | wc -l
sanalu ban list --filter ssh

# Manually ban an IP or CIDR
sanalu ban 198.51.100.45 --reason "abusive scraper"
sanalu ban 192.0.2.0/24 --reason "malicious subnet"

# Unban an IP or CIDR
sanalu unban 198.51.100.45
sanalu unban 192.0.2.0/24

# Manage whitelist
sanalu whitelist add 203.0.113.1
sanalu whitelist add 10.0.0.0/8
sanalu whitelist list
sanalu whitelist remove 203.0.113.1

# Cloudflare Free WAF integration
sanalu cloudflare status
sanalu cloudflare list
sanalu cloudflare sync

# Bot categories & ASN rules
sanalu category block ai_crawler
sanalu category list
sanalu asn block 400529
sanalu region allow US

# Auto-generate shell autocompletions (bash, zsh, fish)
sanalu completions bash | sudo tee /etc/bash_completion.d/sanalu > /dev/null

# Print version and build diagnostics
sanalu version
sanalu version --short

# Cleanly uninstall sanalu and flush nftables rules
sudo sanalu uninstall --dry-run
sudo sanalu uninstall --purge
```

---

## CLI Guide

### 1. `sanalu status`
Prints real-time runtime statistics:
- Total active kernel bans and remaining durations
- Blocked bot categories
- Blocked Autonomous System Numbers (ASNs)
- Allowed ISO country/region codes
- Active Cloudflare WAF rule expression

### 2. `sanalu check <target>`
Instantly diagnoses any IP address or CIDR range:
- Evaluates whether the target is directly banned or caught inside a banned CIDR range
- Displays tier level, duration, and reason
- Displays recorded offense history (first seen, last seen, incident count)
- Shows whitelist evaluation

```
=== Sanalu Target Diagnostics ===
Target:            198.51.100.22 (IP)
Status:            BANNED [Direct Ban]
Tier Level:        1
Expiry:            expires at unix 1788939600 (3600s duration)
Reason:            ssh_brute_force
Banned At:         unix 1788936000
Whitelisted:       NO

Offense History:
  Recorded Count:  3
  First Seen:      unix 1788935400
  Last Seen:       unix 1788936000
```

### 3. `sanalu ban list`
Inspect active bans without overwhelming your terminal:
- **Default**: Shows summary count and top 50 active bans formatted neatly.
- `--all`: Displays all bans. Automatically pipes into `$PAGER` / `less -R` when running interactively in a TTY.
- `--plain`: Outputs machine-readable entries (one target per line), ideal for piping into `wc -l`, `grep`, or external tools.
- `--filter <text>`: Filters bans by target IP, subnet, or reason string.

### 4. `sanalu cloudflare`
Synchronizes active local bans with your Cloudflare Free Tier WAF:
- `sanalu cloudflare status`: Displays character consumption against Cloudflare's 4,000-character budget, zone details, and capacity.
- `sanalu cloudflare list`: Displays the compiled active Cloudflare WAF filter expression.
- `sanalu cloudflare sync`: Manually triggers an atomic push to the Cloudflare API.

### 5. `sanalu uninstall`
Completely cleans up the host system:
- Stops and disables `sanalu.service`
- Drops `table inet sanalu` from the Linux kernel
- Removes completion scripts and `/var/lib/sanalu`
- Preserves `/etc/sanalu/` unless `--purge` is passed
- Use `--dry-run` to preview all cleanup actions safely before executing.

### 6. `sanalu version`
Displays build metadata and environment target:
- `sanalu version`: Outputs binary version, target architecture, OS, repository, and license.
- `sanalu version --short` (or `-s`): Prints only the clean semver number (e.g., `0.1.0`), ideal for automation scripts and deployment checks.

---

## Configuration (`/etc/sanalu/sanalu.toml`)

```toml
[general]
db_path = "/var/lib/sanalu/sanalu.redb"
ip_db_path = "/var/lib/sanalu/ip_asn_geo.bin"
whitelist = ["127.0.0.1", "::1", "10.0.0.0/8"]

[nginx]
enabled = true
find_time = "10m"
max_retry = 1
ban_tiers = ["15m", "1h", "24h", "permanent"]
probe_instant_ban = true
allowed_endpoints = [
    "^/api/.*",
    "^/health$",
    "^/webhooks/.*"
]

[ssh]
enabled = true
find_time = "10m"
max_retry = 5
ban_tiers = ["15m", "1h", "24h", "permanent"]
scanner_instant_ban = true

[bots]
blocked_categories = [
    "scanners",
    "ai_crawler",
    "bad_scraper",
    "generic_tools"
]

[asn_rules]
enabled = true
restricted_asns = [15169, 16509, 14061, 31898, 13238, 13335]
allowed_regions = ["ID", "MY", "SG", "US", "PH", "JP"]
blocked_asns = [400529, 48090]

[cloudflare]
enabled = false
api_token = "your-cloudflare-api-token"
zone_id = "your-zone-id"
rule_name = "sanalu_auto_block"
action = "block"
max_rule_chars = 3950
sync_batch_seconds = 5
```

---

## Architecture & Kernel Firewall

`sanalu` initializes an atomic table within `nftables`:

```nft
add table inet sanalu
add set inet sanalu blacklist_v4 { type ipv4_addr; flags interval, timeout; }
add set inet sanalu blacklist_v6 { type ipv6_addr; flags interval, timeout; }
add chain inet sanalu prerouting { type filter hook prerouting priority -100; policy accept; }
add rule inet sanalu prerouting ip saddr @blacklist_v4 drop
add rule inet sanalu prerouting ip6 saddr @blacklist_v6 drop
```

### Why Priority -100?
- Priority `-100` executes in the `prerouting` hook **before Linux connection tracking (`conntrack`)**.
- Dropped packets consume virtually zero CPU and never allocate connection state.
- Because it lives strictly in `table inet sanalu`, it operates in parallel with any existing firewall (UFW, Firewalld, raw iptables, or Docker network bridges) without race conditions.

---

## Cloudflare Free Tier WAF Synchronization

Cloudflare Free plans limit custom security rules to **4,000 characters** per expression. `sanalu` maximizes this budget through an intelligent optimizer:
1. **LRU Eviction**: Keeps the most active and dangerous attackers in Cloudflare while retiring older, inactive threats back to local kernel filtering.
2. **Regional ASN Reduction**: Combines datacenter ASNs with country clauses (`(ip.geoip.asnum in {15169} and not ip.geoip.country in {"ID" "SG"})`) to block cloud scraper farms in single compact statements.
3. **Automatic Character Budgeting**: Pre-calculates syntax overhead and safely caps rules under 3,950 characters to prevent API rejection.

---

## Testing & Replay Tools

You can verify threat detection rules against real historical logs before running the daemon:

```bash
# Replay and test an access or auth log file
sanalu test-log /var/log/nginx/access.log
```

---

## License

Dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
