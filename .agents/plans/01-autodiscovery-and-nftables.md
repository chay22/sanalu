# Plan 01: Auto-Discovery & Zero-Conflict Firewall Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** By strictly targeting systems with systemd + nftables (Ubuntu 22/24 & Debian 11/12), we avoid speculative iptables fallback code. `table inet sanalu` at prerouting priority -100 guarantees zero conflict with Docker, UFW, or iptables-nft.

**Goal:** Create the auto-discovery module that discovers server environment capabilities (systemd journald presence, active Nginx virtual host log paths, custom Nginx `log_format` directives, SSH auth sources) and the zero-configuration isolated `nftables` firewall engine.

**Architecture:** 
1. **Target Platform Baseline**:
   - Requires Linux with **`systemd`** and **`nftables`** (Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Debian 11/12).
   - Kernel $\ge 5.4$ with `nf_tables` (default on all target distros).
2. **Coexistence with `iptables-nft` / UFW / Docker**:
   - `iptables-nft` is a translation wrapper over `nf_tables` that manages `table ip filter`.
   - `sanalu` manages its own isolated table: `table inet sanalu`.
   - By hooking into `prerouting` at priority `-100`, `sanalu` drops bad packets immediately at ingress before any `iptables-nft`, Docker, or UFW rule is evaluated.
   - When `sanalu` flushes or stops, only `table inet sanalu` is affected. Zero conflict.
3. `DiscoveryEngine`:
   - Checks if `systemd-journald` is active and streaming SSH (`_COMM=sshd` or `UNIT=ssh.service`), falling back to `/var/log/auth.log` if running on a system with rsyslog (Ubuntu 22).
   - Scans `/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/*`, and `/etc/nginx/conf.d/*` to extract:
     - All `log_format <name> '...'` statements.
     - All `access_log /path/to/log [format_name]` mappings.
     - Resolves the format tokens (Combined, Cloudflare proxy IP headers like `$http_cf_connecting_ip`, or JSON).
4. `FirewallEngine`:
   - Auto-initializes an isolated `nftables` table named `inet sanalu`.
   - Defines sets `blacklist_v4` (`type ipv4_addr; flags timeout;`) and `blacklist_v6` (`type ipv6_addr; flags timeout;`).
   - Requires zero user configuration in `sanalu.toml`.
   - Built-in dry-run mode for local developer environments and tests without root.

**Tech Stack:** Rust 2024, `std::process::Command`, `walkdir`, `serde`, `thiserror`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- Always use `rtk` prefix for shell commands.
- Pedantic clippy compliance, zero unwraps in library code.

---

### Task 1: Environment & Nginx Log Format Discovery

**Files:**
- Create: `src/discovery/mod.rs`
- Create: `src/discovery/nginx.rs`
- Create: `src/discovery/ssh.rs`
- Test: `tests/discovery_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub enum SshLogSource {
      JournaldService(String),
      File(std::path::PathBuf),
  }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum NginxLogFormatKind {
      Combined,
      CloudflareProxy,
      Json,
      Custom(Vec<NginxFieldToken>),
  }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum NginxFieldToken {
      RemoteAddr,
      CfConnectingIp,
      XForwardedFor,
      TimeLocal,
      Request,
      Status,
      BytesSent,
      HttpReferer,
      HttpUserAgent,
      Other(String),
  }

  pub struct DiscoveredNginxLog {
      pub path: std::path::PathBuf,
      pub format_kind: NginxLogFormatKind,
  }

  pub struct DiscoveredEnvironment {
      pub nginx_logs: Vec<DiscoveredNginxLog>,
      pub nginx_error_logs: Vec<std::path::PathBuf>,
      pub ssh_source: SshLogSource,
  }

  pub fn parse_nginx_config_for_formats(config_content: &str) -> std::collections::HashMap<String, NginxLogFormatKind>;
  pub fn discover_environment() -> DiscoveredEnvironment;
  ```

- [ ] **Step 1: Write failing unit test for log format extraction and SSH source detection**

```rust
#[test]
fn test_parse_nginx_log_format_directives() {
    let conf = r#"
        http {
            log_format custom_cf '$http_cf_connecting_ip - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
            log_format json_fmt '{"ip": "$remote_addr", "req": "$request"}';

            server {
                access_log /var/log/nginx/cf.access.log custom_cf;
                access_log /var/log/nginx/default.access.log;
            }
        }
    "#;
    let formats = sanalu::discovery::parse_nginx_config_for_formats(conf);
    assert_eq!(formats.get("custom_cf"), Some(&sanalu::discovery::NginxLogFormatKind::CloudflareProxy));
    assert_eq!(formats.get("json_fmt"), Some(&sanalu::discovery::NginxLogFormatKind::Json));
}

#[test]
fn test_ssh_source_detection() {
    let source = sanalu::discovery::detect_ssh_source();
    assert!(matches!(source, sanalu::discovery::SshLogSource::JournaldService(_) | sanalu::discovery::SshLogSource::File(_)));
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test discovery_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement Nginx format parser & SSH source probe**
Tokenize `log_format` string variables and build `DiscoveredEnvironment`.
Checks for `/run/systemd/journal` socket for systemd-journald streaming.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test discovery_test`
Expected: PASS.

---

### Task 2: Zero-Config `nftables` Engine

**Files:**
- Create: `src/firewall/mod.rs`
- Create: `src/firewall/nftables.rs`
- Create: `src/firewall/mock.rs`
- Test: `tests/firewall_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub trait FirewallBackend: Send + Sync {
      fn init_tables(&self) -> Result<(), crate::error::FirewallError>;
      fn ban_ip(&self, ip: std::net::IpAddr, timeout_secs: Option<u64>) -> Result<(), crate::error::FirewallError>;
      fn unban_ip(&self, ip: std::net::IpAddr) -> Result<(), crate::error::FirewallError>;
      fn list_banned(&self) -> Result<Vec<std::net::IpAddr>, crate::error::FirewallError>;
      fn flush(&self) -> Result<(), crate::error::FirewallError>;
  }

  pub struct NftablesBackend {
      table: String,
      set_v4: String,
      set_v6: String,
      dry_run: bool,
  }

  impl NftablesBackend {
      pub fn auto_detect(dry_run: bool) -> Self;
  }
  ```

- [ ] **Step 1: Write test for automatic ruleset generation and mock firewall operations**

```rust
#[test]
fn test_auto_nftables_ruleset_syntax() {
    let backend = sanalu::firewall::NftablesBackend::auto_detect(true);
    let init_cmd = backend.render_init_ruleset();
    assert!(init_cmd.contains("add table inet sanalu"));
    assert!(init_cmd.contains("set blacklist_v4 { type ipv4_addr; flags timeout; }"));
    assert!(init_cmd.contains("set blacklist_v6 { type ipv6_addr; flags timeout; }"));
    assert!(init_cmd.contains("hook prerouting priority -100;"));
    assert!(init_cmd.contains("ip saddr @blacklist_v4 drop"));
    assert!(init_cmd.contains("ip6 saddr @blacklist_v6 drop"));
}

#[test]
fn test_mock_firewall_ban_and_unban() {
    let mock = sanalu::firewall::MockFirewallBackend::default();
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    mock.ban_ip(ip, Some(3600)).unwrap();
    assert!(mock.list_banned().unwrap().contains(&ip));
    mock.unban_ip(ip).unwrap();
    assert!(!mock.list_banned().unwrap().contains(&ip));
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test firewall_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `NftablesBackend` with auto-table management**
Applies atomic configuration using `nft -f -`.
Zero table or set names exposed to the user config.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test firewall_test`
Expected: PASS.
