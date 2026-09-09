# Plan 04: Log Monitoring, Stream Parsers & Escalation Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** `sanalu` never writes its own log files. It purely tails external logs and streams clean alerts to stdout for journald. For parsing, a single fast scan handles both Combined and Proxy IP formats without regex allocations.

**Goal:** Implement real-time log ingestion (monitoring Nginx access/error log files and SSH journald/auth streams), flexible format parsers (Combined, Cloudflare proxy IP headers, and JSON), SSH port scanner detection, and tiered ban escalation.

**Architecture:**
1. **Log Tailer & Ingestion**:
   - Nginx: Inotify-based file tailer tracking active `.log` files, automatically recovering from logrotate renames/truncation.
   - SSH: Connects to `systemd-journald` stream for SSH units on Ubuntu 24, falling back to `/var/log/auth.log` tailing on Ubuntu 22.
   - Output: `sanalu` writes operational alerts to `stdout`/`stderr` only. `systemd` handles capture and rotation via `journalctl -u sanalu`.
2. **Nginx Multi-Format Parser**:
   - Reads line by line. Auto-senses format if JSON (`{...}`), or parses based on the discovered `log_format` token order.
   - Extracts real client IP (prioritizing `CF-Connecting-IP` / `X-Forwarded-For` when configured), HTTP method, URI path, HTTP status, and User-Agent.
3. **SSH Scanner & Auth Parser**:
   - Detects standard brute-force (`Failed password for ...`).
   - Detects automated port scanners sending HTTP/garbage probes to SSH:
     - `banner exchange: Connection from <IP> ...: invalid format`
     - `kex_exchange_identification: client sent invalid protocol identifier "GET / HTTP/1.1"`
4. **Ban Escalation Engine**:
   - Enforces `find_time`, `max_retry`, and progressive `ban_tiers` (15m -> 1h -> 24h -> permanent).
   - High-severity probes (`.env`, `/wp-login.php`, `phpunit`, etc.) trigger immediate permanent bans.

**Tech Stack:** Rust 2024, `tokio`, `notify`, `serde_json`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- Always use `rtk` prefix for shell commands.
- Zero panic policy in parser loops.

---

### Task 1: Nginx Multi-Format and Error Log Parsers

**Files:**
- Create: `src/parser/mod.rs`
- Create: `src/parser/nginx.rs`
- Test: `tests/nginx_parser_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct NginxLogEntry<'a> {
      pub client_ip: std::net::IpAddr,
      pub method: &'a str,
      pub path: &'a str,
      pub status: u16,
      pub referer: &'a str,
      pub user_agent: &'a str,
  }

  pub fn parse_nginx_combined_line<'a>(line: &'a str) -> Option<NginxLogEntry<'a>>;
  pub fn parse_nginx_json_line(line: &str) -> Option<(std::net::IpAddr, String, String, u16, String, String)>;
  pub fn parse_nginx_error_line(line: &str) -> Option<(std::net::IpAddr, String)>;
  ```

- [ ] **Step 1: Write unit tests on real reference Nginx logs and JSON logs**

```rust
#[test]
fn test_parse_real_nginx_access_log() {
    let line = "45.194.92.67 - - [09/Sep/2026:00:09:05 +0700] \"GET / HTTP/1.1\" 302 138 \"http://46.250.231.252:80/\" \"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\"";
    let entry = sanalu::parser::parse_nginx_combined_line(line).expect("must parse valid line");
    assert_eq!(entry.client_ip, "45.194.92.67".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/");
    assert_eq!(entry.status, 302);
    assert_eq!(entry.user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");
}

#[test]
fn test_parse_nginx_json_format() {
    let json_line = r#"{"client": "203.0.113.19", "method": "POST", "uri": "/.env", "status": 404, "ua": "curl/7.68.0"}"#;
    let (ip, method, uri, status, _, ua) = sanalu::parser::parse_nginx_json_line(json_line).expect("parse json");
    assert_eq!(ip, "203.0.113.19".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(method, "POST");
    assert_eq!(uri, "/.env");
    assert_eq!(status, 404);
    assert_eq!(ua, "curl/7.68.0");
}

#[test]
fn test_parse_real_nginx_error_forbidden_index() {
    let line = "2026/09/08 07:32:39 [error] 2806333#2806333: *223382 directory index of \"/var/www/\" is forbidden, client: 172.93.212.236, server: investfund.biz.id, request: \"GET /js/ HTTP/1.1\"";
    let (ip, reason) = sanalu::parser::parse_nginx_error_line(line).expect("must parse error line");
    assert_eq!(ip, "172.93.212.236".parse::<std::net::IpAddr>().unwrap());
    assert!(reason.contains("forbidden"));
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test nginx_parser_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement Combined, JSON, and Error log parsers**
Safely skip corrupted binary scan lines (`\x16\x03\x02`) without throwing errors.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test nginx_parser_test`
Expected: PASS.

---

### Task 2: SSH Stream & Port Scanner Parser

**Files:**
- Create: `src/parser/ssh.rs`
- Test: `tests/ssh_parser_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, PartialEq, Eq)]
  pub enum SshEvent {
      AuthFailure { ip: std::net::IpAddr, user: String },
      ScannerProbe { ip: std::net::IpAddr, reason: &'static str },
      Ignore,
  }

  pub fn parse_ssh_log_line(line: &str) -> SshEvent;
  ```

- [ ] **Step 1: Write test on real scanner lines from `references/ubuntu22/auth/auth.log`**

```rust
#[test]
fn test_parse_real_ssh_scanner_and_auth_lines() {
    let probe1 = "Sep  6 09:26:17 vmi1529040 sshd[2698855]: banner exchange: Connection from 44.220.188.23 port 47242: invalid format";
    assert_eq!(
        sanalu::parser::parse_ssh_log_line(probe1),
        sanalu::parser::SshEvent::ScannerProbe {
            ip: "44.220.188.23".parse().unwrap(),
            reason: "banner_invalid_format"
        }
    );

    let probe2 = "Sep  6 09:26:18 vmi1529040 sshd[2698856]: error: kex_exchange_identification: client sent invalid protocol identifier \"GET / HTTP/1.1\"";
    assert_eq!(
        sanalu::parser::parse_ssh_log_line(probe2),
        sanalu::parser::SshEvent::ScannerProbe {
            ip: "44.220.188.23".parse().unwrap(),
            reason: "invalid_protocol_identifier"
        }
    );

    let failed = "Sep  6 10:00:01 vmi1529040 sshd[2699999]: Failed password for invalid user admin from 192.0.2.1 port 55555 ssh2";
    assert_eq!(
        sanalu::parser::parse_ssh_log_line(failed),
        sanalu::parser::SshEvent::AuthFailure {
            ip: "192.0.2.1".parse().unwrap(),
            user: "admin".into()
        }
    );
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test ssh_parser_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `parse_ssh_log_line`**
Parse timestamps, PID brackets, scanner probe signatures, and user failures.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test ssh_parser_test`
Expected: PASS.

---

### Task 3: Multi-Tier Ban Escalation Engine

**Files:**
- Create: `src/engine/mod.rs`
- Create: `src/engine/escalation.rs`
- Test: `tests/escalation_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct BanRecord {
      pub ip: std::net::IpAddr,
      pub tier_level: usize,
      pub banned_at: std::time::SystemTime,
      pub expires_at: Option<std::time::SystemTime>,
      pub reason: String,
  }

  pub struct EscalationEngine {
      find_time: std::time::Duration,
      max_retry: u32,
      tiers: Vec<Option<std::time::Duration>>,
  }
  ```

- [ ] **Step 1: Write test for progressive ban tiers and instant probe bans**

```rust
#[test]
fn test_escalation_tiers() {
    let mut engine = sanalu::engine::EscalationEngine::new(
        std::time::Duration::from_secs(600),
        3,
        vec![
            Some(std::time::Duration::from_secs(3600)),
            Some(std::time::Duration::from_secs(86400)),
            None,
        ],
    );

    let ip: std::net::IpAddr = "198.51.100.1".parse().unwrap();
    assert_eq!(engine.record_offense(ip, "auth_fail", false), None);
    assert_eq!(engine.record_offense(ip, "auth_fail", false), None);
    let ban1 = engine.record_offense(ip, "auth_fail", false).expect("3rd offense must ban");
    assert_eq!(ban1.tier_level, 0);
    assert!(ban1.expires_at.is_some());

    let instant_ban = engine.record_offense(ip, "exploit_probe", true).expect("instant ban");
    assert!(instant_ban.expires_at.is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test escalation_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `EscalationEngine`**
Manages rolling offense windows and assigns progressive expiration tiers.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test escalation_test`
Expected: PASS.
