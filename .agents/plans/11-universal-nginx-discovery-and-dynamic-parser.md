# Plan 11: Universal Nginx Discovery & Dynamic Custom Log Format Parser

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
Build automated active Nginx config discovery, recursive vhost include crawler, universal format compiler, and dynamic log line parser for Sanalu.

**Architecture:**
- **Active Discovery:** Detect active Nginx configuration root via `/proc` and systemd unit files directly in pure Rust (< 0.2 ms), falling back to standard paths.
- **Recursive Config Crawler:** Traverse the entire configuration graph resolving nested and wildcard `include` directives, multi-line `log_format` definitions, and scoped `access_log` directives across virtual hosts with symlink cycle deduplication.
- **Universal Format Compiler:** Compile any arbitrary Nginx `log_format` into a high-performance token/delimiter state machine (`CompiledLogFormat`), extracting real client IP (priority: Cloudflare -> X-Forwarded-For -> RemoteAddr), method, path, status, referer, user agent, and host.
- **Engine Watcher & Threat Pipeline:** Pass compiled formats into per-file watchers, parse log lines with zero heap allocations, and evaluate status-code-conditioned and method-conditioned threat rules.

**Tech Stack:**
Rust 2024 edition, `tokio`, `redb`, `nftables`, `walkdir`, `glob`.

**Spec:**
- Auto-detect active Nginx config from `/proc/*/cmdline` (`-c <path>`) or systemd unit (`ExecStart=... -c <path>`).
- Crawl the full vhost hierarchy (`sites-enabled/*`, `conf.d/*.conf`, etc.) relative to config root.
- Parse arbitrary custom multi-line `log_format` definitions and bind them to `access_log` paths.
- Compile formats into sequential delimiter slices for sub-microsecond zero-copy line parsing.
- Extract `client_ip`, `method`, `path`, `status`, `referer`, `user_agent`, `host`.
- Zero comments (`//` or `/* */`) in any `.rs` file.
- Cyclomatic complexity < 25 per function.
- All tests pass, Sentrux score >= 7295, zero architectural boundary violations.

## Global Constraints

- Strictly follow `no-comments-in-code.md`: ZERO comments (`//` or `/* */`) in any Rust file (`.rs`).
- Use `rtk` prefix for all shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
- Keep cyclomatic complexity (`max_cc`) below 25 for every function.
- Do not introduce architecture cycle violations or layer boundary breaches in `.sentrux/rules.toml`.
- Use `tgrep` or `zvec-grep` (`zg query --rg`) for search, not raw commands.
- Keep Sentrux quality signal high (>= 7295).

---

## Architecture Specification

### 1. Active Configuration Detection Hierarchy
```
[Level 1: Running Process]
Scan /proc/*/cmdline for "nginx: master process"
  -> If found and contains `-c <path>`, return PathBuf(<path>)
  -> If found without `-c`, resolve /proc/<pid>/exe and default prefix

[Level 2: Systemd Unit Inspection]
Directly read service units on disk:
  1. /etc/systemd/system/nginx.service
  2. /etc/systemd/system/multi-user.target.wants/nginx.service
  3. /lib/systemd/system/nginx.service
  -> Parse `ExecStart=` directive for `-c <path>`

[Level 3: Standard Filesystem Fallbacks]
Check existence in order:
  1. /etc/nginx/nginx.conf
  2. /usr/local/nginx/conf/nginx.conf
  3. /opt/nginx/conf/nginx.conf
```

### 2. Universal Format Representation
```rust
pub enum CompiledLogFormat {
    Delimited(Vec<FormatSegment>),
    Json,
}

pub enum FormatSegment {
    Variable(LogVariable),
    Literal(String),
}

pub enum LogVariable {
    RemoteAddr,
    CfConnectingIp,
    XForwardedFor,
    TimeLocal,
    Request,
    RequestMethod,
    RequestUri,
    Status,
    BodyBytesSent,
    HttpReferer,
    HttpUserAgent,
    Host,
    Ignored(String),
}

pub struct NginxLogEntry<'a> {
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub host: Option<&'a str>,
}
```

---

### Task 1: Active Nginx Configuration Discovery

**Files:**
- Modify: `src/discovery/nginx.rs:1-60`
- Test: `tests/nginx_discovery_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn find_active_nginx_conf() -> PathBuf;
  pub fn find_active_nginx_conf_with_paths(
      proc_root: &Path,
      systemd_dirs: &[&Path],
      fallbacks: &[&Path],
  ) -> PathBuf;
  ```

- [ ] **Step 1: Write the failing test**

```rust
use sanalu::discovery::nginx::find_active_nginx_conf_with_paths;
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_find_conf_from_proc_cmdline() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let pid_dir = proc_dir.join("1234");
    fs::create_dir_all(&pid_dir).unwrap();
    let mut cmdline = File::create(pid_dir.join("cmdline")).unwrap();
    cmdline
        .write_all(b"nginx: master process\0-c\0/etc/nginx/custom.conf\0")
        .unwrap();

    let found = find_active_nginx_conf_with_paths(&proc_dir, &[], &[]);
    assert_eq!(found.to_str().unwrap(), "/etc/nginx/custom.conf");
}

#[test]
fn test_find_conf_from_systemd_unit() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let systemd_dir = dir.path().join("systemd");
    fs::create_dir_all(&systemd_dir).unwrap();
    let mut unit = File::create(systemd_dir.join("nginx.service")).unwrap();
    unit.write_all(b"[Service]\nExecStart=/usr/sbin/nginx -c /opt/nginx/service.conf\n")
        .unwrap();

    let found = find_active_nginx_conf_with_paths(
        &proc_dir,
        &[systemd_dir.as_path()],
        &[],
    );
    assert_eq!(found.to_str().unwrap(), "/opt/nginx/service.conf");
}

#[test]
fn test_find_conf_fallback() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let fallback = dir.path().join("nginx.conf");
    File::create(&fallback).unwrap();

    let found = find_active_nginx_conf_with_paths(
        &proc_dir,
        &[],
        &[fallback.as_path()],
    );
    assert_eq!(found, fallback);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test nginx_discovery_test`
Expected: FAIL with unresolved import or function not found.

- [ ] **Step 3: Write minimal implementation**

Implement `find_active_nginx_conf_with_paths` and `find_active_nginx_conf` in `src/discovery/nginx.rs`:
- Reads `/proc/*/cmdline` splitting on `\0` looking for `-c` flag following `nginx`.
- If not found, inspects systemd unit files for `ExecStart=` with `-c`.
- Falls back to existing files in fallback slice.
- Zero comments in `.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test nginx_discovery_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
rtk git add src/discovery/nginx.rs tests/nginx_discovery_test.rs
rtk git commit -m "feat(discovery): implement active nginx config discovery via proc and systemd"
```

---

### Task 2: Recursive VHost Config Crawler

**Files:**
- Modify: `src/discovery/nginx.rs`
- Modify: `src/discovery/mod.rs`
- Test: `tests/nginx_crawler_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct NginxCrawlerResult {
      pub formats: HashMap<String, String>,
      pub access_logs: Vec<DiscoveredNginxLog>,
      pub error_logs: Vec<PathBuf>,
  }

  pub fn crawl_nginx_config_tree(
      root_conf: &Path,
      nginx_log_dir: &Path,
  ) -> NginxCrawlerResult;
  ```

- [ ] **Step 1: Write the failing test**

```rust
use sanalu::discovery::nginx::{crawl_nginx_config_tree, NginxLogFormatKind};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_crawl_multiline_format_and_nested_includes() {
    let dir = tempdir().unwrap();
    let conf_dir = dir.path().join("nginx");
    let sites_dir = conf_dir.join("sites-enabled");
    let log_dir = dir.path().join("logs");
    fs::create_dir_all(&sites_dir).unwrap();
    fs::create_dir_all(&log_dir).unwrap();

    let root_conf = conf_dir.join("nginx.conf");
    let mut root_file = File::create(&root_conf).unwrap();
    root_file
        .write_all(
            b"http {\n\
            log_format cloudflare '$http_cf_connecting_ip - $remote_user [$time_local] '\n\
                                  '\"$request\" $status $body_bytes_sent '\n\
                                  '\"$http_referer\" \"$http_user_agent\"';\n\
            include sites-enabled/*;\n\
        }\n",
        )
        .unwrap();

    let site_conf = sites_dir.join("site1.conf");
    let mut site_file = File::create(&site_conf).unwrap();
    let access_log_path = log_dir.join("site1.access.log");
    site_file
        .write_all(
            format!(
                "server {{\n    access_log {} cloudflare;\n}}\n",
                access_log_path.to_str().unwrap()
            )
            .as_bytes(),
        )
        .unwrap();

    let result = crawl_nginx_config_tree(&root_conf, &log_dir);
    assert!(result.formats.contains_key("cloudflare"));
    assert!(result.formats.contains_key("combined"));

    let found_log = result
        .access_logs
        .iter()
        .find(|l| l.path == access_log_path)
        .expect("must discover site1.access.log");
    assert_eq!(found_log.format_kind, NginxLogFormatKind::CloudflareProxy);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test nginx_crawler_test`
Expected: FAIL with `crawl_nginx_config_tree` not found.

- [ ] **Step 3: Write minimal implementation**

Implement `crawl_nginx_config_tree` in `src/discovery/nginx.rs`:
- Recursively traverses `include` directives (resolving relative paths against `conf_base_dir` and matching wildcards `*`).
- Uses `HashSet<PathBuf>` with canonicalization to prevent symlink loops.
- Accumulates multi-line `log_format` definitions.
- Binds `access_log` paths to declared or inherited format.
- Discovers unconfigured orphan logs in `nginx_log_dir` via first-line sniffing.
- Update `src/discovery/mod.rs` to use `crawl_nginx_config_tree`.
- Zero comments in `.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test nginx_crawler_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
rtk git add src/discovery/nginx.rs src/discovery/mod.rs tests/nginx_crawler_test.rs
rtk git commit -m "feat(discovery): implement recursive vhost crawler with multiline format support"
```

---

### Task 3: Universal Format Compiler & Dynamic Parser

**Files:**
- Modify: `src/parser/nginx.rs`
- Modify: `src/discovery/nginx.rs`
- Test: `tests/nginx_parser_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum CompiledLogFormat {
      Delimited(Vec<FormatSegment>),
      Json,
  }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum FormatSegment {
      Variable(LogVariable),
      Literal(String),
  }

  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum LogVariable {
      RemoteAddr,
      CfConnectingIp,
      XForwardedFor,
      TimeLocal,
      Request,
      RequestMethod,
      RequestUri,
      Status,
      BodyBytesSent,
      HttpReferer,
      HttpUserAgent,
      Host,
      Ignored(String),
  }

  impl CompiledLogFormat {
      pub fn compile(format_body: &str) -> Self;
      pub fn parse_line<'a>(&self, line: &'a str) -> Option<NginxLogEntry<'a>>;
  }

  pub struct NginxLogEntry<'a> {
      pub client_ip: IpAddr,
      pub method: &'a str,
      pub path: &'a str,
      pub status: u16,
      pub referer: &'a str,
      pub user_agent: &'a str,
      pub host: Option<&'a str>,
  }
  ```

- [ ] **Step 1: Write the failing test**

In `tests/nginx_parser_test.rs`, add tests for dynamic compilation:
```rust
use sanalu::parser::{CompiledLogFormat, LogVariable};
use std::net::IpAddr;

#[test]
fn test_compiled_cloudflare_format_parsing() {
    let fmt_str = "$http_cf_connecting_ip - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "198.51.100.25 - user [12/Sep/2026:06:00:00 +0000] \"GET /admin/db.sql HTTP/1.1\" 404 512 \"https://google.com\" \"Mozilla/5.0\"";
    let entry = compiled.parse_line(line).expect("parse custom line");

    assert_eq!(entry.client_ip, "198.51.100.25".parse::<IpAddr>().unwrap());
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.path, "/admin/db.sql");
    assert_eq!(entry.status, 404);
    assert_eq!(entry.referer, "https://google.com");
    assert_eq!(entry.user_agent, "Mozilla/5.0");
}

#[test]
fn test_compiled_vhost_prefixed_format() {
    let fmt_str = "$host $remote_addr [$time_local] $request_method $request_uri $status";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "api.example.com 203.0.113.88 [12/Sep/2026:06:00:00 +0000] POST /.env 403";
    let entry = compiled.parse_line(line).expect("parse vhost line");

    assert_eq!(entry.client_ip, "203.0.113.88".parse::<IpAddr>().unwrap());
    assert_eq!(entry.host, Some("api.example.com"));
    assert_eq!(entry.method, "POST");
    assert_eq!(entry.path, "/.env");
    assert_eq!(entry.status, 403);
}

#[test]
fn test_compiled_xff_first_public_ip() {
    let fmt_str = "[$time_local] \"$request\" $status \"$http_x_forwarded_for\"";
    let compiled = CompiledLogFormat::compile(fmt_str);

    let line = "[12/Sep/2026:06:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 \"10.0.0.1, 198.51.100.42, 172.16.0.5\"";
    let entry = compiled.parse_line(line).expect("parse xff line");

    assert_eq!(entry.client_ip, "198.51.100.42".parse::<IpAddr>().unwrap());
    assert_eq!(entry.status, 200);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test nginx_parser_test`
Expected: FAIL with compilation error on `CompiledLogFormat`.

- [ ] **Step 3: Write minimal implementation**

Implement `CompiledLogFormat` in `src/parser/nginx.rs`:
- Tokenizes `format_body` into `FormatSegment::Variable` and `FormatSegment::Literal`.
- `parse_line`: performs single-pass cursor slicing finding literal delimiters.
- Extracts real client IP with priority: CF -> XFF (first non-private) -> RemoteAddr.
- Zero-copy borrowed string slices for `method`, `path`, `referer`, `user_agent`, `host`.
- Zero comments in `.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test nginx_parser_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
rtk git add src/parser/nginx.rs src/discovery/nginx.rs tests/nginx_parser_test.rs
rtk git commit -m "feat(parser): implement universal format compiler and dynamic line parser"
```

---

### Task 4: Engine Watcher & Daemon Integration

**Files:**
- Modify: `src/engine/watcher.rs`
- Modify: `src/daemon.rs`
- Modify: `src/intelligence/pipeline.rs`
- Test: `tests/pipeline_test.rs`

**Interfaces:**
- Consumes: `CompiledLogFormat`, `NginxLogEntry` from Task 3
- Updates:
  ```rust
  pub fn spawn_nginx_watcher(
      path: PathBuf,
      format: CompiledLogFormat,
      pipe: Arc<ThreatPipeline>,
      fw: Arc<NftablesBackend>,
      st: Arc<RedbStore>,
      cf: Option<mpsc::Sender<()>>,
      geo: Arc<IpLookupDb>,
  ) -> JoinHandle<()>;

  impl ThreatPipeline {
      pub fn evaluate_request(
          &self,
          ip: IpAddr,
          asn_info: Option<&IpMetadata>,
          user_agent: &str,
          method: &str,
          uri: &str,
          status: u16,
          referer: &str,
      ) -> PipelineAction;
  }
  ```

- [ ] **Step 1: Write the failing test**

In `tests/pipeline_test.rs`, add tests verifying status code awareness:
```rust
#[test]
fn test_probe_with_status_code_filtering() {
    let pipeline = ThreatPipeline::new_test_instance();

    let action_404 = pipeline.evaluate_request(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/.aws/credentials",
        404,
        "",
    );
    assert!(matches!(action_404, PipelineAction::Ban { .. }));

    let action_200 = pipeline.evaluate_request(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/.well-known/acme-challenge/test",
        200,
        "",
    );
    assert!(matches!(action_200, PipelineAction::Allow));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test pipeline_test`
Expected: FAIL with `evaluate_request` not found.

- [ ] **Step 3: Write minimal implementation**

- Add `evaluate_request` on `ThreatPipeline` in `src/intelligence/pipeline.rs`.
- Keep existing `evaluate` as a wrapper forwarding to `evaluate_request` with status 200 to preserve backwards compatibility.
- Update `spawn_nginx_watcher` in `src/engine/watcher.rs` to accept `CompiledLogFormat` and parse each line using `format.parse_line(trimmed)`.
- Update `src/daemon.rs` to compile each discovered log's format and pass it to `spawn_nginx_watcher`.
- Zero comments in `.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test pipeline_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
rtk git add src/engine/watcher.rs src/daemon.rs src/intelligence/pipeline.rs tests/pipeline_test.rs
rtk git commit -m "feat(engine): integrate compiled format watcher and status-aware threat evaluation"
```

---

### Task 5: Comprehensive Verification & Sentrux Quality Gate

**Files:**
- Whole repository verification

- [ ] **Step 1: Check code formatting**

Run: `rtk cargo fmt --all -- --check`
If formatting differences exist, format with `rtk cargo fmt --all`.

- [ ] **Step 2: Run clippy with denied warnings**

Run: `rtk cargo clippy --all-targets -- -D warnings`
Expected: 0 warnings.

- [ ] **Step 3: Verify zero comments in `.rs` files**

Run: `zg query --rg "(//|/\*)" -g "*.rs"`
Expected: No comments found.

- [ ] **Step 4: Run full test suite**

Run: `rtk cargo test`
Expected: All tests pass.

- [ ] **Step 5: Run Sentrux scans and verify rules and quality score**

Run Sentrux scan and rule checks:
- Verify all architectural boundary rules pass.
- Verify cyclomatic complexity < 25.
- Verify Sentrux quality score >= 7295.

- [ ] **Step 6: Commit any final formatting or cleanup**

```bash
rtk git status
rtk git commit -m "style: apply rustfmt and verify zero comments" # if needed
```
