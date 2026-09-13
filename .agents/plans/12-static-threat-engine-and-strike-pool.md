# Plan 12: High-Performance Static Threat Engine & Multi-Tier Strike Pool

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
Replace the legacy runtime Aho-Corasick probe matcher with a pure compile-time static decision tree and a high-concurrency sliding-window strike tracker derived from `pathgroup.txt`, achieving sub-5ns request evaluation and zero heap allocation.

**Architecture:**
- **URL Normalization & Pre-Check:** Fast-path bypass for unencoded paths (~1 ns); instant null-byte/CRLF detection; in-place path normalization.
- **Hierarchical 4-Stage Decision Tree:**
  - Stage 0: Universal Whitelist (`/.well-known/` with 200..=399 passes in ~1 ns).
  - Stage 1: Universal 100% Malicious Signatures (Instant BAN even on 200 OK: traversal, stream wrappers, pearcmd, PHPUnit RCE, ThinkPHP RCE).
  - Stage 2: Dotfile Fast-Path Gate (`if path.contains("/.")` skips 60+ rules across VCS, SSH, IDE, Cloud, and `.env` in ~2 ns for 99.9% of normal traffic).
  - Stage 3: Clean Traffic Fast-Exit (`status == 200 || status == 304` passes immediately, skipping all WordPress, PHP, Actuator, Laravel, and Backup probe checks).
  - Stage 4: Clustered Substring Dispatch (Only runs on 4xx/5xx errors; groups checks by `/wp-`, `/actuator`, `/cgi-bin/`, `.php`, backups).
- **Dual-Tier Sliding-Window Strike Pool:**
  - `Shared`: Unified per-IP counter accumulating strikes across all critical probe targets (`/wp-login`, `/.env`, `/.git`, cloud credentials) to stop multi-path scanner rotation.
  - `Isolated`: Dedicated private counters for false-positive prone paths (`.sql`/`.zip` backups, `.py` scripts, `/wp-admin` auth typos) ensuring legitimate user errors never burn down the critical pool.
- **Lean 1-Byte Category Enum:** `ThreatCategory` as `#[repr(u8)]` (11 categories, 75 bytes total `.rodata`, instant integer equality search in Redb/CLI, short `nftables` comments).

**Tech Stack:**
Rust 2024 edition, `tokio`, `redb`, `dashmap` or std synchronization.

**Spec:**
- Source of truth: `/code/rust/sanalu/pathgroup.txt`.
- Sub-5ns evaluation latency for 99.9% of clean requests.
- Strictly ZERO comments (`//` or `/* */`) in any Rust file (`.rs`).
- Cyclomatic complexity < 25 per function.
- All tests pass, Sentrux score >= 7353, zero architectural boundary violations.

## Global Constraints

- Strictly follow `no-comments-in-code.md`: ZERO comments (`//` or `/* */`) in any Rust file (`.rs`).
- Use `rtk` prefix for all shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
- Keep cyclomatic complexity (`max_cc`) below 25 for every function.
- Do not introduce architecture cycle violations or layer boundary breaches in `.sentrux/rules.toml`.
- Use `tgrep` or `zvec-grep` (`zg query --rg`) for search, not raw commands.
- Keep Sentrux quality signal high (>= 7353).

---

## Tasks

### Task 1: ThreatCategory Enum & Fast-Path URL Normalization

**Files:**
- Create: `src/intelligence/category.rs`
- Create: `src/intelligence/normalize.rs`
- Modify: `src/intelligence/mod.rs`
- Test: `tests/threat_normalization_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
  #[repr(u8)]
  pub enum ThreatCategory {
      Common = 1,
      Cloud = 2,
      Ssh = 3,
      Vcs = 4,
      Ide = 5,
      Wordpress = 6,
      Php = 7,
      Laravel = 8,
      Actuator = 9,
      Webmail = 10,
      Backups = 11,
  }

  impl ThreatCategory {
      pub const fn as_str(self) -> &'static str;
      pub const fn from_u8(val: u8) -> Option<Self>;
  }

  pub enum NormalizedUri<'a> {
      Clean(std::borrow::Cow<'a, str>),
      ImmediateMalicious(ThreatCategory),
  }

  pub fn normalize_request_uri<'a>(raw: &'a str) -> NormalizedUri<'a>;
  ```

- [ ] **Step 1: Write failing tests for normalization and categories**
  Create `tests/threat_normalization_test.rs` testing:
  - Fast bypass for clean strings (returns borrowed slice unchanged without allocation).
  - Immediate malicious detection: `%00`, `\x00`, `%0d%0a`.
  - In-place decoding: `%2f` -> `/`, `%2e` -> `.`, `%5c` -> `/`, collapsing multiple slashes `///` -> `/`.
  - Category `as_str()` and `from_u8()` roundtrips.

- [ ] **Step 2: Implement ThreatCategory**
  In `src/intelligence/category.rs`, implement `ThreatCategory` with `#[repr(u8)]` and `as_str()` returning static strings.

- [ ] **Step 3: Implement normalize_request_uri**
  In `src/intelligence/normalize.rs`, implement zero-allocation check:
  If `!raw.contains('%') && !raw.contains('\\') && !raw.contains("//")`, return `NormalizedUri::Clean(Cow::Borrowed(raw))`.
  Otherwise decode and normalize safely into `Cow::Owned(String)`.

- [ ] **Step 4: Verify test passes and commit**
  Run `rtk cargo test --test threat_normalization_test`.
  Commit: `feat(intelligence): implement threat categories and fast-path uri normalization`

---

### Task 2: In-Memory Sliding-Window Multi-Tier Strike Tracker

**Files:**
- Create: `src/intelligence/strikes.rs`
- Modify: `src/intelligence/mod.rs`
- Test: `tests/strike_tracker_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum StrikeResult {
      UnderThreshold { current: u8, max: u8 },
      ThresholdReached { count: u8 },
  }

  pub struct IpStrikeTracker { ... }

  impl IpStrikeTracker {
      pub fn new() -> Self;
      pub fn record_shared_strike(&self, ip: IpAddr, threshold: u8, window_secs: u64, now_secs: u64) -> StrikeResult;
      pub fn record_isolated_strike(&self, ip: IpAddr, cat: ThreatCategory, threshold: u8, window_secs: u64, now_secs: u64) -> StrikeResult;
      pub fn cleanup_stale(&self, now_secs: u64, max_idle_secs: u64);
  }
  ```

- [ ] **Step 1: Write failing tests for strike tracker**
  Create `tests/strike_tracker_test.rs` testing:
  - Shared strikes accumulate across different calls for the same IP.
  - Reaching threshold returns `StrikeResult::ThresholdReached`.
  - Window expiry resets the counter.
  - Isolated strikes do NOT affect shared strikes for the same IP.
  - Different IPs do not interfere.

- [ ] **Step 2: Implement IpStrikeTracker**
  In `src/intelligence/strikes.rs`, implement lock-free or sharded entry storage using `std::sync::RwLock` or `dashmap` with compact 12-byte records.

- [ ] **Step 3: Run tests and verify zero comments**
  Run `rtk cargo test --test strike_tracker_test`.
  Verify zero comments in `src/intelligence/strikes.rs`.

- [ ] **Step 4: Commit changes**
  Commit: `feat(intelligence): implement sliding-window multi-tier strike tracker`

---

### Task 3: The 4-Stage Hierarchical Short-Circuit Decision Tree

**Files:**
- Rewrite: `src/intelligence/probes.rs`
- Test: `tests/threat_probes_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum ThreatDecision {
      Pass,
      InstantBan(ThreatCategory),
      SharedStrike { category: ThreatCategory, threshold: u8, window_secs: u64 },
      IsolatedStrike { category: ThreatCategory, threshold: u8, window_secs: u64 },
  }

  pub fn inspect_threat(method: &str, path: &str, status: u16) -> ThreatDecision;
  ```

- [ ] **Step 1: Write comprehensive test suite matching pathgroup.txt rules**
  Create `tests/threat_probes_test.rs` with test cases:
  - Stage 0: `/.well-known/acme-challenge/...` with 200 returns `Pass`.
  - Stage 1: `../../etc/passwd` (even on 200) returns `InstantBan(Common)`.
  - Stage 1: `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (even on 200) returns `InstantBan(Php)`.
  - Stage 1: `/index.php?s=/index/\think\app/invokefunction` (even on 200) returns `InstantBan(Php)`.
  - Stage 1: `POST /cgi-bin/.../bin/sh` (even on 200) returns `InstantBan(Common)`.
  - Stage 1: `mstshash` returns `InstantBan(Common)`.
  - Stage 2: `/.env` on 404 returns `SharedStrike(Common, 3, 10)` for GET.
  - Stage 2: `/.git/config` on 404 returns `SharedStrike(Vcs, 3, 10)`.
  - Stage 2: `/.vscode/sftp.json` on 404 returns `InstantBan(Ide)`.
  - Stage 2: `/.ds_store` on 404 returns `IsolatedStrike(Vcs, 3, 10)` for GET.
  - Stage 3: Normal `/api/v1/users` or blog post with 200 returns `Pass` immediately.
  - Stage 4: `/wp-login.php` on 404 returns `SharedStrike(Wordpress, 4, 10)`.
  - Stage 4: `/wp-admin/` on 403 returns `IsolatedStrike(Wordpress, 7, 10)` for GET.
  - Stage 4: `/dump.sql` on 404 returns `IsolatedStrike(Backups, 5, 10)`.
  - Stage 4: `/test.py` on 404 returns `IsolatedStrike(Common, 3, 10)` for GET.

- [ ] **Step 2: Implement 4-Stage Decision Tree in src/intelligence/probes.rs**
  - Implement Stage 0 whitelist.
  - Implement Stage 1 pure exploits (null bytes, traversal, RCE tokens, stream wrappers, webshells).
  - Implement Stage 2 dotfile gate: `if path.contains("/.") { ... }`.
  - Implement Stage 3 success exit: `if status == 200 || status == 304 { return ThreatDecision::Pass; }`.
  - Implement Stage 4 clustered substring dispatch:
    - `/wp-`, `xmlrpc`, `wlwmanifest`
    - `/actuator`
    - `/cgi-bin/`, `.php`, `admin`, `pma`
    - `/_ignition`, `telescope`, `horizon`
    - `roundcube`, `webmail`, `horde`
    - Backup extensions (`.sql`, `.zip`, `.gz`, etc.)
  - Keep cyclomatic complexity < 25 by helper subfunctions: `inspect_dotfiles`, `inspect_wordpress`, `inspect_php`, `inspect_cloud`.

- [ ] **Step 3: Verify all test cases pass**
  Run `rtk cargo test --test threat_probes_test`.

- [ ] **Step 4: Commit changes**
  Commit: `feat(intelligence): implement static 4-stage hierarchical threat decision tree`

---

### Task 4: Pipeline Integration & Watcher Wiring

**Files:**
- Modify: `src/intelligence/pipeline.rs`
- Modify: `src/intelligence/mod.rs`
- Test: `tests/pipeline_test.rs`
- Test: `tests/nginx_parser_test.rs`

**Interfaces:**
- Consumes: `inspect_threat`, `IpStrikeTracker`, `normalize_request_uri`.
- Produces: Complete status- and method-aware threat evaluation in `ThreatPipeline::evaluate_request`.

- [ ] **Step 1: Update existing pipeline unit tests**
  Add unit tests in `tests/pipeline_test.rs` testing:
  - Whitelisted IP bypasses all probe checks.
  - Banned IP dropped immediately.
  - Blocked ASN / Restricted ASN evaluated.
  - Normalizing request URIs before inspection.
  - Accumulating shared strikes across `/wp-login` and `/.env` to ban on strike 3.
  - Isolated strikes on `.sql` do not ban until 5 strikes and do not taint shared pool.

- [ ] **Step 2: Integrate IpStrikeTracker into ThreatPipeline**
  In `src/intelligence/pipeline.rs`:
  - Add `strike_tracker: IpStrikeTracker` to `ThreatPipeline`.
  - In `evaluate_request`, call `normalize_request_uri(uri)`.
  - Call `inspect_threat(method, normalized_path, status)`.
  - If `ThreatDecision::InstantBan(cat)`: return `PipelineAction::Ban { reason: format!("probe:{}:instant", cat.as_str()), permanent: false }`.
  - If `ThreatDecision::SharedStrike { category, threshold, window_secs }`:
    Record strike; if threshold reached, return `PipelineAction::Ban { reason: format!("probe:{}:shared_threshold", category.as_str()), permanent: false }`.
  - If `ThreatDecision::IsolatedStrike { category, threshold, window_secs }`:
    Record isolated strike; if threshold reached, return `PipelineAction::Ban { reason: format!("probe:{}:isolated_threshold", category.as_str()), permanent: false }`.

- [ ] **Step 3: Run full pipeline test suite**
  Run `rtk cargo test --test pipeline_test`.
  Verify backwards-compatibility wrappers pass cleanly.

- [ ] **Step 4: Commit changes**
  Commit: `feat(intelligence): wire static threat tree and strike tracker into pipeline`

---

### Task 5: Verification, Rustfmt, Zero Comments & Sentrux Gate

**Files:**
- All changed files in `src/` and `tests/`.

- [ ] **Step 1: Check and format code**
  Run `rtk cargo fmt --all -- --check`. Format with `rtk cargo fmt --all` if needed.

- [ ] **Step 2: Run clippy with -D warnings**
  Run `rtk cargo clippy --all-targets -- -D warnings`. Fix any lints.

- [ ] **Step 3: Verify zero comments in .rs files**
  Use `zg query --rg "(//|/\*)" -g "*.rs"` across `src/` and `tests/`. Ensure 0 comments.

- [ ] **Step 4: Run all test suites**
  Run `rtk cargo test` to verify all 104+ tests pass across all test suites.

- [ ] **Step 5: Run Sentrux quality scan**
  Run `sentrux check_rules` and `sentrux scan` to ensure quality score >= 7353 and zero architectural boundary breaches.

- [ ] **Step 6: Commit final cleanups**
  Commit: `style: apply rustfmt and verify zero comments`
