# Plan 15: Database Auto-Updater, Memory Leak Fixes & Panic Hardening

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate real-world production defects by saving downloaded IP-to-ASN databases to disk with monthly conditional background updates, sealing 3 logical memory leaks (idle strike tracker, unbounded SSH PIDs, stale database offenses), and hardening against lock-poisoning and out-of-bounds string slicing panics.

**Architecture:**
1. **Database Persistence & Monthly Auto-Update**:
   - Update `handle_update_db` to save decompressed TSV directly to `config.general.ip_db_path`.
   - Add conditional HTTP headers (`If-Modified-Since`) checking the local database file's `mtime`. If unmodified, the server returns 304 and 0 bytes are downloaded.
   - Run a monthly background check in `run_daemon` (and one-time download if the database is missing on boot).
   - In `reconcile_watchers`, reload `geo_db` and re-run `sync_asn_fallback` if `ip_asn_geo.bin` was updated or newly created.
2. **Memory Leak Plugs**:
   - Strike Tracker: Call `pipeline.cleanup_stale_strikes(now, 600)` on the 60s sweeper tick to prune idle strikes from RAM.
   - SSH Parser: Bound `SshStatefulParser.pending_pids` to 256 entries max to prevent abandoned connections from accumulating.
   - Storage Engine: Implement `cleanup_stale_offenses` in `src/storage/offenses.rs` to evict offense records older than 30 days during the sweeper tick.
3. **Panic Hardening**:
   - Replace lock `.unwrap()` in `src/intelligence/strikes.rs` with `.unwrap_or_else(|p| p.into_inner())` to prevent cascading daemon crashes from poisoned locks.
   - Replace raw string slicing `&line[start..end]` with safe `.get(start..end)` across SSH and Nginx error parsers to eliminate panics on malformed/binary inputs.

**Tech Stack:** Rust 2024, `reqwest`, `flate2`, `tokio`, `redb`, `sentrux`, `rtk`.

**Spec:** `.agents/plans/00-overview.md`, `.agents/plans/03-asn-geoip-and-cloudflare.md`, `.agents/plans/14-firewall-restoration-service-reload-and-replay-fidelity.md`

## Global Constraints

- STRICTLY ZERO comments (`//` or `/* */`) in any Rust file (`.rs`) - including test files.
- ALWAYS use `rtk` prefix for shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
- Cyclomatic complexity must remain < 20 per function.
- No architectural boundary breaches in `.sentrux/rules.toml`.
- All test suites pass with 0 clippy warnings.

---

### Task 1: Fix `sanalu update-db` File Persistence & Destination Path Wiring

**Files:**
- Modify: `src/geo/downloader.rs`, `src/cli/admin.rs`, `src/cli/dispatch.rs`
- Test: `tests/geo_update_db_test.rs`

**Interfaces:**
- Consumes: `download_ip2asn_db(url: &str) -> Result<(IpLookupDb, Vec<u8>), SanaluError>`, `save_db_to_file(bytes: &[u8], path: &Path) -> Result<(), SanaluError>`
- Produces: Persistent `/var/lib/sanalu/ip_asn_geo.bin` on disk with reporting of loaded IP ranges.

- [x] **Step 1: Write the failing test**
Create `tests/geo_update_db_test.rs` verifying that `handle_update_db` or a download/save helper writes the valid TSV to a target path, creates parent directories if needed, and the resulting file is successfully readable by `IpLookupDb::from_file`.
- [x] **Step 2: Run test to verify RED**
Run `rtk cargo test --test geo_update_db_test`.
- [x] **Step 3: Implement database saving in downloader and admin**
- In `src/geo/downloader.rs`, update `download_ip2asn_db` to return `Result<(IpLookupDb, Vec<u8>), SanaluError>` so decompressed bytes can be saved.
- In `src/cli/admin.rs`, update `handle_update_db<W: Write>(out: &mut W, dest_path: &Path)`:
  - Download database, save bytes to `dest_path` via `save_db_to_file`, write output reporting path and loaded ranges.
- In `src/cli/dispatch.rs`, pass `&config.general.ip_db_path` to `handle_update_db`.
- [x] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test geo_update_db_test`.
- [x] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [x] **Step 6: Commit**
Commit: `feat(geo): persist downloaded ip2asn database to disk in update-db`

---

### Task 2: Monthly Auto-Download & Background Geo-DB Refresh on SIGHUP

**Files:**
- Modify: `src/geo/downloader.rs`, `src/daemon.rs`
- Test: `tests/geo_auto_update_test.rs`

**Interfaces:**
- Consumes: `If-Modified-Since` HTTP header, `fs::metadata(path).modified()`, `reconcile_watchers`
- Produces: Silent once-a-month background refresh and hot-reloading of `geo_db` and `sync_asn_fallback` on SIGHUP or rescan.

- [x] **Step 1: Write the failing test**
Create `tests/geo_auto_update_test.rs` verifying conditional HTTP update logic (skips download if 304 Not Modified or if file was modified within 30 days), and that `reconcile_watchers` re-syncs ASN fallback rules.
- [x] **Step 2: Run test to verify RED**
Run `rtk cargo test --test geo_auto_update_test`.
- [x] **Step 3: Implement conditional downloader and daemon wiring**
- In `src/geo/downloader.rs`, add `download_if_stale_or_missing(url: &str, dest_path: &Path, max_age_secs: u64) -> Result<Option<IpLookupDb>, SanaluError>`:
  - If `dest_path` exists and its `mtime` is newer than `max_age_secs` (30 days = 2,592,000s), skip download and return `Ok(None)`.
  - If stale or missing, send request with `If-Modified-Since` header matching `mtime`. If 304, return `Ok(None)`. If 200, save and return `Ok(Some(db))`.
- In `src/daemon.rs`:
  - On startup: spawn a background task running `download_if_stale_or_missing` if enabled / missing.
  - In `reconcile_watchers`: reload `geo_db` from `config.general.ip_db_path` if modified, and call `sync_asn_fallback`.
- [x] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test geo_auto_update_test`.
- [x] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [x] **Step 6: Commit**
Commit: `feat(daemon): support monthly conditional geo-db auto-refresh and hot-reload`

---

### Task 3: Memory Leak Fixes (Strike Pruning, Bounded SSH PIDs, Offenses Sweeping)

**Files:**
- Modify: `src/intelligence/pipeline.rs`, `src/parser/ssh.rs`, `src/storage/offenses.rs`, `src/daemon.rs`
- Test: `tests/memory_leak_pruning_test.rs`

**Interfaces:**
- Consumes: `pipeline.cleanup_stale_strikes(now, max_idle)`, `store.cleanup_stale_offenses(max_age_secs)`
- Produces: Constant bounded memory and disk usage over months of runtime.

- [x] **Step 1: Write the failing test**
Create `tests/memory_leak_pruning_test.rs`:
- Verify `cleanup_stale_offenses` in Redb deletes offenses older than threshold while retaining fresh ones.
- Verify `SshStatefulParser` bounds `pending_pids` to 256 and does not grow unbounded.
- Verify `pipeline.cleanup_stale_strikes` removes idle IP strikes.
- [x] **Step 2: Run test to verify RED**
Run `rtk cargo test --test memory_leak_pruning_test`.
- [x] **Step 3: Implement leak fixes**
- In `src/storage/offenses.rs`, add `pub fn cleanup_stale_offenses(&self, max_age_secs: u64, now_secs: u64) -> Result<usize, SanaluError>`.
- In `src/parser/ssh.rs`, add bound check: if `self.pending_pids.len() >= 256`, evict oldest entries or clear stale ones.
- In `src/daemon.rs`: in `sweep_ticker.tick()`, call `pipeline.cleanup_stale_strikes(now, 600)` and `store.cleanup_stale_offenses(30 * 86400, now)`.
- [x] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test memory_leak_pruning_test`.
- [x] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [x] **Step 6: Commit**
Commit: `fix(engine): plug memory leaks in strike tracker, ssh parser and offense storage`

---

### Task 4: Panic-Hardening: Lock Poisoning Recovery & Boundary-Safe Slicing

**Files:**
- Modify: `src/intelligence/strikes.rs`, `src/parser/ssh.rs`, `src/parser/nginx.rs`
- Test: `tests/panic_resilience_test.rs`

**Interfaces:**
- Consumes: `unwrap_or_else(|p| p.into_inner())`, safe `.get(start..end)`
- Produces: 100% panic immunity against lock poisoning and malformed/binary input strings.

- [x] **Step 1: Write the failing test**
Create `tests/panic_resilience_test.rs`:
- Feed corrupt strings, truncated multi-byte UTF-8, binary garbage, and arbitrary slices to `parse_ssh_log_line`, `SshStatefulParser::process_line`, and `parse_nginx_error_line`.
- Test `IpStrikeTracker` behavior under poisoned lock conditions.
- [x] **Step 2: Run test to verify RED**
Run `rtk cargo test --test panic_resilience_test`.
- [x] **Step 3: Implement panic hardening**
- In `src/intelligence/strikes.rs`: replace `.write().unwrap()` and `.read().unwrap()` with `.unwrap_or_else(|p| p.into_inner())`.
- In `src/parser/ssh.rs`: replace direct slicing `line[start..end]` with `line.get(start..end)?` and `line.get(pos..)?`.
- In `src/parser/nginx.rs`: replace direct slicing in `parse_nginx_error_line` with boundary-safe `.get(...)`.
- [x] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test panic_resilience_test`.
- [x] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [x] **Step 6: Commit**
Commit: `refactor(parser): harden against lock poisoning and string slice panics`

---

### Task 5: Comprehensive Verification, Rustfmt, Zero Comments & Sentrux Gate

**Files:**
- Verify: all `.rs` files across `src/` and `tests/`

- [ ] **Step 1: Format check**
Run `rtk cargo fmt --all -- --check`.
- [ ] **Step 2: Clippy verification**
Run `rtk cargo clippy --all-targets -- -D warnings`.
- [ ] **Step 3: Check zero comments**
Ensure no single-line `//` or block `/* */` comments exist in any `.rs` file.
- [ ] **Step 4: Run full test suite**
Run `rtk cargo test` to verify all test suites pass.
- [ ] **Step 5: Sentrux architecture check**
Run `sentrux check_rules` and `sentrux scan` to verify 0 violations.
- [ ] **Step 6: Final commit if needed**
Commit any formatting or cleanup: `style: apply rustfmt and verify zero comments`
