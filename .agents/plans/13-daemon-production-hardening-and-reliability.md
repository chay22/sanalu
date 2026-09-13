# Plan 13: Daemon Production Hardening, Inode Logrotate, Dynamic VHost Discovery & SSH Watcher

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform Sanalu into a production-hardened daemon that survives real-world Linux server events:
1. **Inode-Aware Logrotate & Truncation:** Fix file watchers to detect inode swaps and file truncation, preventing silent death after midnight logrotate.
2. **Dynamic Nginx Watcher Registry & Scheduled Rescan:** Periodically (every 60s) and on `SIGHUP` re-crawl Nginx vhosts, hot-reloading changed formats, spawning newly created vhost logs, and aborting deleted vhosts with zero downtime on unchanged vhosts. Drop unneeded `notify` crate.
3. **Active SSH Watcher Activation:** Hook `SshStatefulParser` and `detect_ssh_source` into an active daemon watcher loop for `systemd-journald` and `/var/log/auth.log`, banning port 22 scanner probes and brute-force attacks.
4. **Database Missing Warning Guard & Redb Expiration Sweeper:** Warn loudly on startup and in `sanalu status` if `ip_asn_geo.bin` is missing, and periodically sweep expired temporary bans from Redb storage.
5. **Quality Gate:** Maintain zero comments, cyclomatic complexity < 20, 0 clippy warnings, and Sentrux quality score >= 7354 with 0 violations.

**Tech Stack:** Rust 2024, Tokio, Nftables, Redb, systemd-journald / Linux filesystems.

---

### Task 1: Inode-Aware Logrotate & Truncation Handling in Nginx Watcher

**Files:**
- Modify: `src/engine/watcher.rs`
- Test: `tests/watcher_rotation_test.rs`

**Interfaces:**
- Updates `spawn_nginx_watcher` to track `ino: u64` and `offset: u64`.
- When `read_line` returns 0 (EOF):
  - Checks `fs::metadata(&path)` via `std::os::unix::fs::MetadataExt::ino`.
  - If `metadata.ino() != current_ino`: reopens file at offset 0, resets reader.
  - If `metadata.len() < current_offset`: seeks file back to offset 0 (handles `copytruncate`).
  - If file temporarily unreadable during rotation swap, retries next tick without terminating.

- [ ] **Step 1: Write integration tests in tests/watcher_rotation_test.rs**
  - Test normal line consumption.
  - Test simulated log rotation (rename old file to `.1`, create new file with same name and new content, verify watcher reads new lines).
  - Test simulated file truncation (file truncated in-place, new lines appended, verify watcher reads new lines).
- [ ] **Step 2: Run test to verify it fails**
  Run `rtk cargo test --test watcher_rotation_test`.
- [ ] **Step 3: Implement inode and truncation tracking in src/engine/watcher.rs**
  Keep cyclomatic complexity < 15 by factoring rotation check into a dedicated helper function. Strictly zero comments.
- [ ] **Step 4: Verify test passes**
  Run `rtk cargo test --test watcher_rotation_test`.
- [ ] **Step 5: Commit changes**
  Commit: `feat(engine): implement inode-aware logrotate and truncation detection in watcher`

---

### Task 2: Dynamic Watcher Registry & Scheduled Periodic Rescan (+ SIGHUP)

**Files:**
- Create: `src/engine/registry.rs`
- Modify: `src/engine/mod.rs`
- Modify: `src/engine/watcher.rs`
- Modify: `src/daemon.rs`
- Modify: `Cargo.toml` (remove `notify`)
- Test: `tests/watcher_registry_test.rs`

**Interfaces:**
```rust
pub struct NginxWatcherRegistry {
    watchers: HashMap<PathBuf, (CompiledLogFormat, tokio::task::AbortHandle)>,
}

impl NginxWatcherRegistry {
    pub fn new() -> Self;
    pub fn active_count(&self) -> usize;
    pub fn is_watching(&self, path: &Path) -> bool;
    pub fn reconcile(
        &mut self,
        new_logs: Vec<DiscoveredNginxLog>,
        pipeline: Arc<ThreatPipeline>,
        firewall: Arc<NftablesBackend>,
        store: Arc<RedbStore>,
        cf_tx: Option<mpsc::Sender<()>>,
        geo_db: Arc<IpLookupDb>,
    ) -> ReconcileReport;
}
```
- In `src/daemon.rs`:
  - Run periodic interval every 60 seconds and listen for `SIGHUP` to trigger `reconcile`.
  - Remove `notify = "7.0"` from `Cargo.toml`.

- [ ] **Step 1: Write integration test in tests/watcher_registry_test.rs**
  - Test initial population of registry with multiple vhost logs.
  - Test adding a new vhost log during reconciliation.
  - Test changing format of an existing log (aborts old, spawns new).
  - Test removing a deleted vhost log (aborts old).
  - Test unchanged logs are preserved without restart.
- [ ] **Step 2: Run test to verify it fails**
  Run `rtk cargo test --test watcher_registry_test`.
- [ ] **Step 3: Implement NginxWatcherRegistry and update daemon.rs and Cargo.toml**
  Decompose reconciliation into clean helper functions. Strictly zero comments.
- [ ] **Step 4: Verify test passes**
  Run `rtk cargo test --test watcher_registry_test`.
- [ ] **Step 5: Commit changes**
  Commit: `feat(engine): implement dynamic watcher registry and scheduled rescan`

---

### Task 3: Live SSH Watcher Activation (Journald & Auth.log Tailing)

**Files:**
- Create: `src/engine/ssh.rs`
- Modify: `src/engine/mod.rs`
- Modify: `src/daemon.rs`
- Test: `tests/ssh_watcher_test.rs`

**Interfaces:**
```rust
pub fn spawn_ssh_watcher(
    source: SshLogSource,
    pipe: Arc<ThreatPipeline>,
    fw: Arc<NftablesBackend>,
    st: Arc<RedbStore>,
    cf: Option<mpsc::Sender<()>>,
    geo: Arc<IpLookupDb>,
) -> Option<tokio::task::JoinHandle<()>>;
```
- Consumes `SshLogSource::JournaldService` or `SshLogSource::File`.
- Uses `SshStatefulParser` from `src/parser/ssh.rs`.
- Actions:
  - `SshEvent::ScannerProbe { ip, reason }`: Instant ban (port 22 scanner probe).
  - `SshEvent::AuthFailure { ip, user }`: Records strike via pipeline/store.
- In `src/daemon.rs`:
  - Spawns `spawn_ssh_watcher(env_disc.ssh_source, ...)`.

- [ ] **Step 1: Write integration test in tests/ssh_watcher_test.rs**
  - Test scanner probe line triggers firewall ban and Redb ban record.
  - Test auth failure triggers escalation/strike.
- [ ] **Step 2: Run test to verify it fails**
  Run `rtk cargo test --test ssh_watcher_test`.
- [ ] **Step 3: Implement spawn_ssh_watcher in src/engine/ssh.rs and wire into daemon.rs**
  Handle journalctl child process output or fallback to auth.log. Strictly zero comments.
- [ ] **Step 4: Verify test passes**
  Run `rtk cargo test --test ssh_watcher_test`.
- [ ] **Step 5: Commit changes**
  Commit: `feat(engine): wire active ssh watcher for journald and auth log`

---

### Task 4: Database Missing Warning Guard & Redb Expiration Sweeper

**Files:**
- Modify: `src/storage/mod.rs`
- Modify: `src/daemon.rs`
- Modify: `src/ipc/handlers.rs`
- Test: `tests/db_guard_and_sweeper_test.rs`

**Interfaces:**
- In `src/storage/mod.rs`:
  `pub fn cleanup_expired_bans(&self, now_secs: u64) -> Result<usize, SanaluError>`
  Iterates over bans and removes records where `expires_at_secs <= now_secs`.
- In `src/daemon.rs`:
  - Check `config.general.ip_db_path.exists()`. If missing, output warning banner:
    `[WARN] IP/ASN/Geo database not found at {:?}. ASN blocking and regional rules are INACTIVE. Run 'sanalu update-db' to enable geo-defense.`
  - In `sanalu status` output via `src/ipc/handlers.rs`:
    Report `ASN/Geo Database: MISSING (Geo-defense inactive)` if not loaded.
  - Background loop every 60 seconds calls `store.cleanup_expired_bans(now_secs)`.

- [ ] **Step 1: Write tests in tests/db_guard_and_sweeper_test.rs**
  - Test `cleanup_expired_bans` purges expired bans and keeps permanent/active bans.
  - Test database warning status output when ip_db_path is empty.
- [ ] **Step 2: Run test to verify it fails**
  Run `rtk cargo test --test db_guard_and_sweeper_test`.
- [ ] **Step 3: Implement cleanup_expired_bans, status reporting, and daemon sweeper**
  Strictly zero comments.
- [ ] **Step 4: Verify test passes**
  Run `rtk cargo test --test db_guard_and_sweeper_test`.
- [ ] **Step 5: Commit changes**
  Commit: `feat(daemon): implement db missing warning guard and redb expiration sweeper`

---

### Task 5: Comprehensive Verification, Rustfmt, Zero Comments & Sentrux Quality Gate

**Files:**
- All changed files in `src/` and `tests/`.

- [ ] **Step 1: Check and format code**
  Run `rtk cargo fmt --all -- --check`. Format with `rtk cargo fmt --all` if needed.
- [ ] **Step 2: Run clippy with -D warnings**
  Run `rtk cargo clippy --all-targets -- -D warnings`. Fix any lints.
- [ ] **Step 3: Verify zero comments in .rs files**
  Use AST/token parser across `src/` and `tests/` ensuring strictly 0 comments.
- [ ] **Step 4: Run all test suites**
  Run `rtk cargo test` to verify all test suites pass.
- [ ] **Step 5: Run Sentrux quality scan**
  Run `sentrux check_rules` and `sentrux scan` to ensure quality score >= 7354 and zero architectural boundary breaches.
- [ ] **Step 6: Commit final cleanups**
  Commit: `style: apply rustfmt and verify zero comments`
