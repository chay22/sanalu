# Plan 10: Redb Single Source of Truth (SSOT) Architecture

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
Establish `redb` (`/var/lib/sanalu/sanalu.redb`) as the absolute **Single Source of Truth (SSOT)** for all security state in Sanalu (whitelist, blocked categories, blocked ASNs, restricted ASNs, allowed regions, and bans). Eliminate the "split-brain" state where `sanalu.toml` and `redb` were parallel runtime authorities, resolving the bug where `sanalu asn list`, `sanalu region list`, `sanalu category list`, and `sanalu whitelist list` returned empty arrays (`[]`) despite having policies configured in `sanalu.toml`.

**Architecture:**
- **Declarative Provisioning Baseline:** `sanalu.toml` defines daemon operational parameters and baseline policies. Upon daemon startup (`run_daemon`) and offline CLI invocation (`execute_offline_*`), declared baseline policies are synchronized into `redb` via `RedbStore::sync_from_config(&self, config: &AppConfig)`.
- **Authoritative Database (SSOT):** All subsystems read exclusively from `redb`:
  - CLI list commands (`sanalu asn list`, `sanalu region list`, `sanalu category list`, `sanalu whitelist list`) query `redb` tables directly.
  - `ThreatPipeline` in-memory rule sets are built directly from `redb`.
  - `CloudflareSyncWorker` dynamically constructs WAF rule expressions from active bans, blocked ASNs, restricted ASNs, and allowed regions stored in `redb`.
  - `NftablesBackend` fallback synchronization derives CIDRs from blocked ASNs in `redb`.
  - Dynamic CLI mutations (`sanalu asn block`, `sanalu region allow`, etc.) write directly to `redb` and trigger downstream synchronizations.
  - `sanalu status` displays the unified, authoritative state from `redb`.

**Tech Stack:**
- Rust 2024 edition, `redb` embedded key-value database, `clap`, `tokio`, `nftables`.

**Spec:**
- Problem statement and directives from original author:
  1. `redb` must be the Single Source of Truth.
  2. `sanalu.toml` is the declarative baseline, not a competing parallel runtime authority.
  3. `sanalu <policy> list` commands must never return empty arrays when items are declared in `sanalu.toml`.
  4. Cloudflare WAF worker must not use frozen config vectors; it must reflect real-time `redb` policy state.
  5. Zero comments (`//` or `/* */`) in any `.rs` file.
  6. Sentrux Quality Signal must remain $\ge 7,263$ across all 12 architectural rules.
  7. All shell commands must be run through `rtk`.

## Global Constraints

- Strictly follow `no-comments-in-code.md`: ZERO comments (`//` or `/* */`) in any Rust file (`.rs`).
- Use `rtk` prefix for all shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
- Keep cyclomatic complexity (`max_cc`) below 25 for every function.
- Do not introduce architecture cycle violations or layer boundary breaches in `.sentrux/rules.toml`.
- All existing 75 unit and integration tests across 19 test suites must continue to pass.
- Release versioning is driven via Git tags through GitHub Actions; never rely on local release targets.

---

### Task 1: Storage Layer Extension (`src/storage/`)

**Files:**
- Modify: `src/storage/policies.rs:1-184`
- Modify: `src/storage/mod.rs` (if re-exports needed)
- Test: `tests/storage_test.rs:138-160`

**Interfaces:**
- Consumes: `crate::config::AppConfig`, `TABLE_WHITELIST`, `TABLE_CATEGORIES`, `TABLE_BLOCKED_ASNS`, `TABLE_RESTRICTED_ASNS`, `TABLE_ALLOWED_REGIONS` in `src/storage/db.rs`.
- Produces:
  - `RedbStore::set_asn_restricted(&self, asn: u32, restricted: bool) -> Result<(), SanaluError>`
  - `RedbStore::is_asn_restricted(&self, asn: u32) -> Result<bool, SanaluError>`
  - `RedbStore::list_restricted_asns(&self) -> Result<Vec<u32>, SanaluError>`
  - `RedbStore::sync_from_config(&self, config: &crate::config::AppConfig) -> Result<(), SanaluError>`

- [ ] **Step 1: Write failing unit test for `sync_from_config` and restricted ASNs in `tests/storage_test.rs`**

```rust
#[test]
fn test_redb_sync_from_config_and_restricted_asns() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("sync_test.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.general.whitelist = vec!["127.0.0.1".into(), "10.0.0.0/8".into()];
    cfg.bots.blocked_categories = vec!["security_testing".into(), "bad_scraper".into()];
    cfg.asn_rules.blocked_asns = vec![13335, 15169];
    cfg.asn_rules.restricted_asns = vec![64496];
    cfg.asn_rules.allowed_regions = vec!["ID".into(), "SG".into()];

    store.sync_from_config(&cfg).unwrap();

    let wl = store.list_whitelist().unwrap();
    assert_eq!(wl.len(), 2);
    assert!(wl.contains(&"127.0.0.1".to_string()));
    assert!(wl.contains(&"10.0.0.0/8".to_string()));

    let cats = store.list_blocked_categories().unwrap();
    assert_eq!(cats.len(), 2);
    assert!(cats.contains(&"security_testing".to_string()));
    assert!(cats.contains(&"bad_scraper".to_string()));

    let blocked_asns = store.list_blocked_asns().unwrap();
    assert_eq!(blocked_asns.len(), 2);
    assert!(blocked_asns.contains(&13335));
    assert!(blocked_asns.contains(&15169));

    let restricted_asns = store.list_restricted_asns().unwrap();
    assert_eq!(restricted_asns.len(), 1);
    assert!(restricted_asns.contains(&64496));

    let regions = store.list_allowed_regions().unwrap();
    assert_eq!(regions.len(), 2);
    assert!(regions.contains(&"ID".to_string()));
    assert!(regions.contains(&"SG".to_string()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test storage_test test_redb_sync_from_config_and_restricted_asns`
Expected: Compilation failure due to missing `sync_from_config` and `list_restricted_asns`.

- [ ] **Step 3: Implement restricted ASN methods and `sync_from_config` in `src/storage/policies.rs`**

```rust
    pub fn set_asn_restricted(&self, asn: u32, restricted: bool) -> Result<(), SanaluError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(super::db::TABLE_RESTRICTED_ASNS)?;
            if restricted {
                table.insert(asn, ())?;
            } else {
                table.remove(asn)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn is_asn_restricted(&self, asn: u32) -> Result<bool, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::db::TABLE_RESTRICTED_ASNS)?;
        Ok(table.get(asn)?.is_some())
    }

    pub fn list_restricted_asns(&self) -> Result<Vec<u32>, SanaluError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::db::TABLE_RESTRICTED_ASNS)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (asn, _) = item?;
            results.push(asn.value());
        }
        Ok(results)
    }

    pub fn sync_from_config(&self, config: &crate::config::AppConfig) -> Result<(), SanaluError> {
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let write_txn = self.db.begin_write()?;
        {
            let mut wl = write_txn.open_table(TABLE_WHITELIST)?;
            for entry in &config.general.whitelist {
                if wl.get(entry.as_str())?.is_none() {
                    wl.insert(entry.as_str(), now_secs)?;
                }
            }
            let mut cats = write_txn.open_table(TABLE_CATEGORIES)?;
            for cat in &config.bots.blocked_categories {
                if cats.get(cat.as_str())?.is_none() {
                    cats.insert(cat.as_str(), true)?;
                }
            }
            let mut asns = write_txn.open_table(TABLE_BLOCKED_ASNS)?;
            for &asn in &config.asn_rules.blocked_asns {
                asns.insert(asn, ())?;
            }
            let mut rasns = write_txn.open_table(super::db::TABLE_RESTRICTED_ASNS)?;
            for &asn in &config.asn_rules.restricted_asns {
                rasns.insert(asn, ())?;
            }
            let mut regs = write_txn.open_table(TABLE_ALLOWED_REGIONS)?;
            for reg in &config.asn_rules.allowed_regions {
                regs.insert(reg.as_str(), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test storage_test test_redb_sync_from_config_and_restricted_asns`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/storage/policies.rs tests/storage_test.rs
rtk git commit -m "feat(storage): implement sync_from_config and restricted asns"
```

---

### Task 2: Daemon Startup & Offline CLI Automatic Synchronization

**Files:**
- Modify: `src/daemon.rs:55-76`
- Modify: `src/ipc/offline.rs:57-116`
- Modify: `src/cli/admin.rs:12-63`
- Modify: `src/cli/dispatch.rs:76-81`
- Test: `tests/cli_test.rs`

**Interfaces:**
- Consumes: `RedbStore::sync_from_config`
- Produces:
  - `run_daemon` invokes `store.sync_from_config(&config)?` on initialization.
  - `execute_offline_whitelist(db_path, action, Option<&AppConfig>) -> Result<String, SanaluError>`
  - `execute_offline_category(db_path, action, Option<&AppConfig>) -> Result<String, SanaluError>`
  - `execute_offline_asn(db_path, action, Option<&AppConfig>) -> Result<String, SanaluError>`
  - `execute_offline_region(db_path, action, Option<&AppConfig>) -> Result<String, SanaluError>`
  - `handle_policy_command(out, db_path, socket_path, config, cmd) -> Result<(), Box<dyn Error>>`

- [ ] **Step 1: Write unit test in `tests/cli_test.rs` verifying offline list queries reflect TOML baseline**

```rust
#[tokio::test]
async fn test_offline_policy_list_reflects_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("offline_sync.redb");
    let socket_path = temp_dir.path().join("non_existent.sock");

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.asn_rules.blocked_asns = vec![13335, 15169];
    cfg.asn_rules.allowed_regions = vec!["ID".into(), "SG".into()];

    let mut buf = Vec::new();
    let cmd = sanalu::cli::Commands::Asn {
        action: sanalu::cli::AsnCommands::List,
    };
    sanalu::cli::handle_policy_command(&mut buf, &db_path, &socket_path, &cfg, &cmd)
        .await
        .unwrap();

    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("13335"));
    assert!(output.contains("15169"));

    let mut reg_buf = Vec::new();
    let reg_cmd = sanalu::cli::Commands::Region {
        action: sanalu::cli::RegionCommands::List,
    };
    sanalu::cli::handle_policy_command(&mut reg_buf, &db_path, &socket_path, &cfg, &reg_cmd)
        .await
        .unwrap();

    let reg_output = String::from_utf8(reg_buf).unwrap();
    assert!(reg_output.contains("ID"));
    assert!(reg_output.contains("SG"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test cli_test test_offline_policy_list_reflects_config`
Expected: Compilation failure or missing parameters/empty list.

- [ ] **Step 3: Update `src/daemon.rs`, `src/ipc/offline.rs`, `src/cli/admin.rs`, and `src/cli/dispatch.rs`**

In `src/daemon.rs`:
```rust
    let db_path = &config.general.db_path;
    let store = Arc::new(RedbStore::open(db_path)?);
    store.sync_from_config(&config)?;
```

In `src/ipc/offline.rs`:
```rust
pub fn execute_offline_whitelist(
    db_path: &Path,
    action: WhitelistCommands,
    config: Option<&AppConfig>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    if let Some(cfg) = config {
        let _ = store.sync_from_config(cfg);
    }
    let mut buf = Vec::new();
    execute_whitelist(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_category(
    db_path: &Path,
    action: CategoryCommands,
    config: Option<&AppConfig>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    if let Some(cfg) = config {
        let _ = store.sync_from_config(cfg);
    }
    let mut buf = Vec::new();
    execute_category(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_asn(
    db_path: &Path,
    action: AsnCommands,
    config: Option<&AppConfig>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    if let Some(cfg) = config {
        let _ = store.sync_from_config(cfg);
    }
    let mut buf = Vec::new();
    execute_asn(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}

pub fn execute_offline_region(
    db_path: &Path,
    action: RegionCommands,
    config: Option<&AppConfig>,
) -> Result<String, SanaluError> {
    let store = RedbStore::open(db_path)?;
    if let Some(cfg) = config {
        let _ = store.sync_from_config(cfg);
    }
    let mut buf = Vec::new();
    execute_region(&mut buf, &store, action)?;
    String::from_utf8(buf).map_err(|e| SanaluError::Storage(e.to_string()))
}
```

In `src/cli/admin.rs`:
Update `handle_policy_command` to take `config: &AppConfig` and pass `Some(config)` into offline fallbacks.

In `src/cli/dispatch.rs`:
Pass `config` to `handle_policy_command(out, db_path, socket_path, config, cmd).await?;`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test cli_test test_offline_policy_list_reflects_config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/daemon.rs src/ipc/offline.rs src/cli/admin.rs src/cli/dispatch.rs tests/cli_test.rs
rtk git commit -m "feat(ipc): sync config to redb on daemon start and offline cli commands"
```

---

### Task 3: Threat Pipeline & Nftables Realignment to SSOT

**Files:**
- Modify: `src/engine/pipeline.rs:1-68`
- Modify: `src/daemon.rs:30-42, 74-76`
- Test: `tests/pipeline_test.rs`

**Interfaces:**
- Consumes: `store.list_whitelist()`, `store.list_active_bans()`, `store.list_blocked_asns()`, `store.list_restricted_asns()`, `store.list_allowed_regions()`, `store.list_blocked_categories()`.
- Produces:
  - `build_pipeline_from_store(store: &RedbStore, allowed_endpoints: &[String]) -> Result<ThreatPipeline, SanaluError>`
  - `build_pipeline_from_config(config: &AppConfig, store: &RedbStore) -> Result<ThreatPipeline, SanaluError>` (delegates to `build_pipeline_from_store`).

- [ ] **Step 1: Write test in `tests/pipeline_test.rs` verifying pipeline evaluation directly reflects `store` state**

```rust
#[test]
fn test_threat_pipeline_builds_from_store() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("pipeline_store.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.general.whitelist = vec!["198.51.100.5".into()];
    cfg.asn_rules.blocked_asns = vec![13335];
    store.sync_from_config(&cfg).unwrap();

    let pipeline = sanalu::engine::build_pipeline_from_config(&cfg, &store).unwrap();

    let action = pipeline.evaluate(
        "198.51.100.5".parse().unwrap(),
        None,
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert_eq!(action, sanalu::intelligence::PipelineAction::Allow);

    let meta = sanalu::geo::IpMetadata {
        asn: 13335,
        country: [b'U', b'S'],
    };
    let blocked_action = pipeline.evaluate(
        "198.51.100.99".parse().unwrap(),
        Some(&meta),
        "Mozilla/5.0",
        "GET",
        "/",
    );
    assert!(matches!(blocked_action, sanalu::intelligence::PipelineAction::Ban { .. }));
}
```

- [ ] **Step 2: Run test to verify it passes/fails**

Run: `rtk cargo test --test pipeline_test test_threat_pipeline_builds_from_store`

- [ ] **Step 3: Update `src/engine/pipeline.rs` to read state directly from `store`**

```rust
pub fn build_pipeline_from_store(
    store: &RedbStore,
    allowed_endpoints: &[String],
) -> Result<ThreatPipeline, SanaluError> {
    let mut whitelisted_ips = HashSet::new();
    if let Ok(db_whitelist) = store.list_whitelist() {
        for entry in db_whitelist {
            if let Ok(ip) = entry.parse::<IpAddr>() {
                whitelisted_ips.insert(ip);
            }
        }
    }

    let mut banned_ips = HashSet::new();
    if let Ok(active_bans) = store.list_active_bans() {
        for b in active_bans {
            if let Some(ip) = b.ip {
                banned_ips.insert(ip);
            } else if let Ok(ip) = b.target.parse::<IpAddr>() {
                banned_ips.insert(ip);
            }
        }
    }

    let blocked_asns: HashSet<u32> = store.list_blocked_asns().unwrap_or_default().into_iter().collect();
    let restricted_asns: HashSet<u32> = store.list_restricted_asns().unwrap_or_default().into_iter().collect();
    let allowed_regions: HashSet<String> = store.list_allowed_regions().unwrap_or_default().into_iter().collect();

    let blocked_categories: HashSet<BotCategory> = store
        .list_blocked_categories()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| BotCategory::from_str_name(&c))
        .collect();

    ThreatPipeline::new(
        whitelisted_ips,
        banned_ips,
        blocked_asns,
        restricted_asns,
        allowed_regions,
        blocked_categories,
        allowed_endpoints,
    )
}

pub fn build_pipeline_from_config(
    config: &AppConfig,
    store: &RedbStore,
) -> Result<ThreatPipeline, SanaluError> {
    let _ = store.sync_from_config(config);
    build_pipeline_from_store(store, &config.nginx.allowed_endpoints)
}
```

In `src/daemon.rs`:
```rust
    let blocked_asns = store.list_blocked_asns().unwrap_or_default();
    sync_asn_fallback(&firewall, &geo_db, &blocked_asns);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test pipeline_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/engine/pipeline.rs src/daemon.rs tests/pipeline_test.rs
rtk git commit -m "refactor(engine): load threat pipeline and nftables fallback directly from redb"
```

---

### Task 4: Cloudflare Dynamic SSOT Realignment

**Files:**
- Modify: `src/cloudflare/worker.rs:18-95`
- Modify: `src/ipc/cloudflare.rs:71-95`
- Test: `tests/cloudflare_expression_test.rs`

**Interfaces:**
- Consumes: `store.list_blocked_asns()`, `store.list_restricted_asns()`, `store.list_allowed_regions()`, `store.list_active_bans()`.
- Produces:
  - `CloudflareSyncWorker` dynamically constructs the expression from `self.store` on each iteration of `run_loop`.
  - `execute_cloudflare` (in `CloudflareCommands::Sync`) reads active rulesets directly from `store`.

- [ ] **Step 1: Write unit test in `tests/cloudflare_expression_test.rs` testing dynamic expression rebuilding**

```rust
#[test]
fn test_cloudflare_rule_budget_from_store_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("cf_store.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();

    store.set_asn_blocked(13335, true).unwrap();
    store.set_asn_restricted(64496, true).unwrap();
    store.set_region_allowed("ID", true).unwrap();

    let budget = sanalu::cloudflare::CloudflareRuleBudget::new(
        2048,
        store.list_blocked_asns().unwrap(),
        store.list_restricted_asns().unwrap(),
        store.list_allowed_regions().unwrap(),
    );

    let (expr, _) = budget.render_expression(&[]);
    assert!(expr.contains("ip.src.asnum in {13335}"));
    assert!(expr.contains("ip.src.asnum in {64496}"));
    assert!(expr.contains("not ip.src.country in {\"ID\"}"));
}
```

- [ ] **Step 2: Run test to verify it passes/fails**

Run: `rtk cargo test --test cloudflare_expression_test test_cloudflare_rule_budget_from_store_state`

- [ ] **Step 3: Update `CloudflareSyncWorker` and `execute_cloudflare` to query `store` on every sync**

In `src/cloudflare/worker.rs`:
```rust
pub struct CloudflareSyncWorker {
    client: CloudflareClient,
    store: Arc<RedbStore>,
    max_rule_chars: usize,
    batch_seconds: u64,
    rx: mpsc::Receiver<()>,
}

impl CloudflareSyncWorker {
    pub async fn start_if_enabled(
        config: &AppConfig,
        store: Arc<RedbStore>,
        _effective_asns: Vec<u32>,
        dry_run: bool,
    ) -> Result<Option<mpsc::Sender<()>>, SanaluError> {
        if !config.cloudflare.enabled || config.cloudflare.api_token.is_empty() {
            return Ok(None);
        }
        let cf_client = CloudflareClient::new(config.cloudflare.clone(), dry_run)?;
        let tx = Self::spawn(
            cf_client,
            store,
            config.cloudflare.max_rule_chars,
            config.cloudflare.sync_batch_seconds,
        );
        let _ = tx.send(()).await;
        Ok(Some(tx))
    }

    pub fn spawn(
        client: CloudflareClient,
        store: Arc<RedbStore>,
        max_rule_chars: usize,
        batch_seconds: u64,
    ) -> mpsc::Sender<()> {
        let (tx, rx) = mpsc::channel(100);
        let worker = Self {
            client,
            store,
            max_rule_chars,
            batch_seconds,
            rx,
        };

        tokio::spawn(async move {
            worker.run_loop().await;
        });

        tx
    }

    async fn run_loop(mut self) {
        while self.rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_secs(self.batch_seconds)).await;
            while self.rx.try_recv().is_ok() {}

            let blocked_asns = self.store.list_blocked_asns().unwrap_or_default();
            let restricted_asns = self.store.list_restricted_asns().unwrap_or_default();
            let allowed_regions = self.store.list_allowed_regions().unwrap_or_default();
            let budget = CloudflareRuleBudget::new(
                self.max_rule_chars,
                blocked_asns,
                restricted_asns,
                allowed_regions,
            );

            if let Ok(banned_records) = self.store.list_active_bans() {
                let mut v4_ips = Vec::new();
                for r in banned_records {
                    let maybe_ip = r.ip.or_else(|| r.target.parse().ok());
                    if let Some(std::net::IpAddr::V4(v4)) = maybe_ip {
                        v4_ips.push(v4);
                    }
                }
                v4_ips.reverse();

                let (expr, _) = budget.render_expression(&v4_ips);
                match self.client.update_waf_rule(&expr).await {
                    Ok(()) => {
                        let _ = self.store.set_cloudflare_state(&expr);
                    }
                    Err(e) => {
                        eprintln!("[Cloudflare Sync Error] {e}");
                    }
                }
            }
        }
    }
}
```

In `src/ipc/cloudflare.rs`:
```rust
            let budget = CloudflareRuleBudget::new(
                config.cloudflare.max_rule_chars,
                store.list_blocked_asns().unwrap_or_default(),
                store.list_restricted_asns().unwrap_or_default(),
                store.list_allowed_regions().unwrap_or_default(),
            );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/cloudflare/worker.rs src/ipc/cloudflare.rs tests/cloudflare_expression_test.rs
rtk git commit -m "refactor(cloudflare): query dynamic policies directly from redb on sync"
```

---

### Task 5: Status Formatting Harmonization & CLI List Verification

**Files:**
- Modify: `src/ipc/status.rs:47-90`
- Test: `tests/ipc_formatting_test.rs`
- Test: `tests/ipc_test.rs`

**Interfaces:**
- Consumes: `store.list_blocked_categories()`, `store.list_blocked_asns()`, `store.list_restricted_asns()`, `store.list_allowed_regions()`.
- Produces:
  - Harmonized `format_status` displaying clean, authoritative counts and lists directly from `store`.

- [ ] **Step 1: Write test in `tests/ipc_test.rs` verifying status output cleanly presents database state**

```rust
#[test]
fn test_status_output_presents_authoritative_database() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("status_authoritative.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();

    store.set_asn_blocked(13335, true).unwrap();
    store.set_region_allowed("ID", true).unwrap();
    store.set_category_blocked("bad_scraper", true).unwrap();

    let mut buf = Vec::new();
    sanalu::ipc::handlers::format_status(&mut buf, &store, &db_path, None).unwrap();
    let output = String::from_utf8(buf).unwrap();

    assert!(output.contains("Blocked Categories (1): [\"bad_scraper\"]"));
    assert!(output.contains("Blocked ASNs (1): [13335]"));
    assert!(output.contains("Allowed Regions (1): [\"ID\"]"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test ipc_test test_status_output_presents_authoritative_database`

- [ ] **Step 3: Update `format_status` in `src/ipc/status.rs`**

```rust
    let db_cats = store.list_blocked_categories().unwrap_or_default();
    let _ = writeln!(
        out,
        "\nBlocked Categories ({}): {:?}",
        db_cats.len(),
        db_cats
    );

    let db_asns = store.list_blocked_asns().unwrap_or_default();
    let _ = writeln!(out, "Blocked ASNs ({}): {:?}", db_asns.len(), db_asns);

    let db_rasns = store.list_restricted_asns().unwrap_or_default();
    if !db_rasns.is_empty() {
        let _ = writeln!(out, "Restricted ASNs ({}): {:?}", db_rasns.len(), db_rasns);
    }

    let db_regions = store.list_allowed_regions().unwrap_or_default();
    let _ = writeln!(
        out,
        "Allowed Regions ({}): {:?}",
        db_regions.len(),
        db_regions
    );
```

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test ipc_test test_status_output_presents_authoritative_database`
Expected: PASS.

- [ ] **Step 5: Run existing `tests/ipc_formatting_test.rs` to verify compatibility**

Run: `rtk cargo test --test ipc_formatting_test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rtk git add src/ipc/status.rs tests/ipc_test.rs
rtk git commit -m "refactor(ipc): format status directly from authoritative redb store"
```

---

### Task 6: Comprehensive Verification & Sentrux Quality Gate

**Files:**
- Repository-wide audit

- [ ] **Step 1: Check formatting**

Run: `rtk cargo fmt --all -- --check`
Expected: Exit code 0 (all formatted).

- [ ] **Step 2: Check clippy linter**

Run: `rtk cargo clippy --all-targets -- -D warnings`
Expected: 0 errors, 0 warnings.

- [ ] **Step 3: Verify zero comments in `.rs` files**

Run: `rtk zvec_grep_search` or `tgrep` for `//` and `/*` in `src/` and `tests/`.
Expected: 0 comment tokens in `.rs` files.

- [ ] **Step 4: Run all test suites**

Run: `rtk cargo test`
Expected: All tests pass across all test suites.

- [ ] **Step 5: Run Sentrux architectural compliance check**

Run: `sentrux check .`
Expected: Quality Signal $\ge 7,263$, 12 rules checked, 0 violations.

- [ ] **Step 6: Verify Git working tree cleanliness**

Run: `rtk git status`
Expected: Working tree clean.
