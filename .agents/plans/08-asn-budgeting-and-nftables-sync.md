# Plan 08: Dynamic Cloudflare ASN Budgeting & nftables Kernel Fallback

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement smart Cloudflare character budgeting and rotation for ASNs/IPs (never exceeding 4,000 chars), synchronize effective rules (`TOML ∪ DB`) to Cloudflare upon startup/updates, and expand blocked ASNs to CIDRs in kernel `nftables` for local fallback protection.

**Architecture:**
1. `CloudflareRuleBudget`: Smart character-budget engine that prioritizes active banned IPv4 addresses first, then fits as many blocked ASNs and restricted ASNs as remain within `max_chars` (rotating to newest/highest priority entries), strictly preventing Cloudflare 400 length errors.
2. `StateSync`: Cloudflare synchronization evaluates the effective merged set (`config.asn_rules ∪ store.list_blocked_asns()`), and fires an initial sync signal upon daemon startup so TOML changes reflect on Cloudflare immediately after `systemctl restart`.
3. `NftablesAsnBridge`: Converts configured and dynamic `blocked_asns` into IPv4 CIDRs via `IpLookupDb` and loads them into the `inet sanalu blacklist_v4` interval set on startup and runtime updates, providing local kernel drops even if traffic bypasses Cloudflare or is rotated out of Cloudflare's 4KB budget.
4. `StatusReporting`: `sanalu status` reports both static TOML rules and dynamic DB overrides.

**Tech Stack:** Rust 2024, `nftables`, `redb`, `reqwest`, `ipnet`.

**Spec:** `.agents/plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md` (zero `//` or `/* */` in Rust code).
- Always use `rtk` prefix for shell commands (`rtk cargo test`, `rtk cargo clippy`).
- Single binary architecture (`sanalu`).
- Cyclomatic complexity (`max_cc`) must remain below 25 for every function.

---

### Task 1: Smart Cloudflare Character Budgeting & ASN Rotation

**Files:**
- Modify: `src/cloudflare/expression.rs`
- Test: `tests/cloudflare_expression_test.rs`

**Interfaces:**
- Produces:
  ```rust
  impl CloudflareRuleBudget {
      pub fn new(
          max_chars: usize,
          blocked_asns: Vec<u32>,
          restricted_asns: Vec<u32>,
          allowed_regions: Vec<String>,
      ) -> Self;
      pub fn render_expression(&self, banned_ips_lru: &[std::net::Ipv4Addr]) -> (String, Vec<std::net::Ipv4Addr>);
  }
  ```

- [ ] **Step 1: Write unit tests for ASN budgeting with large ASN lists**

In `tests/cloudflare_expression_test.rs`:
```rust
#[test]
fn test_cloudflare_expression_asn_budget_truncation() {
    let mut large_asns = Vec::new();
    for i in 1000..3000 {
        large_asns.push(i);
    }
    let budget = CloudflareRuleBudget::new(4000, large_asns, Vec::new(), Vec::new());
    let (expr, _) = budget.render_expression(&[]);
    assert!(expr.starts_with("(ip.src.asnum in {"));
    assert!(expr.len() <= 4000);
}

#[test]
fn test_cloudflare_expression_priority_ips_over_asns() {
    let mut large_asns = Vec::new();
    for i in 1000..3000 {
        large_asns.push(i);
    }
    let budget = CloudflareRuleBudget::new(500, large_asns, Vec::new(), Vec::new());
    let test_ips = vec![
        "1.1.1.1".parse().unwrap(),
        "2.2.2.2".parse().unwrap(),
        "3.3.3.3".parse().unwrap(),
    ];
    let (expr, included_ips) = budget.render_expression(&test_ips);
    assert_eq!(included_ips.len(), 3);
    assert!(expr.contains("ip.src in {1.1.1.1 2.2.2.2 3.3.3.3}"));
    assert!(expr.len() <= 500);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: FAIL because `render_expression` does not budget ASNs and exceeds `max_chars`.

- [ ] **Step 3: Implement smart character budgeting in `src/cloudflare/expression.rs`**

Refactor `render_expression` to:
1. Pack high-priority active banned IPv4 addresses into `ip.src in {...}` first.
2. Determine remaining character allowance for static clauses.
3. If `restricted_asns` and `allowed_regions` exist, pack as many restricted ASNs as fit.
4. Pack as many `blocked_asns` (from the end of the list, newest/last configured) into `ip.src.asnum in {...}` as fit within the remaining budget.
5. Ensure the final rendered expression length is guaranteed `<= self.max_chars`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: PASS with all tests green and expressions `<= max_chars`.

---

### Task 2: Synchronize Merged State (`TOML ∪ DB`) and Startup Sync

**Files:**
- Modify: `src/ipc/handlers.rs`
- Modify: `src/daemon.rs`
- Test: `tests/ipc_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn get_effective_blocked_asns(config: &AppConfig, store: &RedbStore) -> Vec<u32>;
  ```

- [ ] **Step 1: Write test for merged state evaluation in handlers**

In `tests/ipc_test.rs`:
```rust
#[test]
fn test_merged_asn_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();
    store.set_asn_blocked(99999, true).unwrap();

    let mut cfg = sanalu::config::AppConfig::default();
    cfg.asn_rules.blocked_asns = vec![11111, 22222];

    let effective = sanalu::daemon::get_effective_blocked_asns(&cfg, &store);
    assert_eq!(effective.len(), 3);
    assert!(effective.contains(&11111));
    assert!(effective.contains(&22222));
    assert!(effective.contains(&99999));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test ipc_test`
Expected: FAIL with `get_effective_blocked_asns` not found.

- [ ] **Step 3: Implement merged state in `src/daemon.rs` and `src/ipc/handlers.rs`**

1. Create `pub fn get_effective_blocked_asns(config: &AppConfig, store: &RedbStore) -> Vec<u32>` in `src/daemon.rs`.
2. In `handlers::execute_cloudflare(CloudflareCommands::Sync)`: Use `get_effective_blocked_asns(config, store)` instead of just `config.asn_rules.blocked_asns`.
3. In `daemon::run_daemon`: Immediately upon starting `CloudflareSyncWorker`, trigger an initial sync signal `let _ = tx.send(()).await;` so Cloudflare updates immediately upon service startup/restart.
4. In `handlers::execute_asn`: After `store.set_asn_blocked()`, notify `cf_tx` if present so Cloudflare syncs immediately when an ASN is blocked/unblocked via CLI.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test ipc_test`
Expected: PASS.

---

### Task 3: Local `nftables` Kernel Fallback for Blocked ASNs

**Files:**
- Modify: `src/geo/lookup.rs`
- Modify: `src/firewall/nftables.rs`
- Modify: `src/daemon.rs`
- Test: `tests/geo_test.rs`

**Interfaces:**
- Produces:
  ```rust
  impl IpLookupDb {
      pub fn cidrs_for_asn(&self, asn: u32) -> Vec<String>;
  }

  impl NftablesBackend {
      pub fn sync_asn_cidrs(&self, cidrs: &[String]) -> Result<(), SanaluError>;
  }
  ```

- [ ] **Step 1: Write test for extracting CIDRs by ASN in `IpLookupDb`**

In `tests/geo_test.rs`:
```rust
#[test]
fn test_extract_cidrs_for_asn() {
    let tsv_data = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                    8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
                    1.0.1.0\t1.0.1.255\t13335\tUS\tCLOUDFLARENET\n";
    let db = sanalu::geo::IpLookupDb::from_tsv_reader(tsv_data.as_bytes()).unwrap();
    let cidrs = db.cidrs_for_asn(13335);
    assert_eq!(cidrs.len(), 2);
    assert!(cidrs.contains(&"1.0.0.0/24".to_string()));
    assert!(cidrs.contains(&"1.0.1.0/24".to_string()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test geo_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `cidrs_for_asn` and `range_to_cidrs` helper**

1. In `src/geo/lookup.rs`: Implement conversion from `(start, end)` range to standard CIDR string prefix representations (e.g. converting `1.0.0.0` to `1.0.0.255` into `1.0.0.0/24`).
2. Add `cidrs_for_asn(&self, asn: u32) -> Vec<String>` to collect CIDRs matching the target ASN.
3. In `src/daemon.rs`: On startup, collect CIDRs for all effective blocked ASNs from `IpLookupDb` and load them into `nftables` via `firewall.ban_target(&cidr, None)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test geo_test`
Expected: PASS.

---

### Task 4: Comprehensive Verification

- [ ] **Step 1: Check formatting**
Run: `rtk cargo fmt --all -- --check`
Expected: Code 0 (clean).

- [ ] **Step 2: Check clippy**
Run: `rtk cargo clippy --all-targets -- -D warnings`
Expected: Code 0 (0 warnings).

- [ ] **Step 3: Run entire test suite**
Run: `rtk cargo test`
Expected: All tests pass.

- [ ] **Step 4: Run Sentrux architecture check**
Run: `sentrux check .`
Expected: All rules pass, CC < 25.

- [ ] **Step 5: Verify zero comments in `.rs` files**
Run: `zg query --rg "^\s*//" -g "*.rs"` and `zg query --rg "/\*" -g "*.rs"`
Expected: No matches.
