# Plan 08: Dynamic Cloudflare ASN Budgeting & nftables Kernel Fallback

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement smart Cloudflare character budgeting and rotation (anchoring ASN rules and rotating attack IPs within the 4,000-character budget), synchronize effective rules (`TOML ∪ DB`) to Cloudflare across restarts, and expand blocked ASNs to CIDRs in kernel `nftables` for local fallback protection.

**Architecture:**
1. `CloudflareRuleBudget`:
   - **Priority 1 (Umbrella Rules):** Blocked ASNs and regional restrictions are anchored as first-class rules. Individual attack IPs never evict ASN rules. If configured ASNs alone exceed the 4,000-character limit (e.g. 10,000 ASNs), the ASN list itself is capped to what fits (e.g. newest ~400 ASNs) to prevent Cloudflare HTTP 400 errors.
   - **Priority 2 (Rotating Attacker IPs):** The remaining character budget (~3,600–3,900 chars) is allocated to the most recent active banned attacker IPs (`ip.src in {...}`). During massive attacks (e.g. 100,000 IPs), IPs rotate among themselves as an LRU pool in Cloudflare while all 100,000 remain blocked locally.
2. `StateSync`: Cloudflare synchronization evaluates the effective merged set (`config.asn_rules ∪ store.list_blocked_asns()`), and fires an initial sync signal upon daemon startup so TOML changes reflect on Cloudflare immediately after `systemctl restart`.
3. `NftablesAsnBridge`: Converts configured and dynamic `blocked_asns` into IPv4 CIDRs via `IpLookupDb` and loads them into the `inet sanalu blacklist_v4` interval set on startup and runtime updates, providing local kernel drops even if traffic bypasses Cloudflare or is rotated out of Cloudflare's 4KB budget.
4. `StatusReporting`: `sanalu status` reports both static TOML rules and dynamic DB overrides.

**Tech Stack:** Rust 2024, `nftables`, `redb`, `reqwest`.

**Spec:** `.agents/plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md` (zero `//` or `/* */` in Rust code).
- Always use `rtk` prefix for shell commands (`rtk cargo test`, `rtk cargo clippy`).
- Single binary architecture (`sanalu`).
- Cyclomatic complexity (`max_cc`) must remain below 25 for every function.

---

### Task 1: Smart Cloudflare Character Budgeting & ASN Anchoring

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

- [x] **Step 1: Write unit tests for ASN anchoring and IP rotation**

In `tests/cloudflare_expression_test.rs`:
```rust
#[test]
fn test_cloudflare_expression_asns_anchored_during_massive_ip_attack() {
    let budget = CloudflareRuleBudget::new(
        4000,
        vec![400529, 48090, 197170, 209630, 202412],
        Vec::new(),
        Vec::new(),
    );

    let mut massive_ips = Vec::new();
    for i in 1..=500 {
        let b3 = (i / 256) as u8;
        let b4 = (i % 256) as u8;
        massive_ips.push(std::net::Ipv4Addr::new(198, 51, b3, b4));
    }

    let (expr, included_ips) = budget.render_expression(&massive_ips);
    assert!(expr.contains("ip.src.asnum in {400529 48090 197170 209630 202412}"));
    assert!(included_ips.len() > 100);
    assert!(included_ips.len() < 500);
    assert!(expr.len() <= 4000);
}

#[test]
fn test_cloudflare_expression_extreme_asns_budget_capped() {
    let mut large_asns = Vec::new();
    for i in 1000..3000 {
        large_asns.push(i);
    }
    let budget = CloudflareRuleBudget::new(4000, large_asns, Vec::new(), Vec::new());
    let (expr, _) = budget.render_expression(&[]);
    assert!(expr.starts_with("(ip.src.asnum in {"));
    assert!(expr.len() <= 4000);
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: FAIL.

- [x] **Step 3: Implement smart character budgeting in `src/cloudflare/expression.rs`**

Refactor `render_expression` to:
1. First, build the umbrella clauses:
   - Regional restrictions: `(ip.src.asnum in {...} and not ip.src.country in {...})`.
   - Blocked ASNs: Pack as many `blocked_asns` as fit within `max_chars` (leaving room for delimiters and active IPs if available). If ASNs alone exceed `max_chars`, cap the ASN list to the newest entries that fit.
2. Calculate remaining character budget: `remaining = max_chars.saturating_sub(clauses_len + overhead)`.
3. Pack as many active banned IPv4 addresses into `ip.src in {...}` as fit within the remaining budget.
4. Guarantee that the final expression length is strictly `<= max_chars`.

- [x] **Step 4: Run test to verify it passes**

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

- [x] **Step 1: Write test for merged state evaluation in handlers**

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

- [x] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test ipc_test`
Expected: FAIL.

- [x] **Step 3: Implement merged state in `src/daemon.rs` and `src/ipc/handlers.rs`**

1. Create `pub fn get_effective_blocked_asns(config: &AppConfig, store: &RedbStore) -> Vec<u32>` in `src/daemon.rs`.
2. In `handlers::execute_cloudflare(CloudflareCommands::Sync)`: Use `get_effective_blocked_asns(config, store)` instead of just `config.asn_rules.blocked_asns`.
3. In `daemon::run_daemon`: Immediately upon starting `CloudflareSyncWorker`, trigger an initial sync signal `let _ = tx.send(()).await;` so Cloudflare updates immediately upon service startup/restart.
4. In `handlers::execute_asn`: After `store.set_asn_blocked()`, notify `cf_tx` if present so Cloudflare syncs immediately when an ASN is blocked/unblocked via CLI.
5. In `handlers::format_status`: Report both configured TOML rules and dynamic database overrides.

- [x] **Step 4: Run test to verify it passes**

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

- [x] **Step 1: Write test for extracting CIDRs by ASN in `IpLookupDb`**

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

- [x] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test geo_test`
Expected: Compilation failure.

- [x] **Step 3: Implement `cidrs_for_asn` and `range_to_cidrs` helper**

1. In `src/geo/lookup.rs`: Implement conversion from `(start, end)` range to standard CIDR string prefix representations (e.g. converting `1.0.0.0` to `1.0.0.255` into `1.0.0.0/24`).
2. Add `cidrs_for_asn(&self, asn: u32) -> Vec<String>` to collect CIDRs matching the target ASN.
3. In `src/daemon.rs`: On startup, collect CIDRs for all effective blocked ASNs from `IpLookupDb` and load them into `nftables` via atomic `nft -f -` ruleset.

- [x] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test geo_test`
Expected: PASS.

---

### Task 4: Comprehensive Verification

- [x] **Step 1: Check formatting**
Run: `rtk cargo fmt --all -- --check`
Expected: Code 0 (clean).

- [x] **Step 2: Check clippy**
Run: `rtk cargo clippy --all-targets -- -D warnings`
Expected: Code 0 (0 warnings).

- [x] **Step 3: Run entire test suite**
Run: `rtk cargo test`
Expected: All tests pass.

- [x] **Step 4: Run Sentrux architecture check**
Run: `sentrux check .`
Expected: All rules pass, CC < 25.

- [x] **Step 5: Verify zero comments in `.rs` files**
Run: `zg query --rg "^\s*//" -g "*.rs"` and `zg query --rg "/\*" -g "*.rs"`
Expected: No matches.
