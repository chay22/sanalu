# Plan 03: Free IP/ASN/Geo Engine & Cloudflare WAF Integration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** We push updates to Cloudflare with an event-driven 5-10 second batch window (`sync_batch_seconds`) upon new bans, making 0 API requests when traffic is quiet, and batching sudden DDoS bursts into a single payload.

**Goal:** Provide registration-free IP-to-ASN and Country lookup, evaluate generic regional ASN rules (allowing specified ASNs only from specified country codes), and synchronize banned IPs to Cloudflare Free Security Rules within the strict 4,000-character limit using an event-driven 5-10s batch window (`sync_batch_seconds`).

**Architecture:**
1. `IpLookupDb`: Loads public domain IP-to-ASN/Country data (from registration-free `iptoasn.com` TSV dumps) into a binary-searchable contiguous slice. CLI command `sanalu update-db` fetches updates.
2. `AsnPolicyEvaluator`:
   - Enforces generic ASN rules configurable per server:
     - `restricted_asns`: Permitted only when `country` is in `allowed_regions` (e.g. AS15169 Google, AS16509 AWS only from ID, MY, SG, US, PH, JP).
     - `blocked_asns`: Unconditionally blocked ASNs (e.g. known hosting/scanner ASNs).
   - Dynamic runtime updates: ASNs and regions can be adjusted at runtime via CLI (`sanalu asn block/unblock`, `sanalu region allow/disallow`) and persisted in `redb`.
3. `CloudflareSynchronizer`:
   - Event-driven: When new bans occur, `sanalu` blocks locally in 0ms and triggers Cloudflare sync with a **5 to 10 second batch window** (`sync_batch_seconds`) to batch multiple bans into a single API call.
   - Zero polling when no attacks occur.
   - Builds compact WAF filter expression:
     `(ip.src in { ... }) or (ip.src.asnum in { ... }) or (ip.src.asnum in { ... } and not ip.src.country in { "ID" "MY" "SG" "US" "PH" "JP" })`
   - 4,000-character budget engine: Tracks expression length. When quota limit is approached (e.g. 3,950 chars), evicts oldest banned IPs (LRU) from Cloudflare while keeping them banned in local `nftables`.
   - Skips IPv6 from Cloudflare expression to maximize banned IPv4 capacity (IPv6 is dropped in local `nftables`).
   - Gracefully skips synchronization if API credentials are empty or invalid.

**Tech Stack:** Rust 2024, `reqwest` (rustls), `serde_json`, `redb`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- Always use `rtk` prefix for shell commands.
- Pedantic clippy compliance.

---

### Task 1: Registration-Free IP-to-ASN/Geo Database

**Files:**
- Create: `src/geo/mod.rs`
- Create: `src/geo/lookup.rs`
- Create: `src/geo/downloader.rs`
- Test: `tests/geo_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct IpMetadata {
      pub asn: u32,
      pub country: [u8; 2],
      pub as_org: String,
  }

  pub struct IpLookupDb {
      entries_v4: Vec<Ipv4RangeEntry>,
  }

  impl IpLookupDb {
      pub fn empty() -> Self;
      pub fn from_tsv_reader<R: std::io::BufRead>(reader: R) -> Result<Self, crate::error::GeoError>;
      pub fn lookup(&self, ip: std::net::IpAddr) -> Option<IpMetadata>;
  }
  ```

- [ ] **Step 1: Write test for TSV parsing and fast IP binary search**

```rust
#[test]
fn test_parse_tsv_and_lookup() {
    let tsv_data = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                    8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
                    103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";
    let db = sanalu::geo::IpLookupDb::from_tsv_reader(tsv_data.as_bytes()).unwrap();

    let meta = db.lookup("8.8.8.8".parse().unwrap()).expect("lookup google ip");
    assert_eq!(meta.asn, 15169);
    assert_eq!(&meta.country, b"US");

    let id_meta = db.lookup("103.10.10.5".parse().unwrap()).expect("lookup id ip");
    assert_eq!(id_meta.asn, 23700);
    assert_eq!(&id_meta.country, b"ID");
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test geo_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `IpLookupDb` with compact integer IP ranges**
Convert IPv4 to `u32` and sort by `start_ip` for `binary_search_by`.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test geo_test`
Expected: PASS.

---

### Task 2: Cloudflare WAF Expression Builder & Batched Sync

**Files:**
- Create: `src/cloudflare/mod.rs`
- Create: `src/cloudflare/expression.rs`
- Create: `src/cloudflare/client.rs`
- Test: `tests/cloudflare_expression_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct CloudflareRuleBudget {
      max_chars: usize,
      blocked_asns: Vec<u32>,
      restricted_asns: Vec<u32>,
      allowed_regions: Vec<String>,
  }

  impl CloudflareRuleBudget {
      pub fn new(max_chars: usize, blocked_asns: Vec<u32>, restricted_asns: Vec<u32>, allowed_regions: Vec<String>) -> Self;
      pub fn render_expression(&self, banned_ips_lru: &[std::net::Ipv4Addr]) -> (String, Vec<std::net::Ipv4Addr>);
  }
  ```

- [ ] **Step 1: Write test verifying 4,000-character cap, regional ASN expression, and LRU rotation**

```rust
#[test]
fn test_cloudflare_expression_with_regional_asns() {
    let budget = sanalu::cloudflare::CloudflareRuleBudget::new(
        4000,
        vec![400529, 48090],
        vec![15169, 16509],
        vec!["ID".into(), "US".into()],
    );

    let (expr, _) = budget.render_expression(&["1.2.3.4".parse().unwrap()]);
    assert!(expr.contains("ip.src.asnum in {400529 48090}"));
    assert!(expr.contains("ip.src.asnum in {15169 16509} and not ip.src.country in {\"ID\" \"US\"}"));
    assert!(expr.contains("ip.src in {1.2.3.4}"));
    assert!(expr.len() <= 4000);
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test cloudflare_expression_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement expression builder and batched client**
- Pack newest banned IPv4 addresses into `ip.src in { ... }` from most recent to older until remaining character allowance would be breached.
- Coalesce rapid ban events with `tokio::time::sleep(Duration::from_secs(sync_batch_seconds))` before dispatching HTTP PUT to Cloudflare.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test cloudflare_expression_test`
Expected: PASS.
