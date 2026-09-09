# Plan 05: CLI Interface, Embedded `redb` Storage, `.deb` Packaging & Systemd Unit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** No separate installer command. `sanalu run` self-bootstraps missing database directories and templates automatically on boot. Deployment is a single `dpkg -i sanalu.deb` or scp of the binary.

**Goal:** Implement the full suite of CLI subcommands with runtime mutability for bot categories, ASNs, regions, and IP whitelists backed by embedded `redb`, configure `.deb` package generation, and provide an unrestricted, hardened systemd service.

**Architecture:**
1. **Self-Bootstrapping Engine (`sanalu run`)**:
   - When spawned by systemd or run as root, checks if `/var/lib/sanalu/` exists (creates with `0700` if missing).
   - Opens or initializes `/var/lib/sanalu/sanalu.redb`.
   - If `/etc/sanalu/sanalu.toml` is missing, writes the default template and loads defaults.
   - Enforces root privileges on boot (exits with clear error if run as non-root without `--dry-run`).
2. `RedbStore`: Embedded database (`/var/lib/sanalu/sanalu.redb`) managing atomic tables:
   - `bans`: key = IP bytes (`[u8; 4]` or `[u8; 16]`), value = `(tier_level, banned_at_secs, expires_at_secs, reason)`.
   - `offenses`: key = IP bytes, value = `(offense_count, first_seen_secs, last_seen_secs)`.
   - `whitelist`: key = IP/CIDR string, value = `added_at_secs`.
   - `blocked_categories`: key = category string, value = `blocked_bool`.
   - `blocked_asns`: key = ASN u32 bytes, value = `()`.
   - `restricted_asns`: key = ASN u32 bytes, value = `()`.
   - `allowed_regions`: key = 2-letter country code string, value = `()`.
   - `cloudflare`: key = `"state"`, value = `(rule_id, rendered_expression, last_sync_time)`.
3. `CliApp`: Built with `clap` (derive). Exposes:
   - `sanalu run`: Starts monitoring daemon in foreground or under systemd.
   - `sanalu status`: Shows active bans, kernel `nftables` status, Cloudflare sync status, and memory metrics.
   - `sanalu ban <ip>`: Immediately bans an IP in `redb`, `nftables`, and queues Cloudflare sync.
   - `sanalu unban <ip>`: Removes IP from `redb`, `nftables`, and Cloudflare.
   - `sanalu whitelist <add|remove|list>`: Manages whitelisted IPs/CIDRs.
   - `sanalu category <block|unblock|list>`: Dynamically toggles bot categories (e.g. `scanners`, `ai`, `generic_tools`).
   - `sanalu asn <block|unblock|list>`: Dynamically manages blocked or restricted ASNs.
   - `sanalu region <allow|disallow|list>`: Dynamically manages allowed country codes for restricted ASNs.
   - `sanalu sync cloudflare`: Forces immediate Cloudflare WAF rule update.
   - `sanalu discover`: Runs and displays auto-discovery diagnostics (OS, Nginx formats, SSH source).
   - `sanalu update-db`: Downloads and compiles the latest registration-free IP/ASN database.
   - `sanalu test-log <file>`: Replays any log file in dry-run mode, printing detected attacks.
4. **Hardened, Limit-Unrestricted Systemd Unit (`sanalu.service`)**:
   - `LimitNOFILE=1048576`: Prevents file descriptor exhaustion when monitoring hundreds of Nginx vhosts and inotify watches.
   - `TasksMax=infinity`, `LimitMEMLOCK=infinity`.
   - `OOMScoreAdjust=-500`: Protects `sanalu` from Linux kernel OOM-killer during memory pressure.
   - `Restart=always`, `RestartSec=3s`.
   - `StandardOutput=journal`, `StandardError=journal`.
5. **Debian Package Configuration (`Cargo.toml` / `cargo-deb`)**:
   - Packages binary into `/usr/bin/sanalu`.
   - Installs systemd service to `/lib/systemd/system/sanalu.service`.
   - Sets `/etc/sanalu/sanalu.toml` as a conffile.

**Tech Stack:** Rust 2024, `clap` (derive), `redb` 2.x, `tempfile`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- Always use `rtk` prefix for shell commands.
- Clear, readable terminal output without colored bloat.

---

### Task 1: CLI Definition & Subcommand Dispatch

**Files:**
- Create: `src/cli/mod.rs`
- Create: `src/cli/args.rs`
- Test: `tests/cli_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(clap::Parser)]
  #[command(name = "sanalu", version, about = "High-performance security daemon")]
  pub struct Cli {
      #[arg(short, long, default_value = "/etc/sanalu/sanalu.toml")]
      pub config: std::path::PathBuf,
      #[command(subcommand)]
      pub command: Commands,
  }

  #[derive(clap::Subcommand)]
  pub enum Commands {
      Run { #[arg(long)] dry_run: bool },
      Status,
      Ban { ip: std::net::IpAddr, #[arg(long)] reason: Option<String> },
      Unban { ip: std::net::IpAddr },
      Whitelist { #[command(subcommand)] action: WhitelistCommands },
      Category { #[command(subcommand)] action: CategoryCommands },
      Asn { #[command(subcommand)] action: AsnCommands },
      Region { #[command(subcommand)] action: RegionCommands },
      SyncCloudflare,
      Discover,
      UpdateDb,
      TestLog { path: std::path::PathBuf },
  }

  #[derive(clap::Subcommand)]
  pub enum WhitelistCommands { Add { entry: String }, Remove { entry: String }, List }
  #[derive(clap::Subcommand)]
  pub enum CategoryCommands { Block { name: String }, Unblock { name: String }, List }
  #[derive(clap::Subcommand)]
  pub enum AsnCommands { Block { asn: u32 }, Unblock { asn: u32 }, List }
  #[derive(clap::Subcommand)]
  pub enum RegionCommands { Allow { code: String }, Disallow { code: String }, List }
  ```

- [ ] **Step 1: Write CLI argument parsing test for category, ASN, and region commands**

```rust
use clap::Parser;

#[test]
fn test_cli_parse_category_and_asn() {
    let cat_args = vec!["sanalu", "category", "block", "generic_tools"];
    let cli = sanalu::cli::Cli::try_parse_from(cat_args).expect("parse category");
    match cli.command {
        sanalu::cli::Commands::Category { action } => match action {
            sanalu::cli::CategoryCommands::Block { name } => assert_eq!(name, "generic_tools"),
            _ => panic!("wrong command"),
        },
        _ => panic!("wrong command"),
    }

    let asn_args = vec!["sanalu", "asn", "block", "400529"];
    let cli = sanalu::cli::Cli::try_parse_from(asn_args).expect("parse asn");
    match cli.command {
        sanalu::cli::Commands::Asn { action } => match action {
            sanalu::cli::AsnCommands::Block { asn } => assert_eq!(asn, 400529),
            _ => panic!("wrong command"),
        },
        _ => panic!("wrong command"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test cli_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `Cli` structure and command handlers**

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test cli_test`
Expected: PASS.

---

### Task 2: Embedded `redb` Persistent Storage

**Files:**
- Create: `src/storage/mod.rs`
- Create: `src/storage/db.rs`
- Test: `tests/storage_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct RedbStore {
      db: redb::Database,
  }

  impl RedbStore {
      pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, crate::error::StorageError>;
      pub fn save_ban(&self, record: &crate::engine::BanRecord) -> Result<(), crate::error::StorageError>;
      pub fn remove_ban(&self, ip: std::net::IpAddr) -> Result<bool, crate::error::StorageError>;
      pub fn list_active_bans(&self) -> Result<Vec<crate::engine::BanRecord>, crate::error::StorageError>;
      pub fn set_category_blocked(&self, category: &str, blocked: bool) -> Result<(), crate::error::StorageError>;
      pub fn list_blocked_categories(&self) -> Result<Vec<String>, crate::error::StorageError>;
      pub fn set_asn_blocked(&self, asn: u32, blocked: bool) -> Result<(), crate::error::StorageError>;
      pub fn list_blocked_asns(&self) -> Result<Vec<u32>, crate::error::StorageError>;
      pub fn set_region_allowed(&self, code: &str, allowed: bool) -> Result<(), crate::error::StorageError>;
      pub fn list_allowed_regions(&self) -> Result<Vec<String>, crate::error::StorageError>;
  }
  ```

- [ ] **Step 1: Write tests for dynamic category and ASN persistence in `redb`**

```rust
#[test]
fn test_redb_dynamic_policies() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("policy.redb");
    let store = sanalu::storage::RedbStore::open(&db_path).unwrap();

    store.set_category_blocked("generic_tools", true).unwrap();
    assert!(store.list_blocked_categories().unwrap().contains(&"generic_tools".to_string()));

    store.set_asn_blocked(400529, true).unwrap();
    assert!(store.list_blocked_asns().unwrap().contains(&400529));

    store.set_region_allowed("ID", true).unwrap();
    assert!(store.list_allowed_regions().unwrap().contains(&"ID".to_string()));
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test storage_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `RedbStore` tables**
Implement typed tables for `bans`, `offenses`, `whitelist`, `categories`, `asns`, and `regions`.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test storage_test`
Expected: PASS.

---

### Task 3: Unrestricted Systemd Unit & `.deb` Packaging

**Files:**
- Create: `dist/systemd/sanalu.service`
- Modify: `Cargo.toml` (add `[package.metadata.deb]`)
- Test: `tests/packaging_test.rs`

**Service Definition:**
```ini
[Unit]
Description=Sanalu High-Performance Security Daemon
Documentation=https://github.com/your-repo/sanalu
After=network.target local-fs.target systemd-journald.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/sanalu run
Restart=always
RestartSec=3s
TimeoutStopSec=10s

# High Performance & Zero Resource Restrictions:
LimitNOFILE=1048576
LimitNPROC=512
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-500

# Logging:
StandardOutput=journal
StandardError=journal

# Security & Capabilities:
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/sanalu /etc/sanalu

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 1: Test validating systemd service syntax**
Verify the service file exists and contains `LimitNOFILE=1048576`, `OOMScoreAdjust=-500`, and `ExecStart=/usr/bin/sanalu run`.

- [ ] **Step 2: Add `cargo-deb` configuration to `Cargo.toml`**
Declare target paths for binary, service unit, and default conffile.
