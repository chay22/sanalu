# Plan 16: Debian Maintainer Scripts, Uninstall Data Safety & Self-Update (`sanalu update`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide professional Debian maintainer scripts (`postinst`, `prerm`, `postrm`) so `dpkg -i` self-enables and starts the daemon, fix data directory preservation in `sanalu uninstall` (preserving `/var/lib/sanalu` when `--purge` is false), and implement a robust `sanalu update` command that queries GitHub Releases and updates atomically with zero config or data loss.

**Architecture:**
- **Debian Maintainer Scripts**: `dist/debian/postinst`, `prerm`, and `postrm` manage systemd lifecycle (`daemon-reload`, `enable`, `start/restart`, `stop`, `disable`) and restrict data/config deletion strictly to package purge (`dpkg -P`). `Cargo.toml` registers `maintainer-scripts = "dist/debian"`.
- **Uninstall Data Preservation**: Fix `execute_uninstall` and `remove_data_dir` in `src/uninstall/` so `/var/lib/sanalu` is only removed on `purge == true`, aligning with Debian non-purge removal conventions.
- **Self-Update Engine**: `src/updater/` fetches latest release metadata from `https://api.github.com/repos/chay22/sanalu/releases/latest`, parses SemVer, detects distribution (`dpkg`), downloads `.deb` (or binary tarball), validates sha256 checksums, and applies the upgrade atomically with zero config and zero database overwrites.

**Tech Stack:** Rust 2024, `reqwest` (rustls-tls), `tokio`, `flate2`, `clap`, Debian packaging (`cargo-deb`), `systemd`, `nftables`.

## Global Constraints
1. **STRICTLY ZERO comments** (`//` or `/* */`) in any Rust file (`.rs`) - including tests.
2. **ALWAYS use `rtk` prefix** for shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
3. **Sentrux Quality Gate**: Maintain quality score >= 7237 with 0 architectural violations, 0 circular dependencies, 0 god files, and downward-only DSM layering.
4. **Cyclomatic Complexity**: Strictly < 20 per function.
5. **No Data Loss / Config Overwrite**: Upgrades must never wipe `/var/lib/sanalu` or overwrite customized `/etc/sanalu/sanalu.toml`.

---

### Task 1: Fix `sanalu uninstall` Data Directory Preservation
**Files:**
- Modify: `src/uninstall/cleanup.rs`
- Modify: `src/uninstall/mod.rs`
- Modify: `tests/uninstall_test.rs`

**Interfaces:**
- `pub fn remove_data_dir<W: Write>(out: &mut W, db_path: &Path, purge: bool, dry_run: bool) -> Result<(), SanaluError>`
- In `src/uninstall/mod.rs`: pass `options.purge` to `remove_data_dir`.

- [ ] **Step 1: Write the failing tests in `tests/uninstall_test.rs`**
  Add `test_uninstall_preserves_data_dir_when_not_purging` verifying that `/var/lib/sanalu` remains when `purge == false`, and is removed when `purge == true`.
- [ ] **Step 2: Run test to verify RED**
  `rtk cargo test --test uninstall_test`
- [ ] **Step 3: Implement data directory preservation in `src/uninstall/`**
  Update `remove_data_dir` to take `purge: bool`. When `purge == false`, print:
  `[i] Preserved database and data directory at {:?}. (Pass '--purge' to delete data).`
  When `purge == true`, delete the directory.
- [ ] **Step 4: Run test to verify GREEN**
  `rtk cargo test --test uninstall_test`
- [ ] **Step 5: Verify zero comments and clippy**
  `rtk cargo clippy --all-targets -- -D warnings`
- [ ] **Step 6: Commit**
  `fix(uninstall): preserve data directory and redb database unless purge is specified`

---

### Task 2: Add Debian Maintainer Scripts (`postinst`, `prerm`, `postrm`) & Configure `Cargo.toml`
**Files:**
- Create: `dist/debian/postinst`
- Create: `dist/debian/prerm`
- Create: `dist/debian/postrm`
- Modify: `Cargo.toml`
- Modify: `README.md`
- Modify: `tests/packaging_test.rs`

**Interfaces:**
- Standard Debian POSIX shell scripts (`#!/bin/sh`, `set -e`).
- `Cargo.toml`: `maintainer-scripts = "dist/debian"` under `[package.metadata.deb]`.

- [ ] **Step 1: Write integration tests in `tests/packaging_test.rs`**
  Verify `dist/debian/postinst`, `dist/debian/prerm`, and `dist/debian/postrm` exist, are executable or valid scripts, contain `daemon-reload`, `enable`, `restart`, and only delete `/var/lib/sanalu` on `purge`. Verify `Cargo.toml` specifies `maintainer-scripts = "dist/debian"`.
- [ ] **Step 2: Run test to verify RED**
  `rtk cargo test --test packaging_test`
- [ ] **Step 3: Create Debian maintainer scripts & update `Cargo.toml`**
  - Create `dist/debian/postinst`: on `configure`, reloads daemon, enables `sanalu.service`, and starts/restarts service.
  - Create `dist/debian/prerm`: on `remove` or `deconfigure`, stops and disables `sanalu.service`.
  - Create `dist/debian/postrm`: on `remove`, reloads daemon; on `purge`, reloads daemon, resets failed, removes `/var/lib/sanalu`, `/etc/sanalu`, and deletes `table inet sanalu`.
  - Add `maintainer-scripts = "dist/debian"` to `[package.metadata.deb]` in `Cargo.toml`.
  - Update `README.md` to remove manual `sudo systemctl enable --now sanalu` from Debian install instructions.
- [ ] **Step 4: Run test to verify GREEN**
  `rtk cargo test --test packaging_test`
- [ ] **Step 5: Verify zero comments and clippy**
  `rtk cargo clippy --all-targets -- -D warnings`
- [ ] **Step 6: Commit**
  `feat(packaging): add debian maintainer scripts for automated service lifecycle and purge`

---

### Task 3: Implement GitHub Release Fetcher & Version Comparison
**Files:**
- Create: `src/updater/release.rs`
- Create: `src/updater/mod.rs`
- Modify: `src/lib.rs`
- Modify: `.sentrux/rules.toml`
- Create: `tests/updater_release_test.rs`

**Interfaces:**
- `pub struct ReleaseInfo { pub tag_name: String, pub name: String, pub body: String, pub assets: Vec<ReleaseAsset> }`
- `pub struct ReleaseAsset { pub name: String, pub browser_download_url: String, pub size: u64 }`
- `pub fn parse_semver(v: &str) -> Option<(u64, u64, u64)>`
- `pub fn is_newer_version(current: &str, candidate: &str) -> bool`
- `pub fn find_matching_asset<'a>(assets: &'a [ReleaseAsset], target_arch: &str, prefers_deb: bool) -> Option<&'a ReleaseAsset>`
- `pub async fn fetch_latest_release(repo: &str) -> Result<ReleaseInfo, SanaluError>`

- [ ] **Step 1: Write tests in `tests/updater_release_test.rs`**
  Test SemVer parsing, `is_newer_version` ("0.1.0" vs "0.2.0", "1.0.0" vs "1.0.0", "0.2.0" vs "0.1.9"), and asset matching for `amd64.deb`, `arm64.deb`, and `tar.gz`.
- [ ] **Step 2: Run test to verify RED**
  `rtk cargo test --test updater_release_test`
- [ ] **Step 3: Implement `src/updater/release.rs`, `src/updater/mod.rs`, `src/lib.rs`**
  Implement release metadata fetching, version comparison, and asset matching without comments.
- [ ] **Step 4: Update `.sentrux/rules.toml` to declare `src/updater/**` in services layer**
- [ ] **Step 5: Run test to verify GREEN**
  `rtk cargo test --test updater_release_test`
- [ ] **Step 6: Verify zero comments and clippy**
  `rtk cargo clippy --all-targets -- -D warnings`
- [ ] **Step 7: Commit**
  `feat(updater): implement github release fetcher and semver comparator`

---

### Task 4: Implement `sanalu update` CLI Command & Safe Apply
**Files:**
- Create: `src/updater/apply.rs`
- Modify: `src/updater/mod.rs`
- Modify: `src/cli/args.rs`
- Modify: `src/cli/admin.rs`
- Modify: `src/cli/dispatch.rs`
- Create: `tests/updater_cli_test.rs`

**Interfaces:**
- `Commands::Update { check: bool, yes: bool }`
- `pub async fn handle_update<W: Write>(out: &mut W, check: bool, yes: bool) -> Result<(), Box<dyn std::error::Error>>`
- `pub async fn execute_update<W: Write>(out: &mut W, check: bool, yes: bool, repo: &str) -> Result<(), SanaluError>`

- [ ] **Step 1: Write integration tests in `tests/updater_cli_test.rs`**
  Test CLI argument parsing (`sanalu update`, `sanalu update --check`, `sanalu update -y`). Test execution with simulated mock release and verify check output.
- [ ] **Step 2: Run test to verify RED**
  `rtk cargo test --test updater_cli_test`
- [ ] **Step 3: Implement `src/updater/apply.rs` & wire into CLI**
  Implement update orchestration:
  - Check current version against latest tag.
  - If `--check`, print version status and return.
  - If already up to date, print and return.
  - Check root privileges if performing install.
  - Download asset to temporary file.
  - If `.deb`: run `dpkg -i <temp_deb>`.
  - If `.tar.gz`: extract and replace binary.
  - Clean up temporary files.
- [ ] **Step 4: Run test to verify GREEN**
  `rtk cargo test --test updater_cli_test`
- [ ] **Step 5: Verify zero comments and clippy**
  `rtk cargo clippy --all-targets -- -D warnings`
- [ ] **Step 6: Commit**
  `feat(cli): wire sanalu update command with automated debian and binary upgrading`

---

### Task 5: Repo-wide Verification, Rustfmt, Zero Comments & Sentrux Gate
**Files:**
- All touched files

- [ ] **Step 1: Run `rtk cargo fmt --all -- --check`**
- [ ] **Step 2: Run `rtk cargo clippy --all-targets -- -D warnings`**
- [ ] **Step 3: Verify zero comments across all `.rs` files**
- [ ] **Step 4: Run `rtk cargo test` (all 175+ tests passing)**
- [ ] **Step 5: Run Sentrux scan and check_rules (quality score >= 7237, 0 violations)**
- [ ] **Step 6: Commit any style adjustments if needed**
