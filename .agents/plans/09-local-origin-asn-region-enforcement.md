# Plan 09: Local Origin Defense, Status Harmonization, Human Timestamps & Auto-Completions

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
1. **Local Origin Defense:** In-memory offline evaluation of blocked ASNs and restricted regional rules on live Nginx logs (zero 3rd party APIs, zero internet).
2. **Status Harmonization:** Report `X in config, Y dynamic in DB (Z effective)` for all policy types (`Blocked Categories`, `Blocked ASNs`, `Allowed Regions`).
3. **Human-Readable Timestamps:** Replace all raw `unix <timestamp>` outputs across all commands with `DD-MMM-YYYY` (e.g. `21 Sept 2026 14:32:05 UTC`).
4. **Automatic Shell Completion on Daemon Boot:** Automatically install completion to `/etc/profile.d/sanalu.sh` (so it works out of the box on root shells without manual commands) along with standard completion directories.

## Technical Clarification: Zero 3rd Party APIs / Zero Internet

- The database `/var/lib/sanalu/ip_asn_geo.bin` is a local flat file stored on disk.
- On daemon startup, it is loaded once into memory as a sorted array: `Vec<Ipv4RangeEntry>`.
- Each lookup is a pure in-memory **binary search** (`binary_search_by`) on 32-bit integers (`u32`).
- Execution time is **~20–50 nanoseconds** in RAM.
- It works 100% offline with zero internet access, zero DNS queries, and zero external APIs.

## Global Constraints

- Strictly follow `no-comments-in-code.md` (zero `//` or `/* */` in Rust code).
- Always use `rtk` prefix for shell commands (`rtk cargo test`, `rtk cargo clippy`).
- Single binary architecture (`sanalu`).
- Cyclomatic complexity (`max_cc`) must remain below 25 for every function.

---

### Task 1: Hook `IpLookupDb` into Live Nginx Monitoring

**Files:**
- Modify: `src/daemon.rs`
- Test: `tests/daemon_pipeline_test.rs`

- [ ] **Step 1: Write unit test for pipeline evaluation with geo metadata**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Load `Arc<IpLookupDb>` in `run_daemon` and pass to Nginx watcher**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 2: Harmonize Status Reporting in `format_status`

**Files:**
- Modify: `src/ipc/handlers.rs`
- Modify: `src/daemon.rs`
- Test: `tests/ipc_test.rs`

- [ ] **Step 1: Write test for effective allowed regions and categories**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement `get_effective_allowed_regions`, `get_effective_blocked_categories`, and update `format_status`**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 3: Human-Readable Timestamps (`DD-MMM-YYYY` Format)

**Files:**
- Modify: `src/ipc/handlers.rs`
- Test: `tests/ipc_test.rs`

- [ ] **Step 1: Write unit test for civil date/time formatting (e.g. `21 Sept 2026 14:32:05 UTC`)**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement zero-dependency `format_datetime` and `format_date` and update all CLI outputs (`format_status`, `format_check`, `format_ban_list`)**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 4: Automatic Universal Shell Completion on Daemon Start

**Files:**
- Modify: `src/daemon.rs`
- Modify: `src/uninstall.rs`
- Test: `tests/daemon_test.rs`

- [ ] **Step 1: Write test verifying `bootstrap_files` writes to `/etc/profile.d/` and completion dirs**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Update `bootstrap_files` to write to `/etc/profile.d/sanalu.sh`, `/etc/bash_completion.d/sanalu`, Zsh, and Fish vendor directories automatically**
- [ ] **Step 4: Update `src/uninstall.rs` to clean up all installed completion files**
- [ ] **Step 5: Run test to verify it passes**

---

### Task 5: Comprehensive Verification

- [ ] **Step 1: Check formatting** (`rtk cargo fmt --all -- --check`)
- [ ] **Step 2: Check clippy** (`rtk cargo clippy --all-targets -- -D warnings`)
- [ ] **Step 3: Run entire test suite** (`rtk cargo test`)
- [ ] **Step 4: Run Sentrux architecture check** (`sentrux check .`)
- [ ] **Step 5: Verify zero comments in `.rs` files**
