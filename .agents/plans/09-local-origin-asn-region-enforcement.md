# Plan 09: Local Origin ASN & Region Enforcement, Status Harmonization, and Shell Completion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 
1. Close the local origin defense gap so that incoming traffic hitting the server directly is evaluated against blocked ASNs and restricted regional rules locally via the offline in-memory `IpLookupDb` (zero 3rd party APIs, zero internet).
2. Harmonize `sanalu status` to clearly display config vs DB vs effective state for all rule types.
3. Fix shell completion so it reliably works on all Linux systems and login shells (including root shells without `bash-completion` package).

## Technical Clarification: Zero 3rd Party APIs / Zero Internet

- The database `/var/lib/sanalu/ip_asn_geo.bin` is a local flat file stored on disk.
- On daemon startup, it is loaded once into memory as a sorted array: `Vec<Ipv4RangeEntry>`.
- Each lookup is a pure in-memory **binary search** (`binary_search_by`) on 32-bit integers (`u32`).
- Execution time is **~20–50 nanoseconds** in RAM.
- It works 100% offline with zero internet access, zero DNS queries, and zero external APIs.

## Why Shell Completion Failed on the Server

1. **Root Shells in Debian/Ubuntu:** Default Debian/Ubuntu `/root/.bashrc` leaves bash-completion commented out (`#if [ -f /etc/bash_completion ] ...`).
2. **Missing Universal `/etc/profile.d/`:** Files in `/etc/profile.d/*.sh` are automatically sourced by all shells on login regardless of `.bashrc` settings.
3. **No Explicit Install Feedback:** `sanalu completions` previously only dumped raw text to stdout without installing or providing activation instructions.

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

### Task 3: Universal Shell Completion Installation & Diagnostics

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/daemon.rs`
- Modify: `src/uninstall.rs`
- Test: `tests/cli_test.rs`

- [ ] **Step 1: Write test for completion installation targets**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement universal completion installer (`/etc/profile.d/sanalu.sh`, `/etc/bash_completion.d/sanalu`, `/usr/share/bash-completion/completions/sanalu`, Zsh, Fish) and CLI `sanalu completions install`**
- [ ] **Step 4: Update `src/uninstall.rs` to clean up all installed completion files**
- [ ] **Step 5: Run test to verify it passes**

---

### Task 4: Comprehensive Verification

- [ ] **Step 1: Check formatting** (`rtk cargo fmt --all -- --check`)
- [ ] **Step 2: Check clippy** (`rtk cargo clippy --all-targets -- -D warnings`)
- [ ] **Step 3: Run entire test suite** (`rtk cargo test`)
- [ ] **Step 4: Run Sentrux architecture check** (`sentrux check .`)
- [ ] **Step 5: Verify zero comments in `.rs` files**
