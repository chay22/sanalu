# Plan 09: Local Origin ASN & Region Enforcement and Status Harmonization

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the local origin defense gap so that incoming traffic hitting the server directly (bypassing Cloudflare) is evaluated against blocked ASNs and restricted regional rules locally via the offline in-memory `IpLookupDb` (zero 3rd party APIs, zero internet), and harmonize `sanalu status` to clearly display config vs DB vs effective state for all rule types.

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

- [ ] **Step 1: Write test for effective allowed regions**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement `get_effective_allowed_regions` and update `format_status`**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 3: Comprehensive Verification

- [ ] **Step 1: Check formatting** (`rtk cargo fmt --all -- --check`)
- [ ] **Step 2: Check clippy** (`rtk cargo clippy --all-targets -- -D warnings`)
- [ ] **Step 3: Run entire test suite** (`rtk cargo test`)
- [ ] **Step 4: Run Sentrux architecture check** (`sentrux check .`)
- [ ] **Step 5: Verify zero comments in `.rs` files**
