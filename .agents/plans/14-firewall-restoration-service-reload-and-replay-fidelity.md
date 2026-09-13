# Plan 14: Firewall Restoration on Boot, Systemd Reload & Replay Fidelity

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure complete production resilience by restoring active bans into `nftables` on daemon boot, enabling `systemctl reload` via `ExecReload`, and aligning `sanalu test-log` replay fidelity with real HTTP status codes, referers, and SSH multi-strike evaluation.

**Architecture:**
1. **Firewall Restoration on Startup**: After initializing `nftables` tables, the daemon fetches `store.list_active_bans()` and loads all active unexpired ban targets into kernel sets (`blacklist_v4` and `blacklist_v6`) via `firewall.ban_targets_batch(&targets)`.
2. **Systemd Service Unit `ExecReload`**: Update `dist/systemd/sanalu.service` with `ExecReload=/bin/kill -HUP $MAINPID` so standard service reload signals dispatch `SIGHUP` to trigger instant Nginx vhost/format reconciliation.
3. **Replay Engine Fidelity**: Update `replay_log_file` in `src/engine/replay.rs` to call `pipeline.evaluate_request` passing real HTTP status codes, referer, and evaluate SSH events via `pipeline.evaluate_ssh_event`.

**Tech Stack:** Rust 2024, `tokio`, `nftables`, `redb`, `cargo-clippy`, `cargo-test`, `sentrux`.

**Spec:** `.agents/plans/00-overview.md`, `.agents/plans/13-daemon-production-hardening-and-reliability.md`

## Global Constraints

- STRICTLY ZERO comments (`//` or `/* */`) in any Rust file (`.rs`) - including test files.
- ALWAYS use `rtk` prefix for shell commands (`rtk cargo test`, `rtk cargo clippy`, `rtk git commit`).
- Cyclomatic complexity must remain < 20 per function.
- No architectural boundary breaches in `.sentrux/rules.toml`.
- All test suites pass with 0 clippy warnings.

---

### Task 1: Active Ban Restoration into Nftables on Daemon Boot

**Files:**
- Modify: `src/daemon.rs:180-210`
- Test: `tests/firewall_restore_test.rs`

**Interfaces:**
- Consumes: `store.list_active_bans() -> Result<Vec<StoredBanRecord>, SanaluError>`, `firewall.ban_targets_batch(&[String]) -> Result<(), SanaluError>`
- Produces: Persistent firewall protection restored on daemon startup without manual intervention.

- [ ] **Step 1: Write the failing test**
Create `tests/firewall_restore_test.rs` verifying that when a store has active bans, restoring them into an `NftablesBackend` (dry-run) populates the firewall sets, while expired bans are not included.
- [ ] **Step 2: Run test to verify RED**
Run `rtk cargo test --test firewall_restore_test` to confirm it fails or fails to compile.
- [ ] **Step 3: Implement active ban restoration in `src/daemon.rs`**
In `src/daemon.rs::run_daemon`, right after `firewall.init_tables()?`:
Query `store.list_active_bans()`, extract targets, and call `firewall.ban_targets_batch(&targets)`.
Log: `println!("Restored {} active bans into firewall", targets.len());`.
- [ ] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test firewall_restore_test` and `rtk cargo test --test daemon_test`.
- [ ] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [ ] **Step 6: Commit**
Commit: `feat(daemon): restore active bans into nftables on startup`

---

### Task 2: Systemd Service Unit `ExecReload` Configuration

**Files:**
- Modify: `dist/systemd/sanalu.service`
- Test: `tests/packaging_test.rs`

**Interfaces:**
- Consumes: Linux `systemd` service reload semantics, `SIGHUP` signal handler in `wait_for_daemon_events`.
- Produces: `ExecReload=/bin/kill -HUP $MAINPID` allowing `systemctl reload sanalu`.

- [ ] **Step 1: Update test in `tests/packaging_test.rs`**
Add assertion in `test_systemd_service_file_and_limits` expecting `content.contains("ExecReload=/bin/kill -HUP $MAINPID")`.
- [ ] **Step 2: Run test to verify RED**
Run `rtk cargo test --test packaging_test` to confirm failure.
- [ ] **Step 3: Add `ExecReload` in `dist/systemd/sanalu.service`**
Add `ExecReload=/bin/kill -HUP $MAINPID` under `[Service]`.
- [ ] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test packaging_test`.
- [ ] **Step 5: Commit**
Commit: `feat(systemd): add ExecReload to send SIGHUP for zero-downtime reload`

---

### Task 3: Replay Fidelity in `sanalu test-log`

**Files:**
- Modify: `src/engine/replay.rs`
- Test: `tests/replay_fidelity_test.rs`

**Interfaces:**
- Consumes: `pipeline.evaluate_request(ip, asn, ua, method, path, status, referer)`, `pipeline.evaluate_ssh_event(&ssh_ev)`
- Produces: Accurate simulation of threat engine decisions during `sanalu test-log`.

- [ ] **Step 1: Write the failing test**
Create `tests/replay_fidelity_test.rs` testing `replay_log_file` against sample Nginx lines with 404 status on probe paths and SSH auth failures, ensuring threats are accurately flagged using the multi-tier threat tree and SSH strike evaluator.
- [ ] **Step 2: Run test to verify RED**
Run `rtk cargo test --test replay_fidelity_test`.
- [ ] **Step 3: Implement replay fidelity in `src/engine/replay.rs`**
Update `replay_log_file`:
- Pass `entry.status` and `entry.referer` to `pipeline.evaluate_request`.
- For JSON logs, pass `status` and `&referer` to `pipeline.evaluate_request`.
- For SSH logs, evaluate with `pipeline.evaluate_ssh_event(&ssh_ev)` and check for `PipelineAction::Ban`.
- [ ] **Step 4: Run test to verify GREEN**
Run `rtk cargo test --test replay_fidelity_test`.
- [ ] **Step 5: Verify zero comments and clippy**
Verify zero comments and 0 clippy warnings.
- [ ] **Step 6: Commit**
Commit: `feat(engine): evaluate real status and ssh events in test-log replay`

---

### Task 4: Comprehensive Verification, Rustfmt, Zero Comments & Sentrux Gate

**Files:**
- Verify: all `.rs` files across `src/` and `tests/`

- [ ] **Step 1: Format check**
Run `rtk cargo fmt --all -- --check`.
- [ ] **Step 2: Clippy verification**
Run `rtk cargo clippy --all-targets -- -D warnings`.
- [ ] **Step 3: Check zero comments**
Ensure no single-line `//` or block `/* */` comments exist in any `.rs` file.
- [ ] **Step 4: Run full test suite**
Run `rtk cargo test` to verify all test suites pass.
- [ ] **Step 5: Sentrux architecture check**
Run `sentrux check_rules` and `sentrux scan` to verify 0 violations.
- [ ] **Step 6: Final commit if needed**
Commit any formatting or cleanup: `style: apply rustfmt and verify zero comments`
