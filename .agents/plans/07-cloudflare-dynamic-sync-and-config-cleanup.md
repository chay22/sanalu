# Plan 07: Dynamic Cloudflare WAF Rule Sync & Configuration Cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up the default configuration file by stripping out redundant internal paths and dynamic IDs, and implement intelligent, dynamic Cloudflare WAF Custom Ruleset synchronization supporting automatic discovery, rule search/creation, explicit override fallback, and parsed error responses.

**Architecture:**
1. **Minimal Default Configuration (`dist/sanalu.toml`)**:
   - Remove internal operational paths (`db_path`, `ip_db_path`, `socket_path`) from the template. They are already automatically defaulted in `GeneralConfig` and should not clutter user-facing configuration.
   - Strip `ruleset_id` and `rule_id` from `[cloudflare]` default section.
2. **Cloudflare WAF Custom Ruleset Engine (`src/cloudflare/client.rs`)**:
   - Reference: https://developers.cloudflare.com/waf/custom-rules/custom-rulesets/
   - **Case 1 (Explicit IDs)**: If both `ruleset_id` and `rule_id` are provided, directly update using `PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`.
   - **Case 2 (Inconsistent Config)**: If `rule_id` is set but `ruleset_id` is missing, return a validation error: `ruleset_id is required when rule_id is configured`.
   - **Case 3 (Manual Ruleset)**: If `ruleset_id` is set without `rule_id`, fetch the ruleset via `GET /zones/{zone_id}/rulesets/{ruleset_id}`. Inspect existing rules for `"sanalu"` (case-insensitive) in description:
     - Found: `PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`
     - Not found: `POST /zones/{zone_id}/rulesets/{ruleset_id}/rules`
   - **Case 4 (Full Auto-Discovery)**: If neither ID is set, query the zone's custom entrypoint:
     `GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint`
     - Ruleset exists: Inspect rules for `"sanalu"`. If found, `PATCH .../rules/{rule_id}`; if not found, `POST .../rules`.
     - Entrypoint does not exist (404): Create it via `POST /zones/{zone_id}/rulesets` for phase `http_request_firewall_custom` containing the sanalu block rule.
3. **Robust Error Parsing & Logging**:
   - Parse Cloudflare API response `{"success": false, "errors": [{"code": ..., "message": ...}]}` into `Cloudflare API error [{code}]: {message}`.
   - Fix HTTP update method from `.put()` to `.patch()`.
   - In `CloudflareSyncWorker`, log errors to stderr (`eprintln!`) and do not update local DB state when API calls fail.

**Tech Stack:** Rust 2024 edition, `reqwest` (rustls), `serde_json`, `redb`.

**Spec:** `.agents/plans/03-asn-geoip-and-cloudflare.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md` (zero `//` or `/* */` comments in any `.rs` file).
- Always use `rtk` prefix for shell commands.
- Ensure `cargo test` and `cargo clippy --all-targets` pass with 0 errors and 0 warnings.
- Keep Sentrux rules passing.

---

### Task 1: Configuration Cleanup & Template Simplification

**Files:**
- Modify: `dist/sanalu.toml`
- Modify: `tests/packaging_test.rs`

**Interfaces:**
- Produces clean `dist/sanalu.toml` with `[general]` containing only `whitelist = []` and `[cloudflare]` containing only `enabled`, `api_token`, `zone_id`, `rule_name`, `action`, `max_rule_chars`, `sync_batch_seconds`.

- [ ] **Step 1: Update `tests/packaging_test.rs` to verify stripped config template**

Verify that `dist/sanalu.toml` does not contain explicit `db_path`, `ip_db_path`, `socket_path`, `ruleset_id`, or `rule_id`, while verifying that `AppConfig` parsing still populates the correct defaults.

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test packaging_test`
Expected: FAIL due to existing assertions on config template.

- [ ] **Step 3: Update `dist/sanalu.toml`**

Remove `db_path`, `ip_db_path`, `socket_path`, `ruleset_id`, and `rule_id` from `dist/sanalu.toml`.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test packaging_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add dist/sanalu.toml tests/packaging_test.rs
rtk git commit -m "chore: simplify default config template by stripping internal paths and IDs"
```

---

### Task 2: Cloudflare Error Parsing Helper

**Files:**
- Modify: `src/cloudflare/client.rs`
- Test: `tests/cloudflare_expression_test.rs`

**Interfaces:**
- Produces: `pub fn parse_cf_error(status: u16, body_text: &str) -> SanaluError`

- [ ] **Step 1: Write test for Cloudflare error parser**

Add unit tests verifying parsing of `{"success":false,"errors":[{"code":9106,"message":"Authentication failed"}]}` into `Cloudflare API error [9106]: Authentication failed`. Also test fallback when response is non-JSON or missing errors array.

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: FAIL with missing `parse_cf_error`.

- [ ] **Step 3: Implement `parse_cf_error` in `src/cloudflare/client.rs`**

Parse JSON response with `serde_json::Value`, extract `errors` array, and format human-readable error messages.

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk cargo test --test cloudflare_expression_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rtk git add src/cloudflare/client.rs tests/cloudflare_expression_test.rs
rtk git commit -m "feat(cloudflare): add structured error response parser"
```

---

### Task 3: Cloudflare Dynamic Rule/Ruleset Resolution & PATCH Method

**Files:**
- Modify: `src/cloudflare/client.rs`
- Modify: `src/ipc/handlers.rs`
- Test: `tests/cloudflare_expression_test.rs`

**Interfaces:**
- Produces:
  ```rust
  impl CloudflareClient {
      pub async fn resolve_or_create_rule(&self, expression: &str) -> Result<(), SanaluError>;
      pub async fn update_waf_rule(&self, expression: &str) -> Result<(), SanaluError>;
  }
  ```

- [ ] **Step 1: Write unit tests for configuration resolution logic**

Test the 4 decision paths in resolution:
1. `rule_id` set without `ruleset_id` -> returns error.
2. Both set -> targets explicit rule.
3. `ruleset_id` set -> targets rules in ruleset.
4. Neither set -> targets entrypoint.

- [ ] **Step 2: Implement dynamic resolution and PATCH call**

In `src/cloudflare/client.rs`:
- Implement `resolve_or_create_rule`:
  - If `rule_id.is_some() && ruleset_id.is_none()`: return `Err(SanaluError::Cloudflare("ruleset_id is required when rule_id is specified"))`.
  - If both present: call `PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`.
  - If `ruleset_id` present but no `rule_id`: fetch ruleset via `GET .../rulesets/{ruleset_id}`, scan for rule with description containing `"sanalu"`. If found, `PATCH`; if not, `POST .../rulesets/{ruleset_id}/rules`.
  - If neither present: fetch entrypoint via `GET .../rulesets/phases/http_request_firewall_custom/entrypoint`. If found, scan rules for `"sanalu"`, `PATCH` or `POST`. If 404, create ruleset via `POST /zones/{zone_id}/rulesets`.
- Update `CloudflareSyncWorker::run_loop`: log errors with `eprintln!("[Cloudflare Sync Error] {e}")` and do not save DB state on failure.

- [ ] **Step 3: Run all tests to verify**

Run: `rtk cargo test`
Expected: PASS.

- [ ] **Step 4: Run clippy and Sentrux check**

Run: `rtk cargo clippy --all-targets`
Expected: 0 errors, 0 warnings.

- [ ] **Step 5: Verify no comments rule**

Run: `rtk proxy rg "^\s*//" src/ tests/`
Expected: 0 matches.

- [ ] **Step 6: Commit**

```bash
rtk git add src/cloudflare/client.rs src/ipc/handlers.rs tests/
rtk git commit -m "feat(cloudflare): dynamic ruleset resolution, PATCH updates, and worker error logging"
```
