# Plan 06: Implementation Milestones, Verification & Quality Gates

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** We measure real-world performance directly using `sanalu test-log` against the 500+ real log files in `references/ubuntu22/`, giving instant verification without mock setups.

**Goal:** Establish the execution phases, verification benchmarks against real reference logs, memory footprint gates, and Sentrux structural quality enforcement.

**Architecture:** A 6-milestone development lifecycle ensuring test-driven delivery and continuous verification:
1. **Milestone 1**: Project bootstrap, `Cargo.toml`, minimal configuration parser (`sanalu.toml`), unified error domain, and embedded `redb` storage engine.
2. **Milestone 2**: Auto-discovery of Ubuntu 22/24 environments (including Nginx `log_format` directives) and isolated zero-config `inet sanalu` `nftables` controller.
3. **Milestone 3**: Threat intelligence engine, 8-category bot taxonomy, harmful path probes, generic UA whitelist bypass, and `references/globalblacklist.conf` integration.
4. **Milestone 4**: Free IP/ASN/Country binary search engine and Cloudflare WAF 4,000-char LRU expression synchronizer.
5. **Milestone 5**: Real-time log monitoring daemon (`sanalu run`), multi-format Nginx parsers (Combined, Proxy, JSON), SSH journald/auth parser, tiered ban escalation, `.deb` package configuration, and unrestricted systemd service.
6. **Milestone 6**: End-to-end replay verification on `references/` real logs, performance benchmark (>100k lines/sec), memory check (<25MB RSS), and `sentrux` structural gating.

**Tech Stack:** Rust 2024, `cargo-clippy`, `cargo-test`, `sentrux`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- All commands run via `rtk`.
- Zero clippy warnings under pedantic mode.

---

### Milestone Breakdown

| Milestone | Deliverable | Verification Command | Gate |
|---|---|---|---|
| **M1** | Project setup, Config & `redb` | `rtk cargo test --test storage_test --test config_test` | Zero warnings, ACID storage |
| **M2** | Discovery & Zero-Config Firewall | `rtk cargo test --test discovery_test --test firewall_test` | Isolated `inet sanalu` ruleset |
| **M3** | Threat Intelligence & Probes | `rtk cargo test --test bot_category_test --test probe_test` | All harmful paths & bots caught |
| **M4** | ASN/Geo & Cloudflare WAF | `rtk cargo test --test geo_test --test cloudflare_expression_test` | Expression <= 4000 chars strictly |
| **M5** | Parsers, Daemon & `.deb`/Service | `rtk cargo test --test nginx_parser_test --test ssh_parser_test --test packaging_test` | End-to-end daemon flow verified |
| **M6** | Reference Replay & Sentrux | `rtk cargo run -- test-log references/ubuntu22/nginx/access.log`<br>`sentrux check` | Architecture clean, no cycles |

---

### Verification Protocol Against Reference Data

- [ ] **Step 1: Replay Real Nginx Reference Logs**
Execute `sanalu test-log references/ubuntu22/nginx/access.log` and verify that known scanner IPs (`45.194.92.67`, `16.5.0.236`) and exploit probes are flagged and banned with appropriate reasons.

- [ ] **Step 2: Replay Real SSH Reference Logs**
Execute `sanalu test-log references/ubuntu22/auth/auth.log` and verify that port scanner IPs (such as `44.220.188.23` sending `GET / HTTP/1.1` to SSH port) are immediately caught.

- [ ] **Step 3: Verify Cloudflare Expression Limit**
Test with 200+ banned IPs and verify that the generated Cloudflare expression stays strictly under the 4,000-character ceiling, dropping older IPs while retaining the ASN blocks and geo-fenced cloud ASNs.

- [ ] **Step 4: Quality Gate with Sentrux**
Run `sentrux check` to ensure zero architectural coupling cycles and verify module boundaries across `parser`, `engine`, `firewall`, `intelligence`, `cloudflare`, and `storage`.

- [ ] **Step 5: Code Review for No-Comments Policy**
Verify with `rtk proxy zg query --rg "//"` across `src/` to confirm that no unnecessary comments were written into the codebase.
