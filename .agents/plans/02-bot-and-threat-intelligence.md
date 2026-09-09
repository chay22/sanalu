# Plan 02: Bot Categorization & Threat Intelligence Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> **Ponytail lite note:** The evaluation order is strictly IP/ASN -> User-Agent -> Path. Checking User-Agents before paths prevents an attacker using `zgrab` from bypassing blocks simply by requesting an application path.

**Goal:** Implement the threat intelligence engine with strict 3-stage evaluation order (IP/ASN -> User-Agent -> Path), 8-category bot taxonomy, runtime category blocking via CLI, harmful path matching, and generic `allowed_endpoints` regex pattern support for polyglot backends (Rust, Go, Python, Node.js/Bun, PHP, etc.).

**Architecture:**
1. **Strict 3-Stage Evaluation Flow**:
   - **Stage 1 (IP / ASN / Country)**: Check whitelist, banned list, blocked ASNs, and restricted ASNs with country check. If blocked, terminate immediately.
   - **Stage 2 (User-Agent / Bot Category)**: Check if User-Agent belongs to a blocked category (`scanners`, `ai`, `aggressive_seo`, `generic_tools`). If matched, BAN client immediately.
   - **Stage 3 (Path / URI Probes - Polyglot)**:
     - Check if URI matches any regex/pattern in `allowed_endpoints`. If yes $\rightarrow$ ALLOW.
     - Check if URI matches known exploit probes (`.env`, `.git`, `/adminer`, `phpunit`, `/telescope`, path traversal `..`, `%00`) or sensitive file dumps (`.sql`, `.bak`, `.swp`, `.key`, `.pem`) $\rightarrow$ BAN.
     - Regular application routes (API, SPA, dynamic routes) $\rightarrow$ ALLOW.
2. **8 Bot Categories + Generic Tools**:
   - `AdsVerification`: Allowed/Neutral.
   - `Search`: Allowed (verified search engines like Googlebot, Bingbot).
   - `AiCrawler`: Blocked (`Bytespider`, `AgentGPT`, `Auto-GPT`, `babyagi`, `OAI-SearchBot`).
   - `Monitoring`: Allowed (`pingdom`, `UptimeRobot`, etc.).
   - `FeedFetching`: Allowed/Neutral.
   - `SecurityTesting`: Blocked immediately (`zgrab`, `Censys`, `InternetMeasurement`, `leakix`, `l9scan`, `Palo Alto`).
   - `SocialPreview`: Allowed (`Twitterbot`, `facebookexternalhit`, `Slackbot`).
   - `BadScraper`: Blocked (`SEOkicks`, `DotBot`, `BLEXBot`, `MegaIndex`, `MJ12bot`, `PetalBot`, `Barkrowler`).
   - `GenericTools`: Blocked (`Java`, `perl`, `python`, `Go-http-client`, `Apache-HttpClient`, `Scrapy`).
3. **Runtime Category Management**:
   - Categories can be blocked/unblocked dynamically at runtime via `redb` (`sanalu category block <cat>`, `sanalu category unblock <cat>`).
4. **Probe & Allowed Endpoints Matcher**:
   - Compiles `allowed_endpoints` regex patterns.
   - Aho-Corasick automaton for high-severity probe paths, traversing patterns (`..`, `%00`), and rules from `references/globalblacklist.conf`.

**Tech Stack:** Rust 2024, `aho-corasick`, `regex`, `redb`.

**Spec:** `plans/00-overview.md`

## Global Constraints

- Strictly follow `no-comments-in-code.md`.
- Always use `rtk` prefix for shell commands.
- Zero allocations in hot path matching loops.

---

### Task 1: Bot Category Taxonomy & Evaluation Pipeline

**Files:**
- Create: `src/intelligence/bot_category.rs`
- Create: `src/intelligence/user_agent.rs`
- Create: `src/intelligence/pipeline.rs`
- Test: `tests/bot_category_test.rs`
- Test: `tests/pipeline_test.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
  pub enum BotCategory {
      AdsVerification,
      Search,
      AiCrawler,
      Monitoring,
      FeedFetching,
      SecurityTesting,
      SocialPreview,
      BadScraper,
      GenericTools,
      BrowserOrUnknown,
  }

  pub enum PipelineAction {
      Allow,
      DropBanned,
      Ban { reason: &'static str, permanent: bool },
  }

  pub struct ThreatPipeline;
  impl ThreatPipeline {
      pub fn evaluate(
          &self,
          ip: std::net::IpAddr,
          asn_info: Option<&crate::geo::IpMetadata>,
          user_agent: &str,
          method: &str,
          uri: &str,
      ) -> PipelineAction;
  }
  ```

- [ ] **Step 1: Write unit tests verifying strict evaluation order**

```rust
#[test]
fn test_scanner_on_allowed_endpoint_is_still_banned() {
    let pipeline = sanalu::intelligence::ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "zgrab/0.x (compatible; Research)",
        "GET",
        "/api/health",
    );
    match action {
        sanalu::intelligence::PipelineAction::Ban { reason, .. } => {
            assert_eq!(reason, "blocked_bot_category:security_testing");
        }
        _ => panic!("Scanner on allowed endpoint must be banned at Stage 2!"),
    }
}

#[test]
fn test_clean_user_agent_on_allowed_endpoint_is_allowed() {
    let pipeline = sanalu::intelligence::ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GET",
        "/api/health",
    );
    assert!(matches!(action, sanalu::intelligence::PipelineAction::Allow));
}

#[test]
fn test_clean_user_agent_on_exploit_path_is_banned() {
    let pipeline = sanalu::intelligence::ThreatPipeline::new_test_instance();
    let action = pipeline.evaluate(
        "203.0.113.10".parse().unwrap(),
        None,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "GET",
        "/.env",
    );
    match action {
        sanalu::intelligence::PipelineAction::Ban { reason, permanent } => {
            assert_eq!(reason, "harmful_probe:.env");
            assert!(permanent);
        }
        _ => panic!("Clean browser hitting .env must be permanently banned!"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test pipeline_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `ThreatPipeline` and `UserAgentClassifier`**
Enforce Stage 1 -> Stage 2 -> Stage 3 order.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test pipeline_test`
Expected: PASS.

---

### Task 2: Harmful Path & `allowed_endpoints` Regex Engine

**Files:**
- Create: `src/intelligence/probes.rs`
- Create: `src/intelligence/blacklist_conf.rs`
- Test: `tests/probe_test.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct ProbeMatcher {
      probes_matcher: aho_corasick::AhoCorasick,
      allowed_endpoints_regex: regex::RegexSet,
  }

  #[derive(Debug, PartialEq, Eq)]
  pub enum ProbeResult {
      AllowedEndpoint,
      HarmfulPattern(&'static str),
      Clean,
  }

  impl ProbeMatcher {
      pub fn new(allowed_patterns: &[String]) -> Result<Self, crate::error::IntelligenceError>;
      pub fn inspect(&self, path: &str) -> ProbeResult;
  }
  ```

- [ ] **Step 1: Write test for regex allowed endpoints and probe detection**

```rust
#[test]
fn test_allowed_endpoints_regex() {
    let patterns = vec![
        "^/api/.*".into(),
        "^/health$".into(),
        "^/webhooks/.*".into(),
    ];
    let matcher = sanalu::intelligence::ProbeMatcher::new(&patterns).unwrap();

    assert_eq!(matcher.inspect("/health"), sanalu::intelligence::ProbeResult::AllowedEndpoint);
    assert_eq!(matcher.inspect("/api/v1/status"), sanalu::intelligence::ProbeResult::AllowedEndpoint);
    assert!(matches!(matcher.inspect("/.env"), sanalu::intelligence::ProbeResult::HarmfulPattern(".env")));
    assert!(matches!(matcher.inspect("/wp-admin/"), sanalu::intelligence::ProbeResult::HarmfulPattern("/wp-")));
    assert!(matches!(matcher.inspect("/db_backup.sql"), sanalu::intelligence::ProbeResult::HarmfulPattern(".sql")));
    assert_eq!(matcher.inspect("/dashboard"), sanalu::intelligence::ProbeResult::Clean);
}
```

- [ ] **Step 2: Run test to verify it fails**
Run: `rtk cargo test --test probe_test`
Expected: Compilation failure.

- [ ] **Step 3: Implement `ProbeMatcher` with `RegexSet` and Aho-Corasick**
Check `allowed_endpoints_regex` first within Stage 3; if no match, check harmful patterns and sensitive dumps.

- [ ] **Step 4: Run test to verify it passes**
Run: `rtk cargo test --test probe_test`
Expected: PASS.
