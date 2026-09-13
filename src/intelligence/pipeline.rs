use super::bot_category::BotCategory;
use super::category::ThreatCategory;
use super::normalize::{NormalizedUri, normalize_request_uri};
use super::probes::{ProbeMatcher, ThreatDecision, inspect_threat};
use super::strikes::{IpStrikeTracker, StrikeResult};
use super::user_agent::UserAgentClassifier;
use crate::error::SanaluError;
use crate::geo::IpMetadata;
use crate::parser::SshEvent;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum PipelineAction {
    Allow,
    DropBanned,
    Ban { reason: String, permanent: bool },
}

pub struct ThreatPipeline {
    whitelisted_ips: HashSet<IpAddr>,
    banned_ips: HashSet<IpAddr>,
    blocked_asns: HashSet<u32>,
    restricted_asns: HashSet<u32>,
    allowed_regions: HashSet<String>,
    blocked_categories: HashSet<BotCategory>,
    ua_classifier: UserAgentClassifier,
    probe_matcher: ProbeMatcher,
    strike_tracker: IpStrikeTracker,
}

impl ThreatPipeline {
    pub fn new(
        whitelisted_ips: HashSet<IpAddr>,
        banned_ips: HashSet<IpAddr>,
        blocked_asns: HashSet<u32>,
        restricted_asns: HashSet<u32>,
        allowed_regions: HashSet<String>,
        blocked_categories: HashSet<BotCategory>,
        allowed_patterns: &[String],
    ) -> Result<Self, SanaluError> {
        let probe_matcher = ProbeMatcher::new(allowed_patterns)?;
        Ok(Self {
            whitelisted_ips,
            banned_ips,
            blocked_asns,
            restricted_asns,
            allowed_regions,
            blocked_categories,
            ua_classifier: UserAgentClassifier::new(),
            probe_matcher,
            strike_tracker: IpStrikeTracker::new(),
        })
    }

    pub fn new_test_instance() -> Self {
        let mut blocked_categories = HashSet::new();
        blocked_categories.insert(BotCategory::SecurityTesting);
        blocked_categories.insert(BotCategory::AiCrawler);
        blocked_categories.insert(BotCategory::BadScraper);
        blocked_categories.insert(BotCategory::GenericTools);
        blocked_categories.insert(BotCategory::Empty);

        let allowed_patterns = vec![
            "^/api/.*".to_string(),
            "^/health$".to_string(),
            "^/webhooks/.*".to_string(),
        ];

        let probe_matcher =
            ProbeMatcher::new(&allowed_patterns).expect("Failed to build test probe matcher");

        Self {
            whitelisted_ips: HashSet::new(),
            banned_ips: HashSet::new(),
            blocked_asns: HashSet::new(),
            restricted_asns: HashSet::new(),
            allowed_regions: HashSet::new(),
            blocked_categories,
            ua_classifier: UserAgentClassifier::new(),
            probe_matcher,
            strike_tracker: IpStrikeTracker::new(),
        }
    }

    pub fn new_with_defaults() -> Self {
        Self::new_test_instance()
    }

    fn evaluate_asn(&self, meta: &IpMetadata) -> Option<PipelineAction> {
        if self.blocked_asns.contains(&meta.asn) {
            return Some(PipelineAction::Ban {
                reason: format!("blocked_asn:{}", meta.asn),
                permanent: false,
            });
        }
        if self.restricted_asns.contains(&meta.asn) {
            let country = meta.country_str();
            if !self.allowed_regions.contains(&country) {
                return Some(PipelineAction::Ban {
                    reason: format!("restricted_asn_region:{}:{}", meta.asn, country),
                    permanent: false,
                });
            }
        }
        None
    }

    fn evaluate_threat_decision(&self, ip: IpAddr, decision: ThreatDecision) -> PipelineAction {
        match decision {
            ThreatDecision::Pass => PipelineAction::Allow,
            ThreatDecision::InstantBan(cat) => PipelineAction::Ban {
                reason: format!("probe:{}:instant", cat.as_str()),
                permanent: false,
            },
            ThreatDecision::SharedStrike {
                category,
                threshold,
                window_secs,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                match self
                    .strike_tracker
                    .record_shared_strike(ip, threshold, window_secs, now)
                {
                    StrikeResult::ThresholdReached { count } => PipelineAction::Ban {
                        reason: format!("probe:{}:shared_threshold:{}", category.as_str(), count),
                        permanent: false,
                    },
                    StrikeResult::UnderThreshold { .. } => PipelineAction::Allow,
                }
            }
            ThreatDecision::IsolatedStrike {
                category,
                threshold,
                window_secs,
            } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                match self.strike_tracker.record_isolated_strike(
                    ip,
                    category,
                    threshold,
                    window_secs,
                    now,
                ) {
                    StrikeResult::ThresholdReached { count } => PipelineAction::Ban {
                        reason: format!("probe:{}:isolated_threshold:{}", category.as_str(), count),
                        permanent: false,
                    },
                    StrikeResult::UnderThreshold { .. } => PipelineAction::Allow,
                }
            }
        }
    }

    fn evaluate_probe(&self, ip: IpAddr, method: &str, uri: &str, status: u16) -> PipelineAction {
        if self.probe_matcher.is_allowed_endpoint(uri) {
            return PipelineAction::Allow;
        }
        match normalize_request_uri(uri) {
            NormalizedUri::ImmediateMalicious(cat) => PipelineAction::Ban {
                reason: format!("probe:{}:immediate_malicious", cat.as_str()),
                permanent: false,
            },
            NormalizedUri::Clean(path) => {
                let decision = inspect_threat(method, &path, status);
                self.evaluate_threat_decision(ip, decision)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_request(
        &self,
        ip: IpAddr,
        asn_info: Option<&IpMetadata>,
        user_agent: &str,
        method: &str,
        uri: &str,
        status: u16,
        referer: &str,
    ) -> PipelineAction {
        if crate::is_loopback_or_private(ip) || self.whitelisted_ips.contains(&ip) {
            return PipelineAction::Allow;
        }
        if self.banned_ips.contains(&ip) {
            return PipelineAction::DropBanned;
        }
        if let Some(meta) = asn_info {
            if let Some(action) = self.evaluate_asn(meta) {
                return action;
            }
        }

        let cat = self.ua_classifier.classify(user_agent);
        if self.blocked_categories.contains(&cat) {
            return PipelineAction::Ban {
                reason: format!("blocked_bot_category:{}", cat.as_str()),
                permanent: false,
            };
        }

        let upper_method = method.to_ascii_uppercase();
        if is_scanner_method(upper_method.as_str()) {
            return PipelineAction::Ban {
                reason: format!("scanner_method:{}", upper_method),
                permanent: false,
            };
        }

        if let Some(pat) = inspect_referer(referer) {
            return PipelineAction::Ban {
                reason: format!("harmful_referer:{}", pat),
                permanent: true,
            };
        }

        self.evaluate_probe(ip, method, uri, status)
    }

    pub fn evaluate(
        &self,
        ip: IpAddr,
        asn_info: Option<&IpMetadata>,
        user_agent: &str,
        method: &str,
        uri: &str,
    ) -> PipelineAction {
        self.evaluate_request(ip, asn_info, user_agent, method, uri, 200, "")
    }

    pub fn cleanup_stale_strikes(&self, now_secs: u64, max_idle_secs: u64) {
        self.strike_tracker.cleanup_stale(now_secs, max_idle_secs);
    }

    pub fn strike_tracker(&self) -> &IpStrikeTracker {
        &self.strike_tracker
    }

    pub fn evaluate_ssh_event(&self, event: &SshEvent) -> PipelineAction {
        match event {
            SshEvent::Ignore => PipelineAction::Allow,
            SshEvent::ScannerProbe { ip, reason } => {
                if crate::is_loopback_or_private(*ip) || self.whitelisted_ips.contains(ip) {
                    return PipelineAction::Allow;
                }
                if self.banned_ips.contains(ip) {
                    return PipelineAction::DropBanned;
                }
                PipelineAction::Ban {
                    reason: format!("probe:ssh:{}", reason),
                    permanent: false,
                }
            }
            SshEvent::AuthFailure { ip, user: _ } => {
                if crate::is_loopback_or_private(*ip) || self.whitelisted_ips.contains(ip) {
                    return PipelineAction::Allow;
                }
                if self.banned_ips.contains(ip) {
                    return PipelineAction::DropBanned;
                }
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                match self.strike_tracker.record_isolated_strike(
                    *ip,
                    ThreatCategory::Common,
                    5,
                    300,
                    now_secs,
                ) {
                    StrikeResult::ThresholdReached { count } => PipelineAction::Ban {
                        reason: format!("probe:ssh:auth_failures:{}", count),
                        permanent: false,
                    },
                    StrikeResult::UnderThreshold { .. } => PipelineAction::Allow,
                }
            }
        }
    }
}

fn is_scanner_method(method: &str) -> bool {
    matches!(method, "PROPFIND" | "DEBUG" | "SEARCH" | "TRACK" | "TRACE")
}

fn inspect_referer(referer: &str) -> Option<&'static str> {
    if referer.is_empty() {
        return None;
    }
    let lower = referer.to_ascii_lowercase();
    if lower.contains("${jndi:") {
        return Some("${jndi:");
    }
    if lower.contains("<script") {
        return Some("<script");
    }
    if lower.contains("..\\") || lower.contains("../") || lower.contains("%2e%2e") {
        return Some("path_traversal");
    }
    None
}
