use super::bot_category::BotCategory;
use super::probes::{ProbeMatcher, ProbeResult};
use super::user_agent::UserAgentClassifier;
use crate::error::SanaluError;
use crate::geo::IpMetadata;
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
        })
    }

    pub fn new_test_instance() -> Self {
        let mut blocked_categories = HashSet::new();
        blocked_categories.insert(BotCategory::SecurityTesting);
        blocked_categories.insert(BotCategory::AiCrawler);
        blocked_categories.insert(BotCategory::BadScraper);
        blocked_categories.insert(BotCategory::GenericTools);

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
        }
    }

    pub fn evaluate(
        &self,
        ip: IpAddr,
        asn_info: Option<&IpMetadata>,
        user_agent: &str,
        _method: &str,
        uri: &str,
    ) -> PipelineAction {
        if self.whitelisted_ips.contains(&ip) {
            return PipelineAction::Allow;
        }
        if self.banned_ips.contains(&ip) {
            return PipelineAction::DropBanned;
        }
        if let Some(meta) = asn_info {
            if self.blocked_asns.contains(&meta.asn) {
                return PipelineAction::Ban {
                    reason: format!("blocked_asn:{}", meta.asn),
                    permanent: false,
                };
            }
            if self.restricted_asns.contains(&meta.asn) {
                let country = meta.country_str();
                if !self.allowed_regions.contains(&country) {
                    return PipelineAction::Ban {
                        reason: format!("restricted_asn_region:{}:{}", meta.asn, country),
                        permanent: false,
                    };
                }
            }
        }

        let cat = self.ua_classifier.classify(user_agent);
        if self.blocked_categories.contains(&cat) {
            return PipelineAction::Ban {
                reason: format!("blocked_bot_category:{}", cat.as_str()),
                permanent: false,
            };
        }

        match self.probe_matcher.inspect(uri) {
            ProbeResult::AllowedEndpoint => PipelineAction::Allow,
            ProbeResult::HarmfulPattern(pat) => PipelineAction::Ban {
                reason: format!("harmful_probe:{}", pat),
                permanent: true,
            },
            ProbeResult::Clean => PipelineAction::Allow,
        }
    }
}
