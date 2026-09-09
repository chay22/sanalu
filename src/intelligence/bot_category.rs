use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl BotCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdsVerification => "ads_verification",
            Self::Search => "search",
            Self::AiCrawler => "ai_crawler",
            Self::Monitoring => "monitoring",
            Self::FeedFetching => "feed_fetching",
            Self::SecurityTesting => "security_testing",
            Self::SocialPreview => "social_preview",
            Self::BadScraper => "bad_scraper",
            Self::GenericTools => "generic_tools",
            Self::BrowserOrUnknown => "browser_or_unknown",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ads_verification" | "ads" => Some(Self::AdsVerification),
            "search" | "search_crawler" => Some(Self::Search),
            "ai_crawler" | "ai" => Some(Self::AiCrawler),
            "monitoring" => Some(Self::Monitoring),
            "feed_fetching" | "feeds" => Some(Self::FeedFetching),
            "security_testing" | "scanners" => Some(Self::SecurityTesting),
            "social_preview" | "social" => Some(Self::SocialPreview),
            "bad_scraper" | "aggressive_seo" => Some(Self::BadScraper),
            "generic_tools" | "tools" => Some(Self::GenericTools),
            "browser_or_unknown" | "unknown" => Some(Self::BrowserOrUnknown),
            _ => None,
        }
    }

    pub fn is_blocked_by_default(&self) -> bool {
        matches!(
            self,
            Self::AiCrawler | Self::SecurityTesting | Self::BadScraper | Self::GenericTools
        )
    }
}
