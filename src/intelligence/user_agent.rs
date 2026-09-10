use super::bot_category::BotCategory;
use super::patterns::BOT_RULES;
use aho_corasick::{AhoCorasick, MatchKind};

pub struct UserAgentClassifier {
    matcher: AhoCorasick,
    categories: Vec<BotCategory>,
}

impl UserAgentClassifier {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        let mut categories = Vec::new();

        for &(pats, cat) in BOT_RULES {
            for &pat in pats {
                patterns.push(pat);
                categories.push(cat);
            }
        }

        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .expect("Failed to build AhoCorasick for User-Agent classifier");

        Self {
            matcher,
            categories,
        }
    }

    pub fn classify(&self, user_agent: &str) -> BotCategory {
        let trimmed = user_agent.trim();
        if trimmed.is_empty() || trimmed == "-" {
            return BotCategory::GenericTools;
        }

        if let Some(mat) = self.matcher.find(trimmed) {
            return self.categories[mat.pattern()];
        }

        BotCategory::BrowserOrUnknown
    }
}

impl Default for UserAgentClassifier {
    fn default() -> Self {
        Self::new()
    }
}
