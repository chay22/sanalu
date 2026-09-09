use super::bot_category::BotCategory;
use aho_corasick::{AhoCorasick, MatchKind};

pub struct UserAgentClassifier {
    matcher: AhoCorasick,
    categories: Vec<BotCategory>,
}

impl UserAgentClassifier {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        let mut categories = Vec::new();

        let rules: &[(&[&str], BotCategory)] = &[
            (
                &[
                    "zgrab",
                    "censys",
                    "internetmeasurement",
                    "leakix",
                    "l9scan",
                    "palo alto",
                    "sqlmap",
                    "nikto",
                    "dirbuster",
                    "gobuster",
                    "masscan",
                    "nmap",
                    "nuclei",
                    "acunetix",
                    "nessus",
                    "openvas",
                    "shodan",
                    "whatweb",
                    "wprecon",
                    "netcraft",
                ],
                BotCategory::SecurityTesting,
            ),
            (
                &[
                    "bytespider",
                    "agentgpt",
                    "auto-gpt",
                    "babyagi",
                    "oai-searchbot",
                    "gptbot",
                    "ccbot",
                    "claude-web",
                    "claudebot",
                    "diffbot",
                    "facebookbot",
                    "applebot-extended",
                    "anthropic-ai",
                    "cohere-ai",
                    "perplexitybot",
                    "amazonbot",
                    "scoutjet",
                    "omgili",
                    "youbot",
                ],
                BotCategory::AiCrawler,
            ),
            (
                &[
                    "seokicks",
                    "dotbot",
                    "blexbot",
                    "megaindex",
                    "mj12bot",
                    "petalbot",
                    "barkrowler",
                    "80legs",
                    "360spider",
                    "404checker",
                    "404enemy",
                    "admantx",
                    "aibot",
                    "backlinkcrawler",
                    "cognitiveseo",
                    "coccocbot",
                    "proximic",
                    "rogerbot",
                    "screaming frog",
                    "searchmetricsbot",
                    "semrushbot",
                    "semrush",
                    "ahrefsbot",
                    "serpstatbot",
                    "sistrix",
                    "spbot",
                    "zoominfobot",
                ],
                BotCategory::BadScraper,
            ),
            (
                &[
                    "googlebot",
                    "bingbot",
                    "yandexbot",
                    "duckduckbot",
                    "baiduspider",
                    "sogou",
                    "qwantify",
                ],
                BotCategory::Search,
            ),
            (
                &[
                    "twitterbot",
                    "facebookexternalhit",
                    "slackbot",
                    "telegrambot",
                    "whatsapp",
                    "linkedinbot",
                    "pinterest",
                    "discordbot",
                    "applebot",
                ],
                BotCategory::SocialPreview,
            ),
            (
                &[
                    "pingdom",
                    "uptimerobot",
                    "betteruptime",
                    "datadog",
                    "newrelic",
                    "statuscake",
                    "nodeping",
                    "site24x7",
                ],
                BotCategory::Monitoring,
            ),
            (
                &["google-adwords", "adbeat", "adidxbot"],
                BotCategory::AdsVerification,
            ),
            (
                &["feedfetcher-google", "rssmicro", "feedspot"],
                BotCategory::FeedFetching,
            ),
            (
                &[
                    "java/",
                    "java",
                    "perl",
                    "python-requests",
                    "python-urllib",
                    "python/",
                    "python",
                    "go-http-client",
                    "apache-httpclient",
                    "scrapy",
                    "curl/",
                    "curl",
                    "wget/",
                    "wget",
                    "libwww-perl",
                    "aiohttp",
                    "httpx",
                    "httpie",
                    "postmanruntime",
                    "insomnia",
                    "axios",
                ],
                BotCategory::GenericTools,
            ),
        ];

        for &(pats, cat) in rules {
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
