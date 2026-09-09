use crate::error::SanaluError;
use aho_corasick::{AhoCorasick, MatchKind};
use regex::RegexSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    AllowedEndpoint,
    HarmfulPattern(&'static str),
    Clean,
}

pub struct ProbeMatcher {
    probes_matcher: AhoCorasick,
    probe_labels: Vec<&'static str>,
    allowed_endpoints_regex: Option<RegexSet>,
}

impl ProbeMatcher {
    pub fn new(allowed_patterns: &[String]) -> Result<Self, SanaluError> {
        let patterns_and_labels: &[(&str, &'static str)] = &[
            (".env", ".env"),
            (".git", ".git"),
            (".svn", ".svn"),
            (".hg", ".hg"),
            (".bzr", ".bzr"),
            (".ds_store", ".ds_store"),
            ("/wp-", "/wp-"),
            ("wp-config", "wp-config"),
            ("/adminer", "/adminer"),
            ("phpunit", "phpunit"),
            ("/telescope", "/telescope"),
            ("phpmyadmin", "phpmyadmin"),
            ("xmlrpc", "xmlrpc"),
            ("eval-stdin", "eval-stdin"),
            ("/actuator", "/actuator"),
            ("/cgi-bin", "/cgi-bin"),
            ("../", "../"),
            ("..%2f", "..%2f"),
            ("%2e%2e", "%2e%2e"),
            ("/%00", "/%00"),
            ("\\x00", "\\x00"),
            ("etc/passwd", "etc/passwd"),
            ("etc/shadow", "etc/shadow"),
            ("boot.ini", "boot.ini"),
            ("win.ini", "win.ini"),
            (".aws/", ".aws"),
            (".ssh/", ".ssh"),
            ("id_rsa", "id_rsa"),
            ("id_ed25519", "id_ed25519"),
            (".sql", ".sql"),
            (".bak", ".bak"),
            (".swp", ".swp"),
            (".backup", ".backup"),
            (".dump", ".dump"),
        ];

        let mut pats = Vec::with_capacity(patterns_and_labels.len());
        let mut labels = Vec::with_capacity(patterns_and_labels.len());
        for &(p, l) in patterns_and_labels {
            pats.push(p);
            labels.push(l);
        }

        let probes_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&pats)
            .map_err(|e| SanaluError::Intelligence(e.to_string()))?;

        let allowed_endpoints_regex = if allowed_patterns.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(allowed_patterns)
                    .map_err(|e| SanaluError::Intelligence(e.to_string()))?,
            )
        };

        Ok(Self {
            probes_matcher,
            probe_labels: labels,
            allowed_endpoints_regex,
        })
    }

    pub fn inspect(&self, path: &str) -> ProbeResult {
        if let Some(ref regex_set) = self.allowed_endpoints_regex {
            if regex_set.is_match(path) {
                return ProbeResult::AllowedEndpoint;
            }
        }

        if let Some(mat) = self.probes_matcher.find(path) {
            return ProbeResult::HarmfulPattern(self.probe_labels[mat.pattern()]);
        }

        ProbeResult::Clean
    }
}
