use std::net::Ipv4Addr;

pub struct CloudflareRuleBudget {
    max_chars: usize,
    blocked_asns: Vec<u32>,
    restricted_asns: Vec<u32>,
    allowed_regions: Vec<String>,
}

impl CloudflareRuleBudget {
    pub fn new(
        max_chars: usize,
        blocked_asns: Vec<u32>,
        restricted_asns: Vec<u32>,
        allowed_regions: Vec<String>,
    ) -> Self {
        Self {
            max_chars,
            blocked_asns,
            restricted_asns,
            allowed_regions,
        }
    }

    pub fn render_expression(&self, banned_ips_lru: &[Ipv4Addr]) -> (String, Vec<Ipv4Addr>) {
        let mut clauses = Vec::new();

        if let Some(reg_clause) = self.build_regional_clause(self.max_chars) {
            clauses.push(reg_clause);
        }

        let current_len = clauses_total_len(&clauses);
        let asn_budget = self.max_chars.saturating_sub(current_len);
        if let Some(asn_clause) = self.build_blocked_asns_clause(asn_budget) {
            clauses.push(asn_clause);
        }

        let prefix_static = if clauses.is_empty() {
            String::new()
        } else {
            format!("{} or ", clauses.join(" or "))
        };

        let ip_wrapper_overhead = prefix_static.len() + "(ip.src in {})".len();
        let remaining_budget = self.max_chars.saturating_sub(ip_wrapper_overhead);

        let (current_ips_str, included_ips) = pack_ips(banned_ips_lru, remaining_budget);

        let full_expr = if !included_ips.is_empty() {
            if clauses.is_empty() {
                format!("(ip.src in {{{current_ips_str}}})")
            } else {
                format!("{prefix_static}(ip.src in {{{current_ips_str}}})")
            }
        } else if !clauses.is_empty() {
            clauses.join(" or ")
        } else {
            String::new()
        };

        (full_expr, included_ips)
    }

    fn build_regional_clause(&self, max_budget: usize) -> Option<String> {
        if self.restricted_asns.is_empty() || self.allowed_regions.is_empty() {
            return None;
        }

        let asns_str = self
            .restricted_asns
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let regions_str = self
            .allowed_regions
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(" ");

        let clause =
            format!("(ip.src.asnum in {{{asns_str}}} and not ip.src.country in {{{regions_str}}})");

        if clause.len() <= max_budget {
            Some(clause)
        } else {
            None
        }
    }

    fn build_blocked_asns_clause(&self, max_budget: usize) -> Option<String> {
        if self.blocked_asns.is_empty() {
            return None;
        }

        let overhead = "(ip.src.asnum in {})".len();
        if max_budget <= overhead {
            return None;
        }
        let content_budget = max_budget - overhead;

        let mut selected = Vec::new();
        let mut current_len = 0;

        for &asn in self.blocked_asns.iter().rev() {
            let s = asn.to_string();
            let added_len = if current_len == 0 {
                s.len()
            } else {
                1 + s.len()
            };

            if current_len + added_len <= content_budget {
                current_len += added_len;
                selected.push(s);
            } else {
                break;
            }
        }

        if selected.is_empty() {
            return None;
        }

        selected.reverse();
        let asns_str = selected.join(" ");
        Some(format!("(ip.src.asnum in {{{asns_str}}})"))
    }
}

fn clauses_total_len(clauses: &[String]) -> usize {
    if clauses.is_empty() {
        0
    } else {
        clauses.iter().map(|c| c.len()).sum::<usize>()
            + (clauses.len() - 1) * " or ".len()
            + " or ".len()
    }
}

fn pack_ips(ips: &[Ipv4Addr], remaining_budget: usize) -> (String, Vec<Ipv4Addr>) {
    let mut included_ips = Vec::new();
    let mut current_ips_str = String::new();

    for &ip in ips {
        let ip_str = ip.to_string();
        let added_len = if current_ips_str.is_empty() {
            ip_str.len()
        } else {
            1 + ip_str.len()
        };

        if current_ips_str.len() + added_len <= remaining_budget {
            if !current_ips_str.is_empty() {
                current_ips_str.push(' ');
            }
            current_ips_str.push_str(&ip_str);
            included_ips.push(ip);
        } else {
            break;
        }
    }

    (current_ips_str, included_ips)
}
