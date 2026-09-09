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

        if !self.blocked_asns.is_empty() {
            let asns_str = self
                .blocked_asns
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            clauses.push(format!("(ip.src.asnum in {{{asns_str}}})"));
        }

        if !self.restricted_asns.is_empty() && !self.allowed_regions.is_empty() {
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
            clauses.push(format!(
                "(ip.src.asnum in {{{asns_str}}} and not ip.src.country in {{{regions_str}}})"
            ));
        }

        let prefix_static = if clauses.is_empty() {
            String::new()
        } else {
            format!("{} or ", clauses.join(" or "))
        };

        let ip_wrapper_overhead = prefix_static.len() + "(ip.src in {})".len();
        let remaining_budget = self.max_chars.saturating_sub(ip_wrapper_overhead);

        let mut included_ips = Vec::new();
        let mut current_ips_str = String::new();

        for &ip in banned_ips_lru {
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
}
