use super::FirewallBackend;
use crate::error::SanaluError;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub struct NftablesBackend {
    table: String,
    set_v4: String,
    set_v6: String,
    dry_run: bool,
}

impl NftablesBackend {
    pub fn new(table: &str, set_v4: &str, set_v6: &str, dry_run: bool) -> Self {
        Self {
            table: table.to_string(),
            set_v4: set_v4.to_string(),
            set_v6: set_v6.to_string(),
            dry_run,
        }
    }

    pub fn auto_detect(dry_run: bool) -> Self {
        Self::new("inet sanalu", "blacklist_v4", "blacklist_v6", dry_run)
    }

    pub fn render_init_ruleset(&self) -> String {
        format!(
            "add table {table}\n\
             add set {table} {set_v4} {{ type ipv4_addr; flags interval, timeout; }}\n\
             add set {table} {set_v6} {{ type ipv6_addr; flags interval, timeout; }}\n\
             add chain {table} prerouting {{ type filter hook prerouting priority -100; policy accept; }}\n\
             add rule {table} prerouting ip saddr @{set_v4} drop\n\
             add rule {table} prerouting ip6 saddr @{set_v6} drop\n",
            table = self.table,
            set_v4 = self.set_v4,
            set_v6 = self.set_v6
        )
    }

    fn execute_nft_ruleset(&self, ruleset: &str) -> Result<(), SanaluError> {
        if self.dry_run {
            return Ok(());
        }
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SanaluError::Firewall(format!("Failed to spawn nft: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SanaluError::Firewall(format!(
                "nft execution failed: {stderr}"
            )));
        }
        Ok(())
    }

    pub fn ban_targets_batch(&self, targets: &[String]) -> Result<(), SanaluError> {
        if targets.is_empty() {
            return Ok(());
        }
        let mut v4_elements = Vec::new();
        let mut v6_elements = Vec::new();
        for t in targets {
            if t.contains(':') {
                v6_elements.push(t.as_str());
            } else {
                v4_elements.push(t.as_str());
            }
        }
        let mut ruleset = String::new();
        if !v4_elements.is_empty() {
            ruleset.push_str(&format!(
                "add element {} {} {{ {} }}\n",
                self.table,
                self.set_v4,
                v4_elements.join(", ")
            ));
        }
        if !v6_elements.is_empty() {
            ruleset.push_str(&format!(
                "add element {} {} {{ {} }}\n",
                self.table,
                self.set_v6,
                v6_elements.join(", ")
            ));
        }
        self.execute_nft_ruleset(&ruleset)
    }

    pub fn sync_asn_cidrs(&self, cidrs: &[String]) -> Result<(), SanaluError> {
        self.ban_targets_batch(cidrs)
    }
}

impl FirewallBackend for NftablesBackend {
    fn init_tables(&self) -> Result<(), SanaluError> {
        let ruleset = self.render_init_ruleset();
        self.execute_nft_ruleset(&ruleset)
    }

    fn ban_ip(&self, ip: IpAddr, timeout_secs: Option<u64>) -> Result<(), SanaluError> {
        self.ban_target(&ip.to_string(), timeout_secs)
    }

    fn unban_ip(&self, ip: IpAddr) -> Result<(), SanaluError> {
        self.unban_target(&ip.to_string())
    }

    fn ban_target(&self, target: &str, timeout_secs: Option<u64>) -> Result<(), SanaluError> {
        let set_name = if target.contains(':') {
            &self.set_v6
        } else {
            &self.set_v4
        };

        let ruleset = if let Some(secs) = timeout_secs {
            format!(
                "add element {table} {set_name} {{ {target} timeout {secs}s }}\n",
                table = self.table
            )
        } else {
            format!(
                "add element {table} {set_name} {{ {target} }}\n",
                table = self.table
            )
        };
        self.execute_nft_ruleset(&ruleset)
    }

    fn unban_target(&self, target: &str) -> Result<(), SanaluError> {
        let set_name = if target.contains(':') {
            &self.set_v6
        } else {
            &self.set_v4
        };

        let ruleset = format!(
            "delete element {table} {set_name} {{ {target} }}\n",
            table = self.table
        );
        self.execute_nft_ruleset(&ruleset)
    }

    fn list_banned(&self) -> Result<Vec<IpAddr>, SanaluError> {
        if self.dry_run {
            return Ok(Vec::new());
        }
        let output = Command::new("nft")
            .arg("-j")
            .arg("list")
            .arg("table")
            .args(self.table.split_whitespace())
            .output()
            .map_err(|e| SanaluError::Firewall(format!("Failed to list nft table: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SanaluError::Firewall(format!("nft list failed: {stderr}")));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| SanaluError::Firewall(format!("Failed to parse nft json: {e}")))?;

        let mut results = Vec::new();
        if let Some(elements) = parsed.get("nftables").and_then(|n| n.as_array()) {
            for item in elements {
                if let Some(set) = item.get("set") {
                    if let Some(elem_list) = set.get("elem").and_then(|e| e.as_array()) {
                        for el in elem_list {
                            let ip_val = if let Some(s) = el.as_str() {
                                s
                            } else if let Some(obj) = el.as_object() {
                                obj.get("elem")
                                    .and_then(|e| e.get("val"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                            } else {
                                ""
                            };
                            if let Ok(parsed_ip) = ip_val.parse::<IpAddr>() {
                                results.push(parsed_ip);
                            }
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    fn flush(&self) -> Result<(), SanaluError> {
        let ruleset = format!(
            "flush set {table} {set_v4}\nflush set {table} {set_v6}\n",
            table = self.table,
            set_v4 = self.set_v4,
            set_v6 = self.set_v6
        );
        self.execute_nft_ruleset(&ruleset)
    }
}
