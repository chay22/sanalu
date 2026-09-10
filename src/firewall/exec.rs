use crate::error::SanaluError;
use std::io::Write;
use std::process::{Command, Stdio};

pub fn execute_nft_ruleset(ruleset: &str, dry_run: bool) -> Result<(), SanaluError> {
    if dry_run {
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

pub fn render_init_ruleset(table: &str, set_v4: &str, set_v6: &str) -> String {
    format!(
        "add table {table}\n\
         add set {table} {set_v4} {{ type ipv4_addr; flags interval, timeout; }}\n\
         add set {table} {set_v6} {{ type ipv6_addr; flags interval, timeout; }}\n\
         add chain {table} prerouting {{ type filter hook prerouting priority -100; policy accept; }}\n\
         add rule {table} prerouting ip saddr @{set_v4} drop\n\
         add rule {table} prerouting ip6 saddr @{set_v6} drop\n",
        table = table,
        set_v4 = set_v4,
        set_v6 = set_v6
    )
}
