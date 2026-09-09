use super::FirewallBackend;
use crate::error::SanaluError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub struct MockFirewallBackend {
    banned: RwLock<HashMap<IpAddr, Option<Instant>>>,
    banned_targets: RwLock<HashMap<String, Option<Instant>>>,
}

impl MockFirewallBackend {
    pub fn new() -> Self {
        Self {
            banned: RwLock::new(HashMap::new()),
            banned_targets: RwLock::new(HashMap::new()),
        }
    }

    pub fn list_banned_targets(&self) -> Result<Vec<String>, SanaluError> {
        let now = Instant::now();
        let map = self
            .banned_targets
            .read()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        let active: Vec<String> = map
            .iter()
            .filter(|(_, exp)| match exp {
                Some(expires) => *expires > now,
                None => true,
            })
            .map(|(target, _)| target.clone())
            .collect();
        Ok(active)
    }
}

impl Default for MockFirewallBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallBackend for MockFirewallBackend {
    fn init_tables(&self) -> Result<(), SanaluError> {
        Ok(())
    }

    fn ban_ip(&self, ip: IpAddr, timeout_secs: Option<u64>) -> Result<(), SanaluError> {
        self.ban_target(&ip.to_string(), timeout_secs)
    }

    fn unban_ip(&self, ip: IpAddr) -> Result<(), SanaluError> {
        self.unban_target(&ip.to_string())
    }

    fn ban_target(&self, target: &str, timeout_secs: Option<u64>) -> Result<(), SanaluError> {
        let mut map = self
            .banned_targets
            .write()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        let expires_at = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
        map.insert(target.to_string(), expires_at);
        if let Ok(ip) = target.parse::<IpAddr>() {
            let mut ip_map = self
                .banned
                .write()
                .map_err(|e| SanaluError::Firewall(e.to_string()))?;
            ip_map.insert(ip, expires_at);
        }
        Ok(())
    }

    fn unban_target(&self, target: &str) -> Result<(), SanaluError> {
        let mut map = self
            .banned_targets
            .write()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        map.remove(target);
        if let Ok(ip) = target.parse::<IpAddr>() {
            let mut ip_map = self
                .banned
                .write()
                .map_err(|e| SanaluError::Firewall(e.to_string()))?;
            ip_map.remove(&ip);
        }
        Ok(())
    }

    fn list_banned(&self) -> Result<Vec<IpAddr>, SanaluError> {
        let now = Instant::now();
        let map = self
            .banned
            .read()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        let active: Vec<IpAddr> = map
            .iter()
            .filter(|(_, exp)| match exp {
                Some(expires) => *expires > now,
                None => true,
            })
            .map(|(&ip, _)| ip)
            .collect();
        Ok(active)
    }

    fn flush(&self) -> Result<(), SanaluError> {
        let mut map = self
            .banned
            .write()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        map.clear();
        let mut target_map = self
            .banned_targets
            .write()
            .map_err(|e| SanaluError::Firewall(e.to_string()))?;
        target_map.clear();
        Ok(())
    }
}
