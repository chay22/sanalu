use crate::storage::StoredBanRecord;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    pub ip: IpAddr,
    pub tier_level: usize,
    pub banned_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub reason: String,
}

impl From<StoredBanRecord> for BanRecord {
    fn from(s: StoredBanRecord) -> Self {
        let ip = s.ip.unwrap_or_else(|| {
            s.target
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        });
        Self {
            ip,
            tier_level: s.tier_level,
            banned_at: UNIX_EPOCH + Duration::from_secs(s.banned_at_secs),
            expires_at: s
                .expires_at_secs
                .map(|sec| UNIX_EPOCH + Duration::from_secs(sec)),
            reason: s.reason,
        }
    }
}

impl From<BanRecord> for StoredBanRecord {
    fn from(b: BanRecord) -> Self {
        let banned_at_secs = b
            .banned_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_secs = b
            .expires_at
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()));
        Self {
            target: b.ip.to_string(),
            ip: Some(b.ip),
            tier_level: b.tier_level,
            banned_at_secs,
            expires_at_secs,
            reason: b.reason,
        }
    }
}

pub struct EscalationEngine {
    find_time: Duration,
    max_retry: u32,
    tiers: Vec<Option<Duration>>,
    offenses: HashMap<IpAddr, (u32, Instant)>,
    ban_history: HashMap<IpAddr, usize>,
}

impl EscalationEngine {
    pub fn new(find_time: Duration, max_retry: u32, tiers: Vec<Option<Duration>>) -> Self {
        Self {
            find_time,
            max_retry,
            tiers,
            offenses: HashMap::new(),
            ban_history: HashMap::new(),
        }
    }

    pub fn record_offense(
        &mut self,
        ip: IpAddr,
        reason: &str,
        instant_permanent: bool,
    ) -> Option<BanRecord> {
        let now = SystemTime::now();
        let now_inst = Instant::now();

        if instant_permanent {
            let record = BanRecord {
                ip,
                tier_level: self.tiers.len().saturating_sub(1),
                banned_at: now,
                expires_at: None,
                reason: reason.to_string(),
            };
            self.offenses.remove(&ip);
            return Some(record);
        }

        let entry = self.offenses.entry(ip).or_insert((0, now_inst));
        if now_inst.duration_since(entry.1) > self.find_time {
            *entry = (1, now_inst);
        } else {
            entry.0 += 1;
        }

        if entry.0 >= self.max_retry {
            self.offenses.remove(&ip);
            let prev_tier = self.ban_history.get(&ip).copied().unwrap_or(0);
            let tier_level = if prev_tier < self.tiers.len() {
                prev_tier
            } else {
                self.tiers.len().saturating_sub(1)
            };
            self.ban_history.insert(ip, tier_level + 1);

            let duration_opt = self.tiers.get(tier_level).copied().flatten();
            let expires_at = duration_opt.map(|d| now + d);

            Some(BanRecord {
                ip,
                tier_level,
                banned_at: now,
                expires_at,
                reason: reason.to_string(),
            })
        } else {
            None
        }
    }
}
