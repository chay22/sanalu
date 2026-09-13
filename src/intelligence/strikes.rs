use super::category::ThreatCategory;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrikeResult {
    UnderThreshold { current: u8, max: u8 },
    ThresholdReached { count: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpStrikeRecord {
    pub critical_strikes: u8,
    pub last_critical_secs: u64,
    pub isolated_cat: u8,
    pub isolated_strikes: u8,
    pub last_isolated_secs: u64,
}

pub struct IpStrikeTracker {
    entries: RwLock<HashMap<IpAddr, IpStrikeRecord>>,
}

impl IpStrikeTracker {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn record_shared_strike(
        &self,
        ip: IpAddr,
        threshold: u8,
        window_secs: u64,
        now_secs: u64,
    ) -> StrikeResult {
        let mut lock = self.entries.write().unwrap();
        let record = lock.entry(ip).or_default();
        if record.last_critical_secs != 0
            && now_secs.saturating_sub(record.last_critical_secs) > window_secs
        {
            record.critical_strikes = 0;
        }
        record.critical_strikes = record.critical_strikes.saturating_add(1);
        record.last_critical_secs = now_secs;
        if record.critical_strikes >= threshold {
            StrikeResult::ThresholdReached {
                count: record.critical_strikes,
            }
        } else {
            StrikeResult::UnderThreshold {
                current: record.critical_strikes,
                max: threshold,
            }
        }
    }

    pub fn record_isolated_strike(
        &self,
        ip: IpAddr,
        cat: ThreatCategory,
        threshold: u8,
        window_secs: u64,
        now_secs: u64,
    ) -> StrikeResult {
        let cat_u8 = cat.as_u8();
        let mut lock = self.entries.write().unwrap();
        let record = lock.entry(ip).or_default();
        if record.isolated_cat != cat_u8
            || (record.last_isolated_secs != 0
                && now_secs.saturating_sub(record.last_isolated_secs) > window_secs)
        {
            record.isolated_cat = cat_u8;
            record.isolated_strikes = 0;
        }
        record.isolated_strikes = record.isolated_strikes.saturating_add(1);
        record.last_isolated_secs = now_secs;
        if record.isolated_strikes >= threshold {
            StrikeResult::ThresholdReached {
                count: record.isolated_strikes,
            }
        } else {
            StrikeResult::UnderThreshold {
                current: record.isolated_strikes,
                max: threshold,
            }
        }
    }

    pub fn cleanup_stale(&self, now_secs: u64, max_idle_secs: u64) {
        let mut lock = self.entries.write().unwrap();
        lock.retain(|_, rec| {
            let crit_idle = if rec.last_critical_secs == 0 {
                u64::MAX
            } else {
                now_secs.saturating_sub(rec.last_critical_secs)
            };
            let iso_idle = if rec.last_isolated_secs == 0 {
                u64::MAX
            } else {
                now_secs.saturating_sub(rec.last_isolated_secs)
            };
            crit_idle <= max_idle_secs || iso_idle <= max_idle_secs
        });
    }

    pub fn clear_ip(&self, ip: &IpAddr) {
        let mut lock = self.entries.write().unwrap();
        lock.remove(ip);
    }

    pub fn get_record(&self, ip: &IpAddr) -> Option<IpStrikeRecord> {
        let lock = self.entries.read().unwrap();
        lock.get(ip).copied()
    }

    pub fn len(&self) -> usize {
        let lock = self.entries.read().unwrap();
        lock.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IpStrikeTracker {
    fn default() -> Self {
        Self::new()
    }
}
