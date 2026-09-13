use sanalu::intelligence::{IpStrikeTracker, StrikeResult, ThreatCategory};
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;

#[test]
fn test_shared_strikes_accumulate_and_reach_threshold() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let threshold = 3;
    let window_secs = 60;
    let now = 1000;

    let res1 = tracker.record_shared_strike(ip, threshold, window_secs, now);
    assert_eq!(res1, StrikeResult::UnderThreshold { current: 1, max: 3 });

    let res2 = tracker.record_shared_strike(ip, threshold, window_secs, now + 10);
    assert_eq!(res2, StrikeResult::UnderThreshold { current: 2, max: 3 });

    let res3 = tracker.record_shared_strike(ip, threshold, window_secs, now + 20);
    assert_eq!(res3, StrikeResult::ThresholdReached { count: 3 });

    let res4 = tracker.record_shared_strike(ip, threshold, window_secs, now + 30);
    assert_eq!(res4, StrikeResult::ThresholdReached { count: 4 });
}

#[test]
fn test_window_expiration_resets_shared_strike_count() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let threshold = 3;
    let window_secs = 60;
    let now = 1000;

    let res1 = tracker.record_shared_strike(ip, threshold, window_secs, now);
    assert_eq!(res1, StrikeResult::UnderThreshold { current: 1, max: 3 });

    let res2 = tracker.record_shared_strike(ip, threshold, window_secs, now + 61);
    assert_eq!(res2, StrikeResult::UnderThreshold { current: 1, max: 3 });

    let res3 = tracker.record_shared_strike(ip, threshold, window_secs, now + 80);
    assert_eq!(res3, StrikeResult::UnderThreshold { current: 2, max: 3 });
}

#[test]
fn test_isolated_strikes_do_not_contaminate_critical_pool() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "172.16.0.5".parse().unwrap();
    let threshold = 3;
    let window_secs = 60;
    let now = 1000;

    let iso_res1 =
        tracker.record_isolated_strike(ip, ThreatCategory::Backups, threshold, window_secs, now);
    assert_eq!(
        iso_res1,
        StrikeResult::UnderThreshold { current: 1, max: 3 }
    );

    let iso_res2 = tracker.record_isolated_strike(
        ip,
        ThreatCategory::Backups,
        threshold,
        window_secs,
        now + 5,
    );
    assert_eq!(
        iso_res2,
        StrikeResult::UnderThreshold { current: 2, max: 3 }
    );

    let record = tracker.get_record(&ip).unwrap();
    assert_eq!(record.critical_strikes, 0);
    assert_eq!(record.last_critical_secs, 0);
    assert_eq!(record.isolated_strikes, 2);
    assert_eq!(record.isolated_cat, ThreatCategory::Backups.as_u8());
    assert_eq!(record.last_isolated_secs, now + 5);

    let crit_res = tracker.record_shared_strike(ip, threshold, window_secs, now + 10);
    assert_eq!(
        crit_res,
        StrikeResult::UnderThreshold { current: 1, max: 3 }
    );

    let record_after = tracker.get_record(&ip).unwrap();
    assert_eq!(record_after.critical_strikes, 1);
    assert_eq!(record_after.isolated_strikes, 2);
}

#[test]
fn test_isolated_strikes_category_switch_resets_isolated_count() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "172.16.0.10".parse().unwrap();
    let threshold = 3;
    let window_secs = 60;
    let now = 1000;

    tracker.record_isolated_strike(ip, ThreatCategory::Backups, threshold, window_secs, now);
    tracker.record_isolated_strike(ip, ThreatCategory::Backups, threshold, window_secs, now + 1);

    let rec1 = tracker.get_record(&ip).unwrap();
    assert_eq!(rec1.isolated_strikes, 2);
    assert_eq!(rec1.isolated_cat, ThreatCategory::Backups.as_u8());

    let res =
        tracker.record_isolated_strike(ip, ThreatCategory::Php, threshold, window_secs, now + 2);
    assert_eq!(res, StrikeResult::UnderThreshold { current: 1, max: 3 });

    let rec2 = tracker.get_record(&ip).unwrap();
    assert_eq!(rec2.isolated_strikes, 1);
    assert_eq!(rec2.isolated_cat, ThreatCategory::Php.as_u8());
}

#[test]
fn test_isolated_strikes_window_expiration() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "172.16.0.15".parse().unwrap();
    let threshold = 3;
    let window_secs = 60;
    let now = 1000;

    tracker.record_isolated_strike(ip, ThreatCategory::Php, threshold, window_secs, now);
    tracker.record_isolated_strike(ip, ThreatCategory::Php, threshold, window_secs, now + 10);

    let res =
        tracker.record_isolated_strike(ip, ThreatCategory::Php, threshold, window_secs, now + 75);
    assert_eq!(res, StrikeResult::UnderThreshold { current: 1, max: 3 });
}

#[test]
fn test_multi_threaded_concurrency() {
    let tracker = Arc::new(IpStrikeTracker::new());
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let mut handles = Vec::new();

    for i in 0..10 {
        let t = Arc::clone(&tracker);
        handles.push(thread::spawn(move || {
            for j in 0..10 {
                let now = 1000 + (i * 10 + j) as u64;
                if (i + j) % 2 == 0 {
                    t.record_shared_strike(ip, 250, 3600, now);
                } else {
                    t.record_isolated_strike(ip, ThreatCategory::Wordpress, 250, 3600, now);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let record = tracker.get_record(&ip).unwrap();
    assert_eq!(record.critical_strikes, 50);
    assert_eq!(record.isolated_strikes, 50);
}

#[test]
fn test_cleanup_stale_records() {
    let tracker = IpStrikeTracker::new();
    let ip_active: IpAddr = "1.1.1.1".parse().unwrap();
    let ip_stale_crit: IpAddr = "2.2.2.2".parse().unwrap();
    let ip_stale_iso: IpAddr = "3.3.3.3".parse().unwrap();

    let now = 10_000;
    let max_idle = 300;

    tracker.record_shared_strike(ip_active, 5, 600, now - 100);
    tracker.record_shared_strike(ip_stale_crit, 5, 600, now - 500);
    tracker.record_isolated_strike(ip_stale_iso, ThreatCategory::Php, 5, 600, now - 400);

    assert_eq!(tracker.len(), 3);

    tracker.cleanup_stale(now, max_idle);

    assert_eq!(tracker.len(), 1);
    assert!(tracker.get_record(&ip_active).is_some());
    assert!(tracker.get_record(&ip_stale_crit).is_none());
    assert!(tracker.get_record(&ip_stale_iso).is_none());
}

#[test]
fn test_clear_ip_and_empty_check() {
    let tracker = IpStrikeTracker::new();
    assert!(tracker.is_empty());
    assert_eq!(tracker.len(), 0);

    let ip1: IpAddr = "10.10.10.1".parse().unwrap();
    let ip2: IpAddr = "10.10.10.2".parse().unwrap();

    tracker.record_shared_strike(ip1, 3, 60, 1000);
    tracker.record_shared_strike(ip2, 3, 60, 1000);

    assert_eq!(tracker.len(), 2);
    assert!(!tracker.is_empty());

    tracker.clear_ip(&ip1);
    assert_eq!(tracker.len(), 1);
    assert!(tracker.get_record(&ip1).is_none());
    assert!(tracker.get_record(&ip2).is_some());

    tracker.clear_ip(&ip2);
    assert!(tracker.is_empty());
}

#[test]
fn test_saturating_strike_counts() {
    let tracker = IpStrikeTracker::new();
    let ip: IpAddr = "8.8.8.8".parse().unwrap();

    for _ in 0..300 {
        tracker.record_shared_strike(ip, 255, 3600, 1000);
    }

    let record = tracker.get_record(&ip).unwrap();
    assert_eq!(record.critical_strikes, 255);
}
