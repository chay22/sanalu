use sanalu::intelligence::ThreatPipeline;
use sanalu::parser::SshStatefulParser;
use sanalu::storage::{RedbStore, StoredOffenseRecord};
use std::net::IpAddr;

#[test]
fn test_cleanup_stale_offenses_prunes_only_old_records() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_offenses_cleanup.redb");
    let store = RedbStore::open(&db_path).unwrap();

    let stale_ip: IpAddr = "198.51.100.10".parse().unwrap();
    let fresh_ip: IpAddr = "198.51.100.20".parse().unwrap();

    let stale_rec = StoredOffenseRecord {
        count: 3,
        first_seen_secs: 100,
        last_seen_secs: 100,
    };
    let fresh_rec = StoredOffenseRecord {
        count: 1,
        first_seen_secs: 500,
        last_seen_secs: 500,
    };

    store.save_offense(stale_ip, &stale_rec).unwrap();
    store.save_offense(fresh_ip, &fresh_rec).unwrap();

    let removed = store.cleanup_stale_offenses(200, 400).unwrap();
    assert_eq!(removed, 1);

    assert!(store.get_offense(stale_ip).unwrap().is_none());
    assert!(store.get_offense(fresh_ip).unwrap().is_some());

    let removed_again = store.cleanup_stale_offenses(200, 400).unwrap();
    assert_eq!(removed_again, 0);
}

#[test]
fn test_ssh_stateful_parser_bounds_pending_pids() {
    let mut parser = SshStatefulParser::new();

    for i in 1..=300 {
        let line = format!(
            "Sep  6 11:33:24 host sshd[{}]: error: kex_exchange_identification: client sent invalid protocol identifier \"GET /\"",
            i
        );
        parser.process_line(&line);
        assert!(parser.pending_count() <= 256);
    }

    assert_eq!(parser.pending_count(), 256);
}

#[test]
fn test_pipeline_cleanup_stale_strikes() {
    let pipeline = ThreatPipeline::new_test_instance();
    let ip1: IpAddr = "203.0.113.10".parse().unwrap();
    let ip2: IpAddr = "203.0.113.20".parse().unwrap();

    pipeline
        .strike_tracker()
        .record_shared_strike(ip1, 5, 300, 100);
    pipeline
        .strike_tracker()
        .record_shared_strike(ip2, 5, 300, 500);

    assert_eq!(pipeline.strike_tracker().len(), 2);

    pipeline.cleanup_stale_strikes(600, 200);

    assert_eq!(pipeline.strike_tracker().len(), 1);
    assert!(pipeline.strike_tracker().get_record(&ip1).is_none());
    assert!(pipeline.strike_tracker().get_record(&ip2).is_some());
}
