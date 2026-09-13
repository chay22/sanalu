use sanalu::discovery::SshLogSource;
use sanalu::engine::spawn_ssh_watcher;
use sanalu::firewall::NftablesBackend;
use sanalu::geo::IpLookupDb;
use sanalu::intelligence::{PipelineAction, ThreatPipeline};
use sanalu::parser::SshEvent;
use sanalu::storage::RedbStore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

async fn setup_ssh_test_watcher() -> (
    tempfile::TempDir,
    PathBuf,
    Arc<RedbStore>,
    mpsc::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_path = temp_dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let store = Arc::new(RedbStore::open(&db_path).unwrap());
    let firewall = Arc::new(NftablesBackend::auto_detect(true));
    let pipeline = Arc::new(ThreatPipeline::new_test_instance());
    let geo_db = Arc::new(IpLookupDb::from_tsv_reader(b"".as_ref()).unwrap());
    let (tx, rx) = mpsc::channel(100);

    let handle = spawn_ssh_watcher(
        SshLogSource::File(log_path.clone()),
        pipeline,
        firewall,
        store.clone(),
        Some(tx),
        geo_db,
    );

    tokio::time::sleep(Duration::from_millis(100)).await;

    (temp_dir, log_path, store, rx, handle)
}

#[tokio::test]
async fn test_ssh_scanner_probe_immediate_ban() {
    let (_temp_dir, log_path, store, mut rx, handle) = setup_ssh_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file,
        "Sep  6 09:26:17 vmi1529040 sshd[2698855]: banner exchange: Connection from 198.51.100.22 port 47242: invalid format"
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive ban notification")
        .expect("channel must remain open");

    let ban = store.get_ban("198.51.100.22").unwrap();
    assert!(ban.is_some());
    let record = ban.unwrap();
    assert_eq!(record.reason, "probe:ssh:banner_invalid_format");
    handle.abort();
}

#[tokio::test]
async fn test_ssh_multiline_pid_correlation_ban() {
    let (_temp_dir, log_path, store, mut rx, handle) = setup_ssh_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file,
        "Sep  6 11:33:24 vmi1529040 sshd[2703646]: error: kex_exchange_identification: client sent invalid protocol identifier \"GET / HTTP/1.1\""
    )
    .unwrap();
    file.flush().unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(store.get_ban("198.51.100.23").unwrap().is_none());

    writeln!(
        file,
        "Sep  6 11:33:24 vmi1529040 sshd[2703646]: banner exchange: Connection from 198.51.100.23 port 41478: invalid format"
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive ban notification")
        .expect("channel must remain open");

    let ban = store.get_ban("198.51.100.23").unwrap();
    assert!(ban.is_some());
    let record = ban.unwrap();
    assert_eq!(record.reason, "probe:ssh:invalid_protocol_identifier");
    handle.abort();
}

#[tokio::test]
async fn test_ssh_auth_failure_strike_accumulation_ban_on_5th() {
    let (_temp_dir, log_path, store, mut rx, handle) = setup_ssh_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    for i in 1..=4 {
        writeln!(
            file,
            "Sep  6 10:00:0{} vmi1529040 sshd[269999{}]: Failed password for invalid user admin from 198.51.100.24 port 55555 ssh2",
            i, i
        )
        .unwrap();
        file.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(store.get_ban("198.51.100.24").unwrap().is_none());
    }

    writeln!(
        file,
        "Sep  6 10:00:05 vmi1529040 sshd[2699995]: Failed password for invalid user admin from 198.51.100.24 port 55555 ssh2"
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive ban notification on 5th strike")
        .expect("channel must remain open");

    let ban = store.get_ban("198.51.100.24").unwrap();
    assert!(ban.is_some());
    let record = ban.unwrap();
    assert_eq!(record.reason, "probe:ssh:auth_failures:5");
    handle.abort();
}

#[test]
fn test_evaluate_ssh_event_unit() {
    let pipe = ThreatPipeline::new_test_instance();

    assert_eq!(
        pipe.evaluate_ssh_event(&SshEvent::Ignore),
        PipelineAction::Allow
    );

    let private_probe = SshEvent::ScannerProbe {
        ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        reason: "banner_invalid_format",
    };
    assert_eq!(
        pipe.evaluate_ssh_event(&private_probe),
        PipelineAction::Allow
    );

    let public_probe = SshEvent::ScannerProbe {
        ip: "198.51.100.50".parse::<IpAddr>().unwrap(),
        reason: "invalid_protocol_identifier",
    };
    assert_eq!(
        pipe.evaluate_ssh_event(&public_probe),
        PipelineAction::Ban {
            reason: "probe:ssh:invalid_protocol_identifier".into(),
            permanent: false,
        }
    );

    let auth_fail_ip: IpAddr = "198.51.100.60".parse().unwrap();
    for _ in 1..=4 {
        assert_eq!(
            pipe.evaluate_ssh_event(&SshEvent::AuthFailure {
                ip: auth_fail_ip,
                user: "root".into(),
            }),
            PipelineAction::Allow
        );
    }
    assert_eq!(
        pipe.evaluate_ssh_event(&SshEvent::AuthFailure {
            ip: auth_fail_ip,
            user: "root".into(),
        }),
        PipelineAction::Ban {
            reason: "probe:ssh:auth_failures:5".into(),
            permanent: false,
        }
    );
}
