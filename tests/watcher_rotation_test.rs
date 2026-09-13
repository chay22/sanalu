use sanalu::discovery::NginxLogFormatKind;
use sanalu::engine::spawn_nginx_watcher;
use sanalu::firewall::NftablesBackend;
use sanalu::geo::IpLookupDb;
use sanalu::intelligence::ThreatPipeline;
use sanalu::storage::RedbStore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

async fn setup_test_watcher() -> (
    tempfile::TempDir,
    PathBuf,
    Arc<RedbStore>,
    mpsc::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_path = temp_dir.path().join("access.log");
    fs::write(&log_path, "").unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let store = Arc::new(RedbStore::open(&db_path).unwrap());
    let firewall = Arc::new(NftablesBackend::auto_detect(true));
    let pipeline = Arc::new(ThreatPipeline::new_test_instance());
    let geo_db = Arc::new(IpLookupDb::from_tsv_reader(b"".as_ref()).unwrap());
    let format = NginxLogFormatKind::Combined.to_compiled();
    let (tx, rx) = mpsc::channel(100);

    let handle = spawn_nginx_watcher(
        log_path.clone(),
        format,
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
async fn test_active_log_append_processed() {
    let (_temp_dir, log_path, store, mut rx, handle) = setup_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file,
        "203.0.113.10 - - [13/Sep/2026:10:00:00 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\""
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive ban notification")
        .expect("channel must remain open");

    let ban = store.get_ban("203.0.113.10").unwrap();
    assert!(ban.is_some());
    handle.abort();
}

#[tokio::test]
async fn test_logrotate_inode_change_detected() {
    let (temp_dir, log_path, store, mut rx, handle) = setup_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file,
        "203.0.113.10 - - [13/Sep/2026:10:00:00 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\""
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive initial ban notification")
        .expect("channel must remain open");
    assert!(store.get_ban("203.0.113.10").unwrap().is_some());

    let rotated_path = temp_dir.path().join("access.log.1");
    fs::rename(&log_path, &rotated_path).unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    fs::write(
        &log_path,
        "203.0.113.20 - - [13/Sep/2026:10:00:01 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\"\n",
    )
    .unwrap();

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive post-rotation ban notification")
        .expect("channel must remain open");

    assert!(store.get_ban("203.0.113.20").unwrap().is_some());
    handle.abort();
}

#[tokio::test]
async fn test_file_truncation_detected() {
    let (_temp_dir, log_path, store, mut rx, handle) = setup_test_watcher().await;

    let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file,
        "203.0.113.30 - - [13/Sep/2026:10:00:00 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\""
    )
    .unwrap();
    writeln!(
        file,
        "203.0.113.31 - - [13/Sep/2026:10:00:00 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\""
    )
    .unwrap();
    file.flush().unwrap();
    drop(file);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive initial ban notification 1")
        .expect("channel must remain open");
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive initial ban notification 2")
        .expect("channel must remain open");
    assert!(store.get_ban("203.0.113.30").unwrap().is_some());
    assert!(store.get_ban("203.0.113.31").unwrap().is_some());

    let truncated = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&log_path)
        .unwrap();
    drop(truncated);

    tokio::time::sleep(Duration::from_millis(600)).await;

    let mut file2 = OpenOptions::new().append(true).open(&log_path).unwrap();
    writeln!(
        file2,
        "203.0.113.40 - - [13/Sep/2026:10:00:01 +0000] \"GET /%00 HTTP/1.1\" 404 100 \"-\" \"curl/7.68.0\""
    )
    .unwrap();
    file2.flush().unwrap();
    drop(file2);

    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("must receive post-truncation ban notification")
        .expect("channel must remain open");

    assert!(store.get_ban("203.0.113.40").unwrap().is_some());
    handle.abort();
}
