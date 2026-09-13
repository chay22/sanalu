use flate2::Compression;
use flate2::write::GzEncoder;
use sanalu::daemon::{NginxWatcherRegistry, reconcile_watchers};
use sanalu::firewall::NftablesBackend;
use sanalu::geo::{IpLookupDb, download_if_stale_or_missing, save_db_to_file};
use sanalu::intelligence::ThreatPipeline;
use sanalu::storage::RedbStore;
use std::fs::{File, FileTimes};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_download_if_stale_or_missing_fresh_file_returns_none() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("fresh.tsv");
    let tsv_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n";
    save_db_to_file(tsv_data, &dest_path).unwrap();

    let result =
        download_if_stale_or_missing("http://127.0.0.1:1/nonexistent", &dest_path, 30 * 86400)
            .await
            .unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_download_if_stale_or_missing_missing_file_downloads() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("missing.tsv");

    let result = download_if_stale_or_missing("mock", &dest_path, 30 * 86400)
        .await
        .unwrap();
    assert_eq!(result, Some(3));
    assert!(dest_path.exists());

    let db = IpLookupDb::from_file(&dest_path).unwrap();
    assert_eq!(db.len(), 3);
}

#[tokio::test]
async fn test_download_if_stale_or_missing_http_304_not_modified() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut req_buf = [0u8; 1024];
            let n = socket.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            assert!(req_str.to_lowercase().contains("if-modified-since"));
            let resp = "HTTP/1.1 304 Not Modified\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("stale.tsv");
    let tsv_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n";
    save_db_to_file(tsv_data, &dest_path).unwrap();

    let file = File::options().write(true).open(&dest_path).unwrap();
    let past = SystemTime::now() - Duration::from_secs(40 * 86400);
    file.set_times(FileTimes::new().set_modified(past)).unwrap();
    drop(file);

    let url = format!("http://{}/ip2asn-v4.tsv.gz", addr);
    let result = download_if_stale_or_missing(&url, &dest_path, 30 * 86400)
        .await
        .unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_download_if_stale_or_missing_http_200_when_stale() {
    let tsv_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(tsv_data).unwrap();
    let gzipped = encoder.finish().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut req_buf = [0u8; 1024];
            let _ = socket.read(&mut req_buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/x-gzip\r\n\r\n",
                gzipped.len()
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.write_all(&gzipped).await;
        }
    });

    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("stale_to_update.tsv");
    let old_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n";
    save_db_to_file(old_data, &dest_path).unwrap();

    let file = File::options().write(true).open(&dest_path).unwrap();
    let past = SystemTime::now() - Duration::from_secs(40 * 86400);
    file.set_times(FileTimes::new().set_modified(past)).unwrap();
    drop(file);

    let url = format!("http://{}/ip2asn-v4.tsv.gz", addr);
    let result = download_if_stale_or_missing(&url, &dest_path, 30 * 86400)
        .await
        .unwrap();
    assert_eq!(result, Some(3));

    let db = IpLookupDb::from_file(&dest_path).unwrap();
    assert_eq!(db.len(), 3);
}

#[tokio::test]
async fn test_reconcile_watchers_syncs_asn_fallback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let redb_path = temp_dir.path().join("test.redb");
    let store = Arc::new(RedbStore::open(&redb_path).unwrap());
    store.set_asn_blocked(13335, true).unwrap();

    let tsv_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n";
    let geo_db = Arc::new(IpLookupDb::from_tsv_reader(&tsv_data[..]).unwrap());

    let firewall = Arc::new(NftablesBackend::auto_detect(true));
    let pipeline = Arc::new(ThreatPipeline::new_test_instance());
    let mut registry = NginxWatcherRegistry::new();

    reconcile_watchers(&mut registry, &pipeline, &firewall, &store, &None, &geo_db);

    let blocked = store.list_blocked_asns().unwrap();
    assert_eq!(blocked, vec![13335]);
}
