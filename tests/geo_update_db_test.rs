use flate2::Compression;
use flate2::write::GzEncoder;
use sanalu::cli::admin::{handle_update_db, handle_update_db_with_url};
use sanalu::geo::{IpLookupDb, download_and_save_ip2asn_db, save_db_to_file};
use std::io::Write;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_save_db_to_file_creates_parent_dirs_and_loads() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir
        .path()
        .join("nested")
        .join("dir")
        .join("test_db.tsv");

    let tsv_data = b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";

    save_db_to_file(tsv_data, &dest_path).unwrap();
    assert!(dest_path.exists());

    let db = IpLookupDb::from_file(&dest_path).unwrap();
    assert_eq!(db.len(), 3);
    assert!(!db.is_empty());

    let meta = db.lookup("8.8.8.8".parse().unwrap()).unwrap();
    assert_eq!(meta.asn, 15169);
    assert_eq!(&meta.country, b"US");
}

#[tokio::test]
async fn test_download_and_save_ip2asn_db_mock() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("mock_dest.tsv");

    let count = download_and_save_ip2asn_db("mock", &dest_path)
        .await
        .unwrap();
    assert_eq!(count, 3);
    assert!(dest_path.exists());

    let db = IpLookupDb::from_file(&dest_path).unwrap();
    assert_eq!(db.len(), 3);
}

#[tokio::test]
async fn test_download_and_save_ip2asn_db_local_http() {
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
    let dest_path = temp_dir.path().join("http_downloaded.tsv");
    let url = format!("http://{}/ip2asn-v4.tsv.gz", addr);

    let count = download_and_save_ip2asn_db(&url, &dest_path).await.unwrap();
    assert_eq!(count, 3);
    assert!(dest_path.exists());

    let db = IpLookupDb::from_file(&dest_path).unwrap();
    assert_eq!(db.len(), 3);
}

#[tokio::test]
async fn test_handle_update_db_output() {
    let temp_dir = tempfile::tempdir().unwrap();
    let dest_path = temp_dir.path().join("test_update_db.tsv");

    let mut output = Vec::new();
    handle_update_db(&mut output, &dest_path).await.unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Downloading latest IP-to-ASN/Country database..."));
    assert!(output_str.contains("Database saved to"));
    assert!(output_str.contains(&format!("{:?}", dest_path)));
    assert!(output_str.contains("IP ranges loaded"));
    assert!(dest_path.exists());
}

#[tokio::test]
async fn test_handle_update_db_with_url_output() {
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
    let dest_path = temp_dir.path().join("server_update.tsv");
    let url = format!("http://{}/ip2asn-v4.tsv.gz", addr);

    let mut output = Vec::new();
    handle_update_db_with_url(&mut output, &dest_path, &url)
        .await
        .unwrap();

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Downloading latest IP-to-ASN/Country database..."));
    assert!(output_str.contains("Database saved to"));
    assert!(output_str.contains("(3 IP ranges loaded)"));
    assert!(dest_path.exists());
}
